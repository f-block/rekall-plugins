#  API pointer detector
#
#    Copyright (c) 2019, Frank Block <coding@f-block.org>
#
#       All rights reserved.
#
#       Redistribution and use in source and binary forms, with or without modification,
#       are permitted provided that the following conditions are met:
#
#       * Redistributions of source code must retain the above copyright notice, this
#         list of conditions and the following disclaimer.
#       * Redistributions in binary form must reproduce the above copyright notice,
#         this list of conditions and the following disclaimer in the documentation
#         and/or other materials provided with the distribution.
#       * The names of the contributors may not be used to endorse or promote products
#         derived from this software without specific prior written permission.
#
#       THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#       AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#       IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#       ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
#       LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#       DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#       SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
#       CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
#       OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#       OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

__author__ = "Frank Block <coding@f-block.org>"

import struct
from rekall import scan
from rekall.plugins import core
from rekall.plugins.windows import common
from rekall.plugins.overlays.windows import pe_vtypes


class PointerDetector(core.DirectoryDumperMixin, common.WinProcessFilter):
    """This plugin numerates all exported functions from all loaded DLLs and 
    searches the memory for any pointer to them (essentially a search for 
    dynamically resolved APIs). This plugin can assist in identifying 
    dynamically resolved APIs and especially memory regions containing DLLs 
    loaded with techniques such as reflective DLL injection."""

    name = "pointerdetector"
    initialized = False

    table_header = [
        dict(name='_EPROCESS', type="_EPROCESS", hidden=True),
        dict(name="divider", type="Divider"),
        dict(name='VAD', style="address"),
        dict(name='Hit', style="address"),
        dict(name='Distance', align='r'),
        dict(name='Pointer', style="address"),
        dict(name='API', width=50),
        dict(name='Count', align='r'),
    ]
    
    # based on impscan, but customized for performance
    def _enum_apis(self, all_mods):
        """Enumerate all exported functions from process space.

        @param all_mods: list of _LDR_DATA_TABLE_ENTRY

        To enum process APIs, all_mods is a list of DLLs.

        The function name is used if available, otherwise
        we take the ordinal value.
        """
        exports = {}

        for i, mod in enumerate(all_mods):
            self.session.report_progress("Scanning exports %s/%s" % (
                i, len(all_mods)))

            pe = pe_vtypes.PE(address_space=mod.obj_vm,
                              session=self.session, image_base=mod.DllBase)

            export_directory = pe.nt_header.OptionalHeader.DataDirectory[
            'IMAGE_DIRECTORY_ENTRY_EXPORT'].dereference()

            dll = export_directory.Name.dereference()
            function_table = export_directory.AddressOfFunctions.dereference()

            for func_index, pointer in enumerate(function_table):
                exports[pointer.v()] = (mod,
                                        pointer,
                                        export_directory,
                                        func_index)

        return exports


    def _resolve_api_pointers(self, pointers, apis):
        """Resolves the given API pointers using the infos in the apis dict.
        The apis dict is the result from _enum_apis
        
        Returns a dict in the form of:
        {api_address: [dll_name, function_name],
         api_address2: ...}
        """

        resolved_pointers = dict()
        pointers = set(pointers)
        apis_sorted = sorted([apis[x] for x in pointers], key=lambda x: x[2])

        working_set = dict()
        for el in apis_sorted:
            _, pointer, export_directory, func_index = el
            if pointer == 0:
                continue
            if export_directory not in working_set:
                working_set[export_directory] = dict()

            working_set[export_directory][func_index] = pointer

        for export_directory, values in working_set.items():
            dll_name = apis[list(values.values())[0]][0].BaseDllName\
                       .v().rstrip("\x00")
            name_table = export_directory.AddressOfNames.dereference()
            ordinal_table = \
                export_directory.AddressOfNameOrdinals.dereference()

            # there are cases, where len(ord_table) > len(name_table)
            for i in range(len(name_table)):
                ord_num = ordinal_table[i]
                if ord_num in values:
                    #TODO consider empty names
                    pointer = values[ord_num]
                    resolved_pointers[pointer] = \
                        [dll_name, name_table[i].dereference()]

        return resolved_pointers


    def initialize(self, task=None):
        if self.initialized:
            return self.initialized

        # if no task is given, we expect the process context to be switched
        # already.
        if task:
            self.task = task
            self.task_as = self.task.get_process_address_space()

        else:
            self.task = self.session.GetParameter("process_context")
            self.task_as = self.task.get_process_address_space()
            
        self.psize = self.profile.get_obj_size("Pointer")

        all_mods = list(self.task.get_load_modules())
        if not all_mods:
            # PEB is paged or no DLLs loaded
            self.session.logging.error(
                "Cannot load DLLs in process AS of process {:d}"
                .format(self.task.pid.v()))
            return False

        self.exported_apis = self._enum_apis(all_mods)
        func_addresses = [x[1].v() for x in list(self.exported_apis.values())]
        func_addresses = set(func_addresses)
        if 0 in func_addresses:
            func_addresses.remove(0)

        self.scanner = scan.PointerScanner(profile=self.profile,
                                           session=self.session,
                                           address_space=self.task_as,
                                           pointers=func_addresses)
        self.initialized = True
        
        return self.initialized

        
    def get_api_pointers(self, api_hits_dict):
        """Returns the final dict with all hits and resolved API names.
        
        Expects a dict in the form of:
        
        {vad_start:
            {'hits': [ [hit: pointer], [hit2: pointer], [hit3: pointer2], ...],
             'pointers': {pointer: count, pointer2: count, ...}
            },
         vad_start2:
            {'hits': ...

        which is essentially the result of scan_for_pointers for all VADs,
        
        and returns:
        
        {vad_start:
            {'hits': ... same format as input ...
             'pointers': { pointer: ['module!apiname', count],
                           pointer2: ['module!apiname2', count2],
                           ...
         vad_start2: ...
        
        This function expects the process context to be switched already.
        """
        
        self.initialize()
        # get a unique list of all api addresses that have an
        # associated pointer
        api_addresses = set([x for _,y in api_hits_dict.items() 
                             for x in y['pointers'].keys()])
        # now we resolve each of those functions to its module and name
        self.resolved_pointers = \
            self._resolve_api_pointers(api_addresses, self.exported_apis)
        impscan = self.session.plugins.impscan()

        result = dict()
        for start_address, api_hits in api_hits_dict.items():
            result[start_address] = dict()
            pointers = api_hits['pointers']

            for pointer, hits in pointers.items():
                if not pointer in self.resolved_pointers:
                    temp = self.exported_apis[pointer]
                    mod_name = self.exported_apis[pointer][0]\
                               .BaseDllName.v().rstrip("\x00")
                    func_name = str(temp[3])
    
                else:
                    mod_name = self.resolved_pointers[pointer][0]
                    func_name = self.resolved_pointers[pointer][1]
                    mod_name, func_name = impscan._original_import(mod_name,
                                                                   func_name)

                resolved_name = "{:s}!{:s}".format(mod_name, func_name)

                #TODO make nicer
                if not 'hits' in result[start_address]:
                    result[start_address]['hits'] = list()
                if not 'pointers' in result[start_address]:
                    result[start_address]['pointers'] = dict()
                result[start_address]['pointers'][pointer] = \
                    [resolved_name, len(hits)]

                for hit in hits:
                    result[start_address]['hits'].append([hit, pointer])

            if 'hits' in result[start_address]:
                result[start_address]['hits'] = \
                    sorted(result[start_address]['hits'])

        return result

        
    def scan_for_pointers(self, start, length):
        """Scans the given memory region from start till start+length for 
        API pointers.
        
        Returns a dict in the form of:
        {'hits': [ [hit: pointer], [hit2: pointer], [hit3: pointer2], ... ],
         'pointers': {pointer: count, pointer2: count, pointer3: count, ...}}
        """
        
        self.initialize()
        unpack_string = 'I' if self.psize == 4 else 'Q'
        api_hits = dict()
        api_hits['hits'] = list()
        api_hits['pointers'] = dict()
        
        for hit in self.scanner.scan(offset=start, maxlen=length):
            pointer = self.task_as.read(hit, self.psize)
            pointer = struct.unpack(unpack_string, pointer)[0]
            if pointer in api_hits['pointers']:
                api_hits['pointers'][pointer].append(hit)
    
            else:
                api_hits['pointers'][pointer] = [hit]
            
            api_hits['hits'].append([hit, pointer])
        
        api_hits['hits'] = sorted(api_hits['hits'])
        return api_hits


    def vad_contains_image_file(self, vad):
        try:
            sec_obj_poi = vad.ControlArea.FilePointer.SectionObjectPointer
            if sec_obj_poi.ImageSectionObject:
                return True
        except AttributeError:
            pass

        return False


    def collect(self):
        cc = self.session.plugins.cc()
        for task in self.filter_processes():
            self.initialized = False
            with cc:
                cc.SwitchProcessContext(task)

                yield dict(divider="Task: %s (%s)" % (task.name, task.pid))

                api_hits = dict()
                task_as = task.get_process_address_space()
                for vad in task.RealVadRoot.traverse():
                    if self.vad_contains_image_file(vad):
                        continue

                    if self.session.plugins.malfind()._is_vad_empty(
                            vad, task_as):
                        continue

                    # we don't generate the exports list unless we find
                    # at least one memory region to investigate
                    if not self.initialize():
                        continue
                    
                    api_hits[vad.Start] = dict()
                    api_hits[vad.Start] = self.scan_for_pointers(
                        vad.Start, vad.Length)

                if len(api_hits) <= 0:
                    continue

                for vad_start, values in \
                        self.get_api_pointers(api_hits).items():

                    if not values:
                        continue

                    prev_hit = 0
                    for hit, pointer in values['hits']:
                        distance = ((hit - prev_hit - self.psize) 
                                    if prev_hit > 0 else 0)

                        yield dict(
                            VAD=vad_start,            
                            Hit=hit,
                            Distance=distance,
                            Pointer=pointer,
                            API=values['pointers'][pointer][0],
                            Count=values['pointers'][pointer][1]
                        )
                        
                        prev_hit = hit
