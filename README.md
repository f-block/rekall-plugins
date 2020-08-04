# pointer_detector

This plugin numerates all exported functions from all loaded DLLs and searches the memory for any pointer to them (essentially a search for dynamically resolved APIs). This plugin can assist in identifying dynamically resolved APIs and especially memory regions containing DLLs loaded with techniques such as reflective DLL injection.

## Usage

One way to use new plugins is to copy them to the appropriate folder (e.g. rekall/plugins/windows) and to add an entry to the __init__.py file, similar to this:
```
    from rekall.plugins.windows import pointer_detector
```

The plugin can then be used like this:

```
rekall -f mem.dump pointerdetector 744

     VAD        Hit     Distance  Pointer                          API                         Count
  ---------- ---------- -------- ---------- -------------------------------------------------- -----
    0x200000   0x20b000        0 0x771cbf0a kernel32.dll!InterlockedExchange                       1
    0x200000   0x20b004        0 0x771d3363 kernel32.dll!LocalAlloc                                1
    0x200000   0x20b008        0 0x77b32dd6 ntdll.dll!RtlAllocateHeap                              1
    0x200000   0x20b00c        0 0x771cbbc0 kernel32.dll!InterlockedIncrement                      1
    0x200000   0x20b010        0 0x771cbbf0 kernel32.dll!InterlockedDecrement                      1
    0x200000   0x20b014        0 0x771cbbd0 kernel32.dll!HeapFree                                  1
    0x200000   0x20b018        0 0x771c2301 kernel32.dll!HeapDestroy                               1
    0x200000   0x20b01c        0 0x771d3ea2 kernel32.dll!HeapCreate                                1
    0x200000   0x20b020        0 0x771cbccc kernel32.dll!SetEvent                                  1
    0x200000   0x20b024        0 0x771cba60 kernel32.dll!GetTickCount                              1
    0x200000   0x20b028        0 0x771c0ef7 kernel32.dll!CreateEventA                              1
    0x200000   0x20b02c        0 0x771cba90 kernel32.dll!WaitForSingleObject                       1
    0x200000   0x20b030        0 0x771cca7c kernel32.dll!CloseHandle                               1
    0x200000   0x20b034        0 0x771ccac4 kernel32.dll!GetCurrentProcessId                       1
    0x200000   0x20b038        0 0x771c0296 kernel32.dll!SleepEx                                   1
    0x200000   0x20b03c        0 0x771b3d7b kernel32.dll!CreateWaitableTimerA                      1
    0x200000   0x20b040        0 0x771ca611 kernel32.dll!lstrlenA                                  1
    0x200000   0x20b044        0 0x771c9793 kernel32.dll!lstrcpyA                                  1
    0x200000   0x20b048        0 0x771c899b kernel32.dll!MapViewOfFile                             1
    0x200000   0x20b04c        0 0x771d2fde kernel32.dll!GetSystemTimeAsFileTime                   1
```

- **VAD**: The start address of the memory region.
- **Hit**: The address where we found a pointer to an exported function.
- **Distance**: The number of bytes between the last hit and this hit.
- **API**: The name of the containing module and function name.
- **Count**: How often this API has been found in this VAD.


# ptemalfind (formerly known as ptenum)
This module implements a class to enumerate all Page Table Entries (PTEs) and a plugin (ptemalfind), using this class, which can be seen as an improved version of
malfind. It retrieves a page's actual protection from its PTE value and from that its executable state, despite any hiding technique described in the following paper.

The most current version of the plugin is in this repository. Other resources:
- The original research material can be grabbed from [https://github.com/f-block/DFRWS-USA-2019](https://github.com/f-block/DFRWS-USA-2019)
- [DFRWS USA 2019 Research Paper and Slides](https://www.dfrws.org/conferences/dfrws-usa-2019/sessions/windows-memory-forensics-detecting-unintentionally-hidden)

# Linux Glibc Heap Analysis plugins

For the current version of the Rekall plugins:
- [heap_analysis](https://github.com/google/rekall/blob/master/rekall-core/rekall/plugins/linux/heap_analysis.py)
- [keepassx](https://github.com/google/rekall/blob/master/rekall-core/rekall/plugins/linux/keepassx.py)
- [zsh](https://github.com/google/rekall/blob/master/rekall-core/rekall/plugins/linux/zsh.py)

The last version for Volatility can be found [here](https://github.com/volatilityfoundation/community/tree/master/FrankBlock). Note: This version is currently not being updated.

# list_plugins

Lists all available plugins for the current session with a description.

```
$ rekall -f win10.dump list_plugins
       plugin                                          description                                   
-------------------- --------------------------------------------------------------------------------
address_resolver     A windows specific address resolver plugin.                                     
aff4acquire          Copy the physical address space to an AFF4 file.                                
                         NOTE: This plugin does not require a working profile - unless the user also 
                         wants to copy the pagefile or mapped files. In that case we must analyze the
                         live memory to gather the required files.                                   
aff4dump             Dump the entire resolver contents for an AFF4 volume.                           
aff4export           Exports all the streams in an AFF4 Volume.                                      
aff4ls               List the content of an AFF4 file.                                               
analyze_struct       A plugin to analyze a memory location.                                          
api                  Generate the plugin API document.                                               
artifact_collector   Collects artifacts.                                                             
artifact_list        List details about all known artifacts.                                         
artifact_view                                                                                        
atoms                Print session and window station atom tables.                                   
...
```
