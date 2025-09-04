# Portable Executable launcher for Windows NT [![Build status](https://ci.appveyor.com/api/projects/status/1b7qta0rs4bwtpho?svg=true)](https://ci.appveyor.com/project/dz333n/pelauncher)

# What is this?

This program lets you trick the Windows NT low-level Portable Executable (``.exe``) loader. It lets you load a valid executable and then replace its memory with any other portable executable you want, even if Windows does not like the target executable.  

# Download
Visit [artifacts page on AppVeyor](https://ci.appveyor.com/project/dz333n/pelauncher/build/artifacts)

![image](https://user-images.githubusercontent.com/25367511/63508722-27735180-c4e3-11e9-8cee-d351832d8b34.png)

# How does this work?

1. PE Launcher launches ``stub.exe`` (any valid executable, which may be changed by the user) in the paused state
2. Windows NT creates a process ``stub.exe`` and loads all the executable resources into memory
3. PE Launcher reads ``target.exe`` and replaces ``stub.exe`` memory with the target resources
5. So at this point, even though NT loaded and verified ``stub.exe``, the actual program that's loaded into memory is ``target.exe`` 
6. Program unpauses ``stub.exe``
7. Windows NT starts executing the app

# Why?

There is no specific reason. This was made just for fun. 


 - I can start any Windows CE application (with [WCECL](https://github.com/feel-the-dz3n/wcecl)) without editing the executable.
 - I can start Windows kernel inside user space (this most likely won't work, I only know that it fails to resolve DLLs).
 - Windows 10 refuses to launch Windows XP setup (``winnt32.exe``). PELauncher tricks the system and successfully launches a soft-locked setup executable on any Windows. However, for some reason, it failed to resolve winnt32u.dll, so an investigation is needed. 
 - It lets you run native NT executables inside Win32 user space. Fun fact: it's probably a Windows issue, but if you try to run the 32-bit version of ``smss.exe`` (for example, the Windows XP version) on Windows 11, then it's going to crash the system completely without administrator permissions.
 - It may avoid some antivirus checks.


# Limitations and issues

1. **Shitcode**. This was shitcoded by me a few years ago, so be aware that there may be code issues and memory leaks.
2. This program works well on Windows 10. ~~It's also known that this program runs on XP~~ (2025 update: Windows XP build doesn't work due to v141_xp toolset deprecation), but often fails. Also, the program for some reason doesn't work on Vista and 7.
3. This software is 32-bit and works only with 32-bit executables. This program still works on 64-bit Windows versions, but only with 32-bit targets. Feel free to contribute if you know how to add support for other architectures. 
 
# Build

Visual Studio 2022, latest toolset.

~~Visual Studio 2017 was used to create this project.~~

# Credits
 - [This](https://stackoverflow.com/questions/48981582/running-portable-executable-in-memory-using-the-winapi-c-programming) question on Stackoverflow

# Interesting fact

Initially, this program was made in VC6 for compatibility with old systems, like Windows NT 3.51:

![image](https://user-images.githubusercontent.com/25367511/63433018-fe8f8580-c42a-11e9-818c-1f59e563016f.png)

But then the VS2017 solution was force-pushed instead of VC6 commits.
