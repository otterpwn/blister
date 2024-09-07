## Blister
*Blister* is a simple-ish rootkit / kernel driver for Windows that turns user-land processes of the user's choice into [Protected Processes](https://support.kaspersky.com/common/windows/13905).
This can potentially make it more difficult for **some** security software and tools to terminate or modify these processes.

While PPLs can offer some resistance to standard termination attempts, they are not foolproof. Advanced security solutions might still be able to detect and potentially disable them.
There are known techniques used to detect and remove rootkits, including PPL-based ones
- [Protecting anti-malware services](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-)
- [About Protected Process Light (PPL) technology for Windows](https://support.kaspersky.com/common/windows/13905)
- [The Evolution of Protected Processes – Part 1: Pass-the-Hash Mitigations in Windows 8.1](https://www.crowdstrike.com/blog/evolution-protected-processes-part-1-pass-hash-mitigations-windows-81/)
- [The Evolution of Protected Processes Part 2: Exploit/Jailbreak Mitigations, Unkillable Processes and Protected Services](https://www.crowdstrike.com/blog/evolution-protected-processes-part-2-exploitjailbreak-mitigations-unkillable-processes-and/)
- [More about rootkits](https://github.com/rmusser01/Infosec_Reference/blob/master/Draft/Rootkits.md#windows)

*Blister* allows to configure a list of entries for all the processes you would like to be protected by the driver.

### Setting up the environment
As the driver is not signed with a valid certifcate, you'll need to enable Test Signing mode on your VM; to do that execute the following commands from an elevated CMD session
```
bcdedit /debug on
bcdedit /set testsigning on
```
These changes can be reverted with
```
bcdedit /debug off
bcdedit /set testsigning off
```

In order to see the debug messages from the driver you will also need to open `regedit`, navigate to `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager` and create a new Key called **Debug Print Filter**.
Within that, add a new `DWORD` Value and ive it the name `DEFAULT` and a value of `8`.

### Loading the driver
To load the driver you will need to create a kernel-type process from an elevated CMD session, create a new service with a `binPath` pointing to the `blister.sys` file (built either with Release or Debug builds) and a `type` of `kernel`.
Once that's set up, you can start the service and the driver will be loaded.
```
sc create blister binPath= C:\path\to\the\driver\blister.sys type= kernel
sc start blister
```

An alternative would be to use a GUI-based program like [OSR Loader](https://www.osronline.com/article.cfm%5Earticle=157.htm) to create and start the service.

If you open `dbgview` or any other utils that can catch kernel debugging messages, starting the `blister` service should print messages like these
```
[INFO] blister: blister has started
[INFO] blister: Mutex and list initialized propely
[~] blister: PsSetLoadImageNotifyRoutine successfully set ImageLoadNotifyCallback callback
[~] blister: PsSetCreateProcessNotifyRoutineEx successfully set PCreateProcessNotifyRoutineEx callback
[INFO] blister: Creating a PPL entry for the "mimikatz.exe" process
[INFO] blister: blister is exiting
[~] blister: The callback address FFFFF80172D51B90 is owned by \??\C:\Users\otter\Desktop\projects\blister\x64\Debug\blister.sys
[~] blister: The callback address FFFFF801709B35D0 is owned by \SystemRoot\SysmonDrv.sys
[INFO] blister: PCreateProcessNotifyExitingHandler successfully acquired a lock
```
If you see similar debug prints, it means that everything went well:
1. The driver loaded successfully through its `DriverEntry` function
2. It initialized the guarded mutex and the linked lists it needs to enumerate the active protected processes
3. The `ImageLoadNotifyCallback` and `PCreateProcessNotifyRoutineEx` got registered successfully
4. The hardcoded entry for the process to protect (`mimikatz.exe`) was successfully added to the list
5. `blister` is now exiting its `DriverEntry` function

The rest of the messages are from the rootkit enumerating callbacks and figuring out what kernel module / driver owns said callbacks as we can see with Sysmon's `SysmonDrv.sys`.

If we start Mimikatz and a process or driver tries to create / duplicate a handle to it we'll see the following
```
[INFO] blister: Comparing imageName entry mimikatz.exe to protected imageName entry mimikatz.exe
[INFO] blister: A process is trying to get a handle to the PP 7244 from a PID of ^5332, blocking the operation
[INFO] blister: A process is trying to get a handle to the PP 7244 from a PID of ^532, blocking the operation
[INFO] blister: A process is trying to get a handle to the PP 7244 from a PID of ^7092, blocking the operation
[INFO] blister: A process is trying to get a handle to the PP 7244 from a PID of ^696, blocking the operation
[INFO] blister: A process is trying to get a handle to the PP 7244 from a PID of ^696, blocking the operation
```

> [!caution]
> The debug messages will be printed **only** if the driver is compiled in Debug mode as I've used `DbgPrint` to [print the messages](https://github.com/otterpwn/blister/blob/main/macros.h) as I felt it would be useless to print them in Release mode.
> If you want to change this, edit the `macros.h` file to use `KdPrint` instead of `DbgPrint`.

As of now, the [code](https://github.com/otterpwn/blister/blob/main/blister.c#L87) only blocks handle creation and duplication, but it would also be possible to block processes from closing the program itself.

---

> I am all, but what am I?
> 
> Another number that isn't equal to any of you
> 
> I control, but I comply
> 
> Pick me apart then pick up the pieces, I'm uneven

[![The Blister Exists](http://i.ytimg.com/vi/4Rog8XY8oxg/hqdefault.jpg)](https://www.youtube.com/watch?v=4Rog8XY8oxg)
