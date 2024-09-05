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

*Blister* allows to configure a list of entries for all the processes you would like to be protecter by the driver.

---

> I am all, but what am I?
> 
> Another number that isn't equal to any of you
> 
> I control, but I comply
> 
> Pick me apart then pick up the pieces, I'm uneven

[![The Blister Exists](http://i.ytimg.com/vi/4Rog8XY8oxg/hqdefault.jpg)](https://www.youtube.com/watch?v=4Rog8XY8oxg)
