# TymSpecial Shellcode Loader


### Description
---
This project was made as a way for myself to learn C++ and gain insight into how EDR products work.

![vtcheck](/TymSpecial/vtcheck.png)

TymSpecial is a shellcode loader which utilizes SysWhispers to make direct syscalls and avoid user-land hooks. The loader takes raw x64 stageless shellcode as input which is then XOR encrypted with a random key and writes a temporary C++ stub to disk and is compiled via g++ to produce an executable. 

TymSpecial offers multiple methods of execution via classic thread injection, Windows callback functions, APC queues, and thread hijacking. Additonally, there is an option to patch EtwEventWrite in the local and remote process and there are 4 anti-sandboxing checks which can enabled including:

- Is the system domain joined?
- Does the system have < X GB of RAM?
- Does the system have < Y processors?
- Are long sleeps fast forwarded?

#### Use cases:

- Provide a variety of malware techniques on purple team engagements
- Inject into an existing process owned by a more privileged user to avoid interacting with LSASS
- Inject into an existing process which normally produces network activity (web browsers, svchost, etc.) to blend C2 traffic
- An alternative to [ScareCrow](https://github.com/optiv/ScareCrow) when module stomping & thread creation does not work.

#### Note: 

- Self-decrypting shellcode is not supported as memory is allocated with RW permissions and then changed to RX after the shellcode has been written into memory to avoid RWX memory pages. 

- Method 5 is not always guaranteed to work and should be targeted against processes with a high thread count and I/O. This is because APCs will not execute until the thread is in an alertable state. Within a local process such as method 1 this is not an issue as we can can force threads into an alertable state via NtTestAlert, however, forcing a remote process to flush it's APC queues is not possible. Additionally, because an APC is queued into every thread it is likely you will get multiple callbacks.


### Requirements
---
- Python3
- x86_64-w64-mingw32-g++ cross compiler


### Usage
---
```
usage: TymSpecial.py [-h] --input FILE --method NUMBER --out FILENAME [--etw] [--hideconsole] [--domainjoined] [--longsleep]
                     [--processors NUMBER] [--ram NUMBER] [--parent PROCESS] [--child PROCESS] [--clonesig FILE]

Shellcode loader which offers multiple execution methods via syscalls and anti-sandboxing options to evade AV & EDR products.

  --method 1 = [LOCAL] Execute shellcode in the local process via the Windows callback function EnumSystemLocalesA
  --method 2 = [LOCAL] Queue an APC in the local process via NtQueueApcThread, and then flush the queue via NtTestAlert
  --method 3 = [INJECTION] Create a thread in a remote process via NtCreateThreadEx (Note: Module Stomping not yet implemented)
  --method 4 = [INJECTION] Spawn a process in a suspended state with a spoofed PPID and queue an APC into the main thread via NtQueueApcThread, then resume the process via NtResumeThread to execute the APC
  --method 5 = [INJECTION] Iterate and queue an APC into every thread in a remote process via NtQueueApcThread
  --method 6 = [INJECTION] Suspend a thread in a remote process via NtSuspendThread, update the thread's RIP register to point to the shellcode via NtGetContextThread & NtSetContextThread, then resume the thread via NtResumeThread
  
optional arguments:
  -h, --help           show this help message and exit
  --input FILE         File containing shellcode, usually a .bin, example: --input shellcode.bin
  --method NUMBER      Method of execution, example: --method 1
  --out FILENAME       The output name of the produced executable (No file extension), example: --out loader
  --etw                Patch EtwEventWrite in the local and remote process
  --hideconsole        Hide the console via: ShowWindow(GetConsoleWindow(), SW_HIDE)
  --domainjoined       Anti-Sandbox Check: If the system is not domain-joined, exit
  --longsleep          Anti-Sandbox Check: Sleep for 90s, if <75s have passed, exit
  --processors NUMBER  Anti-Sandbox Check: If the number of processors is < X, exit
  --ram NUMBER         Anti-Sandbox Check: If the amount of RAM is < X GB, exit
  --parent PROCESS     Specify the parent process for PPID spoofing in method 4, example --parent explorer.exe
  --child PROCESS      Specify the process to spawn for injection into in method 4, example: --child svchost.exe
  --clonesig FILE      Specify a signed file to use for signature cloning, example: --clonesig C:\\chad\\Desktop\\SignedFile.exe

Example Usage: python3 TymSpecial.py --input file.bin --method 6 --domainjoined --ram 8 --processors 4 --hideconsole --clonesig C:\\chad\\Desktop\\RealFile.exe --out threadhijacker
Example Execution: C:\>threadhijacker.exe 20485
```


### Credits / References
---
- [AlternativeShellcodeExec](https://github.com/S4R1N/AlternativeShellcodeExec)
- [SafeBreach Labs Pinjectra](https://github.com/SafeBreach-Labs/pinjectra)
- [Sektor7 Malware Development Courses](https://institute.sektor7.net/)
- [SysWhispers2BOF](https://github.com/FalconForceTeam/SysWhispers2BOF) & [SysWhispers2](https://github.com/jthuraisamy/SysWhispers2)
- [ired.team](https://www.ired.team/)


## To Do:
---
- [ ] Implement module stomping
- [ ] Incorporate SigThief for signature cloning
- [ ] Add the option to unhook ntdll
