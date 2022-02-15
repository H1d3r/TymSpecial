# TymSpecial Shellcode Loader


### Description
---
This project was made as a way for myself to learn C++ and gain insight into how EDR products work.

TymSpecial is a shellcode loader which utilizes SysWhispers to make direct syscalls and avoid user-land hooks. The loader takes raw x64 stageless shellcode as input which is then XOR encrypted with a random key and writes a temporary C++ stub to disk which is compiled via g++ to produce an executable. 

TymSpecial offers multiple methods of execution via classic thread injection, Windows callback functions, APC queues, and thread hijacking. Additonally, there is an option to patch EtwEventWrite in the local and remote process, apply a spoofed code signing certificate via CarbonCopy, and there are 4 anti-sandboxing checks which can enabled including:

- Is the system domain joined?
- Does the system have < X GB of RAM?
- Does the system have < Y processors?
- Are long sleeps fast forwarded?

#### Detection Ratings

Depending on which method of execution is chosen there are approximately 2-5 AV/EDR vendors detecting the payloads on [VirusTotal](https://virustotal.com) when stageless Cobalt Strike shellcode is used with cloud fronting (As of 2/13/22). Results may vary from VirusTotal as we do not have insight into how each product is configured on the back end. 

![vtcheck](/images/VTCheck.png)

![antiscan](/images/scanme.png)

#### Use cases:

- Provide a variety of malware techniques on purple team engagements
- Inject into an existing process owned by a more privileged user to escalate privileges and avoid interacting with LSASS
- Inject into an existing process which normally produces network activity (web browsers, svchost, etc.) to blend C2 traffic
- An alternative to [ScareCrow](https://github.com/optiv/ScareCrow) when module stomping & thread creation does not work.

#### Note: 

- Self-decrypting shellcode is not supported as memory is allocated with RW permissions and then changed to RX after the shellcode has been written into memory to avoid RWX memory pages. 

- Method 5 is not always guaranteed to work and should be targeted against processes with a high thread count and I/O. This is because APCs will not execute until the thread is in an alertable state. Within a local process such as method 2 this is not an issue as we can can force threads into an alertable state via NtTestAlert, however, forcing a remote process to flush it's APC queues is not possible. Additionally, because an APC is queued into every thread it is likely you will get multiple callbacks.


### Requirements
---
This script works on Linux systems only with the following installed:

- Python3

- x86_64-w64-mingw32-g++ cross compiler

pyopenssl & osslsigncode are only required if the domain argument is passed for CarbonCopy usage

- ```apt-get install osslsigncode```

- ```pip3 install pyopenssl```


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
  --domain FILE        Specify a domain to sign the file with a spoofed code signing certificate via CarbonCopy, example: --domain cisco.com

Example Usage: python3 TymSpecial.py --input file.bin --method 6 --etw --domainjoined --ram 8 --processors 4 --hideconsole --domain cisco.com --out threadhijacker
Example Execution: C:\>threadhijacker.exe 20485
```


### Credits / References
---
- [CarbonCopy](https://github.com/paranoidninja/CarbonCopy)
- [AlternativeShellcodeExec](https://github.com/S4R1N/AlternativeShellcodeExec)
- [SafeBreach Labs Pinjectra](https://github.com/SafeBreach-Labs/pinjectra)
- [Sektor7 Malware Development Courses](https://institute.sektor7.net/)
- [SysWhispers2BOF](https://github.com/FalconForceTeam/SysWhispers2BOF) & [SysWhispers2](https://github.com/jthuraisamy/SysWhispers2)
- [ired.team](https://www.ired.team/)
- [CheckPlease](https://github.com/Arvanaghi/CheckPlease)


## To Do:
---
- [ ] Implement module stomping
- [ ] Add the option to unhook ntdll & kernel32
- [ ] Encrypt shellcode at rest via hooking sleep

