# TymSpecial Shellcode Loader

### Requirements
---
TymSpecial requires Python3 and x86_64-w64-mingw32-g++ cross compiler
---

### Description
insert info about injection options, purple teaming use cases, patching etw, 


```
usage: TymSpecial.py [-h] --input FILE --method NUMBER --out FILENAME [--etw] [--hideconsole] [--domainjoined] [--longsleep]
                     [--processors NUMBER] [--ram NUMBER] [--parent PROCESS] [--child PROCESS] [--clonesig FILE]

Shellcode loader which offers multiple execution methods via syscalls and anti-sandboxing options to evade AV & EDR products.

   _____   __  __ 
  / ____| |  \/  |
 | |      | \  / |
 | |      | |\/| |
 | |____  | |  | |
  \_____| |_|  |_|
  
   @ChadMotivation

  --method 1 = [LOCAL] Execute shellcode in the local process via the Windows callback function EnumSystemLocalesA
  --method 2 = [LOCAL] Queue an APC in the local process via NtQueueApcThread, and then flush the queue via NtTestAlert
  --method 3 = [INJECTION] Create a thread in a remote process via NtCreateThreadEx (Note: Module Stomping not yet implemented)
  --method 4 = [INJECTION] Spawn a process in a suspended state with a spoofed PPID and queue an APC into the main thread via NtQueueApcThread, then resume the process via NtResumeThread to execute the APC
  --method 5 = [INJECTION] Iterate and queue an APC into every thread in a remote process via NtQueueApcThread
  --method 6 = [INJECTION] Suspend a thread in a remote process via NtSuspendThread, update the thread's RIP register to point to the shellcode via NtGetContextThread & NtSetContextThread, then resume the thread via NtResumeThread
  

optional arguments:
  -h, --help           show this help message and exit
  --input FILE         File containing shellcode, usually a .bin, example:
                       --input shellcode.bin
  --method NUMBER      Method of execution, example: --method 1
  --out FILENAME       The output name of the produced executable (No file
                       extension), example: --out loader
  --etw                Patch EtwEventWrite in the local and remote process
  --hideconsole        Hide the console via: ShowWindow(GetConsoleWindow(),
                       SW_HIDE)
  --domainjoined       Anti-Sandbox Check: If the system is not domain-joined,
                       exit
  --longsleep          Anti-Sandbox Check: Sleep for 90s, if <75s have passed,
                       exit
  --processors NUMBER  Anti-Sandbox Check: If the number of processors is < X,
                       exit
  --ram NUMBER         Anti-Sandbox Check: If the amount of RAM is < X GB,
                       exit
  --parent PROCESS     Specify the parent process for PPID spoofing, example
                       --parent explorer.exe
  --child PROCESS      Specify the process to spawn for injection into,
                       example: --child svchost.exe
  --clonesig FILE      Specify a signed file to use for signature cloning,
                       example: --clonesig C:\\chad\\Desktop\\SignedFile.exe

Example Usage: python3 TymSpecial.py --input file.bin --method 6 --domainjoined --ram 8 --processors 4 --hideconsole --clonesig C:\\chad\\Desktop\\RealFile.exe --out threadhijacker
Example Execution: C:\>threadhijacker.exe 20485
```

## To Do:

- [ ] Implement module stomping
- [ ] Add the option to compile to a DLL
- [ ] Incorporate SigThief for signature cloning
- [ ] Change memory permissions to RX from RWX
- [ ] Debug anti-sandbox methods
- [ ] Add unhooking of NTDLL
- [ ] Get rid of netapi32.dll
