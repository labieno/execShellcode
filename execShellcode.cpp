#include <iostream>
#include <windows.h>

int main(int argc, char* argv[])
{
    //1. - Get shellcode from file
    if (argc != 2) {
        printf("Usage: %s <file_name>\n", argv[0]);
        return 1;
    }

    BOOL val;
    DWORD oldprotect;
    HANDLE thread_handle;
    DWORD bytes_read;
    const char* raw_shellcode = argv[1];
    HANDLE file = CreateFileA(raw_shellcode, GENERIC_READ, 0, NULL, 3, FILE_ATTRIBUTE_NORMAL, NULL);

    if (file == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Cannot open file!\n");
        return 1;
    }

    DWORD file_size = GetFileSize(file, NULL);
    if (file_size == INVALID_FILE_SIZE) {
        fprintf(stderr, "Cannot to obtain file size!\n");
        CloseHandle(file);
        return 1;
    }
    printf("Size: %d bytes\n", file_size);
    //2. - VirtualAlloc(Ex)
    void* mem = VirtualAlloc(NULL, file_size, MEM_COMMIT, PAGE_READWRITE);
    if (mem == NULL) {
        fprintf(stderr, "Cannot allocate memory!\n");
        CloseHandle(file);
        return 1;
    }

    printf("Allocated region: %x\n", mem);

    //3. - Copy shellcode to allocated memory
    if (!ReadFile(file, mem, file_size, &bytes_read, NULL)) {
        fprintf(stderr, "Cannot read the file!\n");
        VirtualFree(mem, 0, MEM_RELEASE);
        CloseHandle(file);
        return 1;
    }
    printf("Shellcode has been copied...\n");

    //4. - VirtualProtect
    val = VirtualProtect(mem, file_size, PAGE_EXECUTE_READ, &oldprotect);
    if (val == 0) {
        fprintf(stderr, "Error changing protections!\n");
        VirtualFree(mem, 0, MEM_RELEASE);
        CloseHandle(file);
        return 1;
    }
    printf("Protections changed...\n");

    //5. - CreateThread
    printf("Put a BP in the new allocated region of memory and press any key...\n");
    getchar();
    thread_handle = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) mem, 0, 0, 0);
    WaitForSingleObject(thread_handle, -1);
    
    // End
    printf("Press any key to quit...\n");
    getchar();
    CloseHandle(file);
    VirtualFree(mem, 0, MEM_RELEASE);
    printf("Thread terminated...\n");
}
