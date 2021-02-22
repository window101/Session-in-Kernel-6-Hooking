
#include "windows.h"
#include "tchar.h"


typedef DWORD (WINAPI *PFNTCREATETHREADEX) {
    PHANDLE ThreadHandle;
    ACCESS_MASK DesiredAccess,
    LPVOID ObjectAttributes,
    HANDLE ProcessHandle,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    BOOL CreateSuspended,
    DWORD dwStackSize,
    DWORD dw1,
    DWORD dw2,
    LPVOID Unknown
};

BOOL IsVistaOrLater() {
    OSVERSIONINFO osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

    GetVersionEX(&osvi);

    if(osvi.dwMajorVersion == 6) {
        return TRUE;
    }
    return FALSE;
}
BOOL MyCreateRemoteThread(HANDLE hProcess, LPTHREAD_START_ROUTINE pThreadProc, LPVOID pRemoteBuf) {

    HANDLE hThread = NULL;
    FARPROC pFunc = NULL;

    if( IsVistaOrLater()) {
        pFunc = GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtCreateThreadEx");

        if(pFunc == NULL) {
            printf("GetProcAddress(\"NtCreateThreadEx\") failed!!! [%d]\n", GetLastError());
            return FALSE;
        }
        ((PFNTCREATETHREADEX)pFunc )(&hThread,
                                    0x1FFFFF,
                                    NULL,
                                    hProcess,
                                    pThreadProc,
                                    pRemoteBuf,
                                    FALSE,
                                    NULL,
                                    NULL,
                                    NULL,
                                    NULL
                                    );
        if( hThread == NULL) {
             printf("NtCreateThreadEx failed!!! [%d]\n", GetLastError());
             return FALSE;
        }
    }
    else {
        hThread = MyCreateRemoteThread(hProcess,
                                        NULL,
                                        0,
                                        pThreadProc,
                                        pRemoteBuf,
                                        0,
                                        NULL);
        if(hThread == NULL) {
            printf("CreateRemoteThread() failed!!! [%d]\n", GetLastError());
            return FALSE;
        }
    }
    if( WAIT_FAILED == WaitForSingleObject(hThread, INFINITE)) {
        printf("WaitForSingleObject failed!!! [%d]\n", GetLastError());
        return FALSE;
    }
    return TRUE;
}

Bool InjectDll(DWORD dwPID, char *szDllName) {
    
    HANDLE hProcess = NULL;
    LPVOID pRemoteBuf = NULL;
    FARPROC pThreadProc = NULL;
    DWORD dwBufSize = strlen(szDllName) + 1;

    if( !(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPId))) {
        printf("OpenProcess(%d) failed!!! [%d]\n", dwPID, GetLastError());
        return FALSE;
    }

    pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDllName, dwBufSize, NULL);
    pThreadProc = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");

    if(! MyCreateRemoteThread(hProcess, (LPTHREAD_START_ROUTINE)pThreadProc, pRemoteBuf)) {
        printf("MyCreateRemoteThread() failed!!!\n");
        return FALSE;
    }
    VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);

    CloseHandle(hProcess);
    return TRUE;
}
int _tmain(int argc, THCAR *argv[]) {
    
    if(argc != 3) {
        _tprintf(L"USAGE : %s pid dll_path\n", argv[0]);
        return 1;
    }
    if( InjectDll((DWORD)_tstol(argv[1]),argv[2]))
        _tprintf(L"InjectDll(\"%s\") success!!!\n", argv[2]);
    else
        _tprintf(L"InjectDll(\"%s\") failed!!!\n", argv[2]);
    return 0;
}