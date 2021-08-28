// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <Windows.h>
#include <stdio.h>
#include "resource1.h"
#include "msg_proxy.h"


INT_PTR CALLBACK Dlgproc(
    HWND hModule,
    UINT message,
    WPARAM ext_msg_1,
    LPARAM ext_msg_2
) {
    switch (message) {
        case WM_INITDIALOG: {
            break;
        }
        case WM_COMMAND: {
            switch (ext_msg_1) {
                case HOOK_ENABLE: {
                    // 66F27E04      FF50 08       call dword ptr ds:[eax+0x8]              ;  hook点,偏移0x397E04
                    DWORD hook_point = hookEnable(0x397E04 , msg_read, hModule);
                    SetDlgItemText(hModule, HOOK_STAT, L"hook已启用");
                    break;
                }
                case HOOK_DISABLE: {
                    hookDisable(0x397E04);
                    SetDlgItemText(hModule, HOOK_STAT, L"hook已禁用");
                    break;
                }
            }
            break;
        }
        case WM_CLOSE: {
            EndDialog(hModule, 0);
            break;
        }
    }
    return false;
}


DWORD PROXY_THREAD(HMODULE hModule) {
    return DialogBox(hModule, MAKEINTRESOURCE(MAIN), NULL, Dlgproc);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH: {
            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)PROXY_THREAD, hModule, 0, NULL);
            break;
        }
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}