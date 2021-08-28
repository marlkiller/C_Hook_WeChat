#pragma once
#include "pch.h"
#include <Windows.h>
DWORD hookEnable(DWORD offset, LPVOID func, HWND hModule);
void hookDisable(DWORD offset);
void msg_read();