#include "pch.h"
#include <Windows.h>
#include <stdio.h>
#include <atlimage.h>
#include "resource1.h"
#define HOOK_INS_LEN 9
#define HOOK_INS_ACTUAL_LEN 5
BYTE hook_bak[HOOK_INS_LEN] = { 0 };
HWND hDlg = NULL;
bool is_hook_enable = false;
DWORD ret_add, call_add;
DWORD getWeChatWinDLL() {
	return (DWORD)LoadLibrary(L"WeChatWin.dll");
}



DWORD pEax = 0;
DWORD pEcx = 0;
DWORD pEdx = 0;
DWORD pEbx = 0;
DWORD pEsp = 0;
DWORD pEbp = 0;
DWORD pEsi = 0;
DWORD pEdi = 0;

//传入的相当于一个二级指针，要两次解引用才能取得消息的首地址
void msg_read_core(DWORD msg_head) {
	//解引用
	msg_head = *((DWORD*)msg_head);
	//二次解引用
	msg_head = *((DWORD*)msg_head);
	//将关键信息缓存在本地变量
	//消息来源
	LPVOID msg_from = (LPVOID)(msg_head + 0x40);
	//消息内容
	LPVOID msg_what = (LPVOID)(msg_head + 0x68);
	//容错处理，避免空指针
	if (msg_what == NULL) msg_what = msg_from;
	//发送方
	LPVOID msg_sender = (LPVOID)(msg_head + 0x144);
	//？？？
	LPVOID msg_wtf = (LPVOID)(msg_head + 0x158);


	//将所的信息展示在前端
	SetDlgItemText(hDlg, MSG_FROM, *(LPCWSTR*)msg_from);
	SetDlgItemText(hDlg, MSG_WHAT, *(LPCWSTR*)msg_what);
	SetDlgItemText(hDlg, MSG_SENDER, *(LPCWSTR*)msg_sender);
	SetDlgItemText(hDlg, MSG_WTF, *(LPCWSTR*)msg_wtf);

}

//裸函数，不做任何多余操作
void __declspec(naked) msg_read() {

	//保护现场(汇编代码块)
	__asm {
		mov pEax, eax
		mov pEcx, ecx
		mov pEdx, edx
		mov pEbx, ebx
		mov pEsp, esp
		mov pEbp, ebp
		mov pEsi, esi
		mov pEdi, edi
	}
	
	//执行关键代码
	msg_read_core(pEsp);
	//计算返回地址
	//需要返回到 66F27E0D 处，偏移为 397E0D
	ret_add = getWeChatWinDLL() + 0x397E0D;
	//恢复现场
	__asm {
		mov  eax, pEax
		mov  ecx, pEcx
		mov  edx, pEdx
		mov  ebx, pEbx
		mov  esp, pEsp
		mov  ebp, pEbp
		mov  esi, pEsi
		mov  edi, pEdi
	}

	__asm {
		//执行被覆盖的指令
		call dword ptr ds : [eax + 0x8]
		mov ebx, dword ptr ds : [0x6831E978]
		//数据已得，速速返回
		jmp ret_add
	}

}

DWORD hookEnable(DWORD offset, LPVOID func, HWND hModule) {

    // DWORD hook_point = hookEnable(0x397E04 , msg_read, hModule);
	if (is_hook_enable) return NULL;
	is_hook_enable = true;
	// 保存句柄，方便其他函数使用
	hDlg = hModule;
	DWORD WeChatWinDLL = getWeChatWinDLL();
	// 取得hook点
	DWORD hook_point = WeChatWinDLL + offset;
	// MessageBox(NULL,"代码被注入到" + hook_point,"提示",0);
	// 组装二进制数据,我们需要组成一段这样的数据
	BYTE jmpCode[HOOK_INS_LEN] = { 0 };
	jmpCode[0] = 0xE9;//jmp 的字节码
	// 5="EB 8C090000"的长度%2,CALL XX 的机器码长度%2
	// 计算公式为 跳转的地址(也就是我们函数的地址) - hook的地址 - hook的字节长度
	*(DWORD*)&jmpCode[1] = (DWORD)func - hook_point - HOOK_INS_ACTUAL_LEN;

	//获取进程句柄
	HANDLE wx_handle = OpenProcess(PROCESS_ALL_ACCESS, NULL, GetCurrentProcessId());
	//备份hook点数据
	int rpm_result = ReadProcessMemory(wx_handle, (LPCVOID)hook_point, hook_bak, HOOK_INS_LEN, NULL);
	if (rpm_result == 0) {
		MessageBox(NULL, L"内存数据读取失败", L"错误", 0);
		return NULL;
	}
	//覆盖hook点数据
	int wpm_result = WriteProcessMemory(wx_handle, (LPVOID)hook_point, jmpCode, HOOK_INS_LEN, NULL);
	if (wpm_result == 0) {
		MessageBox(NULL, L"内存数据写入失败", L"错误", 0);
		return NULL;
	}
	return hook_point;
}


void hookDisable(DWORD offset) {
	//防止向内存写入空字节，导致程序崩溃
	if (!is_hook_enable) return;
	is_hook_enable = false;
	DWORD hook_point = getWeChatWinDLL() + offset;
	HANDLE wx_handle = OpenProcess(PROCESS_ALL_ACCESS, NULL, GetCurrentProcessId());
	//将数据写回
	int wpm_result = WriteProcessMemory(wx_handle, (LPVOID)hook_point, hook_bak, HOOK_INS_LEN, NULL);
	if (wpm_result == 0) {
		MessageBox(NULL, L"内存数据写入失败", L"错误", 0);
	}
}