// pelauncher.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "resource.h"

#define ARGS_LEN 1024

#if defined (_M_ARM)
#define EnvARM
#define Unsupported
#define IgnoreMainCode
#else
#if _WIN32 || _WIN64
#if _WIN64
#define Env64
#define Unsupported
#define EnvBaseReg    Rdx
#define EnvBaseOffset 8
#define EnvBaseReg2   Rax // check
#else
#define Env86
#define EnvBaseReg    Ebx
#define EnvBaseOffset 8
#define EnvBaseReg2   Eax
#endif
#endif
#endif

#if defined (Unsupported)
#pragma message ("Platform unsupported !!!!")
#endif

// #define DEV_CONTEXT // for NtQueryInformationProcess 

// Global Variables:
HINSTANCE hInst;								// current instance
LRESULT CALLBACK	DlgProc(HWND, UINT, WPARAM, LPARAM);

TCHAR FilePathSafe[MAX_PATH] = { };
TCHAR FilePathArgs[ARGS_LEN] = { };
LPWSTR RunArgumentPath;
BOOL RunArgument = FALSE;
TCHAR StubPath[MAX_PATH] = { };

typedef PWSTR(WINAPI *StrFormatByteSizeW_Import)(LONGLONG qdw, PWSTR pszBuf, UINT cchBuf);

VOID Display32ErrorDialog(HWND Parent, DWORD code)
{
	WCHAR Buffer[512] = { };
	WCHAR ErrorBuffer[256] = { };

	if (code == 0) wcscpy_s(ErrorBuffer, 256, L"Unknown");
	else if (code == -1) wcscpy_s(ErrorBuffer, 256, L"Wrong platform");
	else if (code == -2) wcscpy_s(ErrorBuffer, 256, L"Invalid executable (PE)");
	else FormatMessageW(
		FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		code,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		ErrorBuffer,
		(sizeof(ErrorBuffer) / sizeof(WCHAR)),
		NULL);

	swprintf_s(
		Buffer, 512,
		L"Error %d - %s",
		code,
		ErrorBuffer);

	MessageBoxW(Parent, Buffer, L"PE Launcher", MB_OK);
}

PWSTR WINAPI StrFormatByteSizeW(HWND hDlg, LONGLONG qdw, PWSTR pszBuf, UINT cchBuf)
{
	HMODULE module = LoadLibrary(L"shlwapi.dll");

	if (module == NULL) 
	{
		Display32ErrorDialog(hDlg, GetLastError());
		return NULL;
	}

	StrFormatByteSizeW_Import func = (StrFormatByteSizeW_Import)GetProcAddress(module, "StrFormatByteSizeW");

	PWSTR result = func(qdw, pszBuf, cchBuf);

	FreeLibrary(module);
	return result;
}

#ifdef DEV_CONTEXT
BOOL sm_EnableTokenPrivilege(LPCTSTR pszPrivilege)
{
	HANDLE hToken = 0;
	TOKEN_PRIVILEGES tkp = { 0 };

	// Get a token for this process.

	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES |
		TOKEN_QUERY, &hToken))
	{
		return FALSE;
	}

	// Get the LUID for the privilege. 

	if (LookupPrivilegeValue(NULL, pszPrivilege,
		&tkp.Privileges[0].Luid))
	{
		tkp.PrivilegeCount = 1;  // one privilege to set    

		tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		// Set the privilege for this process. 

		AdjustTokenPrivileges(hToken, FALSE, &tkp, 0,
			(PTOKEN_PRIVILEGES)NULL, 0);

		if (GetLastError() != ERROR_SUCCESS)
			return FALSE;

		return TRUE;
	}

	return FALSE;
}
#endif

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPWSTR    lpCmdLine,
	_In_ int       nCmdShow)
{
	// Perform application initialization:
	hInst = hInstance; // Store instance handle in our global variable

	int pNumArgs;
	LPWSTR *szArglist = CommandLineToArgvW(lpCmdLine, &pNumArgs);

	if (pNumArgs >= 1)
	{
		RunArgument = TRUE; // this actually works every time :/ but we check for lenght later
		RunArgumentPath = lpCmdLine;
	}

	INITCOMMONCONTROLSEX icce = { };
	icce.dwSize = sizeof(icce);
	icce.dwICC = ICC_LINK_CLASS;

	InitCommonControlsEx(&icce);

	DialogBox(hInst, MAKEINTRESOURCE(IDD_MAIN), NULL, (DLGPROC)DlgProc);

	return 0;
}

#define SetStatusDlg(text) SetStatus(hDlg, text)

VOID SetStatus(HWND hDlg, LPCWSTR Text)
{
	SetWindowText(GetDlgItem(hDlg, IDC_PLATFORM), Text);
}

VOID SetStatusInitial(HWND hDlg)
{
#if defined (Env86)
	SetWindowText(GetDlgItem(hDlg, IDC_PLATFORM), L"Current platform: x86");
#elif defined (Env64)
	SetWindowText(GetDlgItem(hDlg, IDC_PLATFORM), L"Current platform: x64");
#elif defined (EnvARM)
	SetWindowText(GetDlgItem(hDlg, IDC_PLATFORM), L"Current platform: ARM");
#else
	SetWindowText(GetDlgItem(hDlg, IDC_PLATFORM), L"Current platform: ???");
#endif
}

BOOL FileExists(TCHAR* szPath)
{
	WIN32_FIND_DATA FindFileData;
	HANDLE hFind;

	hFind = FindFirstFile(szPath, &FindFileData);
	if (hFind == INVALID_HANDLE_VALUE) 
	{
		return FALSE;
	} 
	else 
	{
		FindClose(hFind);
		return TRUE;
	}
}

VOID UpdatePath(HWND hDlg)
{
	SetWindowText(GetDlgItem(hDlg, IDC_EXE_PATH), FilePathSafe);
}

VOID UpdateStub(HWND hDlg)
{
	WCHAR str[256] = { };
	PCWSTR StubName = wcsrchr((wchar_t*)StubPath, L'\\');
	++StubName;
	swprintf_s(str, 256, L"<a>%s</a>", StubName);
	SetWindowText(GetDlgItem(hDlg, IDC_LINK_STUB), str);
}

VOID UpdateButton(HWND hDlg)
{
	TCHAR Path[MAX_PATH];
	GetWindowText(GetDlgItem(hDlg, IDC_EXE_PATH), Path, MAX_PATH);

	BOOL enable = FileExists((TCHAR*)Path);

	EnableWindow(GetDlgItem(hDlg, IDLAUNCH), enable);
}

#define RunPEResult (!success ? GetLastError() : rc)

DWORD FinalizeRunPE(int success, int rc, HANDLE hProcess)
{
	DWORD result = RunPEResult;

	if (IsDebuggerPresent()) DebugBreak();

	if (hProcess != INVALID_HANDLE_VALUE) 
	{
		TerminateProcess(hProcess, 0);
		CloseHandle(hProcess);
	}

	return result;
}

#ifdef DEV_CONTEXT
typedef NTSTATUS(NTAPI *pfnNtQueryInformationProcess)(
	IN  HANDLE ProcessHandle,
	IN  PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN  ULONG ProcessInformationLength,
	OUT PULONG ReturnLength    OPTIONAL
	);

pfnNtQueryInformationProcess gNtQueryInformationProcess;

HMODULE sm_LoadNTDLLFunctions()
{
	// Load NTDLL Library and get entry address

	// for NtQueryInformationProcess

	HMODULE hNtDll = LoadLibrary(_T("ntdll.dll"));
	if (hNtDll == NULL) return NULL;

	gNtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(hNtDll,
		"NtQueryInformationProcess");
	if (gNtQueryInformationProcess == NULL) {
		FreeLibrary(hNtDll);
		return NULL;
	}
	return hNtDll;
}
#endif

int RunPortableExecutable(HWND hDlg)
{
#ifndef IgnoreMainCode // to keep build ok even if broken
	WCHAR LogBuf[512] = { };
	WCHAR SizeBuf[128] = { };
	TCHAR FilePath[MAX_PATH] = { };

	if (!GetFullPathName(FilePathSafe, MAX_PATH, FilePath, NULL))
		return GetLastError();

	// Load file
	HANDLE hFile = CreateFile(
		FilePath,
		GENERIC_READ,
		NULL,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hFile == INVALID_HANDLE_VALUE)
		return GetLastError();

	DWORD fLen = GetFileSize(hFile, NULL);
	char* binary = new char[fLen];

	StrFormatByteSizeW(hDlg, fLen, SizeBuf, 128);
	swprintf_s(LogBuf, 512, L"Reading %s...", SizeBuf);
	SetStatusDlg(LogBuf);

	if (!ReadFile(hFile, binary, fLen, NULL, NULL))
	{
		CloseHandle(hFile);

		return GetLastError();
	}

	CloseHandle(hFile);

	SetStatusDlg(L"Working with headers...");

	int success = 1, rc = 0;
	const uintptr_t binary_address = (uintptr_t)binary;
	IMAGE_DOS_HEADER* const dos_header = (IMAGE_DOS_HEADER*)binary;
	IMAGE_NT_HEADERS* const nt_header = (IMAGE_NT_HEADERS*)(binary_address + dos_header->e_lfanew);

	if (nt_header->Signature != IMAGE_NT_SIGNATURE)
	{
		rc = -2;
		return RunPEResult;
	}

	SetStatusDlg(L"Launching new instance...");

	STARTUPINFOW startup_info;
	PROCESS_INFORMATION process_info;

	SecureZeroMemory(&startup_info, sizeof(startup_info));
	SecureZeroMemory(&process_info, sizeof(process_info));

	WCHAR Args[ARGS_LEN] = { };
	swprintf_s(Args, ARGS_LEN, L"\"%s\" %s", StubPath, FilePathArgs);
	success = CreateProcessW(StubPath, Args, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startup_info, &process_info);

	if (!success)
		return RunPEResult;

	SetStatusDlg(L"Working with instance...");

	CONTEXT* const ctx = (CONTEXT*)VirtualAlloc(NULL, sizeof(ctx), MEM_COMMIT, PAGE_READWRITE);
	ctx->ContextFlags = CONTEXT_FULL;

	success = GetThreadContext(process_info.hThread, ctx);

	if (!success)
		return FinalizeRunPE(success, rc, process_info.hProcess);

	uintptr_t* image_base;

#ifdef DEV_CONTEXT
	PVOID pbi;
	auto hHeap = GetProcessHeap();

	size_t dwSize = sizeof(PROCESS_BASIC_INFORMATION);
	ULONG dwSizeNeeded = 0;

	pbi = (PROCESS_BASIC_INFORMATION*)HeapAlloc(hHeap,
		HEAP_ZERO_MEMORY,
		dwSize);

	NTSTATUS dwStatus = gNtQueryInformationProcess(process_info.hProcess,
		ProcessBasicInformation,
		pbi,
		dwSize,
		&dwSizeNeeded);

	PROCESS_BASIC_INFORMATION* pbix = (PROCESS_BASIC_INFORMATION*)pbi;
#endif

	void* const modified_base = (void*)(ctx->EnvBaseReg + EnvBaseOffset);

	success = ReadProcessMemory(process_info.hProcess, modified_base, &image_base, 4, NULL);

	if (!success)
		return FinalizeRunPE(success, rc, process_info.hProcess);

	void* const binary_base = VirtualAllocEx(process_info.hProcess, (void*)(nt_header->OptionalHeader.ImageBase),
		nt_header->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	success = WriteProcessMemory(process_info.hProcess, binary_base, binary, nt_header->OptionalHeader.SizeOfHeaders, NULL);

	if (!success)
		return FinalizeRunPE(success, rc, process_info.hProcess);

	const uintptr_t binary_base_address = (uintptr_t)binary_base;

	for (unsigned short i = 0; i < nt_header->FileHeader.NumberOfSections; ++i) {
		IMAGE_SECTION_HEADER* section_header = (IMAGE_SECTION_HEADER*)(binary_address + dos_header->e_lfanew + 248 + (i * 40));
		void* const virtual_base_address = (void*)(binary_base_address + section_header->VirtualAddress);
		void* const virtual_buffer = (void*)(binary_address + section_header->PointerToRawData);

		// convert name to normal type for log
		int output_size = MultiByteToWideChar(CP_ACP, 0, (LPCSTR)section_header->Name, -1, NULL, 0);
		wchar_t *converted_buf = new wchar_t[output_size];
		int size = MultiByteToWideChar(CP_ACP, 0, (LPCSTR)section_header->Name, -1, converted_buf, output_size);

		swprintf_s(LogBuf, 512, L"Writing section %s", converted_buf);
		SetStatusDlg(LogBuf);

		success = WriteProcessMemory(process_info.hProcess, virtual_base_address, virtual_buffer, section_header->SizeOfRawData, 0);

		if (!success)
			return FinalizeRunPE(success, rc, process_info.hProcess);
	}

	SetStatusDlg(L"Finalizing...");

	success = WriteProcessMemory(process_info.hProcess, modified_base, (void*)&nt_header->OptionalHeader.ImageBase, 4, 0);

	if (!success)
		return FinalizeRunPE(success, rc, process_info.hProcess);

	ctx->EnvBaseReg2 = binary_base_address + nt_header->OptionalHeader.AddressOfEntryPoint;

	success = SetThreadContext(process_info.hThread, ctx);

	if (!success)
		return FinalizeRunPE(success, rc, process_info.hProcess);

	success = ResumeThread(process_info.hThread);

	if (!success)
		return FinalizeRunPE(success, rc, process_info.hProcess);

	if (SendMessage(GetDlgItem(hDlg, IDC_WAIT_FOR_EXIT), BM_GETCHECK, 0, 0) == BST_CHECKED)
	{
		SetStatusDlg(L"Waiting for target exit...");
		WaitForSingleObject(process_info.hProcess, INFINITE);
	}

	return RunPEResult;
#else
	MessageBox(0, L"Platform unsupported: returning -1", L"PELauncher", 0);
	return -1;
#endif
}

DWORD WINAPI ProcessThreadProc(CONST LPVOID lpParam)
{
	HWND hDlg = (HWND)lpParam;
	BOOL WaitForExitPreviousState = FALSE;

	GetWindowText(GetDlgItem(hDlg, IDC_EXE_PATH), FilePathSafe, MAX_PATH);
	GetWindowText(GetDlgItem(hDlg, IDC_EXE_ARGS), FilePathArgs, ARGS_LEN);

	if (_tcslen(FilePathSafe) <= 0) return TRUE;

	EnableWindow(GetDlgItem(hDlg, IDLAUNCH), FALSE);
	EnableWindow(GetDlgItem(hDlg, IDSELECT), FALSE);
	EnableWindow(GetDlgItem(hDlg, IDC_EXE_PATH), FALSE);
	EnableWindow(GetDlgItem(hDlg, IDC_EXE_ARGS), FALSE);
	WaitForExitPreviousState = IsWindowEnabled(GetDlgItem(hDlg, IDC_WAIT_FOR_EXIT));
	EnableWindow(GetDlgItem(hDlg, IDC_DO_NOT_EXIT), FALSE);
	EnableWindow(GetDlgItem(hDlg, IDC_WAIT_FOR_EXIT), FALSE);

	SetStatusDlg(L"Initializing...");

	int result = RunPortableExecutable(hDlg);

	if (result == 0)
	{
		if (SendMessage(GetDlgItem(hDlg, IDC_DO_NOT_EXIT), BM_GETCHECK, 0, 0) != BST_CHECKED)
			EndDialog(hDlg, 0);
	}
	else
	{
		Display32ErrorDialog(hDlg, result);
	}

	EnableWindow(GetDlgItem(hDlg, IDLAUNCH), TRUE);
	EnableWindow(GetDlgItem(hDlg, IDSELECT), TRUE);
	EnableWindow(GetDlgItem(hDlg, IDC_EXE_PATH), TRUE);
	EnableWindow(GetDlgItem(hDlg, IDC_EXE_ARGS), TRUE);
	EnableWindow(GetDlgItem(hDlg, IDC_DO_NOT_EXIT), TRUE);
	EnableWindow(GetDlgItem(hDlg, IDC_WAIT_FOR_EXIT), WaitForExitPreviousState);

	SetStatusInitial(hDlg);

	return TRUE;
}

VOID DoLaunch(HWND hDlg)
{
	CreateThread(
		NULL,
		0,
		&ProcessThreadProc,
		hDlg,
		0,
		NULL);
}

LRESULT CALLBACK DlgProc(HWND hDlg, UINT Msg, WPARAM wParam, LPARAM lParam)
{
	if (Msg == WM_INITDIALOG)
	{
		SetStatusInitial(hDlg);

		GetModuleFileNameW(NULL, StubPath, MAX_PATH);
		UpdateStub(hDlg);

#ifdef DEV_CONTEXT
		if (!sm_EnableTokenPrivilege(L"SE_DEBUG_NAME"))
			MessageBox(hDlg, L"Unable to get debug privilege", L"PELauncher", 0);

		sm_LoadNTDLLFunctions();
#endif

#if defined (Unsupported)
		MessageBox(hDlg, L"Current platform is unsupported.", L"PELauncher", 0);
#endif
		UpdateButton(hDlg);

		EnableWindow(GetDlgItem(hDlg, IDC_WAIT_FOR_EXIT), FALSE);

		if (RunArgument)
		{
			SetWindowText(GetDlgItem(hDlg, IDC_EXE_PATH), RunArgumentPath);
			DoLaunch(hDlg);
		}

		return TRUE;
	}
	else if (Msg == WM_CLOSE)
	{
		EndDialog(hDlg, 0);
		return TRUE;
	}
	else if (Msg == WM_NOTIFY)
	{
		switch (((NMHDR *)lParam)->code)
		{
			case NM_CLICK:
			{
				switch (wParam)
				{
					case IDC_LINK_STUB:
					{
						OPENFILENAME ofn;

						ZeroMemory(&ofn, sizeof(ofn));
						ofn.lStructSize = sizeof(ofn);
						ofn.hwndOwner = hDlg;
						ofn.lpstrFile = StubPath;
						ofn.nMaxFile = sizeof(StubPath);
						ofn.lpstrFilter = TEXT("Executables (*.exe)\0*.exe\0All Files (*.*)\0*.*\0");
						ofn.nFilterIndex = 1;
						ofn.lpstrFileTitle = NULL;
						ofn.nMaxFileTitle = 0;
						ofn.lpstrInitialDir = NULL;
						ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

						if (GetOpenFileName(&ofn))
							UpdateStub(hDlg);

						return TRUE;
					}
				}
			}
		}
	}
	else if (Msg == WM_COMMAND)
	{
		if (HIWORD(wParam) == EN_CHANGE
			&& LOWORD(wParam) == IDC_EXE_PATH)
		{
			UpdateButton(hDlg);
			return TRUE;
		}
		else if (HIWORD(wParam) == BN_CLICKED
			&& LOWORD(wParam) == IDC_DO_NOT_EXIT)
		{
			if (SendMessage(GetDlgItem(hDlg, IDC_DO_NOT_EXIT), BM_GETCHECK, 0, 0) == BST_UNCHECKED)
			{
				SendMessage(GetDlgItem(hDlg, IDC_WAIT_FOR_EXIT), BM_SETCHECK, BST_UNCHECKED, 0);
				EnableWindow(GetDlgItem(hDlg, IDC_WAIT_FOR_EXIT), FALSE);
			}
			else EnableWindow(GetDlgItem(hDlg, IDC_WAIT_FOR_EXIT), TRUE);

			return TRUE;
		}

		switch (LOWORD(wParam))
		{
			case IDLAUNCH:
				DoLaunch(hDlg);
				return TRUE;

			case IDCANCEL:
				EndDialog(hDlg, 0);
				return TRUE;

			case IDSELECT:
			{
				OPENFILENAME ofn;

				ZeroMemory(&ofn, sizeof(ofn));
				ofn.lStructSize = sizeof(ofn);
				ofn.hwndOwner = hDlg;
				ofn.lpstrFile = FilePathSafe;
				ofn.nMaxFile = sizeof(FilePathSafe);
				ofn.lpstrFilter = TEXT("Executables (*.exe)\0*.exe\0All Files (*.*)\0*.*\0");
				ofn.nFilterIndex = 1;
				ofn.lpstrFileTitle = NULL;
				ofn.nMaxFileTitle = 0;
				ofn.lpstrInitialDir = NULL;
				ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

				if (GetOpenFileName(&ofn))
					UpdatePath(hDlg);

				return TRUE;
			}
		}
	}
	return 0;
}
