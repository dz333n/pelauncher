// pelauncher.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "resource.h"

#define ARGS_LEN 1024

#if defined (_M_ARM)
#define EnvARM
#define Unsupported
#define IgnoreMainCode
#elif defined(_M_X64) || defined(_WIN64)
#define Env64
// In the initial suspended thread context:
//  - RDX points to the PEB
//  - PEB->ImageBaseAddress is at offset 0x10 in PEB64
//  - RCX is used by the start thunk to hold the entry address
#define PEB_PTR_REG        Rdx
#define PEB_IMAGEBASE_OFF  0x10
#define ENTRY_REG          Rcx
#else
#define Env86
// In x86:
//  - EBX points to the PEB
//  - PEB->ImageBaseAddress is at offset 0x8 in PEB32
//  - EAX is used by the start thunk to hold the entry address
#define PEB_PTR_REG        Ebx
#define PEB_IMAGEBASE_OFF  8
#define ENTRY_REG          Eax
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

typedef PWSTR(WINAPI* StrFormatByteSizeW_Import)(LONGLONG qdw, PWSTR pszBuf, UINT cchBuf);

VOID Display32ErrorDialog(HWND Parent, DWORD code)
{
	WCHAR Buffer[512] = { }, ErrorBuffer[256] = { };

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
	LPWSTR* szArglist = CommandLineToArgvW(lpCmdLine, &pNumArgs);

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

#define AppendLogLineDlg(text) SetStatus(hDlg, text)

VOID AppendLog(HWND hDlg, LPCWSTR Text)
{
	// get edit control from dialog
	HWND hwndOutput = GetDlgItem(hDlg, IDC_LOGBOX);

	// get new length to determine buffer size
	int outLength = GetWindowTextLength(hwndOutput) + lstrlen(Text) + 1;

	// create buffer to hold current and new text
	TCHAR* buf = (TCHAR*)GlobalAlloc(GPTR, outLength * sizeof(TCHAR));
	if (!buf) return;

	// get existing text from edit control and put into buffer
	GetWindowText(hwndOutput, buf, outLength);

	// append the newText to the buffer
	_tcscat_s(buf, outLength, Text);

	// Set the text in the edit control
	SetWindowText(hwndOutput, buf);

	// free the buffer
	GlobalFree(buf);

	SendMessage(GetDlgItem(hDlg, IDC_LOGBOX), LOWORD(WM_VSCROLL), SB_BOTTOM, 0);
}

VOID SetStatus(HWND hDlg, LPCWSTR Text)
{
	AppendLog(hDlg, Text);
	AppendLog(hDlg, L"\r\n");
}

VOID SetStatusInitial(HWND hDlg)
{
	AppendLog(hDlg, L"Ready. ");

#if defined (Env86)
	AppendLogLineDlg(L"Current platform: x86");
#elif defined (Env64)
	AppendLogLineDlg(L"Current platform: x64");
#elif defined (EnvARM)
	AppendLogLineDlg(L"Current platform: ARM");
#else
	AppendLogLineDlg(L"Current platform: ???");
#endif
}

BOOL FileExists(TCHAR* szPath)
{
	DWORD dwAttrib = GetFileAttributes(szPath);

	return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		!(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
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
typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
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

	DWORD fLen = GetFileSize(hFile, NULL), fRead;
	char* binary = new char[fLen];

	StrFormatByteSizeW(hDlg, fLen, SizeBuf, 128);
	swprintf_s(LogBuf, 512, L"Reading %s...", SizeBuf);
	AppendLogLineDlg(LogBuf);

	if (!ReadFile(hFile, binary, fLen, &fRead, NULL))
	{
		CloseHandle(hFile);

		return GetLastError();
	}

	CloseHandle(hFile);

	AppendLogLineDlg(L"Working with headers...");

	int success = 1, rc = 0;
	const uintptr_t binary_address = (uintptr_t)binary;
	// after reading the file into `binary`
	IMAGE_DOS_HEADER* const dos = (IMAGE_DOS_HEADER*)binary;
	BYTE* nt_base = (BYTE*)binary + dos->e_lfanew;

	// verify signature
	if (((IMAGE_NT_HEADERS*)nt_base)->Signature != IMAGE_NT_SIGNATURE) {
		rc = -2;
		return RunPEResult;
	}

	// select 32 vs 64 headers
	bool is64 = (((IMAGE_NT_HEADERS*)nt_base)->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

	DWORD entryRVA;
	SIZE_T sizeOfImage, sizeOfHeaders;
	PVOID preferredBase;
	WORD  numberOfSections;
	PIMAGE_SECTION_HEADER firstSection;

	if (is64) {
		auto nt = (IMAGE_NT_HEADERS64*)nt_base;
		entryRVA = nt->OptionalHeader.AddressOfEntryPoint;
		sizeOfImage = nt->OptionalHeader.SizeOfImage;
		sizeOfHeaders = nt->OptionalHeader.SizeOfHeaders;
		preferredBase = (PVOID)(ULONG_PTR)nt->OptionalHeader.ImageBase;
		numberOfSections = nt->FileHeader.NumberOfSections;
		firstSection = IMAGE_FIRST_SECTION(nt);
	}
	else {
		auto nt = (IMAGE_NT_HEADERS32*)nt_base;
		entryRVA = nt->OptionalHeader.AddressOfEntryPoint;
		sizeOfImage = nt->OptionalHeader.SizeOfImage;
		sizeOfHeaders = nt->OptionalHeader.SizeOfHeaders;
		preferredBase = (PVOID)(ULONG_PTR)nt->OptionalHeader.ImageBase;
		numberOfSections = nt->FileHeader.NumberOfSections;
		firstSection = IMAGE_FIRST_SECTION(nt);
	}

	AppendLogLineDlg(L"Launching new instance...");

	STARTUPINFOW startup_info;
	PROCESS_INFORMATION process_info;

	SecureZeroMemory(&startup_info, sizeof(startup_info));
	SecureZeroMemory(&process_info, sizeof(process_info));

	WCHAR Args[ARGS_LEN] = { };
	swprintf_s(Args, ARGS_LEN, L"\"%s\" %s", StubPath, FilePathArgs);
	success = CreateProcessW(StubPath, Args, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startup_info, &process_info);

	if (!success)
		return RunPEResult;

	AppendLogLineDlg(L"Allocating context...");

	CONTEXT* const ctx = (CONTEXT*)VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#if defined(Env64)
	ctx->ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
#else
	ctx->ContextFlags = CONTEXT_FULL;
#endif

	AppendLogLineDlg(L"Getting context...");

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

	// PEB->ImageBaseAddress location inside target process
	void* const pebImageBaseField = (void*)(ctx->PEB_PTR_REG + PEB_IMAGEBASE_OFF);

	// read (optional) existing image base
	uintptr_t* image_base_ptr;
	success = ReadProcessMemory(process_info.hProcess, pebImageBaseField, &image_base_ptr, sizeof(image_base_ptr), NULL);
	if (!success) return FinalizeRunPE(success, rc, process_info.hProcess);

	// allocate at preferred base (no reloc handling in this loader)
	void* const remoteBase = VirtualAllocEx(process_info.hProcess, preferredBase, sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!remoteBase) return FinalizeRunPE(FALSE, rc, process_info.hProcess);

	// write headers
	success = WriteProcessMemory(process_info.hProcess, remoteBase, binary, sizeOfHeaders, NULL);
	if (!success) return FinalizeRunPE(success, rc, process_info.hProcess);

	// write sections
	for (WORD i = 0; i < numberOfSections; ++i) {
		const PIMAGE_SECTION_HEADER sh = &firstSection[i];
		if (!sh->SizeOfRawData) continue;

		void* const dst = (BYTE*)remoteBase + sh->VirtualAddress;
		void* const src = (BYTE*)binary + sh->PointerToRawData;

		success = WriteProcessMemory(process_info.hProcess, dst, src, sh->SizeOfRawData, NULL);
		if (!success) return FinalizeRunPE(success, rc, process_info.hProcess);
	}

	// set PEB->ImageBaseAddress to actual mapping base (pointer-size aware)
	PVOID newBase = remoteBase;
	success = WriteProcessMemory(process_info.hProcess, pebImageBaseField, &newBase, sizeof(newBase), NULL);
	if (!success) return FinalizeRunPE(success, rc, process_info.hProcess);


	AppendLogLineDlg(L"Setting thread context...");

	// set the entry "parameter" register used by the start thunk
	ctx->ENTRY_REG = (DWORD_PTR)remoteBase + entryRVA;

	success = SetThreadContext(process_info.hThread, ctx);

	if (!success)
		return FinalizeRunPE(success, rc, process_info.hProcess);

	AppendLogLineDlg(L"Finalizing...");

	success = ResumeThread(process_info.hThread);

	if (!success)
		return FinalizeRunPE(success, rc, process_info.hProcess);

	if (SendMessage(GetDlgItem(hDlg, IDC_WAIT_FOR_EXIT), BM_GETCHECK, 0, 0) == BST_CHECKED)
	{
		AppendLogLineDlg(L"Waiting for target exit...");
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

	AppendLogLineDlg(L"Initializing...");

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
		switch (((NMHDR*)lParam)->code)
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
