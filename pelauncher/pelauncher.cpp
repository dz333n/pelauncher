// pelauncher.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "resource.h"

#if defined (_M_ARM)
#define EnvARM
#define Unsupported
#define IgnoreMainCode
#else
#if _WIN32 || _WIN64
#if _WIN64
#define Env64
#define Unsupported
#else
#define Env86
#endif
#endif
#endif

#if defined (Unsupported)
#pragma message ("Platform unsupported !!!!")
#endif

// Global Variables:
HINSTANCE hInst;								// current instance
LRESULT CALLBACK	DlgProc(HWND, UINT, WPARAM, LPARAM);

TCHAR FilePath[MAX_PATH] = { };
LPWSTR RunArgumentPath;
BOOL RunArgument = FALSE;

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

	DialogBox(hInst, MAKEINTRESOURCE(IDD_MAIN), NULL, (DLGPROC)DlgProc);

	return 0;
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
	SetWindowText(GetDlgItem(hDlg, IDC_EXE_PATH), FilePath);
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

int RunPortableExecutable()
{
#ifndef IgnoreMainCode // to keep build ok even if broken

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

	if (!ReadFile(hFile, binary, fLen, NULL, NULL))
	{
		CloseHandle(hFile);

		return GetLastError();
	}

	CloseHandle(hFile);
	int success = 1, rc = 0;
	const uintptr_t binary_address = (uintptr_t)binary;
	IMAGE_DOS_HEADER* const dos_header = (IMAGE_DOS_HEADER*)binary;
	IMAGE_NT_HEADERS* const nt_header = (IMAGE_NT_HEADERS*)(binary_address + dos_header->e_lfanew);

	if (nt_header->Signature != IMAGE_NT_SIGNATURE) {
		rc = 1;
		return RunPEResult;
	}

	STARTUPINFOW startup_info;
	PROCESS_INFORMATION process_info;

	SecureZeroMemory(&startup_info, sizeof(startup_info));
	SecureZeroMemory(&process_info, sizeof(process_info));

	wchar_t current_file_path[MAX_PATH];
	GetModuleFileNameW(NULL, current_file_path, MAX_PATH);

	success = CreateProcessW(current_file_path, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startup_info, &process_info);

	if (!success)
		return RunPEResult;

	CONTEXT* const ctx = (CONTEXT*)VirtualAlloc(NULL, sizeof(ctx), MEM_COMMIT, PAGE_READWRITE);
	ctx->ContextFlags = CONTEXT_FULL;

	success = GetThreadContext(process_info.hThread, ctx);

	if (!success)
		return FinalizeRunPE(success, rc, process_info.hProcess);

	uintptr_t* image_base;

#if defined (Env86)
	void* const modified_ebx = (void*)(ctx->Ebx + 8);
#elif defined (Env64)
	void* const modified_ebx = (void*)(ctx->Rbx + 8);
#else
#error "Unknown platfom"
#endif

	success = ReadProcessMemory(process_info.hProcess, modified_ebx, &image_base, 4, NULL);

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

		success = WriteProcessMemory(process_info.hProcess, virtual_base_address, virtual_buffer, section_header->SizeOfRawData, 0);

		if (!success)
			return FinalizeRunPE(success, rc, process_info.hProcess);
	}

	success = WriteProcessMemory(process_info.hProcess, modified_ebx, (void*)&nt_header->OptionalHeader.ImageBase, 4, 0);

	if (!success)
		return FinalizeRunPE(success, rc, process_info.hProcess);

#if defined (Env86)
	ctx->Eax = binary_base_address + nt_header->OptionalHeader.AddressOfEntryPoint;
#elif defined (Env64)
	ctx->Rax = binary_base_address + nt_header->OptionalHeader.AddressOfEntryPoint; 
#else
#error "Unknown platfom"
#endif

	success = SetThreadContext(process_info.hThread, ctx);

	if (!success)
		return FinalizeRunPE(success, rc, process_info.hProcess);

	success = ResumeThread(process_info.hThread);

	if (!success)
		return FinalizeRunPE(success, rc, process_info.hProcess);

	return RunPEResult;
#else
	MessageBox(0, L"Platform unsupported: returning -1", L"PELauncher", 0);
	return -1;
#endif
}

VOID Display32ErrorDialog(HWND Parent, DWORD code)
{
	WCHAR Buffer[512] = { };
	WCHAR ErrorBuffer[256] = { };

	if (code == 0) wcscpy_s(ErrorBuffer, 256, L"Unknown");
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

	LocalFree(Buffer);
	LocalFree(ErrorBuffer);
}

VOID DoLaunch(HWND hDlg)
{
	GetWindowText(GetDlgItem(hDlg, IDC_EXE_PATH), FilePath, MAX_PATH);

	if (_tcslen(FilePath) <= 0) return;

	int result = RunPortableExecutable();

	if (result == 0)
	{
		EndDialog(hDlg, 0);
	}
	else
	{
		Display32ErrorDialog(hDlg, result);
	}
}

LRESULT CALLBACK DlgProc(HWND hDlg, UINT Msg, WPARAM wParam, LPARAM lParam)
{
	if (Msg == WM_INITDIALOG)
	{
#if defined (Env86)
		SetWindowText(GetDlgItem(hDlg, IDC_PLATFORM), L"Platform: x86");
#elif defined (Env64)
		SetWindowText(GetDlgItem(hDlg, IDC_PLATFORM), L"Platform: x64");
#elif defined (EnvARM)
		SetWindowText(GetDlgItem(hDlg, IDC_PLATFORM), L"Platform: ARM");
#else
		SetWindowText(GetDlgItem(hDlg, IDC_PLATFORM), L"Unknown platform");
#endif

#if defined (Unsupported)
		MessageBox(hDlg, L"Current platform is unsupported.", L"PELauncher", 0);
#endif
		UpdateButton(hDlg);

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
	else if (Msg == WM_COMMAND)
	{
		if (HIWORD(wParam) == EN_CHANGE
			&& LOWORD(wParam) == IDC_EXE_PATH)
		{
			UpdateButton(hDlg);
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
				ofn.lpstrFile = FilePath;
				ofn.nMaxFile = sizeof(FilePath);
				ofn.lpstrFilter = TEXT("Executables (*.exe)\0*.exe\0All Files (*.*)\0*.*\0");
				ofn.nFilterIndex = 1;
				ofn.lpstrFileTitle = NULL;
				ofn.nMaxFileTitle = 0;
				ofn.lpstrInitialDir = NULL;
				ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

				if (GetOpenFileName(&ofn))
					UpdatePath(hDlg);

				break;
			}
		}
	}
	return 0;
}
