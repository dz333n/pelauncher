#include "stdafx.h"
#include <vector>
#include <string>
#include <limits>
#include <stdio.h>

#include "resource.h"
#include "platform.h"
#include "state.h"
#include "logging.h"
#include "pe_logging.h"
#include "util.h"

#define RunPEResult (!success ? GetLastError() : rc)

DWORD FinalizeRunPE(int success, int rc, HANDLE hProcess, HANDLE hThread, CONTEXT* ctx)
{
    DWORD result = RunPEResult;

    if (IsDebuggerPresent()) DebugBreak();

    if (ctx)
        VirtualFree(ctx, 0, MEM_RELEASE);

    if (hThread && hThread != INVALID_HANDLE_VALUE)
        CloseHandle(hThread);

    if (hProcess && hProcess != INVALID_HANDLE_VALUE)
    {
        TerminateProcess(hProcess, 0);
        CloseHandle(hProcess);
    }

    return result;
}

int RunPortableExecutable(HWND hDlg)
{
#ifndef IgnoreMainCode
    WCHAR LogBuf[512] = { };
    WCHAR SizeBuf[128] = { };
    TCHAR FilePath[MAX_PATH] = { };

    if (!GetFullPathName(FilePathSafe, MAX_PATH, FilePath, NULL))
    {
        DWORD err = GetLastError();
        Logf(hDlg, L"GetFullPathName failed: %u", err);
        return err;
    }

    Logf(hDlg, L"Target: %s", FilePath);

    // Load file
    HANDLE hFile = CreateFile(
        FilePath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        DWORD err = GetLastError();
        Logf(hDlg, L"CreateFile failed: %u", err);
        return err;
    }

    LARGE_INTEGER fileSizeLi = { 0 };
    if (!GetFileSizeEx(hFile, &fileSizeLi))
    {
        DWORD err = GetLastError();
        CloseHandle(hFile);
        Logf(hDlg, L"GetFileSizeEx failed: %u", err);
        return err;
    }

    if (fileSizeLi.QuadPart <= 0 || (unsigned long long)fileSizeLi.QuadPart > (std::numeric_limits<SIZE_T>::max)())
    {
        CloseHandle(hFile);
        Logf(hDlg, L"File size invalid or too large");
        return ERROR_FILE_INVALID;
    }

    const SIZE_T fLen = (SIZE_T)fileSizeLi.QuadPart;
    DWORD fRead = 0;
    std::vector<char> binary;
    try { binary.resize(fLen); }
    catch (...) { CloseHandle(hFile); return ERROR_NOT_ENOUGH_MEMORY; }

    StrFormatByteSizeW(hDlg, fLen, SizeBuf, 128);
    swprintf_s(LogBuf, 512, L"Reading %s...", SizeBuf);
    SetStatus(hDlg, LogBuf);

    if (!ReadFile(hFile, binary.data(), (DWORD)fLen, &fRead, NULL) || fRead != (DWORD)fLen)
    {
        DWORD err = GetLastError();
        CloseHandle(hFile);
        Logf(hDlg, L"ReadFile failed or short read: %u (read=%u expected=%u)", err, fRead, (DWORD)fLen);
        return err ? err : ERROR_READ_FAULT;
    }

    CloseHandle(hFile);

    SetStatus(hDlg, L"Working with headers...");

    int success = 1, rc = 0;
    IMAGE_DOS_HEADER* const dos = (IMAGE_DOS_HEADER*)binary.data();

    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        rc = -2;
        Logf(hDlg, L"Invalid DOS header signature: 0x%04X", dos ? dos->e_magic : 0);
        return rc;
    }

    LogDosHeader(hDlg, dos);

    if ((SIZE_T)dos->e_lfanew >= fLen)
    {
        rc = -2;
        Logf(hDlg, L"e_lfanew out of range: 0x%08X (file len=%llu)", (UINT)dos->e_lfanew, (unsigned long long)fLen);
        return rc;
    }

    BYTE* nt_base = (BYTE*)binary.data() + dos->e_lfanew;

    if (((IMAGE_NT_HEADERS*)nt_base)->Signature != IMAGE_NT_SIGNATURE) {
        rc = -2;
        Logf(hDlg, L"Invalid NT signature: 0x%08X", ((IMAGE_NT_HEADERS*)nt_base)->Signature);
        return RunPEResult;
    }

    bool is64 = (((IMAGE_NT_HEADERS*)nt_base)->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    Logf(hDlg, L"NT Headers: Signature=0x%08X Magic=0x%04X (is64=%d)",
        ((IMAGE_NT_HEADERS*)nt_base)->Signature,
        ((IMAGE_NT_HEADERS*)nt_base)->OptionalHeader.Magic,
        is64 ? 1 : 0);

    DWORD entryRVA;
    SIZE_T sizeOfImage, sizeOfHeaders;
    PVOID preferredBase;
    WORD  numberOfSections;
    PIMAGE_SECTION_HEADER firstSection;

    if (is64) {
        auto nt = (IMAGE_NT_HEADERS64*)nt_base;
        LogFileHeader(hDlg, &nt->FileHeader);
        LogOptionalHeader64(hDlg, &nt->OptionalHeader);
        entryRVA = nt->OptionalHeader.AddressOfEntryPoint;
        sizeOfImage = nt->OptionalHeader.SizeOfImage;
        sizeOfHeaders = nt->OptionalHeader.SizeOfHeaders;
        preferredBase = (PVOID)(ULONG_PTR)nt->OptionalHeader.ImageBase;
        numberOfSections = nt->FileHeader.NumberOfSections;
        firstSection = IMAGE_FIRST_SECTION(nt);
    }
    else {
        auto nt = (IMAGE_NT_HEADERS32*)nt_base;
        LogFileHeader(hDlg, &nt->FileHeader);
        LogOptionalHeader32(hDlg, &nt->OptionalHeader);
        entryRVA = nt->OptionalHeader.AddressOfEntryPoint;
        sizeOfImage = nt->OptionalHeader.SizeOfImage;
        sizeOfHeaders = nt->OptionalHeader.SizeOfHeaders;
        preferredBase = (PVOID)(ULONG_PTR)nt->OptionalHeader.ImageBase;
        numberOfSections = nt->FileHeader.NumberOfSections;
        firstSection = IMAGE_FIRST_SECTION(nt);
    }

    LogSections(hDlg, firstSection, numberOfSections);

    SetStatus(hDlg, L"Launching new instance...");

    STARTUPINFOW startup_info;
    PROCESS_INFORMATION process_info;

    SecureZeroMemory(&startup_info, sizeof(startup_info));
    SecureZeroMemory(&process_info, sizeof(process_info));
    startup_info.cb = sizeof(startup_info);

    WCHAR Args[ARGS_LEN] = { };
    swprintf_s(Args, ARGS_LEN, L"\"%s\" %s", StubPath, FilePathArgs);
    Logf(hDlg, L"CreateProcess: '%s' args='%s'", StubPath, Args);
    success = CreateProcessW(StubPath, Args, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startup_info, &process_info);

    if (!success)
    {
        DWORD err = GetLastError();
        Logf(hDlg, L"CreateProcess failed: %u", err);
        return RunPEResult;
    }

    SetStatus(hDlg, L"Allocating context...");

    CONTEXT* const ctx = (CONTEXT*)VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#if defined(Env64)
    if (!ctx) { Logf(hDlg, L"VirtualAlloc for CONTEXT failed: %u", GetLastError()); return FinalizeRunPE(FALSE, rc, process_info.hProcess, process_info.hThread, NULL); }
    ctx->ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
#else
    if (!ctx) { Logf(hDlg, L"VirtualAlloc for CONTEXT failed: %u", GetLastError()); return FinalizeRunPE(FALSE, rc, process_info.hProcess, process_info.hThread, NULL); }
    ctx->ContextFlags = CONTEXT_FULL;
#endif

    SetStatus(hDlg, L"Getting context...");

    success = GetThreadContext(process_info.hThread, ctx);
    if (!success)
    {
        Logf(hDlg, L"GetThreadContext failed: %u", GetLastError());
        return FinalizeRunPE(success, rc, process_info.hProcess, process_info.hThread, ctx);
    }

    void* const pebImageBaseField = (void*)(ctx->PEB_PTR_REG + PEB_IMAGEBASE_OFF);
    Logf(hDlg, L"PEB ptr reg=0x%p, ImageBase field=0x%p", (void*)ctx->PEB_PTR_REG, pebImageBaseField);

    Logf(hDlg, L"Allocating remote image: preferred=0x%p size=0x%llX", preferredBase, sizeOfImage);
    void* const remoteBase = VirtualAllocEx(process_info.hProcess, preferredBase, sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteBase) { Logf(hDlg, L"VirtualAllocEx failed: %u", GetLastError()); return FinalizeRunPE(FALSE, rc, process_info.hProcess, process_info.hThread, ctx); }
    Logf(hDlg, L"Remote base: 0x%p", remoteBase);

    success = WriteProcessMemory(process_info.hProcess, remoteBase, binary.data(), sizeOfHeaders, NULL);
    if (!success) { Logf(hDlg, L"Write headers failed: %u", GetLastError()); return FinalizeRunPE(success, rc, process_info.hProcess, process_info.hThread, ctx); }

    for (WORD i = 0; i < numberOfSections; ++i) {
        const PIMAGE_SECTION_HEADER sh = &firstSection[i];
        if (!sh->SizeOfRawData) continue;

        void* const dst = (BYTE*)remoteBase + sh->VirtualAddress;
        void* const src = (BYTE*)binary.data() + sh->PointerToRawData;

        success = WriteProcessMemory(process_info.hProcess, dst, src, sh->SizeOfRawData, NULL);
        if (!success) { Logf(hDlg, L"Section write failed idx=%u: %u", i, GetLastError()); return FinalizeRunPE(success, rc, process_info.hProcess, process_info.hThread, ctx); }
    }

    PVOID newBase = remoteBase;
    success = WriteProcessMemory(process_info.hProcess, pebImageBaseField, &newBase, sizeof(newBase), NULL);
    if (!success) { Logf(hDlg, L"Write PEB ImageBase failed: %u", GetLastError()); return FinalizeRunPE(success, rc, process_info.hProcess, process_info.hThread, ctx); }

    SetStatus(hDlg, L"Setting thread context...");

    ctx->ENTRY_REG = (DWORD_PTR)remoteBase + entryRVA;
    Logf(hDlg, L"Entry point set to 0x%p", (void*)(ctx->ENTRY_REG));

    success = SetThreadContext(process_info.hThread, ctx);
    if (!success)
    {
        Logf(hDlg, L"SetThreadContext failed: %u", GetLastError());
        return FinalizeRunPE(success, rc, process_info.hProcess, process_info.hThread, ctx);
    }

    SetStatus(hDlg, L"Finalizing...");
    success = ResumeThread(process_info.hThread);
    if (!success)
    {
        Logf(hDlg, L"ResumeThread failed: %u", GetLastError());
        return FinalizeRunPE(success, rc, process_info.hProcess, process_info.hThread, ctx);
    }

    if (SendMessage(GetDlgItem(hDlg, IDC_WAIT_FOR_EXIT), BM_GETCHECK, 0, 0) == BST_CHECKED)
    {
        SetStatus(hDlg, L"Waiting for target exit...");
        WaitForSingleObject(process_info.hProcess, INFINITE);
        DWORD exitCode = 0;
        if (GetExitCodeProcess(process_info.hProcess, &exitCode))
            Logf(hDlg, L"Target exited with code: %u (0x%08X)", exitCode, exitCode);
    }

    if (ctx)
        VirtualFree(ctx, 0, MEM_RELEASE);
    if (process_info.hThread && process_info.hThread != INVALID_HANDLE_VALUE)
        CloseHandle(process_info.hThread);
    if (process_info.hProcess && process_info.hProcess != INVALID_HANDLE_VALUE)
        CloseHandle(process_info.hProcess);

    return RunPEResult;
#else
    MessageBox(0, L"Platform unsupported: returning -1", L"PELauncher", 0);
    return -1;
#endif
}

