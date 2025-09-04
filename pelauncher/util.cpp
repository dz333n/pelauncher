#include "stdafx.h"
#include "util.h"

BOOL FileExists(LPCTSTR szPath)
{
    DWORD dwAttrib = GetFileAttributes(szPath);
    return (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

VOID Display32ErrorDialog(HWND Parent, DWORD code)
{
    WCHAR Buffer[512] = { }, ErrorBuffer[256] = { };

    if (code == 0) wcscpy_s(ErrorBuffer, 256, L"Unknown");
    else if (code == (DWORD)-1) wcscpy_s(ErrorBuffer, 256, L"Wrong platform");
    else if (code == (DWORD)-2) wcscpy_s(ErrorBuffer, 256, L"Invalid executable (PE)");
    else FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        code,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        ErrorBuffer,
        (sizeof(ErrorBuffer) / sizeof(WCHAR)),
        NULL);

    swprintf_s(Buffer, 512, L"Error %d - %s", code, ErrorBuffer);
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
    if (!func)
    {
        Display32ErrorDialog(hDlg, GetLastError());
        FreeLibrary(module);
        return NULL;
    }

    PWSTR result = func(qdw, pszBuf, cchBuf);
    FreeLibrary(module);
    return result;
}

