#pragma once

#include "stdafx.h"

BOOL FileExists(LPCTSTR szPath);

VOID Display32ErrorDialog(HWND Parent, DWORD code);

typedef PWSTR(WINAPI* StrFormatByteSizeW_Import)(LONGLONG qdw, PWSTR pszBuf, UINT cchBuf);
PWSTR WINAPI StrFormatByteSizeW(HWND hDlg, LONGLONG qdw, PWSTR pszBuf, UINT cchBuf);

