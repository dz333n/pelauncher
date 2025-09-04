#include "stdafx.h"
#include "resource.h"
#include "logging.h"
#include "platform.h"

VOID AppendLog(HWND hDlg, LPCWSTR Text)
{
    HWND hwndOutput = GetDlgItem(hDlg, IDC_LOGBOX);
    int outLength = GetWindowTextLength(hwndOutput) + lstrlen(Text) + 1;

    TCHAR* buf = (TCHAR*)GlobalAlloc(GPTR, outLength * sizeof(TCHAR));
    if (!buf) return;

    GetWindowText(hwndOutput, buf, outLength);
    _tcscat_s(buf, outLength, Text);
    SetWindowText(hwndOutput, buf);
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
    SetStatus(hDlg, L"Current platform: x86");
#elif defined (Env64)
    SetStatus(hDlg, L"Current platform: x64");
#elif defined (EnvARM)
    SetStatus(hDlg, L"Current platform: ARM");
#else
    SetStatus(hDlg, L"Current platform: ???");
#endif
}

VOID Logf(HWND hDlg, LPCWSTR fmt, ...)
{
    WCHAR buf[1024] = { };
    va_list args;
    va_start(args, fmt);
    vswprintf_s(buf, _countof(buf) - 1, fmt, args);
    va_end(args);
    SetStatus(hDlg, buf);
}

