#include "stdafx.h"
#include "resource.h"

#include "state.h"
#include "logging.h"
#include "util.h"
#include "loader.h"
#include "platform.h"

static HFONT g_hLogFont = NULL;

static VOID UpdatePath(HWND hDlg)
{
    SetWindowText(GetDlgItem(hDlg, IDC_EXE_PATH), FilePathSafe);
}

static VOID UpdateStub(HWND hDlg)
{
    WCHAR str[256] = { };
    PCWSTR StubName = wcsrchr((wchar_t*)StubPath, L'\\');
    if (StubName)
    {
        ++StubName;
        swprintf_s(str, 256, L"<a>%s</a>", StubName);
    }
    else
    {
        swprintf_s(str, 256, L"<a>%s</a>", (wchar_t*)StubPath);
    }
    SetWindowText(GetDlgItem(hDlg, IDC_LINK_STUB), str);
}

static VOID UpdateButton(HWND hDlg)
{
    TCHAR Path[MAX_PATH];
    GetWindowText(GetDlgItem(hDlg, IDC_EXE_PATH), Path, MAX_PATH);
    BOOL enable = FileExists((TCHAR*)Path);
    EnableWindow(GetDlgItem(hDlg, IDLAUNCH), enable);
}

DWORD WINAPI ProcessThreadProc(CONST LPVOID lpParam)
{
    HWND hDlg = (HWND)lpParam;
    BOOL WaitForExitPreviousState = FALSE;

    GetWindowText(GetDlgItem(hDlg, IDC_EXE_PATH), FilePathSafe, MAX_PATH);
    GetWindowText(GetDlgItem(hDlg, IDC_EXE_ARGS), FilePathArgs, ARGS_LEN);

    if (_tcslen(FilePathSafe) > 0)
        Logf(hDlg, L"Selected file: %s", FilePathSafe);
    if (_tcslen(FilePathArgs) > 0)
        Logf(hDlg, L"Arguments: %s", FilePathArgs);

    if (_tcslen(FilePathSafe) <= 0) return TRUE;

    EnableWindow(GetDlgItem(hDlg, IDLAUNCH), FALSE);
    EnableWindow(GetDlgItem(hDlg, IDSELECT), FALSE);
    EnableWindow(GetDlgItem(hDlg, IDC_EXE_PATH), FALSE);
    EnableWindow(GetDlgItem(hDlg, IDC_EXE_ARGS), FALSE);
    WaitForExitPreviousState = IsWindowEnabled(GetDlgItem(hDlg, IDC_WAIT_FOR_EXIT));
    EnableWindow(GetDlgItem(hDlg, IDC_DO_NOT_EXIT), FALSE);
    EnableWindow(GetDlgItem(hDlg, IDC_WAIT_FOR_EXIT), FALSE);

    SetStatus(hDlg, L"Initializing...");

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
    HANDLE hThread = CreateThread(
        NULL,
        0,
        &ProcessThreadProc,
        hDlg,
        0,
        NULL);
    if (hThread)
        CloseHandle(hThread);
}

LRESULT CALLBACK DlgProc(HWND hDlg, UINT Msg, WPARAM wParam, LPARAM lParam)
{
    if (Msg == WM_INITDIALOG)
    {
        SetStatusInitial(hDlg);

        if (!g_hLogFont)
        {
            HDC hdc = GetDC(hDlg);
            int height = -MulDiv(10, GetDeviceCaps(hdc, LOGPIXELSY), 72);
            ReleaseDC(hDlg, hdc);
            g_hLogFont = CreateFont(
                height, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                FIXED_PITCH | FF_MODERN, L"Courier New");
        }
        if (g_hLogFont)
        {
            SendMessage(GetDlgItem(hDlg, IDC_LOGBOX), WM_SETFONT, (WPARAM)g_hLogFont, TRUE);
        }

        GetModuleFileNameW(NULL, StubPath, MAX_PATH);
        UpdateStub(hDlg);

#if defined (Unsupported)
        MessageBox(hDlg, L"Current platform is unsupported.", L"PELauncher", 0);
#endif
        UpdateButton(hDlg);

        SendMessage(GetDlgItem(hDlg, IDC_DO_NOT_EXIT), BM_SETCHECK, BST_CHECKED, 0);
        EnableWindow(GetDlgItem(hDlg, IDC_WAIT_FOR_EXIT), TRUE);
        SendMessage(GetDlgItem(hDlg, IDC_WAIT_FOR_EXIT), BM_SETCHECK, BST_CHECKED, 0);

        if (RunArgument)
        {
            SetWindowText(GetDlgItem(hDlg, IDC_EXE_PATH), RunArgumentPath);
            DoLaunch(hDlg);
        }

        return TRUE;
    }
    else if (Msg == WM_CLOSE)
    {
        if (g_hLogFont) { DeleteObject(g_hLogFont); g_hLogFont = NULL; }
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
        if (HIWORD(wParam) == EN_CHANGE && LOWORD(wParam) == IDC_EXE_PATH)
        {
            UpdateButton(hDlg);
            return TRUE;
        }
        else if (HIWORD(wParam) == BN_CLICKED && LOWORD(wParam) == IDC_DO_NOT_EXIT)
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

