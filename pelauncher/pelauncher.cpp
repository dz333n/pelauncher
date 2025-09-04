// pelauncher.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "resource.h"

#include "state.h"
#include "ui.h"

// Global instance
HINSTANCE hInst;

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE /*hPrevInstance*/,
    _In_ LPWSTR    lpCmdLine,
    _In_ int       /*nCmdShow*/)
{
    hInst = hInstance;

    int pNumArgs = 0;
    LPWSTR* szArglist = CommandLineToArgvW(lpCmdLine, &pNumArgs);
    if (pNumArgs >= 1)
    {
        RunArgument = TRUE; // verify length later
        RunArgumentPath = lpCmdLine;
    }

    INITCOMMONCONTROLSEX icce = { };
    icce.dwSize = sizeof(icce);
    icce.dwICC = ICC_LINK_CLASS;
    InitCommonControlsEx(&icce);

    DialogBox(hInst, MAKEINTRESOURCE(IDD_MAIN), NULL, (DLGPROC)DlgProc);

    if (szArglist)
        LocalFree(szArglist);

    return 0;
}
