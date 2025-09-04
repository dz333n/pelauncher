#pragma once

#include "stdafx.h"

DWORD FinalizeRunPE(int success, int rc, HANDLE hProcess, HANDLE hThread, CONTEXT* ctx);
int RunPortableExecutable(HWND hDlg);

