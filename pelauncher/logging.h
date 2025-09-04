#pragma once

#include "stdafx.h"
#include "resource.h"

// Append raw text to the log control
VOID AppendLog(HWND hDlg, LPCWSTR Text);

// Append a line to the log
VOID SetStatus(HWND hDlg, LPCWSTR Text);

// Initial status message including platform
VOID SetStatusInitial(HWND hDlg);

// Small printf-style logger to log box
VOID Logf(HWND hDlg, LPCWSTR fmt, ...);

