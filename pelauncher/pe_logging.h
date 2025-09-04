#pragma once

#include "stdafx.h"
#include "logging.h"

LPCWSTR DirName(UINT i);
VOID LogDosHeader(HWND hDlg, const IMAGE_DOS_HEADER* dos);
VOID LogFileHeader(HWND hDlg, const IMAGE_FILE_HEADER* fh);
VOID LogOptionalHeader32(HWND hDlg, const IMAGE_OPTIONAL_HEADER32* oh);
VOID LogOptionalHeader64(HWND hDlg, const IMAGE_OPTIONAL_HEADER64* oh);
VOID LogSections(HWND hDlg, const IMAGE_SECTION_HEADER* firstSection, WORD numberOfSections);

