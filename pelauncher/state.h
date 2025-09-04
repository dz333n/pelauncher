#pragma once

#include "stdafx.h"

#define ARGS_LEN 1024

// Shared UI/loader state
extern TCHAR FilePathSafe[MAX_PATH];
extern TCHAR FilePathArgs[ARGS_LEN];
extern LPWSTR RunArgumentPath;
extern BOOL RunArgument;
extern TCHAR StubPath[MAX_PATH];

