#include "stdafx.h"
#include "state.h"

TCHAR FilePathSafe[MAX_PATH] = { };
TCHAR FilePathArgs[ARGS_LEN] = { };
LPWSTR RunArgumentPath = nullptr;
BOOL RunArgument = FALSE;
TCHAR StubPath[MAX_PATH] = { };

