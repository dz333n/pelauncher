#define WIN32_LEAN_AND_MEAN
#include <windows.h>

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPWSTR    lpCmdLine,
	_In_ int       nCmdShow)
{
	MessageBox(NULL, lpCmdLine, L"PELauncher Stub", 0);
	return 0;
}
