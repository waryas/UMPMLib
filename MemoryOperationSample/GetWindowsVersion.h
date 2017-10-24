#pragma once

#include <windows.h>

#pragma comment(lib,"Version.lib")

enum Windows {
	WINDOWS7,
	WINDOWS8,
	WINDOWS81,
	WINDOWS10,
	UNSUPPORTED
};

Windows getVersion() {
	static const wchar_t kernel32[] = L"\\kernel32.dll";
	wchar_t *path = NULL;
	void *ver = NULL, *block;
	Windows version;
	UINT n;
	BOOL r;
	DWORD versz, blocksz;
	VS_FIXEDFILEINFO *vinfo;

	path = (wchar_t*)malloc(sizeof(*path) * MAX_PATH);
	if (!path)
		abort();

	n = GetSystemDirectory(path, MAX_PATH);
	if (n >= MAX_PATH || n == 0 ||
		n > MAX_PATH - sizeof(kernel32) / sizeof(*kernel32))
		abort();
	memcpy(path + n, kernel32, sizeof(kernel32));

	versz = GetFileVersionInfoSize(path, NULL);
	if (versz == 0)
		abort();
	ver = malloc(versz);
	if (!ver)
		abort();
	r = GetFileVersionInfo(path, 0, versz, ver);
	if (!r)
		abort();
	r = VerQueryValue(ver, L"\\", &block, (PUINT)&blocksz);
	if (!r || blocksz < sizeof(VS_FIXEDFILEINFO))
		abort();
	vinfo = (VS_FIXEDFILEINFO *)block;
	if ((int)HIWORD(vinfo->dwProductVersionMS) == 10) {
		version = WINDOWS10;
	}
	else if ((int)HIWORD(vinfo->dwProductVersionMS) == 6) {
		switch ((int)LOWORD(vinfo->dwProductVersionMS)) {
		case 0:
			version = UNSUPPORTED;
			break;
		case 1:
			version = WINDOWS7;
			break;
		case 2:
			version = WINDOWS8;
			break;
		case 3:
			version = WINDOWS81;
			break;
		default:
			version = UNSUPPORTED;
		}
	}
	else {
		version = UNSUPPORTED;
	}
	free(path);
	free(ver);
	return version;
}