#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <shlobj.h>
#include <winhttp.h>
#include <fdi.h>
#include <stdarg.h>
#include <intrin.h>

#define MAX_THREAD_COUNT 8
#define UPDATE_INTERVAL_MSEC 250

#pragma comment (lib, "kernel32.lib")
#pragma comment (lib, "user32.lib")
#pragma comment (lib, "shell32.lib")
#pragma comment (lib, "shlwapi.lib")
#pragma comment (lib, "winhttp.lib")
#pragma comment (lib, "cabinet.lib")

#ifdef _DEBUG
#define Assert(cond) do { if (!(cond)) __debugbreak(); } while (0)
#else
#define Assert(cond) (void)(cond)
#endif

static void print(const char* msg, ...)
{
	va_list args;
	va_start(args, msg);

	char buffer[1024];
	DWORD length = wvsprintfA(buffer, msg, args);

	DWORD written;
	WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), buffer, length, &written, NULL);

	va_end(args);
}

static int argc;
static LPWSTR* argv;

static LPCWSTR output_folder;
static HANDLE iocp;
static HANDLE threads[MAX_THREAD_COUNT];

static volatile DWORD total_files;
static volatile DWORD processed_files;
static volatile DWORD exe_files;
static volatile DWORD debug_files;
static volatile DWORD missing_files;
static volatile DWORD error_files;
static volatile DWORD new_files;

static volatile LONG downloaded_bytes;
static LONG last_bytes;
static LARGE_INTEGER freq;
static LONG64 time[2];
static DWORD64 total_bytes;

static LPCWSTR server_url;
static WCHAR hostname[1024];
static HINTERNET session;
static INTERNET_PORT port;

static DWORD rva_to_offset(const IMAGE_NT_HEADERS* nt, DWORD rva)
{
	const IMAGE_SECTION_HEADER* section = (void*)((char*)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);

	for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++)
	{
		if (rva >= section[i].VirtualAddress && rva < section[i].VirtualAddress + section[i].SizeOfRawData)
		{
			return section[i].PointerToRawData + (rva - section[i].VirtualAddress);
		}
	}
	return 0;
}

static FNALLOC(CabAlloc)
{
	return HeapAlloc(GetProcessHeap(), 0, cb);
}

static FNFREE(CabFree)
{
	HeapFree(GetProcessHeap(), 0, pv);
}

static FNOPEN(CabOpen)
{
	const int O_RDONLY = 0;
	const int O_WRONLY = 1;
	const int O_RDWR = 2;
	const int O_CREAT = 0x200;
	DWORD access = oflag & O_RDWR ? GENERIC_READ | GENERIC_WRITE : oflag & O_WRONLY ? GENERIC_WRITE : GENERIC_READ;
	DWORD create = oflag & O_CREAT ? CREATE_ALWAYS : OPEN_EXISTING;
	return (INT_PTR)CreateFileA(pszFile, access, FILE_SHARE_READ, NULL, create, FILE_ATTRIBUTE_NORMAL, NULL);
}

static FNREAD(CabRead)
{
	DWORD read;
	return ReadFile((HANDLE)hf, pv, cb, &read, NULL) ? read : -1;
}

static FNWRITE(CabWrite)
{
	DWORD written;
	return WriteFile((HANDLE)hf, pv, cb, &written, NULL) ? written : -1;
}

static FNCLOSE(CabClose)
{
	return CloseHandle((HANDLE)hf) ? 0 : -1;
}

static FNSEEK(CabSeek)
{
	return SetFilePointer((HANDLE)hf, dist, NULL, seektype);
}

static FNFDINOTIFY(CabNotify)
{
	if (fdint == fdintCOPY_FILE)
	{
		return (INT_PTR)CreateFileW((LPWSTR)pfdin->pv, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	}
	else if (fdint == fdintCLOSE_FILE_INFO)
	{
		CloseHandle((HANDLE)pfdin->hf);
		return TRUE;
	}
	return 0;
}

static void download(HINTERNET connection, LPCWSTR name, LPCWSTR guid)
{
	WCHAR folder[MAX_PATH];
	PathCombineW(folder, output_folder, name);
	PathAppendW(folder, guid);

	WCHAR output[MAX_PATH];
	PathCombineW(output, folder, name);

	if (PathFileExistsW(output))
	{
		return;
	}

	// start download

	WCHAR full_url[1024];
	wsprintfW(full_url, L"%s/%s/%s/%s", server_url, name, guid, name);

	WCHAR temp_name[MAX_PATH];
	wsprintfW(temp_name, L"%s_%s.temp", name, guid);

	WCHAR temp_path[MAX_PATH];
	PathCombineW(temp_path, output_folder, temp_name);

#if 0
	// simulate 10MB/s downloading for 5 sec
	for (int i = 0; i < 50; i++)
	{
		Sleep(100);
		InterlockedAdd(&downloaded_bytes, 1024 * 1024);
	}
#else
	DWORD err = 0;
	DWORD status = 0;

	HANDLE handle = INVALID_HANDLE_VALUE;
	BOOL compressed = FALSE;

	WCHAR url_path[1024];
	URL_COMPONENTSW url =
	{
		.dwStructSize = sizeof(url),
		.lpszUrlPath = url_path,
		.dwUrlPathLength = _countof(url_path),
	};
	int trycount = 0;
	if (WinHttpCrackUrl(full_url, 0, 0, &url))
	{
retry:;
		HINTERNET request = WinHttpOpenRequest(connection, NULL, url_path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, url.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0);
		if (request != NULL)
		{
			if (WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) && WinHttpReceiveResponse(request, NULL))
			{
				DWORD size = sizeof(status);
				WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &status, &size, WINHTTP_NO_HEADER_INDEX);
				if (status == HTTP_STATUS_NOT_FOUND)
				{
					if (url_path[url.dwUrlPathLength - 1] != L'_')
					{
						// try compressed
						url_path[url.dwUrlPathLength - 1] = L'_';
						WinHttpCloseHandle(request);
						Sleep(100);
						compressed = TRUE;
						goto retry;
					}
				}
				else if (status == HTTP_STATUS_OK)
				{
					for (;;)
					{
						BYTE buffer[65536];
						DWORD read;
						if (!WinHttpReadData(request, buffer, sizeof(buffer), &read))
						{
							err = GetLastError();
							break;
						}

						if (read == 0)
						{
							break;
						}
						InterlockedAdd(&downloaded_bytes, read);

						if (handle == INVALID_HANDLE_VALUE)
						{
							if (buffer[0] == 'R' &&
								buffer[1] == 'e' &&
								buffer[2] == 'f' &&
								buffer[3] == ' ' &&
								buffer[4] == 'A' &&
								buffer[5] == ':' &&
								buffer[6] == ' ')
							{
								if (trycount == 10)
								{
									status = HTTP_STATUS_NOT_FOUND;
									break;
								}
								WinHttpCloseHandle(request);
								Sleep(100);
								++trycount;
								goto retry;	
							}

							handle = CreateFileW(temp_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
							if (handle == INVALID_HANDLE_VALUE)
							{
								err = GetLastError();
								if (err == ERROR_SHARING_VIOLATION)
								{
									// ok, just return - some other thread is already downloading this file
									WinHttpCloseHandle(request);
									return;
								}
								break;
							}
						}

						DWORD written;
						if (!WriteFile(handle, buffer, read, &written, NULL) || written != read)
						{
							err = GetLastError();
							break;
						}
					}
				}
			}
			else
			{
				err = GetLastError();
			}
			WinHttpCloseHandle(request);
		}
		else
		{
			err = GetLastError();
		}
	}

	if (handle != INVALID_HANDLE_VALUE)
	{
		if (!CloseHandle(handle))
		{
			err = GetLastError();
		}
	}

	if (status != HTTP_STATUS_OK)
	{
		// missing symbol file, nothing is downloaded
		InterlockedIncrement(&missing_files);
		return;
	}

	if (err != 0)
	{
		// error downloading
		InterlockedIncrement(&error_files);
		DeleteFileW(temp_path);
		return;
	}

	err = SHCreateDirectory(NULL, folder);
	if (err != ERROR_SUCCESS && err != ERROR_ALREADY_EXISTS)
	{
		// cannot create folder for output file
		InterlockedIncrement(&error_files);
		DeleteFileW(temp_path);
		return;
	}

	if (compressed)
	{
		ERF err;
		HFDI ctx = FDICreate(&CabAlloc, &CabFree, &CabOpen, &CabRead, &CabWrite, &CabClose, &CabSeek, cpuUNKNOWN, &err);
		if (ctx)
		{
			char file[MAX_PATH];
			char folder[MAX_PATH];
			WideCharToMultiByte(CP_ACP, 0, temp_name, -1, file, _countof(file), NULL, NULL);
			WideCharToMultiByte(CP_ACP, 0, output_folder, -1, folder, _countof(folder), NULL, NULL);
			PathAddBackslashA(folder);

			if (!FDICopy(ctx, file, folder, 0, &CabNotify, NULL, output))
			{
				// cannot uncompress
				InterlockedIncrement(&error_files);
				DeleteFileW(temp_path);
				DeleteFileW(output);
				FDIDestroy(ctx);
				return;
			}
			FDIDestroy(ctx);

			DeleteFileW(temp_path);
		}
		else
		{
			// cannot initialize cab decompression
			InterlockedIncrement(&error_files);
			DeleteFileW(temp_path);
			return;
		}
	}
	else
	{
		if (MoveFileExW(temp_path, output, MOVEFILE_REPLACE_EXISTING) == 0)
		{
			// cannot move temp file into folder
			InterlockedIncrement(&error_files);
			DeleteFileW(temp_path);
			return;
		}
	}
#endif

	// success
	InterlockedIncrement(&new_files);
}

static BOOL process(HINTERNET connection, LPCVOID base, const IMAGE_NT_HEADERS* nt)
{
	const IMAGE_DATA_DIRECTORY* debug_data;

	if (nt->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 && nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		const IMAGE_NT_HEADERS32* nt32 = (void*)nt;
		const IMAGE_OPTIONAL_HEADER32* opt = &nt32->OptionalHeader;
		debug_data = &opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
	}
	else if (nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 && nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		const IMAGE_NT_HEADERS64* nt64 = (void*)nt;
		const IMAGE_OPTIONAL_HEADER64* opt = &nt64->OptionalHeader;
		debug_data = &opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
	}
	else
	{
		return FALSE;
	}

	DWORD offset = rva_to_offset(nt, debug_data->VirtualAddress);
	if (offset == 0)
	{
		return FALSE;
	}
	DWORD count = debug_data->Size / sizeof(IMAGE_DEBUG_DIRECTORY);
	const IMAGE_DEBUG_DIRECTORY* entries = (void*)((char*)base + offset);
	for (DWORD i = 0; i < count; i++)
	{
		if (entries[i].Type == IMAGE_DEBUG_TYPE_CODEVIEW)
		{
			char* debug = (char*)base + entries[i].PointerToRawData;

			DWORD signature = *(DWORD*)debug;

			if (signature == 'SDSR')
			{
				const GUID* guid = (void*)(debug + sizeof(signature));
				const DWORD* age = (void*)(guid + 1);
				const CHAR* pdb = (void*)(age + 1);

				WCHAR filename[MAX_PATH];
				MultiByteToWideChar(CP_UTF8, 0, pdb, -1, filename, MAX_PATH);
				PathStripPathW(filename);

				WCHAR sguid[MAX_PATH];
				wsprintfW(sguid, L"%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%x",
					guid->Data1, guid->Data2, guid->Data3,
					guid->Data4[0], guid->Data4[1], guid->Data4[2], guid->Data4[3],
					guid->Data4[4], guid->Data4[5], guid->Data4[6], guid->Data4[7],
					*age);

				download(connection, filename, sguid);

				return TRUE;
			}
			else if (signature == '01BN')
			{
				const DWORD* offset = (void*)(debug + sizeof(signature));
				const DWORD* timestamp = (void*)(offset + 1);
				const DWORD* age = (void*)(timestamp + 1);
				const CHAR* pdb = (void*)(age + 1);

				WCHAR filename[MAX_PATH];
				MultiByteToWideChar(CP_UTF8, 0, pdb, -1, filename, MAX_PATH);
				PathStripPathW(filename);

				WCHAR sguid[MAX_PATH];
				wsprintfW(sguid, L"%08X%x", *timestamp, *age);

				download(connection, filename, sguid);

				return TRUE;
			}
			else
			{
				// TODO: are there any other formats possible here?
				Assert(0);
				return FALSE;
			}
		}
	}

	return FALSE;
}

static DWORD WINAPI ProcessThread(LPVOID arg)
{
	HINTERNET connection = WinHttpConnect(session, hostname, port, 0);
	if (connection == NULL)
	{
		return 0;
	}

	DWORD bytes;
	ULONG_PTR key;
	OVERLAPPED* overlapped;
	while (GetQueuedCompletionStatus(iocp, &bytes, &key, &overlapped, INFINITE))
	{
		if (key == 0)
		{
			break;
		}
		LPWSTR file = (LPWSTR)key;

		HANDLE h = CreateFileW(file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		if (h != INVALID_HANDLE_VALUE)
		{
			LARGE_INTEGER size;
			if (GetFileSizeEx(h, &size) && size.QuadPart > sizeof(IMAGE_DOS_HEADER))
			{
				HANDLE mapping = CreateFileMappingW(h, NULL, PAGE_READONLY, size.HighPart, size.LowPart, NULL);
				if (mapping != NULL)
				{
					LPVOID base = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, size.QuadPart);
					if (base)
					{
						const IMAGE_DOS_HEADER* dos = base;
						if (dos->e_magic == IMAGE_DOS_SIGNATURE && ((SIZE_T)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) < (SIZE_T)size.QuadPart))
						{
							const IMAGE_NT_HEADERS* nt = (void*)((char*)base + dos->e_lfanew);
							if (nt->Signature == IMAGE_NT_SIGNATURE)
							{
								InterlockedIncrement(&exe_files);

								if (process(connection, base, nt))
								{
									InterlockedIncrement(&debug_files);
								}
							}
						}

						UnmapViewOfFile(base);
					}
					CloseHandle(mapping);
				}
			}
			CloseHandle(h);
		}

		LocalFree(file);
		InterlockedIncrement(&processed_files);
	}

	WinHttpCloseHandle(connection);
	return 0;
}

static void add_file(LPCWSTR file)
{
	InterlockedIncrement(&total_files);
	PostQueuedCompletionStatus(iocp, 0, (ULONG_PTR)StrDupW(file), NULL);
}

static void run_folder(LPCWSTR folder)
{
	WCHAR path[MAX_PATH];
	PathCombineW(path, folder, L"*");

	WIN32_FIND_DATAW data;
	HANDLE find = FindFirstFileExW(path, FindExInfoBasic, &data, FindExSearchNameMatch, NULL, FIND_FIRST_EX_LARGE_FETCH);
	if (find != INVALID_HANDLE_VALUE)
	{
		do
		{
			if ((data.cFileName[0] == L'.' && data.cFileName[1] == 0) ||
				(data.cFileName[0] == L'.' && data.cFileName[1] == L'.' && data.cFileName[2] == 0))
			{
				continue;
			}
			else if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				PathCombineW(path, folder, data.cFileName);
				run_folder(path);
			}
			else
			{
				WCHAR file[1024];
				wsprintfW(file, L"%s\\%s", folder, data.cFileName);
				add_file(file);
			}
		}
		while (FindNextFileW(find, &data));

		FindClose(find);
	}
}

static DWORD WINAPI RunThread(LPVOID arg)
{
	for (int i = 3; i < argc; i++)
	{
		LPCWSTR input = argv[i];

		if (PathIsDirectoryW(input))
		{
			run_folder(input);
		}
		else
		{
			add_file(input);
		}
	}
	return 0;
}

static void display(void)
{
	LARGE_INTEGER now;
	QueryPerformanceCounter(&now);

	while (now.QuadPart >= time[0] + freq.QuadPart)
	{
		time[1] = time[0];
		time[0] = now.QuadPart;

		last_bytes = downloaded_bytes;
		InterlockedAdd(&downloaded_bytes, -last_bytes);
		total_bytes += last_bytes;
	}

	DWORD64 current_bytes = last_bytes + downloaded_bytes;
	DWORD64 elapsed_time = now.QuadPart - time[1];
	
	DWORD speed = 0;
	if (elapsed_time != 0)
	{
		speed = (DWORD)((current_bytes * freq.QuadPart * 10) / (elapsed_time << 20));
	}

	print("\rF:%d/%d X:%d D:%d M:%d E:%d N:%d - %3d.%d MiB/s", total_files, processed_files, exe_files, debug_files, missing_files, error_files, new_files, speed / 10, speed % 10);
}

void mainCRTStartup()
{
	argv = CommandLineToArgvW(GetCommandLineW(), &argc);

	if (argc < 4)
	{
		print("Usage: %S SymbolServer OutputFolder [InputFolder...]\n", argv[0]);
		ExitProcess(1);
	}

	server_url = argv[1];
	output_folder = argv[2];

	DWORD err = SHCreateDirectory(NULL, output_folder);
	if (err != ERROR_SUCCESS && err != ERROR_ALREADY_EXISTS)
	{
		print("Cannot create output folder: %S\n", output_folder);
		ExitProcess(1);
	}


	URL_COMPONENTSW url =
	{
		.dwStructSize = sizeof(url),
		.lpszHostName = hostname,
		.dwHostNameLength = _countof(hostname),
	};

	if (!WinHttpCrackUrl(server_url, 0, 0, &url))
	{
		print("Bad server url: %S\n", server_url);
		ExitProcess(1);
	}
	port = url.nPort;

	QueryPerformanceFrequency(&freq);

	LARGE_INTEGER c1;
	QueryPerformanceCounter(&c1);
	time[0] = time[1] = c1.QuadPart;

	SYSTEM_INFO info;
	GetSystemInfo(&info);
	DWORD thread_count = min(info.dwNumberOfProcessors * 2, MAX_THREAD_COUNT);

	session = WinHttpOpen(NULL, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
	Assert(session);

	iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, thread_count);
	for (DWORD i = 0; i < thread_count; i++)
	{
		threads[i] = CreateThread(NULL, 0, &ProcessThread, NULL, 0, NULL);
	}

	HANDLE thread = CreateThread(NULL, 0, &RunThread, NULL, 0, NULL);
	for (;;)
	{
		DWORD wait = WaitForSingleObject(thread, UPDATE_INTERVAL_MSEC);
		if (wait == WAIT_TIMEOUT)
		{
			display();
		}
		else
		{
			break;
		}
	}
	CloseHandle(thread);

	for (DWORD i = 0; i < thread_count; i++)
	{
		PostQueuedCompletionStatus(iocp, 0, 0, NULL);
	}

	for (;;)
	{
		DWORD wait = WaitForMultipleObjects(thread_count, threads, TRUE, UPDATE_INTERVAL_MSEC);
		if (wait == WAIT_TIMEOUT)
		{
			display();
		}
		else
		{
			break;
		}
	}

	LARGE_INTEGER c2;
	QueryPerformanceCounter(&c2);

	total_bytes += downloaded_bytes;
	last_bytes = downloaded_bytes = 0;
	display();
	print("\n");

	DWORD seconds = (DWORD)((c2.QuadPart - c1.QuadPart) / freq.QuadPart);
	char total_time[64];
	StrFromTimeIntervalA(total_time, sizeof(total_time), seconds * 1000, 6);

	print("Total files on disk:     %d\n", total_files);
	print("Executables detected:    %d\n", exe_files);
	print("Executables with debug:  %d\n", debug_files);
	print("Files missing on server: %d\n", missing_files);
	print("Error downloading:       %d\n", error_files);
	print("New files downloaded:    %d\n", new_files);
	print("Total size downloaded:   %d MiB\n", (int)(total_bytes >> 20));
	if (seconds < 60)
	{
		print("Total runtime:          %s\n", total_time);
	}
	else
	{
		print("Total runtime:          %s (%d seconds)\n", total_time, seconds);
	}

	ExitProcess(0);
}
