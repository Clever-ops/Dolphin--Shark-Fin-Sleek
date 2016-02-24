// Copyright 2008 Dolphin Emulator Project
// Licensed under GPLv2+
// Refer to the license.txt file included.

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <limits.h>
#include <string>
#include <vector>
#include <sys/stat.h>

#include "Common/Common.h"
#include "Common/CommonFuncs.h"
#include "Common/CommonPaths.h"
#include "Common/CommonTypes.h"
#include "Common/FileUtil.h"
#include "Common/Logging/Log.h"

#ifdef _WIN32
#include <commdlg.h>   // for GetSaveFileName
#include <direct.h>    // getcwd
#include <io.h>
#include <objbase.h>   // guid stuff
#include <shellapi.h>
#include <windows.h>
#else
#include <dirent.h>
#include <errno.h>
#include <libgen.h>
#include <stdlib.h>
#include <unistd.h>
#endif

#if defined(__APPLE__)
#include <CoreFoundation/CFBundle.h>
#include <CoreFoundation/CFString.h>
#include <CoreFoundation/CFURL.h>
#include <sys/param.h>
#endif

#ifndef S_ISDIR
#define S_ISDIR(m)  (((m)&S_IFMT) == S_IFDIR)
#endif

#if defined BSD4_4 || defined __FreeBSD__
#define stat64 stat
#define fstat64 fstat
#endif

// This namespace has various generic functions related to files and paths.
// The code still needs a ton of cleanup.
// REMEMBER: strdup considered harmful!
namespace File
{

// Remove any ending forward slashes from directory paths
// Modifies argument.
static void StripTailDirSlashes(std::string& fname)
{
	if (fname.length() > 1)
	{
		while (fname.back() == DIR_SEP_CHR)
			fname.pop_back();
	}
}

// Returns true if file filename exists
bool Exists(const std::string& filename)
{
	struct stat64 file_info;

	std::string copy(filename);
	StripTailDirSlashes(copy);

#ifdef _WIN32
	int result = _tstat64(UTF8ToTStr(copy).c_str(), &file_info);
#else
	int result = stat64(copy.c_str(), &file_info);
#endif

	return (result == 0);
}

// Returns true if filename is a directory
bool IsDirectory(const std::string& filename)
{
	struct stat64 file_info;

	std::string copy(filename);
	StripTailDirSlashes(copy);

#ifdef _WIN32
	int result = _tstat64(UTF8ToTStr(copy).c_str(), &file_info);
#else
	int result = stat64(copy.c_str(), &file_info);
#endif

	if (result < 0)
	{
		WARN_LOG(COMMON, "IsDirectory: stat failed on %s: %s",
				 filename.c_str(), GetLastErrorMsg().c_str());
		return false;
	}

	return S_ISDIR(file_info.st_mode);
}

// Deletes a given filename, return true on success
// Doesn't supports deleting a directory
bool Delete(const std::string& filename)
{
	INFO_LOG(COMMON, "Delete: file %s", filename.c_str());

	// Return true because we care about the file no
	// being there, not the actual delete.
	if (!Exists(filename))
	{
		WARN_LOG(COMMON, "Delete: %s does not exist", filename.c_str());
		return true;
	}

	// We can't delete a directory
	if (IsDirectory(filename))
	{
		WARN_LOG(COMMON, "Delete failed: %s is a directory", filename.c_str());
		return false;
	}

#ifdef _WIN32
	if (!DeleteFile(UTF8ToTStr(filename).c_str()))
	{
		WARN_LOG(COMMON, "Delete: DeleteFile failed on %s: %s",
				 filename.c_str(), GetLastErrorMsg().c_str());
		return false;
	}
#else
	if (unlink(filename.c_str()) == -1)
	{
		WARN_LOG(COMMON, "Delete: unlink failed on %s: %s",
				 filename.c_str(), GetLastErrorMsg().c_str());
		return false;
	}
#endif

	return true;
}

// Returns true if successful, or path already exists.
bool CreateDir(const std::string& path)
{
	INFO_LOG(COMMON, "CreateDir: directory %s", path.c_str());
#ifdef _WIN32
	if (::CreateDirectory(UTF8ToTStr(path).c_str(), nullptr))
		return true;
	DWORD error = GetLastError();
	if (error == ERROR_ALREADY_EXISTS)
	{
		WARN_LOG(COMMON, "CreateDir: CreateDirectory failed on %s: already exists", path.c_str());
		return true;
	}
	ERROR_LOG(COMMON, "CreateDir: CreateDirectory failed on %s: %i", path.c_str(), error);
	return false;
#else
	if (mkdir(path.c_str(), 0755) == 0)
		return true;

	int err = errno;

	if (err == EEXIST)
	{
		WARN_LOG(COMMON, "CreateDir: mkdir failed on %s: already exists", path.c_str());
		return true;
	}

	ERROR_LOG(COMMON, "CreateDir: mkdir failed on %s: %s", path.c_str(), strerror(err));
	return false;
#endif
}

// Creates the full path of fullPath returns true on success
bool CreateFullPath(const std::string& fullPath)
{
	int panicCounter = 100;
	INFO_LOG(COMMON, "CreateFullPath: path %s", fullPath.c_str());

	if (File::Exists(fullPath))
	{
		INFO_LOG(COMMON, "CreateFullPath: path exists %s", fullPath.c_str());
		return true;
	}

	size_t position = 0;
	while (true)
	{
		// Find next sub path
		position = fullPath.find(DIR_SEP_CHR, position);

		// we're done, yay!
		if (position == fullPath.npos)
			return true;

		// Include the '/' so the first call is CreateDir("/") rather than CreateDir("")
		std::string const subPath(fullPath.substr(0, position + 1));
		if (!File::IsDirectory(subPath))
			File::CreateDir(subPath);

		// A safety check
		panicCounter--;
		if (panicCounter <= 0)
		{
			ERROR_LOG(COMMON, "CreateFullPath: directory structure is too deep");
			return false;
		}
		position++;
	}
}


// Deletes a directory filename, returns true on success
bool DeleteDir(const std::string& filename)
{
	INFO_LOG(COMMON, "DeleteDir: directory %s", filename.c_str());

	// check if a directory
	if (!File::IsDirectory(filename))
	{
		ERROR_LOG(COMMON, "DeleteDir: Not a directory %s", filename.c_str());
		return false;
	}

#ifdef _WIN32
	if (::RemoveDirectory(UTF8ToTStr(filename).c_str()))
		return true;
#else
	if (rmdir(filename.c_str()) == 0)
		return true;
#endif
	ERROR_LOG(COMMON, "DeleteDir: %s: %s", filename.c_str(), GetLastErrorMsg().c_str());

	return false;
}

// renames file srcFilename to destFilename, returns true on success
bool Rename(const std::string& srcFilename, const std::string& destFilename)
{
	INFO_LOG(COMMON, "Rename: %s --> %s",
			srcFilename.c_str(), destFilename.c_str());
#ifdef _WIN32
	auto sf = UTF8ToTStr(srcFilename);
	auto df = UTF8ToTStr(destFilename);
	// The Internet seems torn about whether ReplaceFile is atomic or not.
	// Hopefully it's atomic enough...
	if (ReplaceFile(df.c_str(), sf.c_str(), nullptr, REPLACEFILE_IGNORE_MERGE_ERRORS, nullptr, nullptr))
		return true;
	// Might have failed because the destination doesn't exist.
	if (GetLastError() == ERROR_FILE_NOT_FOUND)
	{
		if (MoveFile(sf.c_str(), df.c_str()))
			return true;
	}
#else
	if (rename(srcFilename.c_str(), destFilename.c_str()) == 0)
		return true;
#endif
	ERROR_LOG(COMMON, "Rename: failed %s --> %s: %s",
			  srcFilename.c_str(), destFilename.c_str(), GetLastErrorMsg().c_str());
	return false;
}

#ifndef _WIN32
static void FSyncPath(const char* path)
{
	int fd = open(path, O_RDONLY);
	if (fd != -1)
	{
		fsync(fd);
		close(fd);
	}
}
#endif

bool RenameSync(const std::string& srcFilename, const std::string& destFilename)
{
	if (!Rename(srcFilename, destFilename))
		return false;
#ifdef _WIN32
	int fd = _topen(UTF8ToTStr(srcFilename).c_str(), _O_RDONLY);
	if (fd != -1)
	{
		_commit(fd);
		close(fd);
	}
#else
	char* path = strdup(srcFilename.c_str());
	FSyncPath(path);
	FSyncPath(dirname(path));
	free(path);
	path = strdup(destFilename.c_str());
	FSyncPath(dirname(path));
	free(path);
#endif
	return true;
}

// copies file srcFilename to destFilename, returns true on success
bool Copy(const std::string& srcFilename, const std::string& destFilename)
{
	INFO_LOG(COMMON, "Copy: %s --> %s",
			srcFilename.c_str(), destFilename.c_str());
#ifdef _WIN32
	if (CopyFile(UTF8ToTStr(srcFilename).c_str(), UTF8ToTStr(destFilename).c_str(), FALSE))
		return true;

	ERROR_LOG(COMMON, "Copy: failed %s --> %s: %s",
			srcFilename.c_str(), destFilename.c_str(), GetLastErrorMsg().c_str());
	return false;
#else

	// buffer size
#define BSIZE 1024

	char buffer[BSIZE];

	// Open input file
	std::ifstream input;
	OpenFStream(input, srcFilename, std::ifstream::in | std::ifstream::binary);
	if (!input.is_open())
	{
		ERROR_LOG(COMMON, "Copy: input failed %s --> %s: %s",
				srcFilename.c_str(), destFilename.c_str(), GetLastErrorMsg().c_str());
		return false;
	}

	// open output file
	File::IOFile output(destFilename, "wb");

	if (!output.IsOpen())
	{
		ERROR_LOG(COMMON, "Copy: output failed %s --> %s: %s",
				srcFilename.c_str(), destFilename.c_str(), GetLastErrorMsg().c_str());
		return false;
	}

	// copy loop
	while (!input.eof())
	{
		// read input
		input.read(buffer, BSIZE);
		if (!input)
		{
			ERROR_LOG(COMMON,
					"Copy: failed reading from source, %s --> %s: %s",
					srcFilename.c_str(), destFilename.c_str(), GetLastErrorMsg().c_str());
			return false;
		}

		// write output
		if (!output.WriteBytes(buffer, BSIZE))
		{
			ERROR_LOG(COMMON,
					"Copy: failed writing to output, %s --> %s: %s",
					srcFilename.c_str(), destFilename.c_str(), GetLastErrorMsg().c_str());
			return false;
		}
	}

	return true;
#endif
}

// Returns the size of filename (64bit)
u64 GetSize(const std::string& filename)
{
	if (!Exists(filename))
	{
		WARN_LOG(COMMON, "GetSize: failed %s: No such file", filename.c_str());
		return 0;
	}

	if (IsDirectory(filename))
	{
		WARN_LOG(COMMON, "GetSize: failed %s: is a directory", filename.c_str());
		return 0;
	}

	struct stat64 buf;
#ifdef _WIN32
	if (_tstat64(UTF8ToTStr(filename).c_str(), &buf) == 0)
#else
	if (stat64(filename.c_str(), &buf) == 0)
#endif
	{
		DEBUG_LOG(COMMON, "GetSize: %s: %lld",
				filename.c_str(), (long long)buf.st_size);
		return buf.st_size;
	}

	ERROR_LOG(COMMON, "GetSize: Stat failed %s: %s",
			filename.c_str(), GetLastErrorMsg().c_str());
	return 0;
}

// Overloaded GetSize, accepts file descriptor
u64 GetSize(const int fd)
{
	struct stat64 buf;
	if (fstat64(fd, &buf) != 0)
	{
		ERROR_LOG(COMMON, "GetSize: stat failed %i: %s",
			fd, GetLastErrorMsg().c_str());
		return 0;
	}
	return buf.st_size;
}

// Overloaded GetSize, accepts FILE*
u64 GetSize(FILE* f)
{
	// can't use off_t here because it can be 32-bit
	u64 pos = ftello(f);
	if (fseeko(f, 0, SEEK_END) != 0)
	{
		ERROR_LOG(COMMON, "GetSize: seek failed %p: %s",
			  f, GetLastErrorMsg().c_str());
		return 0;
	}

	u64 size = ftello(f);
	if ((size != pos) && (fseeko(f, pos, SEEK_SET) != 0))
	{
		ERROR_LOG(COMMON, "GetSize: seek failed %p: %s",
			  f, GetLastErrorMsg().c_str());
		return 0;
	}

	return size;
}

// creates an empty file filename, returns true on success
bool CreateEmptyFile(const std::string& filename)
{
	INFO_LOG(COMMON, "CreateEmptyFile: %s", filename.c_str());

	if (!File::IOFile(filename, "wb"))
	{
		ERROR_LOG(COMMON, "CreateEmptyFile: failed %s: %s",
				  filename.c_str(), GetLastErrorMsg().c_str());
		return false;
	}

	return true;
}


// Scans the directory tree gets, starting from _Directory and adds the
// results into parentEntry. Returns the number of files+directories found
FSTEntry ScanDirectoryTree(const std::string& directory, bool recursive)
{
	INFO_LOG(COMMON, "ScanDirectoryTree: directory %s", directory.c_str());
	// How many files + directories we found
	FSTEntry parent_entry;
	parent_entry.physicalName = directory;
	parent_entry.isDirectory = true;
	parent_entry.size = 0;
#ifdef _WIN32
	// Find the first file in the directory.
	WIN32_FIND_DATA ffd;

	HANDLE hFind = FindFirstFile(UTF8ToTStr(directory + "\\*").c_str(), &ffd);
	if (hFind == INVALID_HANDLE_VALUE)
	{
		FindClose(hFind);
		return parent_entry;
	}
	// Windows loop
	do
	{
		const std::string virtual_name(TStrToUTF8(ffd.cFileName));
#else
	struct dirent dirent, *result = nullptr;

	DIR* dirp = opendir(directory.c_str());
	if (!dirp)
			return parent_entry;

		// non Windows loop
		while (!readdir_r(dirp, &dirent, &result) && result)
		{
			const std::string virtual_name(result->d_name);
	#endif
			if (virtual_name == "." || virtual_name == "..")
				continue;
			auto physical_name = directory + DIR_SEP + virtual_name;
			FSTEntry entry;
			entry.isDirectory = IsDirectory(physical_name);
			if (entry.isDirectory)
			{
				if (recursive)
					entry = ScanDirectoryTree(physical_name, true);
				else
					entry.size = 0;
				parent_entry.size += entry.size;
			}
			else
			{
				entry.size = GetSize(physical_name);
			}
			entry.virtualName = virtual_name;
			entry.physicalName = physical_name;

			++parent_entry.size;
			// Push into the tree
			parent_entry.children.push_back(entry);
	#ifdef _WIN32
		} while (FindNextFile(hFind, &ffd) != 0);
	FindClose(hFind);
#else
	}
	closedir(dirp);
#endif
	// Return number of entries found.
	return parent_entry;
}


// Deletes the given directory and anything under it. Returns true on success.
bool DeleteDirRecursively(const std::string& directory)
{
	INFO_LOG(COMMON, "DeleteDirRecursively: %s", directory.c_str());
#ifdef _WIN32
	// Find the first file in the directory.
	WIN32_FIND_DATA ffd;
	HANDLE hFind = FindFirstFile(UTF8ToTStr(directory + "\\*").c_str(), &ffd);

	if (hFind == INVALID_HANDLE_VALUE)
	{
		FindClose(hFind);
		return false;
	}

	// Windows loop
	do
	{
		const std::string virtualName(TStrToUTF8(ffd.cFileName));
#else
	struct dirent dirent, *result = nullptr;
	DIR* dirp = opendir(directory.c_str());
	if (!dirp)
		return false;

	// non Windows loop
	while (!readdir_r(dirp, &dirent, &result) && result)
	{
		const std::string virtualName = result->d_name;
#endif

		// check for "." and ".."
		if (((virtualName[0] == '.') && (virtualName[1] == '\0')) ||
			((virtualName[0] == '.') && (virtualName[1] == '.') &&
			 (virtualName[2] == '\0')))
			continue;

		std::string newPath = directory + DIR_SEP_CHR + virtualName;
		if (IsDirectory(newPath))
		{
			if (!DeleteDirRecursively(newPath))
			{
				#ifndef _WIN32
				closedir(dirp);
				#endif

				return false;
			}
		}
		else
		{
			if (!File::Delete(newPath))
			{
				#ifndef _WIN32
				closedir(dirp);
				#endif

				return false;
			}
		}

#ifdef _WIN32
	} while (FindNextFile(hFind, &ffd) != 0);
	FindClose(hFind);
#else
	}
	closedir(dirp);
#endif
	File::DeleteDir(directory);

	return true;
}

// Create directory and copy contents (does not overwrite existing files)
void CopyDir(const std::string& source_path, const std::string& dest_path)
{
	if (source_path == dest_path) return;
	if (!File::Exists(source_path)) return;
	if (!File::Exists(dest_path)) File::CreateFullPath(dest_path);

#ifdef _WIN32
	WIN32_FIND_DATA ffd;
	HANDLE hFind = FindFirstFile(UTF8ToTStr(source_path + "\\*").c_str(), &ffd);

	if (hFind == INVALID_HANDLE_VALUE)
	{
		FindClose(hFind);
		return;
	}

	do
	{
		const std::string virtualName(TStrToUTF8(ffd.cFileName));
#else
	struct dirent dirent, *result = nullptr;
	DIR* dirp = opendir(source_path.c_str());
	if (!dirp) return;

	while (!readdir_r(dirp, &dirent, &result) && result)
	{
		const std::string virtualName(result->d_name);
#endif
		// check for "." and ".."
		if (virtualName == "." || virtualName == "..")
			continue;

		std::string source = source_path + DIR_SEP + virtualName;
		std::string dest = dest_path + DIR_SEP + virtualName;
		if (IsDirectory(source))
		{
			if (!File::Exists(dest)) File::CreateFullPath(dest + DIR_SEP);
			CopyDir(source, dest);
		}
		else if (!File::Exists(dest)) File::Copy(source, dest);
#ifdef _WIN32
	} while (FindNextFile(hFind, &ffd) != 0);
	FindClose(hFind);
#else
	}
	closedir(dirp);
#endif
}

// Returns the current directory
std::string GetCurrentDir()
{
	char* dir;
	// Get the current working directory (getcwd uses malloc)
	if (!(dir = __getcwd(nullptr, 0)))
	{
		ERROR_LOG(COMMON, "GetCurrentDirectory failed: %s",
				GetLastErrorMsg().c_str());
		return nullptr;
	}
	std::string strDir = dir;
	free(dir);
	return strDir;
}

// Sets the current directory to the given directory
bool SetCurrentDir(const std::string& directory)
{
	return __chdir(directory.c_str()) == 0;
}

std::string CreateTempDir()
{
#ifdef _WIN32
	TCHAR temp[MAX_PATH];
	if (!GetTempPath(MAX_PATH, temp))
		return "";

	GUID guid;
	CoCreateGuid(&guid);
	TCHAR tguid[40];
	StringFromGUID2(guid, tguid, 39);
	tguid[39] = 0;
	std::string dir = TStrToUTF8(temp) + "/" + TStrToUTF8(tguid);
	if (!CreateDir(dir))
		return "";
	dir = ReplaceAll(dir, "\\", DIR_SEP);
	return dir;
#else
	const char* base = getenv("TMPDIR") ?: "/tmp";
	std::string path = std::string(base) + "/DolphinWii.XXXXXX";
	if (!mkdtemp(&path[0]))
		return "";
	return path;
#endif
}

std::string GetTempFilenameForAtomicWrite(const std::string& path)
{
	std::string abs = path;
#ifdef _WIN32
	TCHAR absbuf[MAX_PATH];
	if (_tfullpath(absbuf, UTF8ToTStr(path).c_str(), MAX_PATH) != nullptr)
		abs = TStrToUTF8(absbuf);
#else
	char absbuf[PATH_MAX];
	if (realpath(path.c_str(), absbuf) != nullptr)
		abs = absbuf;
#endif
	return abs + ".xxx";
}

#if defined(__APPLE__)
std::string GetBundleDirectory()
{
	CFURLRef BundleRef;
	char AppBundlePath[MAXPATHLEN];
	// Get the main bundle for the app
	BundleRef = CFBundleCopyBundleURL(CFBundleGetMainBundle());
	CFStringRef BundlePath = CFURLCopyFileSystemPath(BundleRef, kCFURLPOSIXPathStyle);
	CFStringGetFileSystemRepresentation(BundlePath, AppBundlePath, sizeof(AppBundlePath));
	CFRelease(BundleRef);
	CFRelease(BundlePath);

	return AppBundlePath;
}
#endif

std::string& GetExeDirectory()
{
	static std::string DolphinPath;
	if (DolphinPath.empty())
	{
#ifdef _WIN32
		TCHAR Dolphin_exe_Path[2048];
		TCHAR Dolphin_exe_Clean_Path[MAX_PATH];
		GetModuleFileName(nullptr, Dolphin_exe_Path, 2048);
		if (_tfullpath(Dolphin_exe_Clean_Path, Dolphin_exe_Path, MAX_PATH) != nullptr)
			DolphinPath = TStrToUTF8(Dolphin_exe_Clean_Path);
		else
			DolphinPath = TStrToUTF8(Dolphin_exe_Path);
		DolphinPath = DolphinPath.substr(0, DolphinPath.find_last_of('\\'));
#else
		char Dolphin_exe_Path[PATH_MAX];
		ssize_t len = ::readlink("/proc/self/exe", Dolphin_exe_Path, sizeof(Dolphin_exe_Path));
		if (len == -1 || len == sizeof(Dolphin_exe_Path))
		{
			len = 0;
		}
		Dolphin_exe_Path[len] = '\0';
		DolphinPath = Dolphin_exe_Path;
		DolphinPath = DolphinPath.substr(0, DolphinPath.rfind('/'));
#endif
	}
	return DolphinPath;
}

std::string GetSysDirectory()
{
	std::string sysDir;

#if defined (__APPLE__)
	sysDir = GetBundleDirectory() + DIR_SEP + SYSDATA_DIR;
#elif defined (_WIN32) || defined (LINUX_LOCAL_DEV)
	sysDir = GetExeDirectory() + DIR_SEP + SYSDATA_DIR;
#else
	sysDir = SYSDATA_DIR;
#endif
	sysDir += DIR_SEP;

	INFO_LOG(COMMON, "GetSysDirectory: Setting to %s:", sysDir.c_str());
	return sysDir;
}

static std::string s_user_paths[NUM_PATH_INDICES];
static void RebuildUserDirectories(unsigned int dir_index)
{
	switch (dir_index)
	{
	case D_USER_IDX:
		s_user_paths[D_GCUSER_IDX]         = s_user_paths[D_USER_IDX] + GC_USER_DIR DIR_SEP;
		s_user_paths[D_WIIROOT_IDX]        = s_user_paths[D_USER_IDX] + WII_USER_DIR;
		s_user_paths[D_CONFIG_IDX]         = s_user_paths[D_USER_IDX] + CONFIG_DIR DIR_SEP;
		s_user_paths[D_GAMESETTINGS_IDX]   = s_user_paths[D_USER_IDX] + GAMESETTINGS_DIR DIR_SEP;
		s_user_paths[D_MAPS_IDX]           = s_user_paths[D_USER_IDX] + MAPS_DIR DIR_SEP;
		s_user_paths[D_CACHE_IDX]          = s_user_paths[D_USER_IDX] + CACHE_DIR DIR_SEP;
		s_user_paths[D_SHADERCACHE_IDX]    = s_user_paths[D_CACHE_IDX] + SHADERCACHE_DIR DIR_SEP;
		s_user_paths[D_SHADERS_IDX]        = s_user_paths[D_USER_IDX] + SHADERS_DIR DIR_SEP;
		s_user_paths[D_STATESAVES_IDX]     = s_user_paths[D_USER_IDX] + STATESAVES_DIR DIR_SEP;
		s_user_paths[D_SCREENSHOTS_IDX]    = s_user_paths[D_USER_IDX] + SCREENSHOTS_DIR DIR_SEP;
		s_user_paths[D_LOAD_IDX]           = s_user_paths[D_USER_IDX] + LOAD_DIR DIR_SEP;
		s_user_paths[D_HIRESTEXTURES_IDX]  = s_user_paths[D_LOAD_IDX] + HIRES_TEXTURES_DIR DIR_SEP;
		s_user_paths[D_DUMP_IDX]           = s_user_paths[D_USER_IDX] + DUMP_DIR DIR_SEP;
		s_user_paths[D_DUMPFRAMES_IDX]     = s_user_paths[D_DUMP_IDX] + DUMP_FRAMES_DIR DIR_SEP;
		s_user_paths[D_DUMPAUDIO_IDX]      = s_user_paths[D_DUMP_IDX] + DUMP_AUDIO_DIR DIR_SEP;
		s_user_paths[D_DUMPTEXTURES_IDX]   = s_user_paths[D_DUMP_IDX] + DUMP_TEXTURES_DIR DIR_SEP;
		s_user_paths[D_DUMPDSP_IDX]        = s_user_paths[D_DUMP_IDX] + DUMP_DSP_DIR DIR_SEP;
		s_user_paths[D_LOGS_IDX]           = s_user_paths[D_USER_IDX] + LOGS_DIR DIR_SEP;
		s_user_paths[D_MAILLOGS_IDX]       = s_user_paths[D_LOGS_IDX] + MAIL_LOGS_DIR DIR_SEP;
		s_user_paths[D_THEMES_IDX]         = s_user_paths[D_USER_IDX] + THEMES_DIR DIR_SEP;
		s_user_paths[D_PIPES_IDX]          = s_user_paths[D_USER_IDX] + PIPES_DIR DIR_SEP;
		s_user_paths[F_DOLPHINCONFIG_IDX]  = s_user_paths[D_CONFIG_IDX] + DOLPHIN_CONFIG;
		s_user_paths[F_DEBUGGERCONFIG_IDX] = s_user_paths[D_CONFIG_IDX] + DEBUGGER_CONFIG;
		s_user_paths[F_LOGGERCONFIG_IDX]   = s_user_paths[D_CONFIG_IDX] + LOGGER_CONFIG;
		s_user_paths[F_MAINLOG_IDX]        = s_user_paths[D_LOGS_IDX] + MAIN_LOG;
		s_user_paths[F_RAMDUMP_IDX]        = s_user_paths[D_DUMP_IDX] + RAM_DUMP;
		s_user_paths[F_ARAMDUMP_IDX]       = s_user_paths[D_DUMP_IDX] + ARAM_DUMP;
		s_user_paths[F_FAKEVMEMDUMP_IDX]   = s_user_paths[D_DUMP_IDX] + FAKEVMEM_DUMP;
		s_user_paths[F_GCSRAM_IDX]         = s_user_paths[D_GCUSER_IDX] + GC_SRAM;

		s_user_paths[D_MEMORYWATCHER_IDX]          = s_user_paths[D_USER_IDX] + MEMORYWATCHER_DIR DIR_SEP;
		s_user_paths[F_MEMORYWATCHERLOCATIONS_IDX] = s_user_paths[D_MEMORYWATCHER_IDX] + MEMORYWATCHER_LOCATIONS;
		s_user_paths[F_MEMORYWATCHERSOCKET_IDX]    = s_user_paths[D_MEMORYWATCHER_IDX] + MEMORYWATCHER_SOCKET;

		// The shader cache has moved to the cache directory, so remove the old one.
		// TODO: remove that someday.
		File::DeleteDirRecursively(s_user_paths[D_USER_IDX] + SHADERCACHE_LEGACY_DIR DIR_SEP);
		break;

	case D_CONFIG_IDX:
		s_user_paths[F_DOLPHINCONFIG_IDX]  = s_user_paths[D_CONFIG_IDX] + DOLPHIN_CONFIG;
		s_user_paths[F_DEBUGGERCONFIG_IDX] = s_user_paths[D_CONFIG_IDX] + DEBUGGER_CONFIG;
		s_user_paths[F_LOGGERCONFIG_IDX]   = s_user_paths[D_CONFIG_IDX] + LOGGER_CONFIG;
		break;

	case D_CACHE_IDX:
		s_user_paths[D_SHADERCACHE_IDX]    = s_user_paths[D_CACHE_IDX] + SHADERCACHE_DIR DIR_SEP;
		break;

	case D_GCUSER_IDX:
		s_user_paths[F_GCSRAM_IDX]         = s_user_paths[D_GCUSER_IDX] + GC_SRAM;
		break;

	case D_DUMP_IDX:
		s_user_paths[D_DUMPFRAMES_IDX]     = s_user_paths[D_DUMP_IDX] + DUMP_FRAMES_DIR DIR_SEP;
		s_user_paths[D_DUMPAUDIO_IDX]      = s_user_paths[D_DUMP_IDX] + DUMP_AUDIO_DIR DIR_SEP;
		s_user_paths[D_DUMPTEXTURES_IDX]   = s_user_paths[D_DUMP_IDX] + DUMP_TEXTURES_DIR DIR_SEP;
		s_user_paths[D_DUMPDSP_IDX]        = s_user_paths[D_DUMP_IDX] + DUMP_DSP_DIR DIR_SEP;
		s_user_paths[F_RAMDUMP_IDX]        = s_user_paths[D_DUMP_IDX] + RAM_DUMP;
		s_user_paths[F_ARAMDUMP_IDX]       = s_user_paths[D_DUMP_IDX] + ARAM_DUMP;
		s_user_paths[F_FAKEVMEMDUMP_IDX]   = s_user_paths[D_DUMP_IDX] + FAKEVMEM_DUMP;
		break;

	case D_LOGS_IDX:
		s_user_paths[D_MAILLOGS_IDX]       = s_user_paths[D_LOGS_IDX] + MAIL_LOGS_DIR DIR_SEP;
		s_user_paths[F_MAINLOG_IDX]        = s_user_paths[D_LOGS_IDX] + MAIN_LOG;
		break;

	case D_LOAD_IDX:
		s_user_paths[D_HIRESTEXTURES_IDX]  = s_user_paths[D_LOAD_IDX] + HIRES_TEXTURES_DIR DIR_SEP;
		break;
	}
}

// Gets a set user directory path
// Don't call prior to setting the base user directory
const std::string& GetUserPath(unsigned int dir_index)
{
	return s_user_paths[dir_index];
}

// Sets a user directory path
// Rebuilds internal directory structure to compensate for the new directory
void SetUserPath(unsigned int dir_index, const std::string& path)
{
	if (path.empty())
		return;

	s_user_paths[dir_index] = path;
	RebuildUserDirectories(dir_index);
}

std::string GetThemeDir(const std::string& theme_name)
{
	std::string dir = File::GetUserPath(D_THEMES_IDX) + theme_name + "/";

	// If theme does not exist in user's dir load from shared directory
	if (!File::Exists(dir))
		dir = GetSysDirectory() + THEMES_DIR "/" + theme_name + "/";

	return dir;
}

bool WriteStringToFile(const std::string& str, const std::string& filename)
{
	return File::IOFile(filename, "wb").WriteBytes(str.data(), str.size());
}

bool ReadFileToString(const std::string& filename, std::string& str)
{
	File::IOFile file(filename, "rb");

	if (!file.IsOpen())
		return false;

	size_t read_size;
	str.resize(file.GetSize());
	bool retval = file.ReadArray(&str[0], str.size(), &read_size);

	return retval;
}

IOFile::IOFile()
#ifdef _WIN32
	: m_file(INVALID_HANDLE_VALUE),
	m_unbuf_buffer(nullptr),
	m_chunks_written(0),
	m_write_buf_pos(0),
	m_read_buf_pos(0),
	m_read_last_pos(0),
#else
	: m_file(nullptr),
#endif
	m_good(true)
{}

IOFile::IOFile(const std::string& filename, const char openmode[],
               OpenFlags flags)
#ifdef _WIN32
	: m_file(INVALID_HANDLE_VALUE),
	  m_unbuf_buffer(nullptr),
	  m_chunks_written(0),
	  m_write_buf_pos(0),
	  m_read_buf_pos(0),
	  m_read_last_pos(0),
#else
	: m_file(nullptr),
#endif
	  m_good(true)
{
	Open(filename, openmode, flags);
}

IOFile::~IOFile()
{
	Close();
}

IOFile::IOFile(IOFile&& other)
#ifdef _WIN32
	: m_file(INVALID_HANDLE_VALUE),
	m_unbuf_buffer(nullptr),
	m_chunks_written(0),
	m_write_buf_pos(0),
	m_read_buf_pos(0),
	m_read_last_pos(0),
#else
	: m_file(nullptr),
#endif
	m_good(true)
{
	Swap(other);
}

IOFile& IOFile::operator=(IOFile&& other)
{
	Swap(other);
	return *this;
}

void IOFile::Swap(IOFile& other)
{
	std::swap(m_file, other.m_file);
#ifdef _WIN32
	std::swap(m_unbuf_buffer, other.m_unbuf_buffer);
	std::swap(m_chunks_written, other.m_chunks_written);
	std::swap(m_write_buf_pos, other.m_write_buf_pos);
	std::swap(m_read_buf_pos, other.m_read_buf_pos);
	std::swap(m_read_last_pos, other.m_read_last_pos);
#endif
	std::swap(m_good, other.m_good);
}

bool IOFile::Open(const std::string& filename, const char openmode[],
                  OpenFlags flags)
{
	Close();
	DEBUG_LOG(COMMON, "IOFile::Open file %s, mode %s, flags 0x%lX", filename.c_str(), openmode, flags);
#ifdef _WIN32
	// We'll ignore 'b' here, it's all the same in Windows.
	u32 access = 0;
	u32 create = 0;
	u32 attributes = FILE_ATTRIBUTE_NORMAL;

	// Check write last, so that write can over-write the create flag.
	if (std::strchr(openmode, 'r')) {
		access |= GENERIC_READ;
		create = OPEN_EXISTING;
	}
	else if (std::strchr(openmode, 'a')) {
		access |= GENERIC_WRITE;
		create = OPEN_ALWAYS;
	}
	else if (std::strchr(openmode, 'w')) {
		access |= GENERIC_WRITE;
		create = CREATE_ALWAYS;
	}
	// Update mode opens for both read and write, no matter what.
	// It maintains the create configuration of the previous setting.
	if (std::strchr(openmode, '+')) {
		access = GENERIC_WRITE | GENERIC_READ;
	}
	if (flags & OpenFlags::DISABLE_BUFFERING) {
		attributes |= FILE_FLAG_NO_BUFFERING;
		m_unbuf_buffer = (LPBYTE)VirtualAlloc(nullptr,
		                                      UNBUF_ALLOC_BUFFER_SIZE,
		                                      MEM_COMMIT,
		                                      PAGE_READWRITE);
		if (m_unbuf_buffer == nullptr)
			return m_good;
		VirtualLock(m_unbuf_buffer, UNBUF_ALLOC_BUFFER_SIZE);
	}

	m_file = CreateFile(UTF8ToTStr(filename).c_str(),
	                    access,
	                    0,
	                    nullptr,
	                    create,
	                    attributes,
	                    nullptr);

	if (IsOpen() && std::strchr(openmode, 'a'))
		SetFilePointer(m_file, 0, 0, FILE_END);
#else
	m_file = fopen(filename.c_str(), openmode);

	if (IsOpen())
	{
		if (flags & DISABLE_BUFFERING)
			std::setvbuf(m_file, nullptr, _IONBF, 0);
	}
#endif

	m_good = IsOpen();
	return m_good;
}

bool IOFile::Close()
{
#ifdef _WIN32
	if (m_unbuf_buffer) {
		VirtualUnlock(m_unbuf_buffer, UNBUF_ALLOC_BUFFER_SIZE);
		VirtualFree(m_unbuf_buffer, 0, MEM_RELEASE);
		if (IsOpen()) {
			u64 target_size = (UNBUF_WRITE_BUFFER_SIZE * m_chunks_written) + m_write_buf_pos;
			// Try to truncate the file from any over-writing that happened.
			HANDLE h = ReOpenFile(m_file, GENERIC_WRITE, 0, FILE_ATTRIBUTE_NORMAL);
			CloseHandle(m_file);
			m_file = h;
			Resize(target_size);
		}
	}

	if (!IsOpen() || FALSE == CloseHandle(m_file))
#else
	if (!IsOpen() || 0 != std::fclose(m_file))
#endif
		m_good = false;

#ifdef _WIN32
	m_file = INVALID_HANDLE_VALUE;
#else
	m_file = nullptr;
#endif
	return m_good;
}

u64 IOFile::GetSize()
{
	if (IsOpen()) {
#ifdef _WIN32
		LARGE_INTEGER size;
		BOOL rv = GetFileSizeEx(m_file, &size);
		if (rv == FALSE)
			return 0;
		else
			return size.QuadPart;
#else
		return File::GetSize(m_file);
#endif
    }
	else
		return 0;
}

bool IOFile::IsEOF()
{
#ifdef _WIN32
	if (Tell() >= GetSize())
		return true;
	return false;
#else
	return std::feof(m_file) != 0;
#endif
}

bool IOFile::Seek(s64 off, int origin)
{
#ifdef _WIN32
	LARGE_INTEGER offset;
	offset.QuadPart = off;
	DWORD method;
	// origin and method may not always map 1:1, so switch-set them.
	switch (origin) {
	case SEEK_SET:
		method = FILE_BEGIN;
		break;
	case SEEK_CUR:
		method = FILE_CURRENT;
		break;
	case SEEK_END:
		method = FILE_END;
		break;
	}
    if (!IsOpen() || FALSE == SetFilePointerEx(m_file, offset, nullptr, method))
#else
	if (!IsOpen() || 0 != fseeko(m_file, off, origin))
#endif
		m_good = false;

	return m_good;
}

u64 IOFile::Tell() const
{
	if (IsOpen()) {
#ifdef _WIN32
		LARGE_INTEGER move;
		memset(&move, 0, sizeof(move));
		LARGE_INTEGER pos;
		if (FALSE == SetFilePointerEx(m_file, move, &pos, FILE_CURRENT))
			return -1;
		return pos.QuadPart;
#else
		return ftello(m_file);
#endif
    }
	else
		return -1;
}

bool IOFile::Flush()
{
#ifdef _WIN32
    if (!IsOpen() || FALSE == FlushFileBuffers(m_file))
#else
	if (!IsOpen() || 0 != std::fflush(m_file))
#endif
		m_good = false;

	return m_good;
}

bool IOFile::Resize(u64 size)
{
#ifdef _WIN32
	if (!IsOpen() || !IsGood()) {
		m_good = false;
		return m_good;
	}

	// Restore position in file as good as possible.
	LARGE_INTEGER pos;
	pos.QuadPart = Tell();
	DWORD method;
	if (static_cast<u64>(pos.QuadPart) < size) {
		method = FILE_BEGIN;
	}
	else {
		method = FILE_END;
		pos.QuadPart = 0;
	}
	LARGE_INTEGER new_size;
	new_size.QuadPart = size;

	if (FALSE == SetFilePointerEx(m_file, new_size, nullptr, FILE_BEGIN) ||
		FALSE == SetEndOfFile(m_file) ||
		FALSE == SetFilePointerEx(m_file, pos, nullptr, method))
#else
	// TODO: handle 64bit and growing
	if (!IsOpen() || 0 != ftruncate(fileno(m_file), size))
#endif
		m_good = false;

	return m_good;
}

} // namespace
