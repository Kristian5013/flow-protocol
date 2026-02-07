#include "fs.h"

#include <cstdlib>
#include <fstream>
#include <random>
#include <sstream>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  include <io.h>
#else
#  include <sys/file.h>
#  include <unistd.h>
#endif

namespace core::fs {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generates a short random suffix for temporary file names.
static std::string random_suffix()
{
    static constexpr char CHARS[] =
        "abcdefghijklmnopqrstuvwxyz0123456789";
    static constexpr int SUFFIX_LEN = 8;

    // Thread-local RNG seeded from the system random device.
    thread_local std::mt19937 rng{std::random_device{}()};
    std::uniform_int_distribution<int> dist(
        0, static_cast<int>(sizeof(CHARS) - 2));

    std::string suffix;
    suffix.reserve(SUFFIX_LEN);
    for (int i = 0; i < SUFFIX_LEN; ++i) {
        suffix.push_back(CHARS[dist(rng)]);
    }
    return suffix;
}

/// Returns a temporary path adjacent to `target` (same parent directory).
static path temp_path_for(const path& target)
{
    return target.parent_path() /
           (target.filename().string() + ".tmp." + random_suffix());
}

// ---------------------------------------------------------------------------
// get_default_data_dir
// ---------------------------------------------------------------------------

path get_default_data_dir()
{
#ifdef _WIN32
    // %APPDATA% is always set on modern Windows.
    const char* appdata = std::getenv("APPDATA");
    if (appdata && appdata[0] != '\0') {
        return path(appdata) / "FTC";
    }
    // Fallback: use the user profile directory.
    const char* userprofile = std::getenv("USERPROFILE");
    if (userprofile && userprofile[0] != '\0') {
        return path(userprofile) / "AppData" / "Roaming" / "FTC";
    }
    return path("C:\\FTC");

#elif defined(__APPLE__)
    const char* home = std::getenv("HOME");
    if (home && home[0] != '\0') {
        return path(home) / "Library" / "Application Support" / "FTC";
    }
    return path("/tmp/FTC");

#else  // Linux / other POSIX
    const char* home = std::getenv("HOME");
    if (home && home[0] != '\0') {
        return path(home) / ".ftc";
    }
    return path("/tmp/.ftc");
#endif
}

// ---------------------------------------------------------------------------
// Directory / path utilities
// ---------------------------------------------------------------------------

bool ensure_directory(const path& dir)
{
    std::error_code ec;
    if (std::filesystem::exists(dir, ec) &&
        std::filesystem::is_directory(dir, ec)) {
        return true;
    }
    return std::filesystem::create_directories(dir, ec) || !ec;
}

path absolute(const path& p)
{
    std::error_code ec;
    auto result = std::filesystem::absolute(p, ec);
    if (ec) {
        return p;  // Best-effort: return the original path.
    }
    return result;
}

bool file_exists(const path& p)
{
    std::error_code ec;
    return std::filesystem::is_regular_file(p, ec);
}

bool dir_exists(const path& p)
{
    std::error_code ec;
    return std::filesystem::is_directory(p, ec);
}

std::optional<uint64_t> file_size(const path& p)
{
    std::error_code ec;
    auto sz = std::filesystem::file_size(p, ec);
    if (ec) {
        return std::nullopt;
    }
    return static_cast<uint64_t>(sz);
}

// ---------------------------------------------------------------------------
// Safe copy / rename / read / write
// ---------------------------------------------------------------------------

bool copy_file_safe(const path& src, const path& dst)
{
    if (!file_exists(src)) {
        return false;
    }

    path tmp = temp_path_for(dst);

    // Copy src -> tmp.
    std::error_code ec;
    std::filesystem::copy_file(
        src, tmp,
        std::filesystem::copy_options::overwrite_existing, ec);
    if (ec) {
        std::filesystem::remove(tmp, ec);
        return false;
    }

    // Rename tmp -> dst (atomic where the OS supports it).
    if (!rename_safe(tmp, dst)) {
        std::filesystem::remove(tmp, ec);
        return false;
    }
    return true;
}

bool rename_safe(const path& src, const path& dst)
{
#ifdef _WIN32
    // ReplaceFileW handles the case where dst already exists, performing an
    // atomic replace on NTFS.  If dst does not yet exist, fall back to
    // MoveFileExW with MOVEFILE_REPLACE_EXISTING.
    if (file_exists(dst)) {
        if (ReplaceFileW(
                dst.wstring().c_str(),
                src.wstring().c_str(),
                nullptr,    // no backup
                REPLACEFILE_IGNORE_MERGE_ERRORS |
                    REPLACEFILE_IGNORE_ACL_ERRORS,
                nullptr,
                nullptr)) {
            return true;
        }
    }
    // Fallback / dst does not exist yet.
    if (MoveFileExW(
            src.wstring().c_str(),
            dst.wstring().c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        return true;
    }
    return false;

#else
    // On POSIX, rename(2) is atomic on the same filesystem and replaces the
    // target if it exists.
    std::error_code ec;
    std::filesystem::rename(src, dst, ec);
    return !ec;
#endif
}

std::optional<std::string> read_file(const path& p)
{
    std::ifstream ifs(p, std::ios::binary | std::ios::ate);
    if (!ifs.is_open()) {
        return std::nullopt;
    }

    auto size = ifs.tellg();
    if (size < 0) {
        return std::nullopt;
    }
    ifs.seekg(0, std::ios::beg);

    std::string content;
    content.resize(static_cast<size_t>(size));
    if (!ifs.read(content.data(), size)) {
        return std::nullopt;
    }
    return content;
}

bool write_file(const path& p, std::string_view content)
{
    // Ensure the parent directory exists.
    if (p.has_parent_path()) {
        if (!ensure_directory(p.parent_path())) {
            return false;
        }
    }

    path tmp = temp_path_for(p);

    {
        std::ofstream ofs(tmp, std::ios::binary | std::ios::trunc);
        if (!ofs.is_open()) {
            return false;
        }
        ofs.write(content.data(),
                  static_cast<std::streamsize>(content.size()));
        if (!ofs.good()) {
            ofs.close();
            std::error_code ec;
            std::filesystem::remove(tmp, ec);
            return false;
        }
        ofs.flush();
        ofs.close();
    }

    if (!rename_safe(tmp, p)) {
        std::error_code ec;
        std::filesystem::remove(tmp, ec);
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// FileLock
// ---------------------------------------------------------------------------

FileLock::FileLock(const path& p)
    : lock_path_(p)
#ifdef _WIN32
    , handle_(INVALID_HANDLE_VALUE)
#endif
{
}

FileLock::~FileLock()
{
    unlock();

#ifdef _WIN32
    if (handle_ != INVALID_HANDLE_VALUE) {
        CloseHandle(handle_);
        handle_ = INVALID_HANDLE_VALUE;
    }
#else
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
#endif
}

FileLock::FileLock(FileLock&& other) noexcept
    : lock_path_(std::move(other.lock_path_))
    , locked_(other.locked_)
#ifdef _WIN32
    , handle_(other.handle_)
#else
    , fd_(other.fd_)
#endif
{
    other.locked_ = false;
#ifdef _WIN32
    other.handle_ = INVALID_HANDLE_VALUE;
#else
    other.fd_ = -1;
#endif
}

FileLock& FileLock::operator=(FileLock&& other) noexcept
{
    if (this != &other) {
        unlock();

#ifdef _WIN32
        if (handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
        }
        handle_ = other.handle_;
        other.handle_ = INVALID_HANDLE_VALUE;
#else
        if (fd_ >= 0) {
            ::close(fd_);
        }
        fd_ = other.fd_;
        other.fd_ = -1;
#endif

        lock_path_ = std::move(other.lock_path_);
        locked_ = other.locked_;
        other.locked_ = false;
    }
    return *this;
}

bool FileLock::try_lock()
{
    if (locked_) {
        return true;  // Already held.
    }

#ifdef _WIN32
    if (handle_ == INVALID_HANDLE_VALUE) {
        handle_ = CreateFileW(
            lock_path_.wstring().c_str(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (handle_ == INVALID_HANDLE_VALUE) {
            return false;
        }
    }

    OVERLAPPED ov{};
    // LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY = non-blocking
    // exclusive lock.
    if (!LockFileEx(
            handle_,
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,          // reserved
            MAXDWORD,   // lock the whole file
            MAXDWORD,
            &ov)) {
        return false;
    }
    locked_ = true;
    return true;

#else
    if (fd_ < 0) {
        fd_ = ::open(lock_path_.c_str(),
                      O_RDWR | O_CREAT | O_CLOEXEC, 0644);
        if (fd_ < 0) {
            return false;
        }
    }

    if (::flock(fd_, LOCK_EX | LOCK_NB) != 0) {
        return false;
    }
    locked_ = true;
    return true;
#endif
}

void FileLock::unlock()
{
    if (!locked_) {
        return;
    }

#ifdef _WIN32
    if (handle_ != INVALID_HANDLE_VALUE) {
        OVERLAPPED ov{};
        UnlockFileEx(handle_, 0, MAXDWORD, MAXDWORD, &ov);
    }
#else
    if (fd_ >= 0) {
        ::flock(fd_, LOCK_UN);
    }
#endif

    locked_ = false;
}

} // namespace core::fs
