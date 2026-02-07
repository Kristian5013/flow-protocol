#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

namespace core::fs {

/// Convenience alias so callers don't need to spell out std::filesystem::path.
using path = std::filesystem::path;

/// Returns the platform-appropriate default data directory for FTC:
///   Windows : %APPDATA%/FTC
///   macOS   : ~/Library/Application Support/FTC
///   Linux   : ~/.ftc
path get_default_data_dir();

/// Creates the directory (and parents) if it does not exist.
/// Returns true on success or if the directory already exists.
bool ensure_directory(const path& dir);

/// Resolves a path to an absolute path using the current working directory.
path absolute(const path& p);

/// Returns true if `p` refers to an existing regular file.
bool file_exists(const path& p);

/// Returns true if `p` refers to an existing directory.
bool dir_exists(const path& p);

/// Returns the size of the file in bytes, or std::nullopt on error.
std::optional<uint64_t> file_size(const path& p);

/// Copies `src` to `dst` safely by writing to a temporary file first, then
/// performing an atomic rename.  Returns true on success.
bool copy_file_safe(const path& src, const path& dst);

/// Attempts an atomic rename from `src` to `dst`.
/// On Windows this uses ReplaceFileW; on POSIX it uses std::filesystem::rename.
/// Returns true on success.
bool rename_safe(const path& src, const path& dst);

/// Reads the entire contents of `p` into a string.
/// Returns std::nullopt if the file cannot be opened or read.
std::optional<std::string> read_file(const path& p);

/// Writes `content` to `p` atomically (write to temp, then rename).
/// Returns true on success.
bool write_file(const path& p, std::string_view content);

// ---------------------------------------------------------------------------
// FileLock - cross-platform advisory file lock with RAII semantics.
// ---------------------------------------------------------------------------

class FileLock {
public:
    /// Constructs a FileLock targeting the given path.  Does NOT acquire the
    /// lock; call try_lock() to actually lock.
    explicit FileLock(const path& p);

    /// Releases the lock if held and closes any OS handles.
    ~FileLock();

    // Non-copyable.
    FileLock(const FileLock&) = delete;
    FileLock& operator=(const FileLock&) = delete;

    // Movable.
    FileLock(FileLock&& other) noexcept;
    FileLock& operator=(FileLock&& other) noexcept;

    /// Attempts to acquire the advisory lock.
    /// Returns true if the lock was successfully acquired, false if it is
    /// already held by another process or an error occurred.
    bool try_lock();

    /// Releases the lock if currently held.
    void unlock();

private:
    path lock_path_;
    bool locked_{false};

#ifdef _WIN32
    void* handle_{nullptr};   // HANDLE (INVALID_HANDLE_VALUE when closed)
#else
    int fd_{-1};
#endif
};

} // namespace core::fs
