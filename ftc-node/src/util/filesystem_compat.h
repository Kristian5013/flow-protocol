#pragma once

// Filesystem compatibility header for older GCC versions
#if __GNUC__ < 8
    #include <experimental/filesystem>
    namespace std {
        namespace filesystem = std::experimental::filesystem;
    }
#else
    #include <filesystem>
#endif
