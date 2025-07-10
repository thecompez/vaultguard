cmake_minimum_required(VERSION 3.26)
project(VaultGuard LANGUAGES CXX)

# Set C++26 standard
set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Include FetchContent module for dependency management
include(FetchContent)

# Try to find libsodium on the system first
find_library(SODIUM_LIBRARY
        NAMES sodium libsodium
        HINTS
        /opt/homebrew/lib        # macOS Homebrew (Apple Silicon)
        /usr/local/lib          # macOS Homebrew (Intel), Linux
        /usr/lib                # Linux
        /usr/lib64              # Linux 64-bit
        ${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/lib  # Windows vcpkg
        PATH_SUFFIXES lib libsodium
)

find_path(SODIUM_INCLUDE_DIR
        NAMES sodium.h
        HINTS
        /opt/homebrew/include    # macOS Homebrew (Apple Silicon)
        /usr/local/include      # macOS Homebrew (Intel), Linux
        /usr/include            # Linux
        ${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/include  # Windows vcpkg
        PATH_SUFFIXES include sodium
)

# If libsodium is not found, download and build it
if(NOT SODIUM_LIBRARY OR NOT SODIUM_INCLUDE_DIR)
    message(WARNING "libsodium not found on system. Downloading and building from source...")
    FetchContent_Declare(
            libsodium
            GIT_REPOSITORY https://github.com/jedisct1/libsodium.git
            GIT_TAG stable  # Use the latest stable release
    )
    FetchContent_MakeAvailable(libsodium)
    set(SODIUM_LIBRARY sodium)
    set(SODIUM_INCLUDE_DIR ${libsodium_SOURCE_DIR}/src/libsodium/include)
else()
    message(STATUS "Found libsodium: ${SODIUM_LIBRARY}")
    message(STATUS "libsodium include dir: ${SODIUM_INCLUDE_DIR}")
endif()

# Configure C++ modules
set(CMAKE_EXPERIMENTAL_CXX_MODULE_CMAKE_API "aa1f7df0-828a-4fcd-9afc-2dc80491aca7")
set(CMAKE_EXPERIMENTAL_CXX_MODULE_DYNDEP 1)

# Define module files
set(MODULE_FILES
        include/crypto.cppm
        include/file.cppm
        include/wallet.cppm
        include/block.cppm
        include/utils.cppm
)

# Define source files for vaultguard
set(SOURCE_FILES
        src/main.cpp
)

# Define source files for recover_key
set(RECOVER_KEY_SOURCES
        src/recover_key.cpp
)

# Add executable for vaultguard
add_executable(vaultguard)
target_sources(vaultguard
        PUBLIC
        FILE_SET CXX_MODULES
        TYPE CXX_MODULES
        BASE_DIRS ${CMAKE_SOURCE_DIR}/include
        FILES ${MODULE_FILES}
        PRIVATE
        ${SOURCE_FILES}
)

# Add executable for recover_key
add_executable(recover_key)
target_sources(recover_key
        PUBLIC
        FILE_SET CXX_MODULES
        TYPE CXX_MODULES
        BASE_DIRS ${CMAKE_SOURCE_DIR}/include
        FILES ${MODULE_FILES}
        PRIVATE
        ${RECOVER_KEY_SOURCES}
)

# Enable module scanning
set_target_properties(vaultguard PROPERTIES
        CXX_SCAN_FOR_MODULES ON
)
set_target_properties(recover_key PROPERTIES
        CXX_SCAN_FOR_MODULES ON
)

# Link libsodium
target_include_directories(vaultguard PRIVATE ${SODIUM_INCLUDE_DIR})
target_include_directories(recover_key PRIVATE ${SODIUM_INCLUDE_DIR})
target_link_libraries(vaultguard PRIVATE ${SODIUM_LIBRARY})
target_link_libraries(recover_key PRIVATE ${SODIUM_LIBRARY})

# Set include directories
target_include_directories(vaultguard PRIVATE include)
target_include_directories(recover_key PRIVATE include)

# Compiler flags for module support
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_compile_options(vaultguard PRIVATE
            -fmodules
            -fimplicit-modules
            -fimplicit-module-maps
            -Wno-include-angled-in-module-purview
    )
    target_compile_options(recover_key PRIVATE
            -fmodules
            -fimplicit-modules
            -fimplicit-module-maps
            -Wno-include-angled-in-module-purview
    )
elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    target_compile_options(vaultguard PRIVATE
            -fmodules-ts
    )
    target_compile_options(recover_key PRIVATE
            -fmodules-ts
    )
elseif(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    target_compile_options(vaultguard PRIVATE
            /experimental:module
            /module:stdIfcDir "${CMAKE_CXX_COMPILER_EXTERNAL_TOOLCHAIN}/modules"
    )
    target_compile_options(recover_key PRIVATE
            /experimental:module
            /module:stdIfcDir "${CMAKE_CXX_COMPILER_EXTERNAL_TOOLCHAIN}/modules"
    )
endif()

# Windows-specific settings
if(WIN32)
    target_link_libraries(vaultguard PRIVATE ws2_32)
    target_link_libraries(recover_key PRIVATE ws2_32)
endif()

# Install executables
install(TARGETS vaultguard recover_key DESTINATION bin)