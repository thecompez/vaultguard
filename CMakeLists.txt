cmake_minimum_required(VERSION 3.26)
project(VaultGuard LANGUAGES C CXX)

# Set C++26 standard
set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Include FetchContent module for dependency management
include(FetchContent)
include(ExternalProject)
include(CTest)

# Try to find libsodium on the system first
find_library(SODIUM_LIBRARY
    NAMES sodium libsodium
    HINTS
    /opt/homebrew/opt/libsodium/lib
    /opt/homebrew/lib
    /usr/local/opt/libsodium/lib
    /usr/local/lib
    /usr/lib
    /usr/lib64
    ${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/lib
    PATH_SUFFIXES lib libsodium
)

find_path(SODIUM_INCLUDE_DIR
    NAMES sodium.h
    HINTS
    /opt/homebrew/opt/libsodium/include
    /opt/homebrew/include
    /usr/local/opt/libsodium/include
    /usr/local/include
    /usr/include
    ${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/include
    PATH_SUFFIXES include sodium
)

if(SODIUM_LIBRARY AND SODIUM_INCLUDE_DIR)
    set(USE_BUNDLED_SODIUM OFF)
    add_library(sodium::sodium UNKNOWN IMPORTED GLOBAL)
    set_target_properties(sodium::sodium PROPERTIES
        IMPORTED_LOCATION "${SODIUM_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${SODIUM_INCLUDE_DIR}"
    )
    message(STATUS "Found libsodium: ${SODIUM_LIBRARY}")
    message(STATUS "libsodium include dir: ${SODIUM_INCLUDE_DIR}")
else()
    set(USE_BUNDLED_SODIUM ON)
    if(WIN32)
        message(FATAL_ERROR
            "libsodium not found. Install via vcpkg (e.g. 'vcpkg install libsodium') "
            "and configure CMAKE_TOOLCHAIN_FILE.")
    endif()

    message(WARNING "libsodium not found on system. Downloading and building from source (autotools)...")

    FetchContent_Declare(
        libsodium_src
        GIT_REPOSITORY https://github.com/jedisct1/libsodium.git
        GIT_TAG stable
        GIT_SHALLOW TRUE
    )
    if(POLICY CMP0169)
        cmake_policy(SET CMP0169 OLD)
    endif()
    FetchContent_Populate(libsodium_src)

    set(LIBSODIUM_INSTALL_DIR "${CMAKE_BINARY_DIR}/libsodium-install")
    set(LIBSODIUM_STATIC_LIB "${LIBSODIUM_INSTALL_DIR}/lib/libsodium.a")
    set(LIBSODIUM_INCLUDE_DIR "${LIBSODIUM_INSTALL_DIR}/include")

    # Imported targets are validated at configure/generate time; create staging dirs up front.
    file(MAKE_DIRECTORY "${LIBSODIUM_INCLUDE_DIR}")
    file(MAKE_DIRECTORY "${LIBSODIUM_INSTALL_DIR}/lib")

    ExternalProject_Add(libsodium_external
        SOURCE_DIR "${libsodium_src_SOURCE_DIR}"
        BINARY_DIR "${CMAKE_BINARY_DIR}/libsodium-build"
        CONFIGURE_COMMAND "${libsodium_src_SOURCE_DIR}/configure" --disable-shared --enable-static --prefix=${LIBSODIUM_INSTALL_DIR}
        BUILD_COMMAND make
        INSTALL_COMMAND make install
        BUILD_BYPRODUCTS "${LIBSODIUM_STATIC_LIB}"
        UPDATE_DISCONNECTED TRUE
    )

    add_library(sodium::sodium STATIC IMPORTED GLOBAL)
    set_target_properties(sodium::sodium PROPERTIES
        IMPORTED_LOCATION "${LIBSODIUM_STATIC_LIB}"
        INTERFACE_INCLUDE_DIRECTORIES "${LIBSODIUM_INCLUDE_DIR}"
    )
endif()

# Configure C++ modules
set(CMAKE_EXPERIMENTAL_CXX_MODULE_CMAKE_API "aa1f7df0-828a-4fcd-9afc-2dc80491aca7")
set(CMAKE_EXPERIMENTAL_CXX_MODULE_DYNDEP 1)
set(CLANG_MODULE_CACHE_DIR "${CMAKE_BINARY_DIR}/clang-module-cache")
file(MAKE_DIRECTORY "${CLANG_MODULE_CACHE_DIR}")

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

# Add executable for tests
if(BUILD_TESTING)
    add_executable(vaultguard_tests)
    target_sources(vaultguard_tests
            PUBLIC
            FILE_SET CXX_MODULES
            TYPE CXX_MODULES
            BASE_DIRS ${CMAKE_SOURCE_DIR}/include
            FILES ${MODULE_FILES}
            PRIVATE
            tests/wallet_security_tests.cpp
    )

    add_executable(vaultguard_integration_tests)
    target_sources(vaultguard_integration_tests
            PUBLIC
            FILE_SET CXX_MODULES
            TYPE CXX_MODULES
            BASE_DIRS ${CMAKE_SOURCE_DIR}/include
            FILES ${MODULE_FILES}
            PRIVATE
            tests/wallet_integration_tests.cpp
    )
endif()

# Enable module scanning
set_target_properties(vaultguard PROPERTIES
        CXX_SCAN_FOR_MODULES ON
)
set_target_properties(recover_key PROPERTIES
        CXX_SCAN_FOR_MODULES ON
)
if(BUILD_TESTING)
    set_target_properties(vaultguard_tests PROPERTIES
            CXX_SCAN_FOR_MODULES ON
    )
    set_target_properties(vaultguard_integration_tests PROPERTIES
            CXX_SCAN_FOR_MODULES ON
    )
endif()

# Link libsodium
target_link_libraries(vaultguard PRIVATE sodium::sodium)
target_link_libraries(recover_key PRIVATE sodium::sodium)
if(BUILD_TESTING)
    target_link_libraries(vaultguard_tests PRIVATE sodium::sodium)
    target_link_libraries(vaultguard_integration_tests PRIVATE sodium::sodium)
endif()
if(USE_BUNDLED_SODIUM)
    add_dependencies(vaultguard libsodium_external)
    add_dependencies(recover_key libsodium_external)
    if(BUILD_TESTING)
        add_dependencies(vaultguard_tests libsodium_external)
        add_dependencies(vaultguard_integration_tests libsodium_external)
    endif()
endif()

# Set include directories
target_include_directories(vaultguard PRIVATE include)
target_include_directories(recover_key PRIVATE include)
if(BUILD_TESTING)
    target_include_directories(vaultguard_tests PRIVATE include)
    target_include_directories(vaultguard_integration_tests PRIVATE include)
endif()

# Compiler flags for module support
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_compile_options(vaultguard PRIVATE
            -fmodules
            -fmodules-cache-path=${CLANG_MODULE_CACHE_DIR}
            -fimplicit-modules
            -fimplicit-module-maps
            -Wno-include-angled-in-module-purview
    )
    target_compile_options(recover_key PRIVATE
            -fmodules
            -fmodules-cache-path=${CLANG_MODULE_CACHE_DIR}
            -fimplicit-modules
            -fimplicit-module-maps
            -Wno-include-angled-in-module-purview
    )
    if(BUILD_TESTING)
        target_compile_options(vaultguard_tests PRIVATE
                -fmodules
                -fmodules-cache-path=${CLANG_MODULE_CACHE_DIR}
                -fimplicit-modules
                -fimplicit-module-maps
                -Wno-include-angled-in-module-purview
        )
        target_compile_options(vaultguard_integration_tests PRIVATE
                -fmodules
                -fmodules-cache-path=${CLANG_MODULE_CACHE_DIR}
                -fimplicit-modules
                -fimplicit-module-maps
                -Wno-include-angled-in-module-purview
        )
    endif()
elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    target_compile_options(vaultguard PRIVATE
            -fmodules-ts
    )
    target_compile_options(recover_key PRIVATE
            -fmodules-ts
    )
    if(BUILD_TESTING)
        target_compile_options(vaultguard_tests PRIVATE
                -fmodules-ts
        )
        target_compile_options(vaultguard_integration_tests PRIVATE
                -fmodules-ts
        )
    endif()
elseif(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    target_compile_options(vaultguard PRIVATE
            /experimental:module
            /module:stdIfcDir "${CMAKE_CXX_COMPILER_EXTERNAL_TOOLCHAIN}/modules"
    )
    target_compile_options(recover_key PRIVATE
            /experimental:module
            /module:stdIfcDir "${CMAKE_CXX_COMPILER_EXTERNAL_TOOLCHAIN}/modules"
    )
    if(BUILD_TESTING)
        target_compile_options(vaultguard_tests PRIVATE
                /experimental:module
                /module:stdIfcDir "${CMAKE_CXX_COMPILER_EXTERNAL_TOOLCHAIN}/modules"
        )
        target_compile_options(vaultguard_integration_tests PRIVATE
                /experimental:module
                /module:stdIfcDir "${CMAKE_CXX_COMPILER_EXTERNAL_TOOLCHAIN}/modules"
        )
    endif()
endif()

# Windows-specific settings
if(WIN32)
    target_link_libraries(vaultguard PRIVATE ws2_32)
    target_link_libraries(recover_key PRIVATE ws2_32)
    if(BUILD_TESTING)
        target_link_libraries(vaultguard_tests PRIVATE ws2_32)
        target_link_libraries(vaultguard_integration_tests PRIVATE ws2_32)
    endif()
endif()

if(BUILD_TESTING)
    add_test(NAME vaultguard_tests COMMAND vaultguard_tests)
    add_test(NAME vaultguard_integration_tests COMMAND vaultguard_integration_tests)
endif()

# Install executables
install(TARGETS vaultguard recover_key DESTINATION bin)
