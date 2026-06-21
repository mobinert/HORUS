cmake_minimum_required(VERSION 3.15)
project(argus LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT WIN32)
    message(FATAL_ERROR "ARGUS targets Windows - it needs the BCrypt and WinHTTP APIs.")
endif()

add_executable(argus
    src/main.cpp
    src/crypto.cpp
    src/http.cpp
    src/intel.cpp
)

target_include_directories(argus PRIVATE src)
target_link_libraries(argus PRIVATE bcrypt winhttp)

if(MSVC)
    target_compile_options(argus PRIVATE /W4 /O2 /EHsc)
    target_compile_definitions(argus PRIVATE _WIN32_WINNT=0x0601 NOMINMAX WIN32_LEAN_AND_MEAN)
else()
    target_compile_options(argus PRIVATE -Wall -Wextra -O2)
    target_compile_definitions(argus PRIVATE _WIN32_WINNT=0x0601 NOMINMAX WIN32_LEAN_AND_MEAN)
endif()
