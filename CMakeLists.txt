cmake_minimum_required(VERSION 3.15)
project(horus LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT WIN32)
    message(FATAL_ERROR "Horus targets Windows — it needs the BCrypt and WinHTTP APIs.")
endif()

add_executable(horus
    src/main.cpp
    src/crypto.cpp
    src/http.cpp
    src/intel.cpp
)

target_include_directories(horus PRIVATE src)
target_link_libraries(horus PRIVATE bcrypt winhttp)

if(MSVC)
    target_compile_options(horus PRIVATE /W4 /O2 /EHsc)
    target_compile_definitions(horus PRIVATE _WIN32_WINNT=0x0601 NOMINMAX WIN32_LEAN_AND_MEAN)
else()
    target_compile_options(horus PRIVATE -Wall -Wextra -O2)
    target_compile_definitions(horus PRIVATE _WIN32_WINNT=0x0601 NOMINMAX WIN32_LEAN_AND_MEAN)
endif()
