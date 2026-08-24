cmake_minimum_required(VERSION 3.15)
project(horus LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT WIN32)
    message(FATAL_ERROR "Horus targets Windows - it needs the BCrypt and WinHTTP APIs.")
endif()

# ---- embed the GUI page into the binary (single source: gui/ui.html) --------
set(HORUS_GEN "${CMAKE_BINARY_DIR}/generated")
file(READ "${CMAKE_SOURCE_DIR}/src/gui/ui.html" HORUS_UI_HEX HEX)
string(REGEX REPLACE "(..)" "0x\\1," HORUS_UI_BYTES "${HORUS_UI_HEX}")
configure_file("${CMAKE_SOURCE_DIR}/src/gui/ui_html.hpp.in"
               "${HORUS_GEN}/gui/ui_html.hpp" @ONLY)

file(READ "${CMAKE_SOURCE_DIR}/src/gui/case.html" HORUS_CASE_HEX HEX)
string(REGEX REPLACE "(..)" "0x\\1," HORUS_CASE_BYTES "${HORUS_CASE_HEX}")
configure_file("${CMAKE_SOURCE_DIR}/src/gui/case_html.hpp.in"
               "${HORUS_GEN}/gui/case_html.hpp" @ONLY)

# ---- shared analysis engine (the bits that need their own .cpp) -------------
add_library(horus_core STATIC
    src/crypto.cpp
    src/http.cpp
    src/intel.cpp
    src/authenticode.cpp
)
target_include_directories(horus_core PUBLIC src)
target_link_libraries(horus_core PUBLIC bcrypt winhttp crypt32 wintrust ole32)
target_compile_definitions(horus_core PUBLIC _WIN32_WINNT=0x0601 NOMINMAX WIN32_LEAN_AND_MEAN)
if(MSVC)
    target_compile_options(horus_core PRIVATE /W4 /O2 /EHsc)
else()
    target_compile_options(horus_core PRIVATE -Wall -Wextra -O2)
endif()

set(GUI_LIBS shell32 comdlg32 user32)

# ---- horus-cli.exe : pure command line, zero third-party deps ---------------
add_executable(horus-cli src/main_cli.cpp src/horus.rc)
target_include_directories(horus-cli PRIVATE "${HORUS_GEN}")
target_link_libraries(horus-cli PRIVATE horus_core)

# ---- horus.exe : unified build (CLI by default, --gui opens the glass UI) ----
add_executable(horus src/main.cpp src/horus.rc)
target_include_directories(horus PRIVATE "${HORUS_GEN}")
target_link_libraries(horus PRIVATE horus_core ${GUI_LIBS})

# ---- horus-gui.exe : windows-subsystem GUI build ----------------------------
add_executable(horus-gui WIN32 src/gui/main_gui.cpp src/horus.rc)
target_include_directories(horus-gui PRIVATE "${HORUS_GEN}")
target_link_libraries(horus-gui PRIVATE horus_core ${GUI_LIBS})

# our .rc already carries the manifest - stop the linker adding a second one
if(MSVC)
    target_link_options(horus-cli PRIVATE /MANIFEST:NO)
    target_link_options(horus     PRIVATE /MANIFEST:NO)
    target_link_options(horus-gui PRIVATE /MANIFEST:NO)
endif()

if(MSVC)
    foreach(t horus-cli horus horus-gui)
        target_compile_options(${t} PRIVATE /W4 /O2 /EHsc)
    endforeach()
endif()

# ---- tests (ctest) ----------------------------------------------------------
option(BUILD_TESTING "Build the unit tests" ON)
if(BUILD_TESTING)
    enable_testing()
    set(HORUS_TESTS test_ioc test_json test_pe test_score test_fuzzy
                    test_core test_config test_cache test_diff test_case)
    foreach(t IN LISTS HORUS_TESTS)
        add_executable(${t} tests/${t}.cpp)
        target_link_libraries(${t} PRIVATE horus_core)
        target_include_directories(${t} PRIVATE src "${HORUS_GEN}")
        if(MSVC)
            target_compile_options(${t} PRIVATE /EHsc)
        endif()
        add_test(NAME ${t} COMMAND ${t})
    endforeach()
    target_link_libraries(test_case PRIVATE shell32)
endif()
