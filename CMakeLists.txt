cmake_minimum_required(VERSION 3.15)
if(POLICY CMP0091)
    cmake_policy(SET CMP0091 NEW)
endif()
project(horus VERSION 4.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

if(NOT WIN32)
    message(FATAL_ERROR "Horus targets Windows - it needs the BCrypt and WinHTTP APIs.")
endif()
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "Horus v4 supports Windows 10/11 x64 only. Configure an x64 build.")
endif()

# ---- generated version metadata and embedded reports -----------------------
set(HORUS_GEN "${CMAKE_BINARY_DIR}/generated")
file(MAKE_DIRECTORY "${HORUS_GEN}/gui")
set(HORUS_VERSION_COMMA
    "${PROJECT_VERSION_MAJOR},${PROJECT_VERSION_MINOR},${PROJECT_VERSION_PATCH},0")
set(HORUS_VERSION_QUAD "${PROJECT_VERSION}.0")
configure_file("${CMAKE_SOURCE_DIR}/src/version.hpp.in"
               "${HORUS_GEN}/version.hpp" @ONLY)
configure_file("${CMAKE_SOURCE_DIR}/src/horus.manifest.in"
               "${HORUS_GEN}/horus.manifest" @ONLY)
configure_file("${CMAKE_SOURCE_DIR}/.github/release-notes.md.in"
               "${HORUS_GEN}/release-notes.md" @ONLY)
file(TO_CMAKE_PATH "${HORUS_GEN}/horus.manifest" HORUS_MANIFEST_PATH)

function(horus_make_resource original_filename output_var)
    set(HORUS_ORIGINAL_FILENAME "${original_filename}")
    string(REPLACE ".exe" "" resource_name "${original_filename}")
    configure_file("${CMAKE_SOURCE_DIR}/src/horus.rc.in"
                   "${HORUS_GEN}/${resource_name}.rc" @ONLY)
    set(${output_var} "${HORUS_GEN}/${resource_name}.rc" PARENT_SCOPE)
endfunction()
horus_make_resource("horus.exe" HORUS_RC)
horus_make_resource("horus-cli.exe" HORUS_CLI_RC)
horus_make_resource("horus-gui.exe" HORUS_GUI_RC)

configure_file("${CMAKE_SOURCE_DIR}/src/gui/ui.html"
               "${HORUS_GEN}/gui/ui.html" @ONLY)
file(READ "${HORUS_GEN}/gui/ui.html" HORUS_UI_HEX HEX)
string(REGEX REPLACE "(..)" "0x\\1," HORUS_UI_BYTES "${HORUS_UI_HEX}")
configure_file("${CMAKE_SOURCE_DIR}/src/gui/ui_html.hpp.in"
               "${HORUS_GEN}/gui/ui_html.hpp" @ONLY)

configure_file("${CMAKE_SOURCE_DIR}/src/gui/case.html"
               "${HORUS_GEN}/gui/case.html" @ONLY)
file(READ "${HORUS_GEN}/gui/case.html" HORUS_CASE_HEX HEX)
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
target_include_directories(horus_core PUBLIC src "${HORUS_GEN}")
target_link_libraries(horus_core PUBLIC bcrypt winhttp crypt32 wintrust ole32)
target_compile_definitions(horus_core PUBLIC _WIN32_WINNT=0x0A00 NOMINMAX WIN32_LEAN_AND_MEAN)
if(MSVC)
    target_compile_options(horus_core PRIVATE /W4 /O2 /EHsc)
else()
    target_compile_options(horus_core PRIVATE -Wall -Wextra -O2)
endif()

set(GUI_LIBS shell32 comdlg32 user32)

# ---- horus-cli.exe : pure command line, zero third-party deps ---------------
add_executable(horus-cli src/main_cli.cpp "${HORUS_CLI_RC}")
target_include_directories(horus-cli PRIVATE "${HORUS_GEN}")
target_link_libraries(horus-cli PRIVATE horus_core)

# ---- horus.exe : unified build (CLI by default, --gui opens the glass UI) ----
add_executable(horus src/main.cpp "${HORUS_RC}")
target_include_directories(horus PRIVATE "${HORUS_GEN}")
target_link_libraries(horus PRIVATE horus_core ${GUI_LIBS})

# ---- horus-gui.exe : windows-subsystem GUI build ----------------------------
add_executable(horus-gui WIN32 src/gui/main_gui.cpp "${HORUS_GUI_RC}")
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
                    test_core test_config test_cache test_diff test_case
                    test_http test_report test_output)
    foreach(t IN LISTS HORUS_TESTS)
        add_executable(${t} tests/${t}.cpp)
        target_link_libraries(${t} PRIVATE horus_core)
        target_include_directories(${t} PRIVATE src "${HORUS_GEN}")
        if(MSVC)
            target_compile_options(${t} PRIVATE /EHsc)
        endif()
        add_test(NAME ${t} COMMAND ${t})
    endforeach()
    target_link_libraries(test_case PRIVATE shell32 psapi)
    target_link_libraries(test_report PRIVATE ${GUI_LIBS})
    add_test(NAME test_direct_cli
             COMMAND powershell -NoProfile -ExecutionPolicy Bypass
                     -File "${CMAKE_SOURCE_DIR}/tests/direct_smoke.ps1"
                     -Horus $<TARGET_FILE:horus>
                     -HorusGui $<TARGET_FILE:horus-gui>)
    set_tests_properties(test_direct_cli PROPERTIES TIMEOUT 60)
    add_test(NAME test_release_metadata
             COMMAND powershell -NoProfile -ExecutionPolicy Bypass
                     -File "${CMAKE_SOURCE_DIR}/tests/release_checks.ps1"
                     -BinDir $<TARGET_FILE_DIR:horus>
                     -ExpectedVersion ${PROJECT_VERSION})
    set_tests_properties(test_release_metadata PROPERTIES TIMEOUT 30)
endif()
