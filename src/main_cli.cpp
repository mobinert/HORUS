// ---------------------------------------------------------------------------
//  main_cli.cpp  -  horus-cli.exe: the pure command-line build.
//
//  Zero third-party dependencies, links only Windows OS libraries. This is the
//  binary the README's "one .exe, zero deps" badge is about - no GUI code, no
//  WebView2, nothing but the analysis engine and the terminal renderer.
// ---------------------------------------------------------------------------
#include "cli.hpp"

int main(int argc, char** argv) {
    return horus::cli::run(argc, argv);
}
