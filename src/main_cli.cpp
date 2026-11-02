// ---------------------------------------------------------------------------
//  main_cli.cpp  -  horus-cli.exe: the pure command-line build.
//
//  Zero third-party dependencies, links only Windows OS libraries. This is the
//  binary the README's "one .exe, zero deps" badge is about - no GUI code, no
//  WebView2, nothing but the analysis engine and the terminal renderer.
// ---------------------------------------------------------------------------
#include "cli.hpp"

int main(int argc, char** argv) {
    horus::core::Options opts = horus::cli::parse_args(argc, argv);
    if (opts.gui || !opts.html_out.empty())
        horus::cli::argument_error("--gui and --html require horus.exe or horus-gui.exe");
    return horus::cli::run(opts);
}
