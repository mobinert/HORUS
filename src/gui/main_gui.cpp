// ---------------------------------------------------------------------------
//  gui/main_gui.cpp  -  horus-gui.exe: the GUI-only build.
//
//  Windows subsystem app, so no console flashes up. Drag a file onto it, or run
//  it and pick one; either way it opens the glass console report. Shares the
//  whole back-end with horus.exe via gui/host.hpp.
// ---------------------------------------------------------------------------
#include "cli.hpp"          // parse_args
#include "gui/host.hpp"

#include <windows.h>

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    horus::core::Options opts = horus::cli::parse_args(__argc, __argv);
    if (!opts.html_out.empty())
        return horus::gui::write_html(opts, opts.html_out);
    return horus::gui::launch(opts);
}
