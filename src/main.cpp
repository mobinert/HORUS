// ---------------------------------------------------------------------------
//  main.cpp  -  horus.exe: the unified build (CLI + GUI in one).
//
//  Behaves exactly like horus-cli by default. Pass --gui (or just double-click
//  it with no arguments) and it brings up the glass console instead. The GUI
//  itself lives in gui/host.hpp so horus-gui.exe can share it.
// ---------------------------------------------------------------------------
#include "cli.hpp"
#include "gui/host.hpp"

int main(int argc, char** argv) {
    horus::core::Options opts = horus::cli::parse_args(argc, argv);

    if (!opts.html_out.empty())
        return horus::gui::write_html(opts, opts.html_out);

    if (!opts.case_dir.empty())
        return horus::cli::run(opts);

    // no args at all + launched from Explorer -> friendlier to open the GUI
    bool bare_launch = (argc == 1) && horus::gui::launched_from_gui();

    if (opts.gui || bare_launch)
        return horus::gui::launch(opts);

    return horus::cli::run(opts);
}
