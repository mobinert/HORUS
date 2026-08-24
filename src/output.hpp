#pragma once

#include <windows.h>

#include <filesystem>
#include <fstream>
#include <string>

namespace horus {
namespace output {

namespace fs = std::filesystem;

inline bool write_atomic(const fs::path& path, const std::string& content,
                         std::string& error) {
    fs::path temp = path;
    temp += ".tmp-" + std::to_string(GetCurrentProcessId());
    {
        std::ofstream file(temp, std::ios::binary | std::ios::trunc);
        if (!file) { error = "cannot open output: " + path.string(); return false; }
        file.write(content.data(), static_cast<std::streamsize>(content.size()));
        file.flush();
        if (!file) {
            error = "cannot write output: " + path.string();
            file.close();
            std::error_code ec;
            fs::remove(temp, ec);
            return false;
        }
    }
    if (!MoveFileExW(temp.c_str(), path.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        error = "cannot replace output: " + path.string() +
                " (Windows error " + std::to_string(GetLastError()) + ")";
        std::error_code ec;
        fs::remove(temp, ec);
        return false;
    }
    return true;
}

inline std::string csv_cell(std::string value) {
    if (!value.empty() && (value[0] == '=' || value[0] == '+' || value[0] == '-' ||
                           value[0] == '@' || value[0] == '\t' || value[0] == '\r'))
        value.insert(value.begin(), '\'');
    bool quote = value.find_first_of(",\"\r\n") != std::string::npos;
    if (!quote) return value;
    std::string out = "\"";
    for (char c : value) { if (c == '\"') out += '\"'; out += c; }
    return out + "\"";
}

} // namespace output
} // namespace horus
