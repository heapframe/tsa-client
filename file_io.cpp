//
// Created by axjp on 25/06/2026.
//
#include "file_io.h"
#include <fstream>
#include <iostream>

std::vector<char> read_file(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::in | std::ios::binary | std::ios::ate);

    if (!file.is_open()) {
        std::cerr << "Error: Could not open " << filepath << " for reading.\n";
        return {};
    }

    const auto size = static_cast<std::streamsize>(file.tellg());
    file.seekg(0, std::ios::beg);

    std::vector<char> buffer(size);

    if (file.read(buffer.data(), size)) {
        return buffer;
    }
    std::cerr << "Error: Failed to read from " << filepath << ".\n";
    return {};
}

bool write_file(const std::string& filepath, const char* data, size_t len) {
    std::ofstream file(filepath, std::ios::out | std::ios::binary);

    if (!file.is_open()) {
        std::cerr << "Error: Could not open " << filepath << " for writing.\n";
        return false;
    }

    if (file.write(data, static_cast<std::streamsize>(len))) {
        return true;
    }
    std::cerr << "Error: Failed to write to " << filepath << ".\n";
    return false;
}
