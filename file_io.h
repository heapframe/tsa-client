//
// Created by axjp on 25/06/2026.
//

#ifndef TSA_CLIENT_WRITE_H
#define TSA_CLIENT_WRITE_H
#include <string>
#include <vector>

std::vector<char> read_file(const std::string& filepath);
bool write_file(const std::string& filepath, const char* data, size_t len);

#endif //TSA_CLIENT_WRITE_H