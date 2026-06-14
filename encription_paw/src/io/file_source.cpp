#include "file_source.h"

#include <fstream>
#include <stdexcept>

FileSource::FileSource(std::string path) : m_path(std::move(path)) {}

std::vector<uint8_t> FileSource::readAll() {
    std::ifstream f(m_path, std::ios::binary);
    if (!f) {
        throw std::runtime_error("Cannot open file for reading: " + m_path);
    }
    return std::vector<uint8_t>(std::istreambuf_iterator<char>(f),
                                std::istreambuf_iterator<char>());
}
