#include "file_sink.h"

#include <fstream>
#include <stdexcept>

FileSink::FileSink(std::string path) : m_path(std::move(path)) {}

void FileSink::write(const std::vector<uint8_t>& data) {
    std::ofstream f(m_path, std::ios::binary);
    if (!f) {
        throw std::runtime_error("Cannot open file for writing: " + m_path);
    }
    f.write(reinterpret_cast<const char*>(data.data()),
            static_cast<std::streamsize>(data.size()));
}
