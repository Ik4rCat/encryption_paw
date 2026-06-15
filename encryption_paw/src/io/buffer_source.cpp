#include "buffer_source.h"

BufferSource::BufferSource(std::vector<uint8_t> data) : m_data(std::move(data)) {}

BufferSource::BufferSource(const std::string& text)
    : m_data(text.begin(), text.end()) {}

std::vector<uint8_t> BufferSource::readAll() {
    return m_data;
}
