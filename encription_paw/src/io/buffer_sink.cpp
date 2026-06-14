#include "buffer_sink.h"

void BufferSink::write(const std::vector<uint8_t>& data) {
    m_data = data;
}

std::vector<uint8_t> BufferSink::getData() {
    return m_data;
}
