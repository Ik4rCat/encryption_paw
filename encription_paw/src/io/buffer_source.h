#pragma once

#include "data_source.h"

#include <string>

class BufferSource : public DataSource {
public:
    explicit BufferSource(std::vector<uint8_t> data);
    explicit BufferSource(const std::string& text);
    std::vector<uint8_t> readAll() override;

private:
    std::vector<uint8_t> m_data;
};
