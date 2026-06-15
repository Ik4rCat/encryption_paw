#pragma once

#include <cstdint>
#include <vector>

class DataSource {
public:
    virtual ~DataSource() = default;
    virtual std::vector<uint8_t> readAll() = 0;
};
