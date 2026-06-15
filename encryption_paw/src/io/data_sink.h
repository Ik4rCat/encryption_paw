#pragma once

#include <cstdint>
#include <vector>

class DataSink {
public:
    virtual ~DataSink() = default;
    virtual void write(const std::vector<uint8_t>& data) = 0;
    virtual std::vector<uint8_t> getData() { return {}; }
};
