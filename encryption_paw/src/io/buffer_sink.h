#pragma once

#include "data_sink.h"

class BufferSink : public DataSink {
public:
    void write(const std::vector<uint8_t>& data) override;
    std::vector<uint8_t> getData() override;

private:
    std::vector<uint8_t> m_data;
};
