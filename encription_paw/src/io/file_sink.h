#pragma once

#include "data_sink.h"

#include <string>

class FileSink : public DataSink {
public:
    explicit FileSink(std::string path);
    void write(const std::vector<uint8_t>& data) override;

private:
    std::string m_path;
};
