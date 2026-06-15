#pragma once

#include "data_source.h"

#include <string>

class FileSource : public DataSource {
public:
    explicit FileSource(std::string path);
    std::vector<uint8_t> readAll() override;

private:
    std::string m_path;
};
