cmake_minimum_required(VERSION 3.16)

project(encription_paw VERSION 0.1 LANGUAGES CXX)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 REQUIRED COMPONENTS Widgets)
find_package(Qt6 REQUIRED COMPONENTS Widgets)
find_package(OpenSSL REQUIRED)

set(CRYPTO_SOURCES
    src/crypto/xor_cipher.cpp
    src/crypto/rsa_cipher.cpp
    src/crypto/key_validator.cpp
    src/crypto/key_generator.cpp
)

set(IO_SOURCES
    src/io/file_source.cpp
    src/io/file_sink.cpp
    src/io/buffer_source.cpp
    src/io/buffer_sink.cpp
)

qt_add_executable(encription_paw
    MANUAL_FINALIZATION
    ${CRYPTO_SOURCES}
    ${IO_SOURCES}
    src/gui/main_gui.cpp
    src/gui/mainwindow.h
    src/gui/mainwindow.cpp
)

target_include_directories(encription_paw PRIVATE src)

target_link_libraries(encription_paw PRIVATE
    Qt6::Widgets
    OpenSSL::SSL
    OpenSSL::Crypto
)

set_target_properties(encription_paw PROPERTIES
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

include(GNUInstallDirs)
install(TARGETS encription_paw
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

qt_finalize_executable(encription_paw)

add_executable(test_cli
    src/cli/test_cli.cpp
    ${CRYPTO_SOURCES}
    ${IO_SOURCES}
)

target_include_directories(test_cli PRIVATE src)

target_link_libraries(test_cli PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
)

target_compile_definitions(test_cli PRIVATE
    LEGACY_PAW_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../legacy_paw"
)
