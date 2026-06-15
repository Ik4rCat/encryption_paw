#pragma once

#include <cstdint>
#include <vector>

#include <QLabel>
#include <QLineEdit>
#include <QMainWindow>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QRadioButton>
#include <QSpinBox>
#include <QStackedWidget>
#include <QTabWidget>

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override = default;

private slots:
    void execute();
    void browseInputFile();
    void browsePubKey();
    void browsePrivKey();
    void validatePrivKey();
    void copyOutput();
    void generateXorKey();
    void generateRsaKeys();

private:
    void setupUi();
    void connectSignals();
    void updatePrevLabel();

    QRadioButton* m_srcText{};
    QRadioButton* m_srcFile{};
    QRadioButton* m_srcPrev{};
    QStackedWidget* m_srcStack{};
    QPlainTextEdit* m_srcTextEdit{};
    QLineEdit* m_srcFilePath{};
    QLabel* m_srcPrevLabel{};

    QTabWidget* m_algTabs{};

    QLineEdit* m_xorKey{};
    QSpinBox* m_xorKeyLen{};
    QRadioButton* m_xorEncrypt{};
    QRadioButton* m_xorDecrypt{};

    QRadioButton* m_rsaEncrypt{};
    QRadioButton* m_rsaDecrypt{};
    QLineEdit* m_rsaPubKey{};
    QLineEdit* m_rsaPrivKey{};
    QLabel* m_rsaKeyStatus{};

    QRadioButton* m_outGui{};
    QRadioButton* m_outFile{};
    QStackedWidget* m_outStack{};
    QPlainTextEdit* m_outTextEdit{};

    QPushButton* m_executeBtn{};

    std::vector<uint8_t> m_lastResult;
};
