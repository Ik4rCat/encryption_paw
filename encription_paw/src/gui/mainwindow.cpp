#include "mainwindow.h"

#include "crypto/key_generator.h"
#include "crypto/key_validator.h"
#include "crypto/rsa_cipher.h"
#include "crypto/xor_cipher.h"
#include "io/buffer_sink.h"
#include "io/buffer_source.h"
#include "io/file_sink.h"
#include "io/file_source.h"

#include <QApplication>
#include <QClipboard>
#include <QFile>
#include <QFileDialog>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QMessageBox>
#include <QVBoxLayout>
#include <QWidget>

static QString bytesToDisplay(const std::vector<uint8_t>& data) {
    bool isPrintable = true;
    for (uint8_t b : data) {
        if (b < 0x20 && b != '\n' && b != '\r' && b != '\t') {
            isPrintable = false;
            break;
        }
    }
    if (isPrintable) {
        return QString::fromUtf8(reinterpret_cast<const char*>(data.data()),
                                 static_cast<int>(data.size()));
    }
    QString hex;
    hex.reserve(static_cast<int>(data.size()) * 3);
    for (uint8_t b : data) {
        hex += QString::asprintf("%02X ", b);
    }
    return hex.trimmed();
}

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
    setupUi();
    connectSignals();
    setWindowTitle("EncryptionPaw");
    resize(700, 720);
}

void MainWindow::setupUi() {
    QWidget* central = new QWidget(this);
    setCentralWidget(central);
    QVBoxLayout* mainLayout = new QVBoxLayout(central);
    mainLayout->setSpacing(10);
    mainLayout->setContentsMargins(12, 12, 12, 12);

    {
        QGroupBox* srcGroup = new QGroupBox("Источник", central);
        QVBoxLayout* gl = new QVBoxLayout(srcGroup);

        QHBoxLayout* radioRow = new QHBoxLayout();
        m_srcText = new QRadioButton("Текст", srcGroup);
        m_srcFile = new QRadioButton("Файл", srcGroup);
        m_srcPrev = new QRadioButton("Предыдущий результат", srcGroup);
        m_srcText->setChecked(true);
        radioRow->addWidget(m_srcText);
        radioRow->addWidget(m_srcFile);
        radioRow->addWidget(m_srcPrev);
        radioRow->addStretch();
        gl->addLayout(radioRow);

        m_srcStack = new QStackedWidget(srcGroup);

        m_srcTextEdit = new QPlainTextEdit(m_srcStack);
        m_srcTextEdit->setPlaceholderText("Введите текст...");
        m_srcTextEdit->setFixedHeight(80);
        m_srcStack->addWidget(m_srcTextEdit);

        QWidget* filePage = new QWidget(m_srcStack);
        QHBoxLayout* fileRow = new QHBoxLayout(filePage);
        fileRow->setContentsMargins(0, 0, 0, 0);
        m_srcFilePath = new QLineEdit(filePage);
        m_srcFilePath->setPlaceholderText("Путь к файлу...");
        QPushButton* srcBrowse = new QPushButton("Обзор...", filePage);
        fileRow->addWidget(m_srcFilePath);
        fileRow->addWidget(srcBrowse);
        m_srcStack->addWidget(filePage);
        connect(srcBrowse, &QPushButton::clicked, this, &MainWindow::browseInputFile);

        QWidget* prevPage = new QWidget(m_srcStack);
        QVBoxLayout* prevLayout = new QVBoxLayout(prevPage);
        prevLayout->setContentsMargins(0, 4, 0, 4);
        m_srcPrevLabel = new QLabel("Нет предыдущего результата", prevPage);
        m_srcPrevLabel->setStyleSheet("color: gray;");
        prevLayout->addWidget(m_srcPrevLabel);
        m_srcStack->addWidget(prevPage);

        gl->addWidget(m_srcStack);
        mainLayout->addWidget(srcGroup);
    }

    {
        QGroupBox* algGroup = new QGroupBox("Алгоритм", central);
        QVBoxLayout* gl = new QVBoxLayout(algGroup);
        m_algTabs = new QTabWidget(algGroup);

        QWidget* xorTab = new QWidget(m_algTabs);
        QVBoxLayout* xorLayout = new QVBoxLayout(xorTab);

        QHBoxLayout* keyRow = new QHBoxLayout();
        keyRow->addWidget(new QLabel("Ключ:"));
        m_xorKey = new QLineEdit(xorTab);
        m_xorKey->setPlaceholderText("Введите ключ XOR...");
        keyRow->addWidget(m_xorKey);
        keyRow->addWidget(new QLabel("Длина:"));
        m_xorKeyLen = new QSpinBox(xorTab);
        m_xorKeyLen->setRange(1, 256);
        m_xorKeyLen->setValue(32);
        m_xorKeyLen->setFixedWidth(60);
        keyRow->addWidget(m_xorKeyLen);
        QPushButton* xorGenBtn = new QPushButton("Сгенерировать", xorTab);
        keyRow->addWidget(xorGenBtn);
        xorLayout->addLayout(keyRow);
        connect(xorGenBtn, &QPushButton::clicked, this, &MainWindow::generateXorKey);

        QHBoxLayout* xorOpRow = new QHBoxLayout();
        m_xorEncrypt = new QRadioButton("Шифровать", xorTab);
        m_xorDecrypt = new QRadioButton("Расшифровать", xorTab);
        m_xorEncrypt->setChecked(true);
        xorOpRow->addWidget(m_xorEncrypt);
        xorOpRow->addWidget(m_xorDecrypt);
        xorOpRow->addStretch();
        xorLayout->addLayout(xorOpRow);
        m_algTabs->addTab(xorTab, "XOR");

        QWidget* rsaTab = new QWidget(m_algTabs);
        QVBoxLayout* rsaLayout = new QVBoxLayout(rsaTab);

        QHBoxLayout* rsaOpRow = new QHBoxLayout();
        m_rsaEncrypt = new QRadioButton("Шифровать", rsaTab);
        m_rsaDecrypt = new QRadioButton("Расшифровать", rsaTab);
        m_rsaEncrypt->setChecked(true);
        rsaOpRow->addWidget(m_rsaEncrypt);
        rsaOpRow->addWidget(m_rsaDecrypt);
        rsaOpRow->addStretch();
        rsaLayout->addLayout(rsaOpRow);

        QHBoxLayout* pubRow = new QHBoxLayout();
        pubRow->addWidget(new QLabel("Публичный ключ:"));
        m_rsaPubKey = new QLineEdit(rsaTab);
        m_rsaPubKey->setPlaceholderText("public.pem...");
        QPushButton* pubBrowse = new QPushButton("Обзор...", rsaTab);
        pubRow->addWidget(m_rsaPubKey);
        pubRow->addWidget(pubBrowse);
        rsaLayout->addLayout(pubRow);
        connect(pubBrowse, &QPushButton::clicked, this, &MainWindow::browsePubKey);

        QHBoxLayout* privRow = new QHBoxLayout();
        privRow->addWidget(new QLabel("Приватный ключ:"));
        m_rsaPrivKey = new QLineEdit(rsaTab);
        m_rsaPrivKey->setPlaceholderText("private.pem...");
        QPushButton* privBrowse = new QPushButton("Обзор...", rsaTab);
        privRow->addWidget(m_rsaPrivKey);
        privRow->addWidget(privBrowse);
        rsaLayout->addLayout(privRow);
        connect(privBrowse, &QPushButton::clicked, this, &MainWindow::browsePrivKey);

        QPushButton* rsaGenBtn = new QPushButton("Сгенерировать пару ключей (RSA-2048)", rsaTab);
        rsaLayout->addWidget(rsaGenBtn);
        connect(rsaGenBtn, &QPushButton::clicked, this, &MainWindow::generateRsaKeys);

        m_rsaKeyStatus = new QLabel("● Не проверен", rsaTab);
        m_rsaKeyStatus->setStyleSheet("color: gray;");
        rsaLayout->addWidget(m_rsaKeyStatus);

        m_algTabs->addTab(rsaTab, "RSA");

        gl->addWidget(m_algTabs);
        mainLayout->addWidget(algGroup);
    }

    {
        QGroupBox* outGroup = new QGroupBox("Вывод", central);
        QVBoxLayout* gl = new QVBoxLayout(outGroup);

        QHBoxLayout* radioRow = new QHBoxLayout();
        m_outGui = new QRadioButton("В интерфейсе", outGroup);
        m_outFile = new QRadioButton("В файл (.bin)", outGroup);
        m_outGui->setChecked(true);
        radioRow->addWidget(m_outGui);
        radioRow->addWidget(m_outFile);
        radioRow->addStretch();
        gl->addLayout(radioRow);

        m_outStack = new QStackedWidget(outGroup);

        QWidget* guiOutPage = new QWidget(m_outStack);
        QVBoxLayout* guiOutLayout = new QVBoxLayout(guiOutPage);
        guiOutLayout->setContentsMargins(0, 0, 0, 0);
        m_outTextEdit = new QPlainTextEdit(guiOutPage);
        m_outTextEdit->setReadOnly(true);
        m_outTextEdit->setFixedHeight(100);
        m_outTextEdit->setPlaceholderText("Результат появится здесь...");
        QPushButton* copyBtn = new QPushButton("Копировать", guiOutPage);
        guiOutLayout->addWidget(m_outTextEdit);
        guiOutLayout->addWidget(copyBtn);
        m_outStack->addWidget(guiOutPage);
        connect(copyBtn, &QPushButton::clicked, this, &MainWindow::copyOutput);

        QWidget* fileOutPage = new QWidget(m_outStack);
        QVBoxLayout* fileOutLayout = new QVBoxLayout(fileOutPage);
        fileOutLayout->setContentsMargins(0, 0, 0, 0);
        fileOutLayout->addWidget(
            new QLabel("Файл (.bin) для сохранения будет выбран при нажатии «Выполнить»"));
        m_outStack->addWidget(fileOutPage);

        gl->addWidget(m_outStack);
        mainLayout->addWidget(outGroup);
    }

    m_executeBtn = new QPushButton("Выполнить", central);
    m_executeBtn->setFixedHeight(36);
    mainLayout->addWidget(m_executeBtn);
    mainLayout->addStretch();
}

void MainWindow::connectSignals() {
    connect(m_srcText, &QRadioButton::toggled, this, [this](bool checked) {
        if (checked) { m_srcStack->setCurrentIndex(0); }
    });
    connect(m_srcFile, &QRadioButton::toggled, this, [this](bool checked) {
        if (checked) { m_srcStack->setCurrentIndex(1); }
    });
    connect(m_srcPrev, &QRadioButton::toggled, this, [this](bool checked) {
        if (checked) { m_srcStack->setCurrentIndex(2); }
    });
    connect(m_outGui, &QRadioButton::toggled, this, [this](bool checked) {
        m_outStack->setCurrentIndex(checked ? 0 : 1);
    });
    connect(m_rsaPrivKey, &QLineEdit::editingFinished, this, &MainWindow::validatePrivKey);
    connect(m_executeBtn, &QPushButton::clicked, this, &MainWindow::execute);
}

void MainWindow::updatePrevLabel() {
    if (m_lastResult.empty()) {
        m_srcPrevLabel->setText("Нет предыдущего результата");
        m_srcPrevLabel->setStyleSheet("color: gray;");
    } else {
        m_srcPrevLabel->setText(
            QString("Предыдущий результат: %1 байт").arg(m_lastResult.size()));
        m_srcPrevLabel->setStyleSheet("color: green;");
    }
}

void MainWindow::browseInputFile() {
    QString path = QFileDialog::getOpenFileName(this, "Выберите файл источника");
    if (!path.isEmpty()) {
        m_srcFilePath->setText(path);
    }
}

void MainWindow::browsePubKey() {
    QString path = QFileDialog::getOpenFileName(
        this, "Публичный ключ (PEM)", "", "PEM (*.pem);;All (*)");
    if (!path.isEmpty()) {
        m_rsaPubKey->setText(path);
    }
}

void MainWindow::browsePrivKey() {
    QString path = QFileDialog::getOpenFileName(
        this, "Приватный ключ (PEM)", "", "PEM (*.pem);;All (*)");
    if (!path.isEmpty()) {
        m_rsaPrivKey->setText(path);
        validatePrivKey();
    }
}

void MainWindow::validatePrivKey() {
    QString path = m_rsaPrivKey->text().trimmed();
    if (path.isEmpty()) {
        m_rsaKeyStatus->setText("● Не проверен");
        m_rsaKeyStatus->setStyleSheet("color: gray;");
        return;
    }
    auto res = validatePrivateKey(path.toStdString());
    if (res.valid) {
        m_rsaKeyStatus->setText("✓ " + QString::fromStdString(res.message));
        m_rsaKeyStatus->setStyleSheet("color: green;");
    } else {
        m_rsaKeyStatus->setText("✗ Ключ не прошёл проверку");
        m_rsaKeyStatus->setStyleSheet("color: red;");
    }
}

void MainWindow::copyOutput() {
    QApplication::clipboard()->setText(m_outTextEdit->toPlainText());
}

void MainWindow::generateXorKey() {
    try {
        std::string key = ::generateXorKey(m_xorKeyLen->value());
        m_xorKey->setText(QString::fromStdString(key));
    } catch (const std::exception& ex) {
        QMessageBox::critical(this, "Ошибка", QString::fromStdString(ex.what()));
    }
}

void MainWindow::generateRsaKeys() {
    QString dir = QFileDialog::getExistingDirectory(
        this, "Выберите папку для сохранения ключей");
    if (dir.isEmpty()) {
        return;
    }
    try {
        auto pair = generateRsaKeyPair(2048);

        QString pubPath = dir + "/public.pem";
        QString privPath = dir + "/private.pem";

        QFile pubFile(pubPath);
        if (!pubFile.open(QIODevice::WriteOnly)) {
            throw std::runtime_error("Не удалось записать public.pem");
        }
        pubFile.write(pair.publicKey.data(), static_cast<qint64>(pair.publicKey.size()));

        QFile privFile(privPath);
        if (!privFile.open(QIODevice::WriteOnly)) {
            throw std::runtime_error("Не удалось записать private.pem");
        }
        privFile.write(pair.privateKey.data(), static_cast<qint64>(pair.privateKey.size()));

        m_rsaPubKey->setText(pubPath);
        m_rsaPrivKey->setText(privPath);
        validatePrivKey();

        QMessageBox::information(this, "Готово",
            "Ключи сгенерированы:\n" + pubPath + "\n" + privPath +
            "\n\n⚠ Никогда не добавляйте private.pem в git!");
    } catch (const std::exception& ex) {
        QMessageBox::critical(this, "Ошибка генерации", QString::fromStdString(ex.what()));
    }
}

void MainWindow::execute() {
    try {
        std::vector<uint8_t> inputData;

        if (m_srcText->isChecked()) {
            std::string text = m_srcTextEdit->toPlainText().toStdString();
            inputData.assign(text.begin(), text.end());
        } else if (m_srcFile->isChecked()) {
            QString path = m_srcFilePath->text().trimmed();
            if (path.isEmpty()) {
                QMessageBox::warning(this, "Ошибка", "Укажите путь к файлу источника.");
                return;
            }
            FileSource src(path.toStdString());
            inputData = src.readAll();
        } else {
            if (m_lastResult.empty()) {
                QMessageBox::warning(this, "Ошибка",
                    "Нет предыдущего результата. Сначала выполните шифрование.");
                return;
            }
            inputData = m_lastResult;
        }

        std::vector<uint8_t> result;

        if (m_algTabs->currentIndex() == 0) {
            QString key = m_xorKey->text();
            if (key.isEmpty()) {
                QMessageBox::warning(this, "Ошибка", "Введите ключ XOR.");
                return;
            }
            if (m_xorEncrypt->isChecked()) {
                result = xorEncrypt(inputData, key.toStdString());
            } else {
                result = xorDecrypt(inputData, key.toStdString());
            }
        } else {
            if (m_rsaEncrypt->isChecked()) {
                QString pub = m_rsaPubKey->text().trimmed();
                if (pub.isEmpty()) {
                    QMessageBox::warning(this, "Ошибка", "Укажите путь к публичному ключу.");
                    return;
                }
                result = rsaEncrypt(inputData, pub.toStdString());
            } else {
                QString priv = m_rsaPrivKey->text().trimmed();
                if (priv.isEmpty()) {
                    QMessageBox::warning(this, "Ошибка", "Укажите путь к приватному ключу.");
                    return;
                }
                result = rsaDecrypt(inputData, priv.toStdString());
            }
        }

        m_lastResult = result;
        updatePrevLabel();

        if (m_outGui->isChecked()) {
            m_outTextEdit->setPlainText(bytesToDisplay(result));
        } else {
            QString path = QFileDialog::getSaveFileName(
                this, "Сохранить результат", "", "Binary (*.bin);;All (*)");
            if (path.isEmpty()) {
                return;
            }
            if (!path.endsWith(".bin", Qt::CaseInsensitive)) {
                path += ".bin";
            }
            FileSink sink(path.toStdString());
            sink.write(result);
            QMessageBox::information(this, "Готово", "Файл сохранён:\n" + path);
        }
    } catch (const std::exception& ex) {
        QMessageBox::critical(this, "Ошибка", QString::fromStdString(ex.what()));
    }
}
