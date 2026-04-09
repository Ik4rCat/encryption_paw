#include <iostream>
#include <fstream>

using namespace std;

void xorEncryptDecrypt(const string &inputFile, const string &outputFile, const string &key)
{
    ifstream in(inputFile, ios::binary);
    ofstream out(outputFile, ios::binary);

    if (!in || !out)
    {
        cout << "Ошибка открытия файла\n";
        return;
    }

    char ch;

    for (int i = 0; in.get(ch); i++)
    {
        char encrypted = ch ^ key[i % key.size()];
        out.put(encrypted);
    }

    in.close();
    out.close();
}

int main()
{
    int choice;

    cout << "1 - XOR Шифрование\n";
    cout << "2 - XOR Дешифрование\n";
    cout << "Выбор: ";
    cin >> choice;

    string inFile, outFile;

    if (choice == 1 || choice == 2)
    {
        string key;

        cout << "Файл входных данных: ";
        cin >> inFile;

        cout << "Файл выходных данных: ";
        cin >> outFile;

        cout << "Key: ";
        cin >> key;

        xorEncryptDecrypt(inFile, outFile, key);
    }
    else
    {
        cout << "Неверный выбор\n";
    }

    return 0;
}