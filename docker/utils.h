#ifndef UTILS_H
#define UTILS_H

#include <fstream>
#include <string>
#include <libcryptosec/ByteArray.h>

/**
 * Gera um arquivo com o conteúdo do ByteArray.
 * @param ba ByteArray que será gravado no arquivo.
 * @param filename Nome do arquivo que será gerado.
 */
void generateFile(ByteArray &ba, std::string filename);

/**
 * Gera um arquivo com o conteúdo da string.
 * @param str String que será gravado no arquivo.
 * @param filename Nome do arquivo que será gerado.
 */
void generateFile(const std::string &str, std::string filename);

/**
 * Lê um arquivo e retorna seu conteúdo em um ByteArray.
 * @param filename Nome do arquivo que será lido.
 * @return ByteArray com o conteúdo do arquivo.
 */
ByteArray readFileToByteArray(std::string filename);

/**
 * Lê um arquivo e retorna seu conteúdo em uma string.
 * @param filename Nome do arquivo que será lido.
 * @return String com o conteúdo do arquivo.
 */
std::string readFileToString(std::string filename);

/**
 * A partir de um nome John Doe, retorna john_doe.
 * @param name Nome que será convertido.
 * @return String com o nome convertido.
 */
std::string getFilename(std::string name);

#endif // UTILS_H

void generateFile(ByteArray &ba, std::string filename)
{
    // Escreve o conteúdo do ByteArray em um arquivo
    std::ofstream file(filename.c_str(), std::ios::binary);
    unsigned char *data = ba.getDataPointer();
    file.write(reinterpret_cast<char *>(data), ba.size());
    file.close();
}

void generateFile(const std::string &str, std::string filename)
{
    // Escreve o conteúdo da string em um arquivo
    std::ofstream file(filename.c_str(), std::ios::binary);
    file.write(str.c_str(), str.size());
    file.close();
}

// Lê um arquivo e retorna seu conteúdo em um ByteArray
ByteArray readFileToByteArray(std::string filename)
{
    std::ifstream file(filename.c_str(), std::ios::binary);
    file.seekg(0, std::ios::end);
    int length = file.tellg();
    file.seekg(0, std::ios::beg);
    char *buffer = new char[length];
    file.read(buffer, length);
    file.close();
    ByteArray ba((unsigned char *)buffer, length);
    delete[] buffer;
    return ba;
}

std::string readFileToString(std::string filename)
{
    std::ifstream file(filename.c_str(), std::ios::binary);
    file.seekg(0, std::ios::end);
    int length = file.tellg();
    file.seekg(0, std::ios::beg);
    char *buffer = new char[length];
    file.read(buffer, length);
    file.close();
    std::string str(buffer, length);
    delete[] buffer;
    return str;
}

std::string getFilename(std::string name)
{
    // A partir de um nome John Doe, retorna john_doe
    std::string filename = "";
    for (std::size_t i = 0; i < name.size(); i++)
    {
        if (name[i] == ' ')
            filename += '_';
        else
            filename += std::tolower(name[i]);
    }
    return filename;
}