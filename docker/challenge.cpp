#include <iostream>
#include <fstream>

#include "operator.h"
#include <libcryptosec/ByteArray.h>

#include <libcryptosec/Pkcs12Factory.h>
#include <libcryptosec/PrivateKey.h>
#include <libcryptosec/Pkcs7SignedDataBuilder.h>

void generateFile(ByteArray &ba, std::string filename)
{
	// Escreve o conteúdo do ByteArray em um arquivo
	std::ofstream file(filename.c_str(), std::ios::binary);
	unsigned char *data = ba.getDataPointer();
	file.write(reinterpret_cast<char *>(data), ba.size());
	file.close();
}

// Lê um arquivo e retorna seu conteúdo em um ByteArray
ByteArray readFile(std::string filename)
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

int main(int argc, char *argv[])
{
	OpenSSL_add_all_algorithms();

	ByteArray pdf = readFile("testfile.pdf");

	Operator op1("Teste");
	Operator op2("Teste2");

	// Gera um pacote Pkcs7
	Pkcs7SignedDataBuilder builder(MessageDigest::SHA256, *op1.getCertificate(), *op1.getPrivateKey(), true);
	builder.addSigner(MessageDigest::SHA256, *op2.getCertificate(), *op2.getPrivateKey());

	Pkcs7SignedData *final = builder.doFinal(pdf);

	// Libera a memória alocada
	delete final;

	return 0;
}
