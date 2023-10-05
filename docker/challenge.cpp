#include <iostream>
#include <fstream>

#include "operator.h"
#include <libcryptosec/ByteArray.h>

#include <libcryptosec/Pkcs12Factory.h>
#include <libcryptosec/PrivateKey.h>

void generateFile(ByteArray &ba, std::string filename)
{
	// Escreve o conteúdo do ByteArray em um arquivo
	std::ofstream file(filename.c_str(), std::ios::binary);
	unsigned char *data = ba.getDataPointer();
	file.write(reinterpret_cast<char *>(data), ba.size());
	file.close();
}

int main(int argc, char *argv[])
{
	OpenSSL_add_all_algorithms();

	Operator op1("Teste");
	ByteArray *ba1 = op1.getPkcs12DerEncoded();

	std::string filename = op1.getName() + ".p12";

	generateFile(*ba1, filename);

	// Lê o arquivo criado e carrega o conteúdo em um ByteArray
	std::ifstream file(filename.c_str(), std::ios::binary);
	file.seekg(0, std::ios::end);
	int length = file.tellg();
	file.seekg(0, std::ios::beg);
	char *buffer = new char[length];
	file.read(buffer, length);
	file.close();
	ByteArray ba2((unsigned char *)buffer, length);
	delete[] buffer;

	// Cria um objeto Pkcs12 a partir do conteúdo do arquivo
	Pkcs12 *op1Pkcs12 = Pkcs12Factory::fromDerEncoded(ba2);

	// Obtém a chave do pacote lido e compara com a chave original
	PrivateKey *pk = op1Pkcs12->getPrivKey("123456");

	// Compara o getPemEncoded das duas chaves
	if (pk->getPemEncoded() == op1.getPrivateKey()->getPemEncoded())
		std::cout << "OK" << std::endl;
	else
		std::cout << "FAIL" << std::endl;

	// Cria um novo operador a partir do pacote lido
	std::string password = "123456";
	Operator op2(op1Pkcs12, password);
}
