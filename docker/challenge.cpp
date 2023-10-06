#include <iostream>
#include <fstream>

#include "Operator.h"
#include "CertificateAuthority.h"
#include "MultiSignature.h"
#include <libcryptosec/ByteArray.h>

// Test 2
#include <openssl/pem.h>
#include <libcryptosec/Signer.h>
#include <libcryptosec/MessageDigest.h>
#include <libcryptosec/Base64.h>

// Teste de geração de certificados e assinatura de arquivos
/* #include <libcryptosec/Pkcs12Factory.h>
#include <libcryptosec/PrivateKey.h>
#include <libcryptosec/Pkcs7SignedDataBuilder.h>
#include <libcryptosec/Pkcs7Factory.h> */

// Teste de certificate authority
#include <libcryptosec/certificate/RDNSequence.h>

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

// Cria o CA
CertificateAuthority getCertificateAuthorityRDN()
{
	RDNSequence caRdn;
	caRdn.addEntry(RDNSequence::COUNTRY, "BR");
	caRdn.addEntry(RDNSequence::STATE_OR_PROVINCE, "Santa Catarina");
	caRdn.addEntry(RDNSequence::LOCALITY, "Florianópolis");
	caRdn.addEntry(RDNSequence::ORGANIZATION, "UFSC");
	caRdn.addEntry(RDNSequence::ORGANIZATION_UNIT, "INE");
	caRdn.addEntry(RDNSequence::COMMON_NAME, "CA");
	return caRdn;
}

int main(int argc, char *argv[])
{
	OpenSSL_add_all_algorithms();

	// Cria o CA
	CertificateAuthority ca(getCertificateAuthorityRDN());

	ByteArray pdf = readFileToByteArray("testfile.pdf");
	MessageDigest md(MessageDigest::SHA256);
	ByteArray hash = md.doFinal(pdf);

	Operator op1("Teste", &ca);
	Operator op2("Teste2", &ca);
	Operator op3("Teste3", &ca);

	std::vector<Operator *> operators;
	operators.push_back(&op1);
	operators.push_back(&op2);
	operators.push_back(&op3);

	MultiSignature ms(operators, hash);

	bool verify = ms.verify(operators, hash);
	if (verify)
		std::cout << "Assinaturas válidas." << std::endl;
	else
		std::cout << "Assinaturas inválidas." << std::endl;

	std::vector<Operator *> operators2;
	operators2.push_back(&op1);
	operators2.push_back(&op2);

	verify = ms.verify(operators2, hash);
	if (verify)
		std::cout << "Assinaturas válidas." << std::endl;
	else
		std::cout << "Assinaturas inválidas." << std::endl;

	Operator op4("Teste4", &ca);
	operators2.push_back(&op4);

	verify = ms.verify(operators2, hash);
	if (verify)
		std::cout << "Assinaturas válidas." << std::endl;
	else
		std::cout << "Assinaturas inválidas." << std::endl;

	std::string *mulsig = ms.getMulsigFile();
	std::cout << *mulsig << std::endl;

	return 0;
}
