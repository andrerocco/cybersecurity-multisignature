#include <iostream>
#include <fstream>
#include <string>

#include "utils.h"
#include "Operator.h"
#include "CertificateAuthority.h"
#include "MultiSignature.h"

#include <libcryptosec/ByteArray.h>
#include <libcryptosec/MessageDigest.h>
#include <libcryptosec/certificate/RDNSequence.h>

bool getConfirmation(std::string message)
{
	std::cout << "> " << message << " (s/n): ";
	char c;
	std::cin >> c;
	return c == 's' || c == 'S';
}

CertificateAuthority getCertificateAuthorityRDN()
{
	// Para fins de simulação, as informações do CA são padrões
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
	if (argc != 2) // Confere se o número de argumentos é válido
	{
		std::cerr << "Erro: número de argumentos inválido\n";
		std::cerr << "Uso: " << argv[0] << " <pdf_file_path>\n";
		return 1;
	}

	MessageDigest::loadMessageDigestAlgorithms(); // Carrega os algoritmos de hash

	// Extrai o caminho do arquivo e tenta abri-lo
	std::string inputPath = argv[1];
	ByteArray pdf;
	try
	{
		pdf = readFileToByteArray(inputPath);
		std::cout << "Arquivo " << inputPath << " aberto com sucesso\n";
	}
	catch (std::exception &e)
	{
		std::cerr << "Não foi possível abrir o arquivo '" << inputPath << "'\n";
		std::cerr << "> Erro: " << e.what() << "\n";
		return 1;
	}

	// Gera o hash do arquivo
	MessageDigest md(MessageDigest::SHA256);
	ByteArray hash = md.doFinal(pdf);

	// Cria o CA
	CertificateAuthority authority(getCertificateAuthorityRDN());

	// Cria alguns operadores de exemplo
	Operator op1("John Doe", "123456", &authority);
	Operator op2("Jane Smith", "123456", &authority);
	Operator op3("Martin Fowler", "123456", &authority);
	Operator op4("Robert Martin", "123456", &authority);
	Operator op5("Kent Beck", "123456", &authority);

	std::vector<Operator *> operators;
	operators.push_back(&op1);
	operators.push_back(&op2);
	operators.push_back(&op3);
	operators.push_back(&op4);
	operators.push_back(&op5);

	// Cria o objeto MultiSignature inicializando-o com o hash do arquivo
	MultiSignature ms(hash);

	// Para cada um dos operadores, simula a assinatura do documento confirmando com o usuário
	for (std::size_t i = 0; i < operators.size(); i++)
	{
		bool shouldSign = getConfirmation("Assinar com " + operators[i]->getName() + "?");
		if (shouldSign)
			ms.addSignature(operators[i]);
		// Seria possível verificar se o acordo não foi satisfeito aqui, mas para fins de simulação será feito com
		// o método verify() de MultiSignature
	}

	// Verifica se todos os operadores assinaram o documento
	bool agreementSatisfied = ms.verify(operators, hash, &authority, true);
	if (agreementSatisfied)
		std::cout << "Acordo realizado com sucesso! Foi possível verificar a assinatura de todos os operadores.\n";
	else
	{
		std::cout << "Não foi possível chegar em um acordo. Não foi possível verificar assinaturas de todos os operadores.\n";
		return 1;
	}

	/*
	Para simular a recuperação do programa, vamos salvar todos os operadores em um arquivo .p12 e salvar o objeto
	MultiSignature em um arquivo .xml
	*/
	std::cout << "Gravando operadores e assinaturas em arquivos...\n";

	// Salva os operadores em um arquivo .p12
	for (std::size_t i = 0; i < operators.size(); i++)
	{
		ByteArray *p12 = operators[i]->getPkcs12DerEncoded();
		generateFile(*p12, "operator_" + getFilename(operators[i]->getName()) + ".p12");
		delete p12;
	}

	// Salva o objeto MultiSignature em um arquivo .xml
	std::string xml = ms.getXmlEncoded();
	generateFile(xml, "signatures.xml");

	return 0;
}
