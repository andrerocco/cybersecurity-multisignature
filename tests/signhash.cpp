#include <iostream>
#include <fstream>

#include "Operator.h"
#include "CertificateAuthority.h"
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

    Operator op1("Teste", &ca);
    Operator op2("Teste2", &ca);
    Operator op3("Teste3", &ca);

    // Hash no pdf
    MessageDigest md(MessageDigest::SHA256);
    md.update(pdf);
    ByteArray hash = md.doFinal();

    // Assina o arquivo com a chave privada do operador 1
    ByteArray signature = op1.sign(hash);
    std::string result = Base64::encode(signature);

    generateFile(result, "signature");

    std::string signatureFromFile = readFileToString("signature");
    ByteArray extracted = Base64::decode(signatureFromFile);

    // Verifica a assinatura com a chave pública do operador 1
    bool verify = Signer::verify(*op1.getPublicKey(), extracted, hash, MessageDigest::SHA256);

    // Imprime o resultado da verificação
    if (verify)
        std::cout << "Assinatura válida." << std::endl;
    else
        std::cout << "Assinatura inválida." << std::endl;

    return 0;
}
