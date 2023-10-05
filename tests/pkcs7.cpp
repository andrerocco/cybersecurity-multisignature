#include <iostream>
#include <fstream>

#include "operator.h"
#include <libcryptosec/Pkcs7SignedDataBuilder.h>
#include <libcryptosec/Pkcs7SignedData.h>
#include <libcryptosec/RSAKeyPair.h>
#include <libcryptosec/certificate/CertificateBuilder.h>
#include <libcryptosec/certificate/CertificateRevocationListBuilder.h>
#include <libcryptosec/certificate/RDNSequence.h>
#include <libcryptosec/DateTime.h>

int main(int argc, char *argv[])
{
    OpenSSL_add_all_algorithms();

    // Reads the PDF file into a ByteArray
    std::ifstream file("testfile.pdf", std::ios::binary);
    file.seekg(0, std::ios::end);
    int length = file.tellg();
    file.seekg(0, std::ios::beg);
    char *buffer = new char[length];
    file.read(buffer, length);
    file.close();
    ByteArray pdf((unsigned char *)buffer, length);
    delete[] buffer;

    RSAKeyPair keyPair(2048);

    CertificateBuilder cb;
    cb.setSerialNumber(1);
    cb.setVersion(3);

    RDNSequence subject;
    subject.addEntry(RDNSequence::COUNTRY, "BR");
    subject.addEntry(RDNSequence::STATE_OR_PROVINCE, "SP");
    subject.addEntry(RDNSequence::LOCALITY, "Sao Paulo");
    subject.addEntry(RDNSequence::ORGANIZATION, "Teste");
    subject.addEntry(RDNSequence::ORGANIZATION_UNIT, "Teste");
    subject.addEntry(RDNSequence::COMMON_NAME, "Teste");
    cb.setSubject(subject);

    RDNSequence issuer;
    issuer.addEntry(RDNSequence::COUNTRY, "BR");
    issuer.addEntry(RDNSequence::STATE_OR_PROVINCE, "SP");
    issuer.addEntry(RDNSequence::LOCALITY, "Sao Paulo");
    issuer.addEntry(RDNSequence::ORGANIZATION, "Teste");
    issuer.addEntry(RDNSequence::ORGANIZATION_UNIT, "Teste");
    issuer.addEntry(RDNSequence::COMMON_NAME, "Teste");
    cb.setIssuer(issuer);

    DateTime dt;
    cb.setNotAfter(dt);
    cb.setNotBefore(dt);
    cb.setPublicKey(*keyPair.getPublicKey());
    cb.setIncludeEcdsaParameters(false);

    // Certificate *CertificateBuilder::sign(PrivateKey &privateKey, MessageDigest::Algorithm messageDigestAlgorithm)
    Certificate *cert = cb.sign(*keyPair.getPrivateKey(), MessageDigest::SHA256);

    // Cria um CRL de teste
    CertificateRevocationListBuilder crlBuilder;
    crlBuilder.setSerialNumber(1);
    crlBuilder.setVersion(2);
    crlBuilder.setIssuer(issuer);
    crlBuilder.setLastUpdate(dt);
    crlBuilder.setNextUpdate(dt);

    CertificateRevocationList *crl = crlBuilder.sign(*keyPair.getPrivateKey(), MessageDigest::SHA256);

    Pkcs7SignedDataBuilder builder(MessageDigest::SHA256, *cert, *keyPair.getPrivateKey(), true);
    // builder.init(MessageDigest::SHA256, *cert, *keyPair.getPrivateKey(), true);

    builder.addCertificate(*cert);
    builder.addSigner(MessageDigest::SHA256, *cert, *keyPair.getPrivateKey());
    builder.addCrl(*crl);

    Pkcs7SignedData *pkcs7 = builder.doFinal(pdf);
}
