#include <iostream>
#include <fstream>

#include <libcryptosec/Pkcs12Builder.h>
#include <libcryptosec/Pkcs12.h>
#include <libcryptosec/RSAKeyPair.h>
#include <libcryptosec/certificate/CertificateBuilder.h>
#include <libcryptosec/certificate/Certificate.h>

int main(int argc, char *argv[])
{
    // Corrige erros causados pelo uso de algoritmos descontinuados do OpenSSL
    OpenSSL_add_all_algorithms();

    RSAKeyPair keyPair(1024);

    CertificateBuilder cb;
    cb.setSerialNumber(1);
    // cb.setVersion(3);

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

    Pkcs12Builder pkcs12Builder;
    std::string name = "Teste";
    pkcs12Builder.setKeyAndCertificate(keyPair.getPrivateKey(), cert, name);

    std::string password = "asjdhasjkd7812y3gjhasbd";
    Pkcs12 *pkcs12 = pkcs12Builder.doFinal(password);
}
