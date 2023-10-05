#include "operator.h"
#include <iostream>
#include <string>

#include <libcryptosec/RSAKeyPair.h>

// Certificado
#include <libcryptosec/certificate/CertificateBuilder.h>
#include <libcryptosec/certificate/Certificate.h>
#include <libcryptosec/certificate/RDNSequence.h>
#include <libcryptosec/DateTime.h>

// PKCS#12
#include <libcryptosec/Pkcs12Builder.h>

Certificate *Operator::generateCertificate()
{
    CertificateBuilder builder;                    // Instancia um objeto CertificateBuilder
    builder.setPublicKey(*keyPair.getPublicKey()); // Define a chave pública do operador como a chave pública do objeto RSAKeyPair

    // Para fins de simulação, as informações do sujeito (excluindo o nome comum) são padrões
    RDNSequence subject;
    subject.addEntry(RDNSequence::COUNTRY, "Ukraine");
    subject.addEntry(RDNSequence::STATE_OR_PROVINCE, "Chernobyl");
    subject.addEntry(RDNSequence::LOCALITY, "Chernobyl");
    subject.addEntry(RDNSequence::ORGANIZATION, "Chernobyl Nuclear Power Plant");
    subject.addEntry(RDNSequence::ORGANIZATION_UNIT, "Reactor 4");
    subject.addEntry(RDNSequence::COMMON_NAME, name);
    builder.setSubject(subject);

    // Para fins de simulação, define um emissor padrão
    RDNSequence issuer;
    issuer.addEntry(RDNSequence::COUNTRY, "Brazil");
    issuer.addEntry(RDNSequence::STATE_OR_PROVINCE, "SC");
    issuer.addEntry(RDNSequence::LOCALITY, "Florianopolis");
    issuer.addEntry(RDNSequence::ORGANIZATION, "UFSC");
    issuer.addEntry(RDNSequence::ORGANIZATION_UNIT, "INE");
    builder.setIssuer(issuer);

    // Define a data de emissão para a data atual e a data de expiração para um ano após a data atual
    DateTime notBefore(time(NULL));
    builder.setNotBefore(notBefore);
    DateTime notAfter(time(NULL) + 31536000);
    builder.setNotAfter(notAfter);

    // Define o número de série do certificado como um valor aleatório de 16 bits
    BigInteger serialNumber;
    serialNumber.setRandValue(16); // Valor aleatório de 16 bits
    builder.setSerialNumber(serialNumber);

    // Cria o certificado
    Certificate *certificate = builder.sign(*keyPair.getPrivateKey(), MessageDigest::SHA256);
    return certificate;
}

Operator::Operator(const std::string &name) : name(name), password("123456"), keyPair(2048)
{
    // Gera o certificado do operador a partir da chave pública
    certificate = generateCertificate();
    std::cout << "Operador " << name << " criado com sucesso." << std::endl; // DEBUG
};

Operator::~Operator()
{
    delete certificate;
}

std::string Operator::getName() const
{
    return name;
}

PublicKey *Operator::getPublicKey()
{
    // Extrai a chave pública do objeto RSAKeyPair
    return keyPair.getPublicKey();
}

Certificate *Operator::getCertificate()
{
    return certificate;
}

ByteArray *Operator::getPkcs12DerEncoded()
{
    Pkcs12Builder builder;
    builder.setKeyAndCertificate(keyPair.getPrivateKey(), certificate, name); // Alteração aqui
    Pkcs12 *pkcs12 = builder.doFinal(password);
    return new ByteArray(pkcs12->getDerEncoded());
}

PrivateKey *Operator::getPrivateKey()
{
    return keyPair.getPrivateKey();
}