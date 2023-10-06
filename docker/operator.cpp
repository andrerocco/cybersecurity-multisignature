#include "Operator.h"
#include <iostream>
#include <string>

#include <libcryptosec/RSAKeyPair.h>

// Certificado
#include "CertificateAuthority.h"
#include <libcryptosec/certificate/Certificate.h>
#include <libcryptosec/certificate/RDNSequence.h>

// Assinatura
#include <libcryptosec/Signer.h>

// PKCS#12
#include <libcryptosec/Pkcs12Builder.h>

Operator::Operator(std::string name, std::string password, CertificateAuthority *ca) : name(name), password(password)
{
    // Gera um par de chaves RSA de 2048 bits
    RSAKeyPair keyPair(2048);
    privateKey = keyPair.getPrivateKey();
    publicKey = keyPair.getPublicKey();

    // Para fins de simulação, as informações do sujeito (excluindo o nome comum) são padrões
    RDNSequence subject;
    subject.addEntry(RDNSequence::COUNTRY, "Ukraine");
    subject.addEntry(RDNSequence::STATE_OR_PROVINCE, "Chernobyl");
    subject.addEntry(RDNSequence::LOCALITY, "Chernobyl");
    subject.addEntry(RDNSequence::ORGANIZATION, "Chernobyl Nuclear Power Plant");
    subject.addEntry(RDNSequence::ORGANIZATION_UNIT, "Reactor 4");
    subject.addEntry(RDNSequence::COMMON_NAME, name);

    // Gera o certificado do operador a partir da chave pública
    certificate = ca->issueCertificate(publicKey, subject);
    std::cout << "Operador(a) '" << name << "' criado(a) com sucesso." << std::endl; // DEBUG
};

Operator::Operator(Pkcs12 *pkcs12, std::string password) : password(password)
{
    // Obtém a chave privada e o certificado do pacote Pkcs12
    try
    {
        privateKey = pkcs12->getPrivKey(password);
        certificate = pkcs12->getCertificate(password);
    }
    catch (Pkcs12Exception &e)
    {
        std::cout << "Erro ao obter a chave privada do pacote Pkcs12 (a senha fornecida pode estar incorreta)." << std::endl;
        std::cout << e.what() << std::endl;
        exit(1);
    }

    name = certificate->getSubject().getEntries(RDNSequence::COMMON_NAME)[0];
    std::cout << "Operador(a) '" << name << "' criado(a) com sucesso." << std::endl; // DEBUG
}

Operator::~Operator()
{
    delete certificate;
}

ByteArray Operator::sign(ByteArray &hash)
{
    return Signer::sign(*privateKey, hash, MessageDigest::SHA256);
}

std::string Operator::getName() const
{
    return name;
}

PublicKey *Operator::getPublicKey()
{
    return publicKey;
}

Certificate *Operator::getCertificate()
{
    return certificate;
}

ByteArray *Operator::getPkcs12DerEncoded()
{
    OpenSSL_add_all_algorithms(); // Carrega os algoritmos de hash para evitar exceção ao chamar as funções de PKCS12 do OpenSSL

    Pkcs12Builder builder;
    builder.setKeyAndCertificate(privateKey, certificate, name);
    Pkcs12 *pkcs12 = builder.doFinal(password);
    return new ByteArray(pkcs12->getDerEncoded());
}

PrivateKey *Operator::getPrivateKey()
{
    return privateKey;
}