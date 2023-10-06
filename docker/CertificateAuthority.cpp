#include "CertificateAuthority.h"

#include <libcryptosec/RSAKeyPair.h>
#include <libcryptosec/certificate/CertificateBuilder.h>
#include <libcryptosec/DateTime.h>

CertificateAuthority::CertificateAuthority(RDNSequence information) : information(information)
{
    // Gera um par de chaves RSA de 2048 bits
    RSAKeyPair keyPair(2048);
    privateKey = keyPair.getPrivateKey();

    // Gera um certificado auto-assinado
    CertificateBuilder builder;
    builder.setPublicKey(*keyPair.getPublicKey());
    builder.setIssuer(information);
    builder.setSubject(information);

    // Define a data de emissão para a data atual
    DateTime notBefore(time(NULL));
    builder.setNotBefore(notBefore);
    /* DateTime notAfter(time(NULL) + 63072000);
    builder.setNotAfter(notAfter); */

    // Define um Serial Number aleatório de 16 bits
    BigInteger serialNumber;
    serialNumber.setRandValue(16);
    builder.setPublicKey(*keyPair.getPublicKey());

    certificate = builder.sign(*privateKey, MessageDigest::SHA256);
}

CertificateAuthority::~CertificateAuthority()
{
    delete privateKey;
    delete certificate;
}

Certificate *CertificateAuthority::issueCertificate(PublicKey *publicKey, RDNSequence subject)
{
    CertificateBuilder builder;
    builder.setPublicKey(*publicKey);
    builder.setIssuer(information);
    builder.setSubject(subject);

    // Define a data de emissão para a data atual e a data de expiração para 1 ano após a atual
    DateTime notBefore(time(NULL));
    builder.setNotBefore(notBefore);
    DateTime notAfter(time(NULL) + 31536000);
    builder.setNotAfter(notAfter);

    // Define um Serial Number aleatório de 16 bits
    BigInteger serialNumber;
    serialNumber.setRandValue(16);
    builder.setSerialNumber(serialNumber);

    Certificate *certificate = builder.sign(*privateKey, MessageDigest::SHA256);
    certificateList.push_back(certificate);

    // std::cout << "Certificado emitido com sucesso." << std::endl; // DEBUG

    return certificate;
}

bool CertificateAuthority::verifyCertificate(Certificate *certificate)
{
    // Verifica se o certificado foi emitido pela autoridade certificadora
    if (certificate->verify(*this->certificate->getPublicKey()) == true)
        return true;
    return false;
}

RDNSequence CertificateAuthority::getInformation()
{
    return information;
}

Certificate *CertificateAuthority::getRootCertificate()
{
    return certificate;
}