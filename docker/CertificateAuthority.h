#ifndef CERTIFICATE_AUTHORITY_H
#define CERTIFICATE_AUTHORITY_H

#include <libcryptosec/certificate/RDNSequence.h>
#include <libcryptosec/certificate/Certificate.h>
#include <libcryptosec/PrivateKey.h>
#include <libcryptosec/PublicKey.h>

class CertificateAuthority
{
private:
    //! Informações sobre a autoridade certificadora.
    RDNSequence information;
    //! Chave privada da autoridade certificadora.
    PrivateKey *privateKey;
    //! Certificado da autoridade certificadora (nessa implementação, é sempre um certificado raiz).
    Certificate *certificate;
    //! Lista de certificados emitidos pela autoridade certificadora.
    std::vector<Certificate *> certificateList;

public:
    /**
     * Construtor padrão que gera um par de chaves RSA de 2048 bits.
     */
    CertificateAuthority(RDNSequence information);

    /**
     * Destrutor.
     */
    ~CertificateAuthority();

    /**
     * Emite um certificado para uma chave pública.
     * @param publicKey Chave pública para a qual o certificado será emitido.
     * @param information Informações sobre o sujeito do certificado no formato RDNSequence.
     */
    Certificate *issueCertificate(PublicKey *publicKey, RDNSequence subject);

    /**
     * Verifica se um certificado é válido (não expirado e emitido pela autoridade certificadora).
     * @param certificate Certificado a ser verificado.
     * @return true se o certificado é válido, false caso contrário.
     */
    bool verifyCertificate(Certificate *certificate);

    /**
     * @return RDNSequence contendo as informações sobre a autoridade certificadora.
     */
    RDNSequence getInformation();

    /**
     * @return Certificado da autoridade certificadora.
     */
    Certificate *getRootCertificate();
};

#endif // CERTIFICATE_AUTHORITY_H
