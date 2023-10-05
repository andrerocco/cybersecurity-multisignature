#ifndef OPERATOR_H
#define OPERATOR_H

#include <iostream>
#include <string>

#include <libcryptosec/RSAKeyPair.h>
#include <libcryptosec/certificate/Certificate.h>
#include <libcryptosec/Pkcs12.h>

/**
 * @brief Representa um operador.
 */
class Operator
{
private:
    //! Nome do operador.
    std::string name;
    //! Senha do operador.
    std::string password;
    //! RSAKeyPair que contém as chaves pública e privada do operador.
    RSAKeyPair keyPair;
    //! Certificado identifica o operador.
    Certificate *certificate;

    /**
     * Função auxiliar para gerar o certificado do operador a partir de uma chave pública.
     */
    Certificate *generateCertificate();

public:
    /**
     * Construtor.
     * @param name Nome do operador.
     */
    Operator(const std::string &name);

    /**
     * Destrutor.
     */
    ~Operator();

    /**
     * @return Nome do operador.
     */
    std::string getName() const;

    /**
     * @return Chave pública do operador.
     */
    PublicKey *getPublicKey();

    /**
     * @return Certificado do operador.
     */
    Certificate *getCertificate();

    /**
     * @return
     */
    ByteArray *getPkcs12DerEncoded();

    PrivateKey *getPrivateKey();

    /**
     * @param Pkcs7Builder Objeto Pkcs7SignerBuilder o qual o operador irá assinar.
     */
    // void sign(Pkcs7SignerBuilder &builder);
};

#endif // OPERATOR_H
