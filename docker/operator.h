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
    //! Chave privada do operador.
    PrivateKey *privateKey;
    //! Certificado identifica o operador (contém a chave pública e informações sobre o operador)
    Certificate *certificate;

    /**
     * Função auxiliar para gerar o certificado do operador a partir de uma chave pública.
     */
    Certificate *generateCertificate(PublicKey *publicKey);

public:
    /**
     * Construtor padrão que gerará um par de chaves RSA de 2048 bits e um certificado para o operador.
     * @param name Nome do operador.
     */
    Operator(const std::string &name);

    /**
     * Construtor alternativo para criar um operador a partir de uma chave privada e um certificado.
     * @param pckcs12 Objeto Pkcs12 contendo a chave privada e o certificado do operador.
     * @param password Senha de acesso ao pacote Pkcs12.
     */
    Operator(Pkcs12 *pkcs12, std::string password);

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
