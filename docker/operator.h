#ifndef OPERATOR_H
#define OPERATOR_H

#include <iostream>
#include <string>

#include "CertificateAuthority.h"
#include <libcryptosec/PrivateKey.h>
#include <libcryptosec/PublicKey.h>
#include <libcryptosec/certificate/Certificate.h>
#include <libcryptosec/Pkcs7SignedDataBuilder.h>
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
    //! Chave pública do operador.
    PublicKey *publicKey;
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
     * @param password Senha de acesso ao pacote Pkcs12.
     * @param ca Referência para a autoridade certificadora que irá emitir o certificado do operador.
     */
    Operator(std::string name, std::string password, CertificateAuthority *ca);

    /**
     * Construtor que gera o operador a partir um pacote Pkcs12 (contendo a chave privada e o certificado do operador).
     * @param pckcs12 Objeto Pkcs12 contendo a chave privada e o certificado do operador.
     * @param password Senha de acesso ao pacote Pkcs12.
     */
    Operator(Pkcs12 *pkcs12, std::string password);

    /**
     * Destrutor.
     */
    ~Operator();

    /**
     * Assina um hash com a chave privada do operador.
     * @param hash Hash a ser assinado.
     * @return ByteArray contendo a assinatura.
     */
    ByteArray sign(ByteArray &hash);

    /**
     * Constroi um pacote Pkcs7 e o inicializa com as informações do operador. Método normalmente utilizado para iniciar
     * a construção de um pacote Pkcs7 para posteriormente ser assinado por outros operadores.
     * @return Pkcs7SignedDataBuilder
     * @param attached Se true, o conteúdo do pacote estará contido no mesmo, caso contrário apenas a assinatura do conteúdo estará presente.
     * @see Pckcs7SignedDataBuilder
     */
    // Pkcs7SignedDataBuilder *generatePkcs7(bool attached); // TODO - Remove

    /**
     * Assina um pacote Pkcs7.
     * @param builder Endereço do objeto Pkcs7SignedDataBuilder o qual o operador irá assinar.
     */
    // void signPkcs7(Pkcs7SignedDataBuilder &builder); // TODO - Remove

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
     * @return Pacote Pkcs12 gerado a partir da chave privada, certificado e senha do operador.
     */
    ByteArray *getPkcs12DerEncoded();

    PrivateKey *getPrivateKey(); // TODO - Remove
};

#endif // OPERATOR_H
