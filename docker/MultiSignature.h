#include <iostream>
#include <string>
#include <vector>
#include <map>

#include "Operator.h"

#include <libcryptosec/ByteArray.h>

class MultiSignature
{
public:
    /**
     * Construtor padrão.
     */
    MultiSignature(ByteArray &hash);

    /**
     * Construtor que gera o objeto MultiSignature a partir de uma lista de objetos Operators.
     */
    MultiSignature(std::vector<Operator *> operators, ByteArray &hash);

    /**
     * Construtor que gera o objeto MultiSignature a partir do conteúdo de um arquivo .xml (gerado pelo método getMulsigFile())
     * @see getMulsigFile()
     * @param xmlContent String que contém o conteúdo de um arquivo .xml
     */
    MultiSignature(std::string xmlContent);

    /**
     * Destrutor.
     */
    ~MultiSignature();

    /**
     * Adiciona uma assinatura ao objeto MultiSignature a partir de um objeto Operator.
     * @param operator Objeto Operator que será utilizado para assinar o documento.
     */
    void addSignature(Operator *op);

    /**
     * Recebe uma lista de objetos Operators e verifica se todos eles assinaram o documento.
     * @param operators Lista de objetos Operators que serão verificados.
     * @param hash Hash do documento que será verificado.
     * @param checkContainsAll Se true, retornará false se a lista fornecida não contiver todos os operadores que assinaram o documento.
     * @return true se todos os operadores fornecidos possuem assinaturas válidas para o documento.
     * @return false se não foi possível verificar a assinatura de algum operador.
     */
    bool verify(std::vector<Operator *> operators, ByteArray &hash, bool checkContainsAll = false);

    /**
     * Gera uma string XML cujo conteúdo representa o objeto MultiSignature.
     * "<signer><name>Jonh Doe</name><signature>zvIvg0qoutvGG22TAffqB1Hq870bVv1nfSFifoGfBg92D...</signature></signer>" (para cada assinatura)
     * @return Retorna uma string que contém o conteúdo de um arquivo .xml que representa o objeto MultiSignature.
     */
    std::string getXmlEncoded();

private:
    //! Map para armazenar as assinaturas (chave: nome do operador, valor: assinatura)
    std::map<std::string, ByteArray> signatures;
    //! Hash do documento que será assinada
    ByteArray hash;
};