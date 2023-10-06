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
    MultiSignature(std::vector<Operator *> operators, ByteArray &hash);

    /**
     * Construtor que gera o objeto MultiSignature a partir de um conteúdo de um arquivo .mulsig
     * @see getMulsigFile()
     * @param mulsigFile String contendo o conteúdo do arquivo .mulsig
     */
    MultiSignature(std::string mulsigFile);

    /**
     * Destrutor.
     */
    ~MultiSignature();

    /**
     * Recebe uma lista de objetos Operators e verifica se todos eles assinaram o documento.
     * @return true se todos os operadores fornecidos possuem assinaturas válidas para o documento.
     * @return false se não foi possível verificar a assinatura de algum operador.
     * @return false se todos os operadores fornecidos possuem assinaturas válidas, mas a lista fornecida falta algum operador que assinou o documento.
     */
    bool verify(std::vector<Operator *> operators, ByteArray &hash);

    /**
     * @return Retorna uma string que contém o conteúdo de um arquivo .mulsig.
     */
    std::string *getMulsigFile();

private:
    //! Map para armazenar as assinaturas (chave: nome do operador, valor: assinatura)
    std::map<std::string, ByteArray> signatures;
};