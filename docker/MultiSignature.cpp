#include "MultiSignature.h"

#include <vector>
#include <stack>

#include <libcryptosec/Signer.h>

MultiSignature::MultiSignature(std::vector<Operator *> operators, ByteArray &hash)
{
    for (std::size_t i = 0; i < operators.size(); i++)
    {
        // Assina o hash com a chave privada do operador
        ByteArray signature = operators[i]->sign(hash);

        // Insere a assinatura no mapa
        signatures.insert(std::make_pair(operators[i]->getName(), signature));
    }
}

MultiSignature::MultiSignature(std::string mulsigFile)
{
    std::stack<std::string> stack;
    std::string line;
    std::string name;
    std::string signature;

    // Separa o conteúdo do arquivo em linhas
    std::stringstream ss(mulsigFile);
    while (std::getline(ss, line, '\n'))
    {
        // Se a linha for vazia, pula para a próxima
        if (line.empty())
            continue;

        // Se a linha for -----BEGIN SIGNER-----, empilha
        if (line.compare("-----BEGIN SIGNER-----") == 0)
        {
            stack.push(line);
            continue;
        }

        // Se a linha for -----END SIGNER-----, desempilha
        if (line.compare("-----END SIGNER-----") == 0)
        {
            stack.pop();
            continue;
        }

        // Se a linha for -----BEGIN NAME-----, empilha
        if (line.compare("-----BEGIN NAME-----") == 0)
        {
            stack.push(line);
            continue;
        }

        // Se a linha for -----END NAME-----, desempilha
        if (line.compare("-----END NAME-----") == 0)
        {
            stack.pop();
            continue;
        }

        // Se a linha for -----BEGIN SIGNATURE-----, empilha
        if (line.compare("-----BEGIN SIGNATURE-----") == 0)
        {
            stack.push(line);
            continue;
        }

        // Se a linha for -----END SIGNATURE-----, desempilha
        if (line.compare("-----END SIGNATURE-----") == 0)
        {
            stack.pop();
            continue;
        }

        // Se a linha for o nome do operador, armazena
        if (stack.top().compare("-----BEGIN NAME-----") == 0)
        {
            name = line;
            continue;
        }

        // Se a linha for a assinatura do operador, armazena
        if (stack.top().compare("-----BEGIN SIGNATURE-----") == 0)
        {
            signature = line;
            continue;
        }
    }

    // Insere o nome e a assinatura no mapa
    signatures.insert(std::make_pair(name, Base64::decode(signature)));
}

MultiSignature::~MultiSignature()
{
}

bool MultiSignature::verify(std::vector<Operator *> toVerify, ByteArray &hash)
{
    std::size_t toVerifyAmount = toVerify.size();
    std::size_t countVerified = 0;

    for (std::size_t i = 0; i < toVerifyAmount; i++) // Para cada operador
    {
        // Verifica se o nome do operador está no mapa
        std::map<std::string, ByteArray>::iterator it = signatures.find(toVerify[i]->getName());
        if (it != signatures.end()) // Se encontrou o nome do operador
        {
            // Verifica a assinatura com a chave pública do operador fornecido
            bool verify = Signer::verify(*toVerify[i]->getPublicKey(), it->second, hash, MessageDigest::SHA256);
            // Valida o certificado do operador com CA
            // bool verifyCertificate = toVerify[i]->getCertificate()->verify(*ca->getCertificate());
            if (!verify)
                return false;
            else
                countVerified++;
        }
        else // Se não encontrou o nome do operador, retorna false
            return false;
    }

    // Se a quantidade de assinaturas verificadas for diferente da quantidade de assinaturas no mapa (no caso de faltar
    // alguma assinatura na lista fornecida), retorna false
    if (countVerified != signatures.size())
        return false;

    return true;
}

std::string *MultiSignature::getMulsigFile()
{
    /*
    Cria um arquivo com a seguinte estrutura:
    -----BEGIN SIGNER-----
    -----BEGIN NAME-----
    Jonh Doe
    -----END NAME-----
    -----BEGIN SIGNATURE-----
    zvIvg0qoutvGG22TAffqB1Hq870bVv1nfSFifoGfBg92D...
    -----END SIGNATURE-----
    -----END SIGNER-----
    */

    std::string *mulsig = new std::string();

    // Para cada assinatura no mapa
    for (std::map<std::string, ByteArray>::iterator it = signatures.begin(); it != signatures.end(); it++)
    {
        mulsig->append("-----BEGIN SIGNER-----\n");

        // Insere o nome do operador
        mulsig->append("-----BEGIN NAME-----\n");
        mulsig->append(it->first);
        mulsig->append("\n-----END NAME-----\n");

        // Insere a assinatura
        mulsig->append("-----BEGIN SIGNATURE-----\n");
        mulsig->append(Base64::encode(it->second));
        mulsig->append("\n-----END SIGNATURE-----\n");

        mulsig->append("-----END SIGNER-----\n\n");
    }

    return mulsig;
}