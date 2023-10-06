#include <vector>

#include "MultiSignature.h"
#include <libcryptosec/Signer.h>

MultiSignature::MultiSignature(ByteArray &hash) : hash(hash)
{
}

MultiSignature::MultiSignature(std::vector<Operator *> operators, ByteArray &hash) : hash(hash)
{
    for (std::size_t i = 0; i < operators.size(); i++)
    {
        // Assina o hash com a chave privada do operador
        ByteArray signature = operators[i]->sign(hash);

        // Insere a assinatura no mapa
        signatures.insert(std::make_pair(operators[i]->getName(), signature));
    }
}

MultiSignature::MultiSignature(std::string xmlContent)
{
    size_t pos = 0;

    while ((pos = xmlContent.find("<signer>", pos)) != std::string::npos)
    {
        // Verifica se a tag <name> está presente
        size_t nameStart = xmlContent.find("<name>", pos);
        if (nameStart == std::string::npos)
            throw std::runtime_error("Tag <name> não encontrada.");

        nameStart += 6; // Pula <name>
        size_t nameEnd = xmlContent.find("</name>", nameStart);
        if (nameEnd == std::string::npos)
            throw std::runtime_error("Tag de fechamento </name> não encontrada.");

        // Extrai o conteúdo da tag <name>
        std::string name = xmlContent.substr(nameStart, nameEnd - nameStart);

        // Verifica se a tag <signature> está presente
        size_t sigStart = xmlContent.find("<signature>", pos);
        if (sigStart == std::string::npos)
            throw std::runtime_error("Tag <signature> não encontrada.");

        sigStart += 11; // Pula <signature>
        size_t sigEnd = xmlContent.find("</signature>", sigStart);
        if (sigEnd == std::string::npos)
            throw std::runtime_error("Tag de fechamento </signature> não encontrada.");

        // Extrai o conteúdo da tag <signature>
        std::string signature = xmlContent.substr(sigStart, sigEnd - sigStart);

        // Insere a assinatura no mapa
        signatures.insert(std::make_pair(name, Base64::decode(signature)));

        // std::cout << "Name: " << name << std::endl;
        // std::cout << "Signature: " << signature << std::endl;

        // Move a posição para o próximo
        pos = sigEnd + 12; // Pula </signature>
    }
}

MultiSignature::~MultiSignature()
{
}

void MultiSignature::addSignature(Operator *op)
{
    // Assina o hash com a chave privada do operador
    ByteArray signature = op->sign(hash);

    // Insere a assinatura no mapa
    signatures.insert(std::make_pair(op->getName(), signature));
}

bool MultiSignature::verify(std::vector<Operator *> toVerify, ByteArray &hash, bool checkContainsAll)
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
    // alguma assinatura na lista fornecida), retorna false (a menos que checkContainsAll seja false)
    if (checkContainsAll && countVerified != signatures.size())
        return false;

    return true;
}

std::string MultiSignature::getXmlEncoded()
{
    /*
    Cria uma string no formato XML com a seguinte estrutura:
    <signer><name>Jonh Doe</name><signature>zvIvg0qoutvGG22TAffqB1Hq870bVv1nfSFifoGfBg92D...</signature></signer>
    <signer><name>Alice May</name><signature>zvIvg0qoutvGG22TAffqB1Hq870bVv1nfSFifoGfBg92D...</signature></signer>
    */

    std::string string;
    string = "<?xml version=\"1.0\"?>\n";

    // Para cada assinatura no mapa
    for (std::map<std::string, ByteArray>::iterator it = signatures.begin(); it != signatures.end(); it++)
    {
        string += "<signer>";

        // Insere o nome do operador
        string += "<name>";
        string += it->first;
        string += "</name>";

        // Insere a assinatura
        string += "<signature>";
        string += Base64::encode(it->second);
        string += "</signature>";

        string += "</signer>";

        if (it != --signatures.end()) // Se não for a última assinatura, insere linha em branco
            string += "\n";
    }

    return string;
}