#include <iostream>
#include <fstream>
#include <libcryptosec/Signer.h>
#include <libcryptosec/MessageDigest.h>
#include <libcryptosec/RSAKeyPair.h>
#include <libcryptosec/ByteArray.h>

int main(int argc, char *argv[])
{
    // Reads the PDF file into a ByteArray
    std::ifstream file("testfile.pdf", std::ios::binary);
    file.seekg(0, std::ios::end);
    int length = file.tellg();
    file.seekg(0, std::ios::beg);
    char *buffer = new char[length];
    file.read(buffer, length);
    file.close();
    ByteArray pdf((unsigned char *)buffer, length);
    delete[] buffer;

    // Creates a private key
    RSAKeyPair key(1024);

    // Compute the hash of the PDF content (SHA256)
    MessageDigest sha256(MessageDigest::SHA256);
    sha256.update(pdf);
    ByteArray pdfHash = sha256.doFinal();

    // Sign the hash with the private key
    ByteArray signature = Signer::sign(*key.getPrivateKey(), pdfHash, MessageDigest::SHA256);

    return 0;
}