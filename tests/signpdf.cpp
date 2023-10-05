#include <iostream>
#include <fstream>
#include <libcryptosec/Signer.h>
#include <libcryptosec/MessageDigest.h>
#include <libcryptosec/RSAKeyPair.h>
#include <libcryptosec/ByteArray.h>

int main(int argc, char *argv[]) {
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

	// Write the signature to a file with a proper extension (e.g., ".bin")
    std::ofstream signatureFile("signature.bin", std::ios::binary);
    unsigned char *data = signature.getDataPointer();
	signatureFile.write(reinterpret_cast<char *>(data), signature.size());
	signatureFile.close();

	// Now let's open the signature file and verify the signature
	std::ifstream signatureFile2("signature.bin", std::ios::binary);
	signatureFile2.seekg(0, std::ios::end);
	int length2 = signatureFile2.tellg();
	signatureFile2.seekg(0, std::ios::beg);
	char *buffer2 = new char[length2];
	signatureFile2.read(buffer2, length2);
	signatureFile2.close();
	ByteArray signature2((unsigned char *)buffer2, length2);
	delete[] buffer2;

	// Verify the signature
	bool result = Signer::verify(*key.getPublicKey(), signature2, pdfHash, MessageDigest::SHA256);
	if (result) {
		std::cout << "Signature is valid" << std::endl;
	} else {
		std::cout << "Signature is invalid" << std::endl;
	}

	return 0;
}
