// #include <libcryptosec/MessageDigest.h>
// #include <libcryptosec/RSAKeyPair.h>
#include <stdio.h>
#include <iostream>
#include "operator.h"

int main(int argc, char *argv[])
{
	if (argc != 2)
	{
		std::cerr << "Usage: " << argv[0] << " <pdf_file_path>\n";
		return 1;
	}

	// Extract the path from the argument
	/* std::string inputPath = argv[1];
	std::cout << "Input path: " << inputPath << "\n"; */

	std::string message = "Hello, world!";

	// Instantiate an Operator object
	Operator op("John Doe");

	return 0;
}
