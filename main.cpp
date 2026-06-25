#include <iostream>
#include <openssl/ts.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <fstream>
#include <iomanip>

int main(const int argc, char *argv[]) {
    if (argc == 1) {
        std::cerr << "Error: Not enough args" << std::endl;
        std::cerr << "Usage: " << argv[0] << " filename" << std::endl;
        return 1;
    }

    if (std::ifstream file(argv[1], std::ios::in|std::ios::binary|std::ios::ate); file.is_open())
    {
        const std::streampos size = file.tellg();
        auto *memblock = new char [size];
        file.seekg(0, std::ios::beg);
        file.read(memblock, size);
        file.close();

        EVP_MD_CTX * context = EVP_MD_CTX_create();
        EVP_DigestInit(context, EVP_sha256());
        EVP_DigestUpdate(context, memblock, size);

        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hash_length = 0;
        EVP_DigestFinal(context, hash, &hash_length);
        EVP_MD_CTX_free(context);

        //std::cout << hash << std::endl;

        delete[] memblock;
    }
    else {
        std::cerr << "Unable to open file";
        return 1;
    }

    return 0;
}
