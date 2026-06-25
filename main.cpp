#include <format>
#include <iostream>
#include <openssl/ts.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <fstream>
#include <iomanip>
#include <curl/curl.h>
#include <openssl/err.h>

#include "tsa/tsa_network.h"
#include "tsa/tsa_crypto.h"
#include "file_io.h"

/*
 * Some other good ones:
 * http://timestamp.apple.com/ts01
 * https://rfc3161.ai.moda/microsoft
*/
#define DEFAULT_TSA "https://freetsa.org/tsr"

int main(const int argc, char *argv[]) {
    const char* tsa_server = DEFAULT_TSA;

    if (argc == 1) {
        std::cerr << "Error: Not enough args" << std::endl;
        std::cerr << "Usage: " << argv[0] << " filename" << std::endl;
        std::cerr << "Usage: " << argv[0] << " filename tsa_server" << std::endl;
        std::cerr << "Default TSA Server is " << DEFAULT_TSA << std::endl;
        return 1;
    }
    if (argc == 3) {
        tsa_server = argv[2];
    }

    if (auto file = read_file(argv[1]); !file.empty())
    {
        unsigned char hash[64];
        unsigned int hash_length;

        if (create_hash(static_cast<std::streamsize>(file.size()), file.data(), hash, hash_length))
            return 1;

        TS_REQ *tsq = createquery(hash, static_cast<int>(hash_length), EVP_sha512());
        if (tsq == nullptr) {
            std::cerr << "Error: Could not create request object" << std::endl;
            return 1;
        }

        //save tsq
        unsigned char *buf = nullptr;

        int len = i2d_TS_REQ(tsq, &buf);
        if (len <= 0) {
            std::cerr << "Error: Failed to DER encode TSQ" << std::endl;
            return 1;
        }

        if (std::string tsq_filename = std::format("{}.tsq", argv[1]);
            write_file(tsq_filename, reinterpret_cast<const char *>(buf), len)) {
            std::cout << "TSR written to " << tsq_filename << std::endl;
        }
        else {
            return 1;
        }


        std::string output;
        long http_code = 0;

        CURLcode ret = curl_global_init(CURL_GLOBAL_ALL);
        CURLcode tsr = sendquery(ret, reinterpret_cast<char*>(buf), len, &output, tsa_server, http_code);
        curl_global_cleanup();

        if (http_code != 200) {
            std::cout << "TSA Server gave non 200 response: " << http_code << std::endl;
        }

        TS_REQ_free(tsq);
        OPENSSL_free(buf);

        //save tsr
        if (tsr == CURLE_OK && http_code == 200) {
            if (const std::string tsr_filename = std::format("{}.tsr", argv[1]);
                write_file(tsr_filename, output.c_str(), output.size())) {
                std::cout << "TSR written to " << tsr_filename << std::endl;
            }
            else {
                return 1;
            }

        } else {
            std::cerr << "Network error, TSA server may be down" << std::endl;
            return 1;
        }
    }
    else {
        std::cerr << "Unable to open file";
        return 1;
    }

    //verify tsr
    auto tsr = read_file(std::format("{}.tsr", argv[1]));
    auto tsq = read_file(std::format("{}.tsq", argv[1]));

    if (!tsr.empty() && !tsq.empty()) {

        if (!verify_tsr(tsa_server,
            static_cast<std::streamsize>(tsr.size()),
            static_cast<std::streamsize>(tsq.size()),
            reinterpret_cast<unsigned char*>(tsr.data()),
            reinterpret_cast<unsigned char*>(tsq.data()))
        )
            return 1;

    } else {
        std::cerr << "Unable to open " << std::format("{}.tsr", argv[1]) << " and "
        << std::format("{}.tsq", argv[1]) << std::endl;
        return 1;
    }

    return 0;
}