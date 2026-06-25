//
// Created by axjp on 25/06/2026.
//

#ifndef TSA_CLIENT_TSA_CRYPTO_H
#define TSA_CLIENT_TSA_CRYPTO_H
#include <ios>

TS_REQ *createquery(unsigned char *digest,
                    const int digest_len, const EVP_MD *md);

#ifdef ENABLE_FREETSA_BUNDLE
X509_STORE* load_store_from_embedded_pem();
#endif

bool create_hash(const std::streamsize size, const char *memblock, unsigned char(&hash)[64], unsigned int &hash_length);

static int verify_cb(const int ok, const X509_STORE_CTX *ctx);

bool verify_tsr(const char *tsaserver, const std::streamsize tsr_size, const std::streamsize tsq_size,
    const unsigned char *response, const unsigned char *request);

#endif //TSA_CLIENT_TSA_CRYPTO_H