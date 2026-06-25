//
// Created by axjp on 25/06/2026.
//

#include <openssl/pem.h>
#include <openssl/ts.h>
#include <openssl/x509.h>

#include "tsa_crypto.h"

#include <iostream>

#ifdef ENABLE_FREETSA_BUNDLE
#include "freetsa_bundle.h"
#endif

TS_REQ *createquery(unsigned char *digest,
                           const int digest_len, const EVP_MD *md) { //adaptation of create_query from openssl/openssl/apps/ts.c:455
    TS_REQ *ts_req = nullptr;
    TS_MSG_IMPRINT *msg_imprint = nullptr;
    X509_ALGOR *algo = nullptr;
    // TODO: Add nonce to prevent replay attacks
    // https://datatracker.ietf.org/doc/html/rfc3161#section-2.2

    //construct ( https://datatracker.ietf.org/doc/html/rfc3161#section-2.4.1 )
    ts_req = TS_REQ_new();
    TS_REQ_set_version(ts_req, 1);
    msg_imprint = TS_MSG_IMPRINT_new();
    algo = X509_ALGOR_new();
    X509_ALGOR_set0(algo, OBJ_nid2obj(EVP_MD_get_type(md)), V_ASN1_NULL, nullptr);
    TS_MSG_IMPRINT_set_algo(msg_imprint, algo);
    TS_MSG_IMPRINT_set_msg(msg_imprint, digest, digest_len);
    TS_REQ_set_msg_imprint(ts_req, msg_imprint);
    TS_REQ_set_cert_req(ts_req, 1);

    TS_MSG_IMPRINT_free(msg_imprint);
    X509_ALGOR_free(algo);

    return ts_req;
}

#ifdef ENABLE_FREETSA_BUNDLE
X509_STORE* load_store_from_embedded_pem()
{
    BIO* bio = BIO_new_mem_buf(
        freetsa_bundle,
        static_cast<int>(freetsa_bundle_len)
    );

    if (!bio) return nullptr;

    X509_STORE* store = X509_STORE_new();
    if (!store) {
        BIO_free(bio);
        return nullptr;
    }

    while (true) {
        X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
        if (!cert)
            break; // end or parse error

        X509_STORE_add_cert(store, cert);

        // X509_STORE_add_cert increments refcount internally in OpenSSL 3
        X509_free(cert);
    }

    BIO_free(bio);
    return store;
}

bool create_hash(const std::streamsize size, const char *memblock, unsigned char(&hash)[64], unsigned int &hash_length) {
    EVP_MD_CTX * context = EVP_MD_CTX_new();

    if (context == nullptr) {
        std::cerr << "Error: Could not create message digest" << std::endl;
        return true;
    }
    if (!EVP_DigestInit_ex(context, EVP_sha512(), nullptr))
        goto cleanup;

    if (!EVP_DigestUpdate(context, memblock, size))
        goto cleanup;

    hash_length = 0;

    if (!EVP_DigestFinal(context, hash, &hash_length))
        goto cleanup;

    EVP_MD_CTX_free(context);
    return false;

cleanup:
    EVP_MD_CTX_free(context);
    std::cerr << "Error: Could not create message digest" << std::endl;
    return true;

}

static int verify_cb(const int ok, const X509_STORE_CTX *ctx) {
    if (!ok) {
        const int err = X509_STORE_CTX_get_error(ctx);

        std::cerr << "error: \"" << X509_verify_cert_error_string(err) << "\"" << std::endl;
        if (err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) {
            std::cerr << "This is normal for public TSA's however you should strongly consider adding their certificates to your certificate store" << std::endl;
        }
    }
    return ok;
}

bool verify_tsr(const char *tsaserver, const std::streamsize tsr_size, const std::streamsize tsq_size,
    const unsigned char *response, const unsigned char *request) {

    bool success = false;
    TS_RESP *resp = d2i_TS_RESP(nullptr, &response, tsr_size);
    TS_REQ *req = d2i_TS_REQ(nullptr, &request, tsq_size);
    TS_VERIFY_CTX *ctx = nullptr;
    X509_STORE *store = nullptr;

    if (!req) {
        std::cerr << "Error: Could not parse TSQ (Request) file. The file is likely corrupted." << std::endl;
        goto cleanup;
    }
    if (!resp) {
        std::cerr << "Error: Could not parse TSR (Response) file. Open the .tsr file in a text editor to see if the server returned an HTML error page." << std::endl;
        goto cleanup;
    }

    if ((ctx = TS_REQ_to_TS_VERIFY_CTX(req, nullptr)) == nullptr) {
        std::cerr << "Error: Failed to create verify context" << std::endl;
        goto cleanup;
    }

    if (!TS_RESP_get_tst_info(resp)) {
        std::cerr << "Missing TST info" << std::endl;
    }

    TS_VERIFY_CTX_add_flags(ctx, TS_VFY_SIGNATURE | TS_VFY_IMPRINT);

#ifdef ENABLE_FREETSA_BUNDLE
    if (strcmp(tsaserver, "https://freetsa.org/tsr") == 0) {
        store = load_store_from_embedded_pem();
    } else {
        store = X509_STORE_new();
    }
#else
    store = X509_STORE_new();
#endif

    if (!store) {
        std::cerr << "Error: Failed to create X509 store" << std::endl;
        goto cleanup;
    }

    X509_STORE_set_default_paths(store);
    X509_STORE_set_verify_cb(store, reinterpret_cast<X509_STORE_CTX_verify_cb>(verify_cb));


    if (!TS_VERIFY_CTX_set0_store(ctx, store)) {
        std::cerr << "Error: Failed to load certificate store into context" << std::endl;
        X509_STORE_free(store); // Free it manually since set0 failed to take ownership
        goto cleanup;
    }

    if (TS_RESP_verify_response(ctx, resp)) {
        std::cout << "Successfully verified TSR" << std::endl;
        success = true;
    } else {
        std::cerr << "Failed to verify TSR" << std::endl;
    }

cleanup:
    if (resp) TS_RESP_free(resp);
    if (req) TS_REQ_free(req);
    if (ctx) TS_VERIFY_CTX_free(ctx);

    return success;
}

#endif