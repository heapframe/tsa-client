#include <format>
#include <iostream>
#include <openssl/ts.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <fstream>
#include <iomanip>

static TS_REQ *createquery(const unsigned char *digest,
    const int digest_len, const EVP_MD *md) { //adaptation of create_query from openssl/openssl/blob/master/apps/ts.c:455
    TS_REQ *ts_req = nullptr;
    TS_MSG_IMPRINT *msg_imprint = nullptr;
    X509_ALGOR *algo = nullptr;
    unsigned char *data = nullptr;
    ASN1_OBJECT *policy_obj = nullptr;
    ASN1_INTEGER *nonce_asn1 = nullptr;

    //construct ( https://datatracker.ietf.org/doc/html/rfc3161#section-2.4.1 )
    ts_req = TS_REQ_new();
    TS_REQ_set_version(ts_req, 1);
    msg_imprint = TS_MSG_IMPRINT_new();
    algo = X509_ALGOR_new();
    algo->algorithm = OBJ_nid2obj(EVP_MD_get_type(md));
    algo->parameter = ASN1_TYPE_new();
    algo->parameter->type = V_ASN1_NULL;
    TS_MSG_IMPRINT_set_algo(msg_imprint, algo);
    TS_MSG_IMPRINT_set_msg(msg_imprint, data, digest_len);
    TS_REQ_set_msg_imprint(ts_req, msg_imprint);
    TS_REQ_set_cert_req(ts_req, 1);

    TS_MSG_IMPRINT_free(msg_imprint);
    X509_ALGOR_free(algo);
    OPENSSL_free(data);
    ASN1_OBJECT_free(policy_obj);
    ASN1_INTEGER_free(nonce_asn1);

    return ts_req;
}

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
        EVP_DigestInit(context, EVP_sha512());
        EVP_DigestUpdate(context, memblock, size);

        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hash_length = 0;
        EVP_DigestFinal(context, hash, &hash_length);
        EVP_MD_CTX_free(context);

        //std::cout << hash << std::endl;

        delete[] memblock;

        TS_REQ *tsq = createquery(hash, sizeof(hash), EVP_sha512());
        if (tsq == nullptr) {
            std::cerr << "Error: Could not create request object" << std::endl;
            return 1;
        }

        //save tsq
        std::string tsq_filename = std::format("{}.tsq", argv[1]);
        unsigned char *buf = nullptr;

        if (int len = i2d_TS_REQ(tsq, &buf); len <= 0) {
            std::cerr << "Error: Failed to DER encode TSQ" << std::endl;
        } else {
            std::ofstream tsq_output;
            tsq_output.open (tsq_filename, std::ios::out | std::ios::app | std::ios::binary);
            if (tsq_output.is_open())
            {
                tsq_output.write(reinterpret_cast<const char*>(buf), len);
                tsq_output.close();
            }
            else std::cout << "Unable to open " << tsq_filename << " for writing" << std::endl;
        }

        OPENSSL_free(buf);


    }
    else {
        std::cerr << "Unable to open file";
        return 1;
    }

    return 0;
}
