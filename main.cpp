#include <format>
#include <iostream>
#include <openssl/ts.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <fstream>
#include <iomanip>
#include <curl/curl.h>
#include <openssl/err.h>

#ifdef ENABLE_FREETSA_BUNDLE
#include "freetsa_bundle.h"
#include <openssl/pem.h>
#endif

#define DEFAULT_TSA "https://freetsa.org/tsr"

/*
 * Some other good ones:
 * http://timestamp.apple.com/ts01
 * https://rfc3161.ai.moda/microsoft
*/

static TS_REQ *createquery(unsigned char *digest,
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

size_t writefunc(void *ptr, size_t size, size_t nmemb, void *userdata)
{ //adapted from https://stackoverflow.com/questions/2329571/c-libcurl-get-output-into-a-string/61805520#61805520
    auto *s = static_cast<std::string*>(userdata);
    s->append(static_cast<char*>(ptr), size * nmemb);
    return size * nmemb;
}

CURLcode sendquery(CURLcode ret, char *buf, int len, std::string *s, const char *tsa_server, long &http_code) {
    curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/timestamp-query");
    if (ret != CURLE_OK) {
        std::cerr << "curl_global_init failed: "<< curl_easy_strerror(ret)<< '\n';
        curl_slist_free_all(headers);
        return ret;
    }

    if (CURL *curl = curl_easy_init()) {
        curl_easy_setopt(curl, CURLOPT_BUFFERSIZE, 102400L);
        curl_easy_setopt(curl, CURLOPT_URL, tsa_server);
        curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, buf);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, len);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "curl/8.2.1");
        curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 50L);
        curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);
        curl_easy_setopt(curl, CURLOPT_FTP_SKIP_PASV_IP, 1L);
        curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, s);

        ret = curl_easy_perform(curl);

        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        curl_easy_cleanup(curl);
    }

    curl_slist_free_all(headers);
    return ret;
}

static int verify_cb(const int ok, const X509_STORE_CTX *ctx)
{
    if (!ok) {
        const int err = X509_STORE_CTX_get_error(ctx);

        std::cerr << "error: \"" << X509_verify_cert_error_string(err) << "\"" << std::endl;
        if (err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) {
            std::cerr << "This is normal for public TSA's however you should strongly consider adding their certificates to your certificate store" << std::endl;
        }
    }
    return ok;
}

#ifdef ENABLE_FREETSA_BUNDLE
X509_STORE* load_store_from_embedded_pem()
{
    BIO* bio = BIO_new_mem_buf(
        freetsa_bundle,
        (int)freetsa_bundle_len
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
#endif

int main(const int argc, char *argv[]) {
    const char* tsaserver = DEFAULT_TSA;

    if (argc == 1) {
        std::cerr << "Error: Not enough args" << std::endl;
        std::cerr << "Usage: " << argv[0] << " filename" << std::endl;
        std::cerr << "Usage: " << argv[0] << " filename tsaserver" << std::endl;
        std::cerr << "Default TSA Server is " << DEFAULT_TSA << std::endl;
        return 1;
    }
    if (argc == 3) {
        tsaserver = argv[2];
    }

    if (std::ifstream file(argv[1], std::ios::in|std::ios::binary|std::ios::ate); file.is_open())
    {
        auto size = static_cast<std::streamsize>(file.tellg());
        auto *memblock = new char[size];
        file.seekg(0, std::ios::beg);
        file.read(memblock, size);
        file.close();

        EVP_MD_CTX * context = EVP_MD_CTX_new();

        if (context == nullptr) {
            delete[] memblock;
            std::cerr << "Error: Could not create message digest" << std::endl;
            return 1;
        }
        if (!EVP_DigestInit_ex(context, EVP_sha512(), nullptr)) {
            EVP_MD_CTX_free(context);
            delete[] memblock;
            std::cerr << "Error: Could not create message digest" << std::endl;
            return 1;
        }

        if (!EVP_DigestUpdate(context, memblock, size)) {
            EVP_MD_CTX_free(context);
            delete[] memblock;
            std::cerr << "Error: Could not create message digest" << std::endl;
            return 1;
        }
        delete[] memblock;

        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hash_length = 0;

        if (!EVP_DigestFinal(context, hash, &hash_length)) {
            EVP_MD_CTX_free(context);
            std::cerr << "Error: Could not create message digest" << std::endl;
            return 1;
        }

        EVP_MD_CTX_free(context);

        //std::cout << hash << std::endl;


        TS_REQ *tsq = createquery(hash, static_cast<int>(hash_length), EVP_sha512());
        if (tsq == nullptr) {
            std::cerr << "Error: Could not create request object" << std::endl;
            return 1;
        }

        //save tsq
        std::string tsq_filename = std::format("{}.tsq", argv[1]);
        unsigned char *buf = nullptr;

        int len = i2d_TS_REQ(tsq, &buf);
        if (len <= 0) {
            std::cerr << "Error: Failed to DER encode TSQ" << std::endl;
            return 1;
        }
        std::ofstream tsq_output;
        tsq_output.open (tsq_filename, std::ios::out | std::ios::binary);
        if (tsq_output.is_open())
        {
            tsq_output.write(reinterpret_cast<const char*>(buf), len);
            tsq_output.close();
            std::cout << "TSQ written to " << tsq_filename << std::endl;
        }
        else {
            std::cerr << "Unable to open " << tsq_filename << " for writing" << std::endl;
            return 1;
        }


        std::string output;
        long http_code = 0;

        CURLcode ret = curl_global_init(CURL_GLOBAL_ALL);
        CURLcode tsr = sendquery(ret, reinterpret_cast<char*>(buf), len, &output, tsaserver, http_code);
        curl_global_cleanup();

        if (http_code != 200) {
            std::cout << "TSA Server gave non 200 response: " << http_code << std::endl;
        }

        TS_REQ_free(tsq);
        OPENSSL_free(buf);

        //save tsr
        if (tsr == CURLE_OK && http_code == 200) {
            std::string tsr_filename = std::format("{}.tsr", argv[1]);
            std::ofstream tsr_output;
            tsr_output.open (tsr_filename, std::ios::out | std::ios::binary);
            if (tsr_output.is_open()) {
                tsr_output.write(output.c_str(), static_cast<std::streamsize>(output.size()));
                tsr_output.close();
                std::cout << "TSR written to " << tsr_filename << std::endl;
            }
            else {
                std::cerr << "Unable to open " << tsr_filename << " for writing" << std::endl;
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

    std::ifstream tsr(std::format("{}.tsr", argv[1]), std::ios::in|std::ios::binary|std::ios::ate);
    std::ifstream tsq(std::format("{}.tsq", argv[1]), std::ios::in|std::ios::binary|std::ios::ate);

    if (tsr.is_open() && tsq.is_open()) {
        auto tsr_size = static_cast<std::streamsize>(tsr.tellg());
        auto *tsr_memblock = new char[tsr_size];
        tsr.seekg(0, std::ios::beg);
        tsr.read(tsr_memblock, tsr_size);
        tsr.close();

        auto tsq_size = static_cast<std::streamsize>(tsq.tellg());
        auto *tsq_memblock = new char[tsq_size];
        tsq.seekg(0, std::ios::beg);
        tsq.read(tsq_memblock, tsq_size);
        tsq.close();

        const unsigned char *response = reinterpret_cast<unsigned char*>(tsr_memblock);
        const unsigned char *request = reinterpret_cast<unsigned char*>(tsq_memblock);

        TS_RESP *resp = d2i_TS_RESP(nullptr, &response, tsr_size);
        TS_REQ *req = d2i_TS_REQ(nullptr, &request, tsq_size);
        TS_VERIFY_CTX *ctx = nullptr;

        if (!resp) {
            std::cerr << "Error: Could not create response object" << std::endl;
            delete[] tsr_memblock;
            delete[] tsq_memblock;
            return 1;
        }

        if ((ctx = TS_REQ_to_TS_VERIFY_CTX(req, nullptr)) == nullptr) {
            std::cerr << "Error: Failed" << std::endl;
            delete[] tsr_memblock;
            delete[] tsq_memblock;
            return 1;
        }

        if (!TS_RESP_get_tst_info(resp)) {
            std::cerr << "Missing TST info" << std::endl;
        }

        TS_VERIFY_CTX_add_flags(ctx, TS_VFY_SIGNATURE | TS_VFY_IMPRINT);

        X509_STORE *store = nullptr;
#ifdef ENABLE_FREETSA_BUNDLE
        if (strcmp(tsaserver, "https://freetsa.org/tsr") == 0) {
            store = load_store_from_embedded_pem();
        } else {
            store = X509_STORE_new();
        }
#else
        store = X509_STORE_new();
#endif
        X509_STORE_set_default_paths(store);
        X509_STORE_set_verify_cb(store, reinterpret_cast<X509_STORE_CTX_verify_cb>(verify_cb));

        if (!TS_VERIFY_CTX_set0_store(ctx, store)) {
            std::cerr << "Error: Failed to load certificate store" << std::endl;
            delete[] tsr_memblock;
            delete[] tsq_memblock;
            return 1;
        }

        if (TS_RESP_verify_response(ctx, resp)) {
            std::cout << "Successfully verified TSR" << std::endl;
        } else {
            std::cerr << "Failed to verify TSR" << std::endl;
        }

        TS_RESP_free(resp);
        TS_REQ_free(req);

        delete[] tsr_memblock;
        delete[] tsq_memblock;
    } else {
        std::cerr << "Unable to open " << std::format("{}.tsr", argv[1]) << " and "
        << std::format("{}.tsq", argv[1]) << std::endl;
    }

    return 0;
}