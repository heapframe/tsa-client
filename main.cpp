#include <format>
#include <iostream>
#include <openssl/ts.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <fstream>
#include <iomanip>
#include <curl/curl.h>

static TS_REQ *createquery(unsigned char *digest,
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
    TS_MSG_IMPRINT_set_msg(msg_imprint, digest, digest_len);
    TS_REQ_set_msg_imprint(ts_req, msg_imprint);
    TS_REQ_set_cert_req(ts_req, 1);

    TS_MSG_IMPRINT_free(msg_imprint);
    X509_ALGOR_free(algo);
    OPENSSL_free(data);
    ASN1_OBJECT_free(policy_obj);
    ASN1_INTEGER_free(nonce_asn1);

    return ts_req;
}

size_t writefunc(void *ptr, size_t size, size_t nmemb, void *userdata)
{ //adapted from https://stackoverflow.com/questions/2329571/c-libcurl-get-output-into-a-string/61805520#61805520
    auto *s = static_cast<std::string*>(userdata);
    s->append(static_cast<char*>(ptr), size * nmemb);
    return size * nmemb;
}

CURLcode sendquery(unsigned char *buf, int len, std::string *s) {
    curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/timestamp-query");
    CURLcode ret = curl_global_init(CURL_GLOBAL_ALL);

    if (CURL *curl = curl_easy_init()) {
        curl_easy_setopt(curl, CURLOPT_BUFFERSIZE, 102400L);
        curl_easy_setopt(curl, CURLOPT_URL, "https://freetsa.org/tsr");
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

        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
    }

    return ret;
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

        TS_REQ *tsq = createquery(hash, hash_length, EVP_sha512());
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
        } else {
            std::ofstream tsq_output;
            tsq_output.open (tsq_filename, std::ios::out | std::ios::binary);
            if (tsq_output.is_open())
            {
                tsq_output.write(reinterpret_cast<const char*>(buf), len);
                tsq_output.close();
                std::cout << "TSQ written to " << tsq_filename << std::endl;
            }
            else std::cout << "Unable to open " << tsq_filename << " for writing" << std::endl;
        }


        std::string output;
        CURLcode tsr = sendquery(buf, len, &output);

        TS_REQ_free(tsq);
        OPENSSL_free(buf);

        //save tsr
        std::string tsr_filename = std::format("{}.tsr", argv[1]);
        std::ofstream tsr_output;
        tsr_output.open (tsr_filename, std::ios::out | std::ios::binary);
        if (tsr_output.is_open())
        {
            tsr_output.write(output.c_str(), len);
            tsr_output.close();
            std::cout << "TSR written to " << tsr_filename << std::endl;
        }
        else std::cerr << "Unable to open " << tsr_filename << " for writing" << std::endl;
    }
    else {
        std::cerr << "Unable to open file";
        return 1;
    }

    return 0;
}
