#include <gtest/gtest.h>
#include <openssl/ts.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/crypto.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/types.h>
#include <stdio.h>
#include <string.h>
#include <iosfwd>
#include <string>

#include "../tsa/tsa_crypto.h"

// ---- create_hash -------------------------------------------------------------

// Known SHA-512 of the ASCII string "hello" (no newline):
// 9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043
static const char HELLO_SHA512[] =
    "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca7"
    "2323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043";

static std::string bytes_to_hex(const unsigned char *buf, unsigned int len) {
    std::string out;
    out.reserve(len * 2);
    for (unsigned int i = 0; i < len; ++i) {
        char tmp[3];
        snprintf(tmp, sizeof(tmp), "%02x", buf[i]);
        out += tmp;
    }
    return out;
}

TEST(CreateHash, KnownVector) {
    const char input[] = "hello";
    unsigned char hash[64];
    unsigned int len = 0;

    bool err = create_hash(5, input, hash, len);

    ASSERT_FALSE(err);
    EXPECT_EQ(len, 64u);
    EXPECT_EQ(bytes_to_hex(hash, len), HELLO_SHA512);
}

TEST(CreateHash, EmptyInput) {
    // SHA-512 of empty string:
    // cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce
    // 47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e
    static const char EMPTY_SHA512[] =
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";

    unsigned char hash[64];
    unsigned int len = 0;

    bool err = create_hash(0, "", hash, len);

    ASSERT_FALSE(err);
    EXPECT_EQ(len, 64u);
    EXPECT_EQ(bytes_to_hex(hash, len), EMPTY_SHA512);
}

TEST(CreateHash, DifferentInputsProduceDifferentHashes) {
    const char input_a[] = "aaa";
    const char input_b[] = "bbb";
    unsigned char hash_a[64], hash_b[64];
    unsigned int len_a = 0, len_b = 0;

    ASSERT_FALSE(create_hash(3, input_a, hash_a, len_a));
    ASSERT_FALSE(create_hash(3, input_b, hash_b, len_b));

    EXPECT_NE(bytes_to_hex(hash_a, len_a), bytes_to_hex(hash_b, len_b));
}

TEST(CreateHash, IsDeterministic) {
    const char input[] = "deterministic test";
    unsigned char hash1[64], hash2[64];
    unsigned int len1 = 0, len2 = 0;

    ASSERT_FALSE(create_hash(18, input, hash1, len1));
    ASSERT_FALSE(create_hash(18, input, hash2, len2));

    ASSERT_EQ(len1, len2);
    EXPECT_EQ(memcmp(hash1, hash2, len1), 0);
}

TEST(CreateHash, LargeInput) {
    std::string large(1024 * 1024, 'x'); // 1 MiB of 'x'
    unsigned char hash[64];
    unsigned int len = 0;

    bool err = create_hash(static_cast<std::streamsize>(large.size()), large.data(), hash, len);

    ASSERT_FALSE(err);
    EXPECT_EQ(len, 64u);
}

// ---- createquery -------------------------------------------------------------

TEST(CreateQuery, ReturnsNonNull) {
    unsigned char hash[64] = {};
    unsigned int len = 64;

    TS_REQ *req = create_query(hash, static_cast<int>(len), EVP_sha512());

    ASSERT_NE(req, nullptr);
    TS_REQ_free(req);
}

TEST(CreateQuery, VersionIsOne) {
    unsigned char hash[64] = {};
    TS_REQ *req = create_query(hash, 64, EVP_sha512());
    ASSERT_NE(req, nullptr);

    EXPECT_EQ(TS_REQ_get_version(req), 1);

    TS_REQ_free(req);
}

TEST(CreateQuery, CertReqIsSet) {
    unsigned char hash[64] = {};
    TS_REQ *req = create_query(hash, 64, EVP_sha512());
    ASSERT_NE(req, nullptr);

    EXPECT_EQ(TS_REQ_get_cert_req(req), 1);

    TS_REQ_free(req);
}

TEST(CreateQuery, DigestAlgorithmIsSHA512) {
    unsigned char hash[64] = {};
    TS_REQ *req = create_query(hash, 64, EVP_sha512());
    ASSERT_NE(req, nullptr);

    TS_MSG_IMPRINT *imprint = TS_REQ_get_msg_imprint(req);
    ASSERT_NE(imprint, nullptr);

    X509_ALGOR *algo = TS_MSG_IMPRINT_get_algo(imprint);
    ASSERT_NE(algo, nullptr);

    const ASN1_OBJECT *obj = nullptr;
    X509_ALGOR_get0(&obj, nullptr, nullptr, algo);
    ASSERT_NE(obj, nullptr);

    EXPECT_EQ(OBJ_obj2nid(obj), NID_sha512);

    TS_REQ_free(req);
}

TEST(CreateQuery, DigestBytesMatchInput) {
    unsigned char hash[64];
    unsigned int hash_len = 0;
    const char input[] = "hello";
    create_hash(5, input, hash, hash_len);

    TS_REQ *req = create_query(hash, static_cast<int>(hash_len), EVP_sha512());
    ASSERT_NE(req, nullptr);

    TS_MSG_IMPRINT *imprint = TS_REQ_get_msg_imprint(req);
    ASSERT_NE(imprint, nullptr);

    const ASN1_OCTET_STRING *msg = TS_MSG_IMPRINT_get_msg(imprint);
    ASSERT_NE(msg, nullptr);

    ASSERT_EQ(static_cast<unsigned int>(ASN1_STRING_length(msg)), hash_len);
    EXPECT_EQ(memcmp(ASN1_STRING_get0_data(msg), hash, hash_len), 0);

    TS_REQ_free(req);
}

TEST(CreateQuery, DEREncodable) {
    unsigned char hash[64] = {};
    TS_REQ *req = create_query(hash, 64, EVP_sha512());
    ASSERT_NE(req, nullptr);

    unsigned char *buf = nullptr;
    int len = i2d_TS_REQ(req, &buf);

    EXPECT_GT(len, 0);
    OPENSSL_free(buf);
    TS_REQ_free(req);
}
