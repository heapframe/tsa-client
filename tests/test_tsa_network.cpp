#include <gtest/gtest.h>
#include <string>
#include "../tsa/tsa_network.h"

// ---- writefunc ---------------------------------------------------------------

TEST(WriteFunc, AppendsSingleChunk) {
    std::string out;
    const char data[] = "hello";
    size_t written = writefunc(const_cast<char*>(data), 1, 5, &out);

    EXPECT_EQ(written, 5u);
    EXPECT_EQ(out, "hello");
}

TEST(WriteFunc, AppendsBinaryData) {
    std::string out;
    const char data[] = "\x00\x01\x02\x03";
    size_t written = writefunc(const_cast<char*>(data), 1, 4, &out);

    EXPECT_EQ(written, 4u);
    ASSERT_EQ(out.size(), 4u);
    EXPECT_EQ(static_cast<unsigned char>(out[0]), 0x00u);
    EXPECT_EQ(static_cast<unsigned char>(out[1]), 0x01u);
    EXPECT_EQ(static_cast<unsigned char>(out[2]), 0x02u);
    EXPECT_EQ(static_cast<unsigned char>(out[3]), 0x03u);
}

TEST(WriteFunc, AppendsMultipleChunks) {
    std::string out;
    const char a[] = "foo";
    const char b[] = "bar";

    writefunc(const_cast<char*>(a), 1, 3, &out);
    writefunc(const_cast<char*>(b), 1, 3, &out);

    EXPECT_EQ(out, "foobar");
}

TEST(WriteFunc, ReturnsCorrectSizeWithMultiplier) {
    std::string out;
    const char data[] = "abcdefgh"; // 8 bytes
    // size=2, nmemb=4 → total 8
    size_t written = writefunc(const_cast<char*>(data), 2, 4, &out);

    EXPECT_EQ(written, 8u);
    EXPECT_EQ(out.size(), 8u);
}

TEST(WriteFunc, ZeroNmemb) {
    std::string out;
    const char data[] = "ignored";
    size_t written = writefunc(const_cast<char*>(data), 1, 0, &out);

    EXPECT_EQ(written, 0u);
    EXPECT_TRUE(out.empty());
}
