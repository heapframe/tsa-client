#include <gtest/gtest.h>
#include <fstream>
#include <filesystem>
#include <string>
#include <vector>

#include "../file_io.h"

namespace fs = std::filesystem;

// Helper: write raw bytes to a file outside of write_file so tests are independent
static void raw_write(const fs::path &p, const std::string &content) {
    std::ofstream f(p, std::ios::binary);
    f.write(content.data(), static_cast<std::streamsize>(content.size()));
}

// ---- read_file ---------------------------------------------------------------

TEST(ReadFile, ReadsKnownContent) {
    const fs::path tmp = fs::temp_directory_path() / "tsa_test_read_known.bin";
    raw_write(tmp, "hello world");

    auto result = read_file(tmp.string());

    ASSERT_EQ(result.size(), 11u);
    EXPECT_EQ(std::string(result.begin(), result.end()), "hello world");

    fs::remove(tmp);
}

TEST(ReadFile, ReadsBinaryContent) {
    const fs::path tmp = fs::temp_directory_path() / "tsa_test_read_binary.bin";
    std::string bytes;
    for (int i = 0; i < 256; ++i)
        bytes += static_cast<char>(i);
    raw_write(tmp, bytes);

    auto result = read_file(tmp.string());

    ASSERT_EQ(result.size(), 256u);
    for (int i = 0; i < 256; ++i)
        EXPECT_EQ(static_cast<unsigned char>(result[i]), static_cast<unsigned char>(i));

    fs::remove(tmp);
}

TEST(ReadFile, ReadsEmptyFile) {
    const fs::path tmp = fs::temp_directory_path() / "tsa_test_read_empty.bin";
    raw_write(tmp, "");

    // An empty file: read_file returns an empty vector (no error, just nothing to read)
    auto result = read_file(tmp.string());
    EXPECT_TRUE(result.empty());

    fs::remove(tmp);
}

TEST(ReadFile, ReturnsEmptyOnMissingFile) {
    auto result = read_file("/tmp/tsa_this_file_does_not_exist_12345.bin");
    EXPECT_TRUE(result.empty());
}

TEST(ReadFile, PreservesNullBytes) {
    const fs::path tmp = fs::temp_directory_path() / "tsa_test_null_bytes.bin";
    std::string content = "ab\x00\x00cd";
    content.resize(6); // ensure the two null bytes are included
    raw_write(tmp, content);

    auto result = read_file(tmp.string());

    ASSERT_EQ(result.size(), 6u);
    EXPECT_EQ(result[2], '\x00');
    EXPECT_EQ(result[3], '\x00');

    fs::remove(tmp);
}

// ---- write_file --------------------------------------------------------------

TEST(WriteFile, WritesAndReadsBack) {
    const fs::path tmp = fs::temp_directory_path() / "tsa_test_write_basic.bin";
    const std::string payload = "timestamp data";

    bool ok = write_file(tmp.string(), payload.data(), payload.size());
    ASSERT_TRUE(ok);

    auto result = read_file(tmp.string());
    EXPECT_EQ(std::string(result.begin(), result.end()), payload);

    fs::remove(tmp);
}

TEST(WriteFile, WritesBinaryData) {
    const fs::path tmp = fs::temp_directory_path() / "tsa_test_write_binary.bin";
    std::string bytes;
    for (int i = 255; i >= 0; --i)
        bytes += static_cast<char>(i);
    raw_write(tmp, ""); // ensure file exists first

    bool ok = write_file(tmp.string(), bytes.data(), bytes.size());
    ASSERT_TRUE(ok);

    auto result = read_file(tmp.string());
    ASSERT_EQ(result.size(), 256u);
    for (int i = 0; i < 256; ++i)
        EXPECT_EQ(static_cast<unsigned char>(result[i]), static_cast<unsigned char>(255 - i));

    fs::remove(tmp);
}

TEST(WriteFile, OverwritesExistingFile) {
    const fs::path tmp = fs::temp_directory_path() / "tsa_test_overwrite.bin";
    raw_write(tmp, "old content that is longer than new");

    bool ok = write_file(tmp.string(), "new", 3);
    ASSERT_TRUE(ok);

    auto result = read_file(tmp.string());
    ASSERT_EQ(result.size(), 3u);
    EXPECT_EQ(std::string(result.begin(), result.end()), "new");

    fs::remove(tmp);
}

TEST(WriteFile, ReturnsFalseOnUnwritablePath) {
    // /proc is readable but not writable by a normal user
    bool ok = write_file("/proc/tsa_no_permission_test.bin", "x", 1);
    EXPECT_FALSE(ok);
}

TEST(WriteFile, WritesZeroBytes) {
    const fs::path tmp = fs::temp_directory_path() / "tsa_test_write_zero.bin";
    bool ok = write_file(tmp.string(), "", 0);
    ASSERT_TRUE(ok);

    auto result = read_file(tmp.string());
    EXPECT_TRUE(result.empty());

    fs::remove(tmp);
}
