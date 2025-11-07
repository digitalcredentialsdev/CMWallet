#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include "common.hpp"

#include <filesystem>
#include <fstream>
#include <string>
#include <sstream> // Required for std::ostringstream

extern "C" int openid_main();

// Helper function to get the path to a test data file relative to the current source file
std::string getTestDataPath(const std::string &relative_path)
{
    std::filesystem::path source_path = __FILE__;
    std::filesystem::path source_dir = source_path.parent_path();
    return (source_dir / relative_path).string();
}

// Helper function to read the entire content of a file into a std::string
std::string readFileToString(const std::string &file_path)
{
    std::ifstream input_file(file_path, std::ios::binary);
    if (!input_file.is_open())
    {
        return ""; // Return empty string if file cannot be opened
    }
    std::ostringstream ss;
    ss << input_file.rdbuf();
    return ss.str();
}

TEST_CASE("OpenID4VP")
{
    TestCredmanState::instance().credentials_buffer = readFileToString(getTestDataPath("data/pnv_registry.bin"));
    TestCredmanState::instance().request_buffer = readFileToString(getTestDataPath("data/request1.json"));
    REQUIRE_EQ(0, openid_main());
    REQUIRE(TestCredmanState::instance().string_id_entries.size() == 1);
}