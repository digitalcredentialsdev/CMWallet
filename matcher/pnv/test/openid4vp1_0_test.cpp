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
    using namespace std::string_literals;
    TestCredmanState::instance().credentials_buffer =
        std::string({'\4', '\0', '\0', '\0'}) +
        readFileToString(getTestDataPath("data/pnv_registry.json"));

    SUBCASE("Only filter by phone number")
    {
        TestCredmanStateGuard guard;
        TestCredmanState::instance().request_buffer =
            RequestGenerator()
                .with_phone_number_hint({"+16502154321", "+16502154322", "+16502154323"})
                .with_vct_values({"number-verification/verify/ts43"})
                .build();
        REQUIRE_EQ(0, openid_main());
        CAPTURE(TestCredmanState::instance());

        REQUIRE(TestCredmanState::instance().string_id_entries.size() == 16);
        REQUIRE(TestCredmanState::instance().string_id_entries[0].id == R"({"entry_id":"verify_1","dcql_cred_id":"aggregator1","req_idx":0})"s);
        REQUIRE(TestCredmanState::instance().string_id_entries[1].id == R"({"entry_id":"verify_3","dcql_cred_id":"aggregator1","req_idx":0})"s);
        REQUIRE(TestCredmanState::instance().string_id_entries[2].id == R"({"entry_id":"verify_5","dcql_cred_id":"aggregator1","req_idx":0})"s);

        REQUIRE(TestCredmanState::instance().string_id_entries[8].id == R"({"entry_id":"verify_2","dcql_cred_id":"aggregator1","req_idx":0})"s);
        REQUIRE(TestCredmanState::instance().string_id_entries[9].id == R"({"entry_id":"verify_4","dcql_cred_id":"aggregator1","req_idx":0})"s);
        REQUIRE(TestCredmanState::instance().string_id_entries[10].id == R"({"entry_id":"verify_6","dcql_cred_id":"aggregator1","req_idx":0})"s);
    }

    SUBCASE("Filter by both carrier and android carrier hint requiring both matches")
    {
        TestCredmanStateGuard guard;
        TestCredmanState::instance().request_buffer =
            RequestGenerator()
                .with_carrier_hint({"22222", "110999"})
                .with_android_carrier_hint({11, 22, 33})
                .with_vct_values({"number-verification/verify/ts43"})
                .build();
        REQUIRE_EQ(0, openid_main());
        CAPTURE(TestCredmanState::instance());

        REQUIRE(TestCredmanState::instance().string_id_entries.size() == 16);
        REQUIRE(TestCredmanState::instance().string_id_entries[0].id == R"({"entry_id":"verify_7","dcql_cred_id":"aggregator1","req_idx":0})"s);
        REQUIRE(TestCredmanState::instance().string_id_entries[1].id == R"({"entry_id":"verify_8","dcql_cred_id":"aggregator1","req_idx":0})"s);
        REQUIRE(TestCredmanState::instance().string_id_entries[2].id == R"({"entry_id":"verify_15","dcql_cred_id":"aggregator1","req_idx":0})"s);
    }

    SUBCASE("Filter by carrier only")
    {
        TestCredmanStateGuard guard;
        TestCredmanState::instance().request_buffer =
            RequestGenerator()
                .with_carrier_hint({"22222", "110999"})
                .with_vct_values({"number-verification/phone_number/ts43"})
                .build();
        REQUIRE_EQ(0, openid_main());
        CAPTURE(TestCredmanState::instance());

        REQUIRE(TestCredmanState::instance().string_id_entries.size() == 16);
        REQUIRE(TestCredmanState::instance().string_id_entries[0].id == R"({"entry_id":"phone_number_5","dcql_cred_id":"aggregator1","req_idx":0})"s);
        REQUIRE(TestCredmanState::instance().string_id_entries[1].id == R"({"entry_id":"phone_number_6","dcql_cred_id":"aggregator1","req_idx":0})"s);
        REQUIRE(TestCredmanState::instance().string_id_entries[2].id == R"({"entry_id":"phone_number_7","dcql_cred_id":"aggregator1","req_idx":0})"s);
    }

    SUBCASE("Filter by both carrier and subscription hint ordering carrier matches first")
    {
        TestCredmanStateGuard guard;
        TestCredmanState::instance().request_buffer =
            RequestGenerator()
                .with_carrier_hint({"22222", "110999"})
                .with_subscription_hint({11, 22, 33})
                .with_vct_values({"number-verification/verify/ts43"})
                .build();
        REQUIRE_EQ(0, openid_main());
        CAPTURE(TestCredmanState::instance());
        REQUIRE(TestCredmanState::instance().string_id_entries.size() == 16);
        REQUIRE(TestCredmanState::instance().string_id_entries[0].id == R"({"entry_id":"verify_13","dcql_cred_id":"aggregator1","req_idx":0})"s);
        REQUIRE(TestCredmanState::instance().string_id_entries[1].id == R"({"entry_id":"verify_14","dcql_cred_id":"aggregator1","req_idx":0})"s);
        REQUIRE(TestCredmanState::instance().string_id_entries[2].id == R"({"entry_id":"verify_15","dcql_cred_id":"aggregator1","req_idx":0})"s);
        REQUIRE(TestCredmanState::instance().string_id_entries[4].id == R"({"entry_id":"verify_5","dcql_cred_id":"aggregator1","req_idx":0})"s);
    }
}