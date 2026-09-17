#pragma once
#include <string>
#include <vector>
#include <map>

#include <nlohmann/json.hpp>
#include <doctest/doctest.h>

struct EntryInSet
{
    std::string cred_id;
    std::string icon;
    std::string title;
    std::string subtitle;
    std::string disclaimer;
    std::string warning;
    std::string metadata;
    std::string set_id;
    int set_index = 0;
    int delegation_type = 0;
    std::string secondary_disclaimer;
    std::string url_display_text;
    std::string url_value;
    std::vector<std::pair<std::string, std::string>> fields;
};

struct EntrySet
{
    std::string set_id;
    int set_length = 0;
};

struct TestCredmanState
{
    std::string request_buffer;
    std::string credentials_buffer;
    uint32_t wasm_version = 7;
    std::vector<EntrySet> entry_sets;
    std::vector<EntryInSet> entries;

    static TestCredmanState &instance();
    void reset();
};

doctest::String toString(const TestCredmanState &state);

struct TestCredmanStateGuard
{
    ~TestCredmanStateGuard()
    {
        TestCredmanState::instance().reset();
    }
};

class RequestGenerator
{
public:
    RequestGenerator();
    RequestGenerator &with_phone_number_hint(const std::vector<std::string> &hints);
    RequestGenerator &with_carrier_hint(const std::vector<std::string> &hints);
    RequestGenerator &with_android_carrier_hint(const std::vector<int> &hints);
    RequestGenerator &with_subscription_hint(const std::vector<int> &hints);
    RequestGenerator &with_vct_values(const std::vector<std::string> &values);
    RequestGenerator &with_user_verification(const std::string &uv);
    RequestGenerator &with_user_verification_hint_claim();
    RequestGenerator &with_credential_sets(const nlohmann::json &sets);
    RequestGenerator &add_credential(const nlohmann::json &cred);
    std::string build();
    nlohmann::json &json_data();

private:
    nlohmann::json request_json_;
};

std::string getTestDataPath(const std::string &relative_path);
std::string readFileToString(const std::string &file_path);
std::string makeRegistryBlob(const nlohmann::json &registry_json);
nlohmann::json loadDefaultRegistryJson();

extern TestCredmanState testCredmanState;
