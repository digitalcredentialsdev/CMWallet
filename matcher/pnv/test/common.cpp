#include "credentialmanager.h"
#include "common.hpp"

#include <nlohmann/json.hpp>

#include <string.h>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>

using json = nlohmann::json;

TestCredmanState &TestCredmanState::instance()
{
    static TestCredmanState state;
    return state;
}

void TestCredmanState::reset()
{
    request_buffer.clear();
    credentials_buffer.clear();
    wasm_version = 7;
    entry_sets.clear();
    entries.clear();
}

std::string getTestDataPath(const std::string &relative_path)
{
    std::filesystem::path source_path = __FILE__;
    std::filesystem::path source_dir = source_path.parent_path();
    return (source_dir / relative_path).string();
}

std::string readFileToString(const std::string &file_path)
{
    std::ifstream input_file(file_path, std::ios::binary);
    if (!input_file.is_open())
    {
        return "";
    }
    std::ostringstream ss;
    ss << input_file.rdbuf();
    return ss.str();
}

std::string makeRegistryBlob(const nlohmann::json &registry_json)
{
    std::string json_str = registry_json.dump();
    std::string blob;
    int offset = 4;
    blob.resize(4 + json_str.size());
    memcpy(blob.data(), &offset, 4);
    memcpy(blob.data() + 4, json_str.data(), json_str.size());
    return blob;
}

nlohmann::json loadDefaultRegistryJson()
{
    std::string content = readFileToString(getTestDataPath("data/pnv_registry.json"));
    return json::parse(content);
}

RequestGenerator::RequestGenerator()
{
    request_json_ = json::parse(R"({
        "requests": [
            {
                "protocol": "openid4vp-v1-unsigned",
                "data": {
                    "dcql_query": {
                        "credentials": [
                            {
                                "claims": [],
                                "format": "dc-authorization+sd-jwt",
                                "id": "aggregator1",
                                "meta": {
                                    "credential_authorization_jwt": "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QiLCJ4NWMiOlsiTUlJQ3BUQ0NBa3VnQXdJQkFnSVVDOWZOSnBkVU1RWWRCbDFuaDgrUml0UndNRDh3Q2dZSUtvWkl6ajBFQXdJd2VERUxNQWtHQTFVRUJoTUNWVk14RXpBUkJnTlZCQWdNQ2tOaGJHbG1iM0p1YVdFeEZqQVVCZ05WQkFjTURVMXZkVzUwWVdsdUlGWnBaWGN4R3pBWkJnTlZCQW9NRWtWNFlXMXdiR1VnUVdkbmNtVm5ZWFJ2Y2pFZk1CMEdBMVVFQXd3V1pYaGhiWEJzWlMxaFoyZHlaV2RoZEc5eUxtUmxkakFlRncweU5UQTFNVEV5TWpRd01EVmFGdzB6TlRBME1qa3lNalF3TURWYU1IZ3hDekFKQmdOVkJBWVRBbFZUTVJNd0VRWURWUVFJREFwRFlXeHBabTl5Ym1saE1SWXdGQVlEVlFRSERBMU5iM1Z1ZEdGcGJpQldhV1YzTVJzd0dRWURWUVFLREJKRmVHRnRjR3hsSUVGblozSmxaMkYwYjNJeEh6QWRCZ05WQkFNTUZtVjRZVzF3YkdVdFlXZG5jbVZuWVhSdmNpNWtaWFl3V1RBVEJnY3Foa2pPUFFJQkJnZ3Foa2pPUFFNQkJ3TkNBQVJRcW5LTGw5U2g4dFcwM0h5aVBnOVRUcGlyQVg2V2haKzlJSWhVWFJGcDlxRFM0eW5YeG1GbjMzWk5nMTlQR1VzRWpxNGwzam9Penh2cHhqWDRoL1JlbzRHeU1JR3ZNQjBHQTFVZERnUVdCQlFBV1I5czRrWFRjeHJPeTFLSE12UldTSkg5YmpBZkJnTlZIU01FR0RBV2dCUUFXUjlzNGtYVGN4ck95MUtITXZSV1NKSDliakFQQmdOVkhSTUJBZjhFQlRBREFRSC9NQTRHQTFVZER3RUIvd1FFQXdJSGdEQXBCZ05WSFJJRUlqQWdoaDVvZEhSd2N6b3ZMMlY0WVcxd2JHVXRZV2RuY21WbllYUnZjaTVqYjIwd0lRWURWUjBSQkJvd0dJSVdaWGhoYlhCc1pTMWhaMmR5WldkaGRHOXlMbU52YlRBS0JnZ3Foa2pPUFFRREFnTklBREJGQWlCeERROUZiby9EUVRkbVNaS0NURUlHOXZma0JkWU5jVHcxUkkzT0k2L25KUUloQUw1NmU3YkVNOTlSTTFTUDAyd3gzbHhxZFZCWnhiVEhJcllCQkY3Y0FzYjMiXX0.eyJpc3MiOiAiZGNhZ2dyZWdhdG9yLmRldiIsICJub25jZSI6ICJrazQzSkthUHNjYWpqWHAzNGZSOHB1SGp0UE1yY09CMzJLNXdLTUQ1Q2J3IiwgImVuY3J5cHRlZF9yZXNwb25zZV9lbmNfdmFsdWVzX3N1cHBvcnRlZCI6IFsiQTEyOEdDTSJdLCAiandrcyI6IHsia2V5cyI6IFt7Imt0eSI6ICJFQyIsICJ1c2UiOiAiZW5jIiwgImFsZyI6ICJFQ0RILUVTIiwgImtpZCI6ICIxIiwgImNydiI6ICJQLTI1NiIsICJ4IjogIjl5TGgtNkJJQ1pMUWdKcGEzdl9FQS1ZbkIyU2FhV1BLWGZQWGNKa2EwMGciLCAieSI6ICJKNkRFWXV5SW90NDM0WG5WOE5GTWppb1cxLUFtSkVCRHdwTW9wRUt4WUdrIn1dfSwgImNvbnNlbnRfZGF0YSI6ICJleUpqYjI1elpXNTBYM1JsZUhRaU9pQWlVbWxrWlhJZ2NISnZZMlZ6YzJWeklIbHZkWElnY0dWeWMyOXVZV3dnWkdGMFlTQmhZMk52Y21ScGJtY2dkRzhnYjNWeUlIQnlhWFpoWTNrZ2NHOXNhV041SWl3Z0luQnZiR2xqZVY5c2FXNXJJam9nSW1oMGRIQnpPaTh2WkdWMlpXeHZjR1Z5TG1GdVpISnZhV1F1WTI5dEwybGtaVzUwYVhSNUwyUnBaMmwwWVd3dFkzSmxaR1Z1ZEdsaGJITXZZM0psWkdWdWRHbGhiQzEyWlhKcFptbGxjaUlzSUNKd2IyeHBZM2xmZEdWNGRDSTZJQ0pNWldGeWJpQmhZbTkxZENCd2NtbDJZV041SUhCdmJHbGplU0o5IiwgInN0YXRlIjogIm9wdGlvbmFsX3N0YXRlX3ZhbHVlIn0.w7_X5hLwjDxw26GguGjxuJnhxfcmqtbcCPiTobUrGpoFIvYWat9Luqi5r8ZTu_CIfC3rismGsYZH6ozNQwXgnw"
                                }
                            }
                        ]
                    },
                    "nonce": "kk43JKaPscajjXp34fR8puHjtPMrcOB32K5wKMD5Cbw",
                    "response_mode": "dc_api",
                    "response_type": "vp_token"
                }
            }
        ]
    })");
}

RequestGenerator &RequestGenerator::with_phone_number_hint(const std::vector<std::string> &hints)
{
    if (!hints.empty())
    {
        request_json_["requests"][0]["data"]["dcql_query"]["credentials"][0]["claims"].push_back({{"path", {"phone_number_hint"}}, {"values", hints}});
    }
    return *this;
}

RequestGenerator &RequestGenerator::with_carrier_hint(const std::vector<std::string> &hints)
{
    if (!hints.empty())
    {
        request_json_["requests"][0]["data"]["dcql_query"]["credentials"][0]["claims"].push_back({{"path", {"carrier_hint"}}, {"values", hints}});
    }
    return *this;
}

RequestGenerator &RequestGenerator::with_android_carrier_hint(const std::vector<int> &hints)
{
    if (!hints.empty())
    {
        request_json_["requests"][0]["data"]["dcql_query"]["credentials"][0]["claims"].push_back({{"path", {"android_carrier_hint"}}, {"values", hints}});
    }
    return *this;
}

RequestGenerator &RequestGenerator::with_subscription_hint(const std::vector<int> &hints)
{
    if (!hints.empty())
    {
        request_json_["requests"][0]["data"]["dcql_query"]["credentials"][0]["claims"].push_back({{"path", {"subscription_hint"}}, {"values", hints}});
    }
    return *this;
}

RequestGenerator &RequestGenerator::with_vct_values(const std::vector<std::string> &values)
{
    if (!values.empty())
    {
        request_json_["requests"][0]["data"]["dcql_query"]["credentials"][0]["meta"]["vct_values"] = values;
    }
    return *this;
}

RequestGenerator &RequestGenerator::with_user_verification(const std::string &uv)
{
    request_json_["requests"][0]["data"]["user_verification"] = uv;
    return *this;
}

RequestGenerator &RequestGenerator::with_user_verification_hint_claim()
{
    nlohmann::json claim = {
        {"path", {"user_verification_hint"}}
    };
    request_json_["requests"][0]["data"]["dcql_query"]["credentials"][0]["claims"].push_back(claim);
    return *this;
}

RequestGenerator &RequestGenerator::with_credential_sets(const nlohmann::json &sets)
{
    request_json_["requests"][0]["data"]["dcql_query"]["credential_sets"] = sets;
    return *this;
}

RequestGenerator &RequestGenerator::add_credential(const nlohmann::json &cred)
{
    request_json_["requests"][0]["data"]["dcql_query"]["credentials"].push_back(cred);
    return *this;
}

std::string RequestGenerator::build()
{
    return request_json_.dump(4);
}

nlohmann::json &RequestGenerator::json_data()
{
    return request_json_;
}

extern "C"
{
    void GetCredentialsSize(uint32_t *size)
    {
        *size = (uint32_t)TestCredmanState::instance().credentials_buffer.size();
    }
    size_t ReadCredentialsBuffer(void *buffer, size_t offset, size_t len)
    {
        if (offset + len > TestCredmanState::instance().credentials_buffer.size())
        {
            len = TestCredmanState::instance().credentials_buffer.size() - offset;
        }
        memcpy(buffer, TestCredmanState::instance().credentials_buffer.data() + offset, len);
        return len;
    }
    void GetWasmVersion(uint32_t *version)
    {
        *version = TestCredmanState::instance().wasm_version;
    }
    void GetRequestSize(uint32_t *size)
    {
        *size = (uint32_t)TestCredmanState::instance().request_buffer.size() + 1;
    }
    void GetRequestBuffer(void *buffer)
    {
        memcpy(buffer, TestCredmanState::instance().request_buffer.c_str(), TestCredmanState::instance().request_buffer.size() + 1);
    }

    void AddEntrySet(const char *set_id, int set_length)
    {
        EntrySet s;
        s.set_id = set_id ? set_id : "";
        s.set_length = set_length;
        TestCredmanState::instance().entry_sets.push_back(s);
    }

    void AddEntryToSet(const char *cred_id, const char *icon, size_t icon_len, const char *title, const char *subtitle, const char *disclaimer, const char *warning, const char *metadata, const char *set_id, int set_index)
    {
        EntryInSet entry;
        entry.cred_id = cred_id ? cred_id : "";
        if (icon && icon_len > 0)
            entry.icon = std::string(icon, icon_len);
        entry.title = title ? title : "";
        entry.subtitle = subtitle ? subtitle : "";
        entry.disclaimer = disclaimer ? disclaimer : "";
        entry.warning = warning ? warning : "";
        entry.metadata = metadata ? metadata : "";
        entry.set_id = set_id ? set_id : "";
        entry.set_index = set_index;
        TestCredmanState::instance().entries.push_back(entry);
    }

    void SetDelegationTypeForEntryInSet(const char *cred_id, int delegation_type, const char *set_id, int set_index)
    {
        auto &entries = TestCredmanState::instance().entries;
        for (auto &e : entries)
        {
            if (e.cred_id == (cred_id ? cred_id : "") &&
                e.set_id == (set_id ? set_id : "") &&
                e.set_index == set_index)
            {
                e.delegation_type = delegation_type;
            }
        }
    }

    void AddFieldToEntrySet(const char *cred_id, const char *field_display_name, const char *field_display_value, const char *set_id, int set_index)
    {
        auto &entries = TestCredmanState::instance().entries;
        for (auto &e : entries)
        {
            if (e.cred_id == (cred_id ? cred_id : "") &&
                e.set_id == (set_id ? set_id : "") &&
                e.set_index == set_index)
            {
                e.fields.emplace_back(field_display_name ? field_display_name : "", field_display_value ? field_display_value : "");
            }
        }
    }

    void SetAdditionalDisclaimerAndUrlForVerificationEntryInCredentialSet(const char *cred_id, const char *secondary_disclaimer, const char *url_display_text, const char *url_value, const char *set_id, int set_index)
    {
        auto &entries = TestCredmanState::instance().entries;
        for (auto &e : entries)
        {
            if (e.cred_id == (cred_id ? cred_id : "") &&
                e.set_id == (set_id ? set_id : "") &&
                e.set_index == set_index)
            {
                if (secondary_disclaimer) e.secondary_disclaimer = secondary_disclaimer;
                if (url_display_text) e.url_display_text = url_display_text;
                if (url_value) e.url_value = url_value;
            }
        }
    }

    void AddMetadataDisplayTextToEntrySet(const char *cred_id, const char *metadata_display_text, const char *set_id, int set_index)
    {
        (void)cred_id; (void)metadata_display_text; (void)set_id; (void)set_index;
    }

    // Unused stubs required to satisfy credentialmanager.h declarations
    void AddEntry(long long, const char *, size_t, const char *, const char *, const char *, const char *) {}
    void AddField(long long, const char *, const char *) {}
    void AddStringIdEntry(const char *, const char *, size_t, const char *, const char *, const char *, const char *) {}
    void AddFieldForStringIdEntry(const char *, const char *, const char *) {}
    void AddPaymentEntry(const char *, const char *, const char *, const char *, const char *, size_t, const char *, const char *, size_t, const char *, size_t) {}
    void AddPaymentEntryToSet(const char *, const char *, const char *, const char *, const char *, size_t, const char *, const char *, size_t, const char *, size_t, const char *, const char *, int) {}
    void AddPaymentEntryToSetV2(const char *, const char *, const char *, const char *, const char *, size_t, const char *, const char *, size_t, const char *, size_t, const char *, const char *, const char *, int) {}
    void AddInlineIssuanceEntry(const char *, const char *, size_t, const char *, const char *) {}
    void SetAdditionalDisclaimerAndUrlForVerificationEntry(const char *, const char *, const char *, const char *) {}
    void GetCallingAppInfo(CallingAppInfo *) {}
    void SelfDeclarePackageInfo(const char *, const char *, size_t) {}
}

doctest::String toString(const TestCredmanState &state)
{
    doctest::String s;
    s += "entries count: ";
    s += std::to_string(state.entries.size()).c_str();
    s += "\n";
    for (const auto &entry : state.entries)
    {
        s += "  id: ";
        s += entry.cred_id.c_str();
        s += " set_id: ";
        s += entry.set_id.c_str();
        s += " set_idx: ";
        s += std::to_string(entry.set_index).c_str();
        s += " del_type: ";
        s += std::to_string(entry.delegation_type).c_str();
        s += "\n";
    }
    return s;
}
