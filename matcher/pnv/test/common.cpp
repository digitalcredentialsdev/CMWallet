#include "credentialmanager.h"
#include "common.hpp"

#include <nlohmann/json.hpp>

#include <string.h>
#include <algorithm>

using json = nlohmann::json;

TestCredmanState &TestCredmanState::instance()
{
    static TestCredmanState state;
    return state;
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

std::string RequestGenerator::build()
{
    return request_json_.dump(4);
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
        *version = -1;
    }
    void GetRequestSize(uint32_t *size)
    {
        *size = (uint32_t)TestCredmanState::instance().request_buffer.size();
    }
    void GetRequestBuffer(void *buffer)
    {
        memcpy(buffer, TestCredmanState::instance().request_buffer.data(), TestCredmanState::instance().request_buffer.size());
    }

    void AddStringIdEntry(char *cred_id, char *icon, size_t icon_len, char *title, char *subtitle, char *disclaimer, char *warning)
    {
        if (!cred_id)
            return;
        StringIdEntry entry;
        entry.id = cred_id;
        if (icon)
            entry.icon = std::string(icon, icon_len);
        if (title)
            entry.title = title;
        if (subtitle)
            entry.subtitle = subtitle;
        if (disclaimer)
            entry.disclaimer = disclaimer;
        if (warning)
            entry.warning = warning;
        TestCredmanState::instance().string_id_entries.push_back(entry);
    }

    void SetAdditionalDisclaimerAndUrlForVerificationEntry(char *cred_id, char *secondary_disclaimer, char *url_display_text, char *url_value)
    {
        if (!cred_id)
            return;
        auto &entries = TestCredmanState::instance().string_id_entries;
        auto it = std::find_if(entries.begin(), entries.end(), [&](const StringIdEntry &entry)
                               { return entry.id == cred_id; });
        if (it != entries.end())
        {
            if (secondary_disclaimer)
                it->secondary_disclaimer = secondary_disclaimer;
            if (url_display_text)
                it->url_display_text = url_display_text;
            if (url_value)
                it->url_value = url_value;
        }
    }

    void AddFieldForStringIdEntry(char *cred_id, char *field_display_name, char *field_display_value)
    {
        if (!cred_id)
            return;
        auto &entries = TestCredmanState::instance().string_id_entries;
        auto it = std::find_if(entries.begin(), entries.end(), [&](const StringIdEntry &entry)
                               { return entry.id == cred_id; });
        if (it != entries.end())
        {
            it->fields.emplace_back(
                field_display_name ? field_display_name : "",
                field_display_value ? field_display_value : "");
        }
    }

    void AddPaymentEntry(char *cred_id, char *merchant_name, char *payment_method_name, char *payment_method_subtitle, char *payment_method_icon, size_t payment_method_icon_len, char *transaction_amount, char *bank_icon, size_t bank_icon_len, char *payment_provider_icon, size_t payment_provider_icon_len)
    {
        if (!cred_id)
            return;
        PaymentEntry entry;
        entry.id = cred_id;
        if (merchant_name)
            entry.merchant_name = merchant_name;
        if (payment_method_name)
            entry.payment_method_name = payment_method_name;
        if (payment_method_subtitle)
            entry.payment_method_subtitle = payment_method_subtitle;
        if (payment_method_icon)
            entry.payment_method_icon = std::string(payment_method_icon, payment_method_icon_len);
        if (transaction_amount)
            entry.transaction_amount = transaction_amount;
        if (bank_icon)
            entry.bank_icon = std::string(bank_icon, bank_icon_len);
        if (payment_provider_icon)
            entry.payment_provider_icon = std::string(payment_provider_icon, payment_provider_icon_len);
        TestCredmanState::instance().payment_entries.push_back(entry);
    }
}

doctest::String toString(const TestCredmanState &state)
{
    doctest::String s;
    s += "string_id_entries:\n";
    for (const auto &entry : state.string_id_entries)
    {
        s += "  id: ";
        s += entry.id.c_str();
        s += "\n";
    }
    return s;
}