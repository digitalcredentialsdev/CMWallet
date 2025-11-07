#pragma once
#pragma once
#include <string>
#include <vector>
#include <map>

#include <nlohmann/json.hpp>
#include <doctest/doctest.h>

struct StringIdEntry
{
    std::string id;
    std::string icon;
    std::string title;
    std::string subtitle;
    std::string disclaimer;
    std::string warning;
    std::string secondary_disclaimer;
    std::string url_display_text;
    std::string url_value;
    std::vector<std::pair<std::string, std::string>> fields;
};

struct PaymentEntry
{
    std::string id;
    std::string merchant_name;
    std::string payment_method_name;
    std::string payment_method_subtitle;
    std::string payment_method_icon;
    std::string transaction_amount;
    std::string bank_icon;
    std::string payment_provider_icon;
};

struct TestCredmanState
{
    std::string request_buffer, credentials_buffer;
    std::vector<StringIdEntry> string_id_entries;
    std::vector<PaymentEntry> payment_entries;

    static TestCredmanState &instance();
};

doctest::String toString(const TestCredmanState &state);

struct TestCredmanStateGuard
{
    ~TestCredmanStateGuard()
    {
        TestCredmanState::instance().string_id_entries.clear();
        TestCredmanState::instance().payment_entries.clear();
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
    std::string build();

private:
    nlohmann::json request_json_;
};

extern TestCredmanState testCredmanState;
