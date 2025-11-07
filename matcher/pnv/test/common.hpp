#pragma once
#pragma once
#include <string>
#include <vector>
#include <map>

struct StringIdEntry {
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

struct PaymentEntry {
    std::string id;
    std::string merchant_name;
    std::string payment_method_name;
    std::string payment_method_subtitle;
    std::string payment_method_icon;
    std::string transaction_amount;
    std::string bank_icon;
    std::string payment_provider_icon;
};

struct TestCredmanState {
    std::string request_buffer, credentials_buffer;
    std::vector<StringIdEntry> string_id_entries;
    std::vector<PaymentEntry> payment_entries;

    static TestCredmanState& instance();
};

extern TestCredmanState testCredmanState;