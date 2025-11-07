#include "credentialmanager.h"
#include "common.hpp"

#include <string.h>
#include <algorithm>

TestCredmanState& TestCredmanState::instance(){
    static TestCredmanState state;
    return state;
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

    void AddStringIdEntry(char *cred_id, char* icon, size_t icon_len, char *title, char *subtitle, char *disclaimer, char *warning) {
        if (!cred_id) return;
        StringIdEntry entry;
        entry.id = cred_id;
        if (icon) entry.icon = std::string(icon, icon_len);
        if (title) entry.title = title;
        if (subtitle) entry.subtitle = subtitle;
        if (disclaimer) entry.disclaimer = disclaimer;
        if (warning) entry.warning = warning;
        TestCredmanState::instance().string_id_entries.push_back(entry);
    }

    void SetAdditionalDisclaimerAndUrlForVerificationEntry(char *cred_id, char *secondary_disclaimer, char *url_display_text, char *url_value) {
        if (!cred_id) return;
        auto& entries = TestCredmanState::instance().string_id_entries;
        auto it = std::find_if(entries.begin(), entries.end(), [&](const StringIdEntry& entry) {
            return entry.id == cred_id;
        });
        if (it != entries.end()) {
            if (secondary_disclaimer) it->secondary_disclaimer = secondary_disclaimer;
            if (url_display_text) it->url_display_text = url_display_text;
            if (url_value) it->url_value = url_value;
        }
    }

    void AddFieldForStringIdEntry(char *cred_id, char *field_display_name, char *field_display_value) {
        if (!cred_id) return;
        auto& entries = TestCredmanState::instance().string_id_entries;
        auto it = std::find_if(entries.begin(), entries.end(), [&](const StringIdEntry& entry) {
            return entry.id == cred_id;
        });
        if (it != entries.end()) {
            it->fields.emplace_back(
                field_display_name ? field_display_name : "",
                field_display_value ? field_display_value : ""
            );
        }
    }

    void AddPaymentEntry(char *cred_id, char *merchant_name, char *payment_method_name, char *payment_method_subtitle, char* payment_method_icon, size_t payment_method_icon_len, char *transaction_amount, char* bank_icon, size_t bank_icon_len, char* payment_provider_icon, size_t payment_provider_icon_len) {
        if (!cred_id) return;
        PaymentEntry entry;
        entry.id = cred_id;
        if (merchant_name) entry.merchant_name = merchant_name;
        if (payment_method_name) entry.payment_method_name = payment_method_name;
        if (payment_method_subtitle) entry.payment_method_subtitle = payment_method_subtitle;
        if (payment_method_icon) entry.payment_method_icon = std::string(payment_method_icon, payment_method_icon_len);
        if (transaction_amount) entry.transaction_amount = transaction_amount;
        if (bank_icon) entry.bank_icon = std::string(bank_icon, bank_icon_len);
        if (payment_provider_icon) entry.payment_provider_icon = std::string(payment_provider_icon, payment_provider_icon_len);
        TestCredmanState::instance().payment_entries.push_back(entry);
    }
}