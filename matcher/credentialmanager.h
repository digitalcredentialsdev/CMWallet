#ifndef CREDENTIALMANAGER_H
#define CREDENTIALMANAGER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdlib.h>

// Deprecated. Use AddStringIdEntry instead.
#if defined(__wasm__)
__attribute__((import_module("credman"), import_name("AddEntry")))
#endif
void AddEntry(long long cred_id, const char* icon, size_t icon_len, const char* title, const char* subtitle, const char* disclaimer, const char* warning);

// Deprecated. Use AddFieldForStringIdEntry instead.
#if defined(__wasm__)
__attribute__((import_module("credman"), import_name("AddField")))
#endif
void AddField(long long cred_id, const char* field_display_name, const char* field_display_value);

#if defined(__wasm__)
__attribute__((import_module("credman_v2"), import_name("AddEntrySet")))
#endif
void AddEntrySet(const char* set_id, int set_length);

#if defined(__wasm__)
__attribute__((import_module("credman_v2"), import_name("AddEntryToSet")))
#endif
void AddEntryToSet(const char* cred_id, const char* icon, size_t icon_len, const char* title, const char* subtitle, const char* disclaimer, const char* warning, const char* metadata, const char* set_id, int set_index);

#if defined(__wasm__)
__attribute__((import_module("credman_v2"), import_name("AddFieldToEntrySet")))
#endif
void AddFieldToEntrySet(const char* cred_id, const char* field_display_name, const char* field_display_value, const char* set_id, int set_index);

#if defined(__wasm__)
__attribute__((import_module("credman_v2"), import_name("AddPaymentEntryToSet")))
#endif
void AddPaymentEntryToSet(const char* cred_id, const char* merchant_name, const char* payment_method_name, const char* payment_method_subtitle, const char* payment_method_icon, size_t payment_method_icon_len, const char* transaction_amount, const char* bank_icon, size_t bank_icon_len, const char* payment_provider_icon, size_t payment_provider_icon_len, const char* metadata, const char* set_id, int set_index);

#if defined(__wasm__)
__attribute__((import_module("credman_v2"), import_name("AddPaymentEntryToSetV2")))
#endif
void AddPaymentEntryToSetV2(const char* cred_id, const char* merchant_name, const char* payment_method_name, const char* payment_method_subtitle, const char* payment_method_icon, size_t payment_method_icon_len, const char* transaction_amount, const char* bank_icon, size_t bank_icon_len, const char* payment_provider_icon, size_t payment_provider_icon_len, const char* additional_info, const char* metadata, const char* set_id, int set_index);

#if defined(__wasm__)
__attribute__((import_module("credman"), import_name("AddStringIdEntry")))
#endif
void AddStringIdEntry(const char* cred_id, const char* icon, size_t icon_len, const char* title, const char* subtitle, const char* disclaimer, const char* warning);

#if defined(__wasm__)
__attribute__((import_module("credman"), import_name("AddFieldForStringIdEntry")))
#endif
void AddFieldForStringIdEntry(const char* cred_id, const char* field_display_name, const char* field_display_value);

#if defined(__wasm__)
__attribute__((import_module("credman"), import_name("GetRequestBuffer")))
#endif
#if defined(__rust_bindgen__)
__attribute__ ((visibility("default")))
#endif
void GetRequestBuffer(void* buffer);

#if defined(__wasm__)
__attribute__((import_module("credman"), import_name("GetRequestSize")))
#endif
void GetRequestSize(uint32_t* size);

#if defined(__wasm__)
__attribute__((import_module("credman"), import_name("ReadCredentialsBuffer")))
#endif
size_t ReadCredentialsBuffer(void* buffer, size_t offset, size_t len);

#if defined(__wasm__)
__attribute__((import_module("credman"), import_name("GetCredentialsSize")))
#endif
void GetCredentialsSize(uint32_t* size);

#if defined(__wasm__)
__attribute__((import_module("credman"), import_name("GetWasmVersion")))
#endif
void GetWasmVersion(uint32_t* version);

#if defined(__wasm__)
__attribute__((import_module("credman"), import_name("AddPaymentEntry")))
#endif
void AddPaymentEntry(const char* cred_id, const char* merchant_name, const char* payment_method_name, const char* payment_method_subtitle, const char* payment_method_icon, size_t payment_method_icon_len, const char* transaction_amount, const char* bank_icon, size_t bank_icon_len, const char* payment_provider_icon, size_t payment_provider_icon_len);

#if defined(__wasm__)
__attribute__((import_module("credman"), import_name("AddInlineIssuanceEntry")))
#endif
void AddInlineIssuanceEntry(const char* cred_id, const char* icon, size_t icon_len, const char* title, const char* subtitle);

#if defined(__wasm__)
__attribute__((import_module("credman"), import_name("SetAdditionalDisclaimerAndUrlForVerificationEntry")))
#endif
void SetAdditionalDisclaimerAndUrlForVerificationEntry(const char* cred_id, const char* secondary_disclaimer, const char* url_display_text, const char* url_value);

typedef struct CallingAppInfo {
	char package_name[256];
	char origin[512];
} CallingAppInfo;

#if defined(__wasm__)
__attribute__((import_module("credman"), import_name("GetCallingAppInfo")))
#endif
void GetCallingAppInfo(CallingAppInfo* info);


// Only works for system applications
#if defined(__wasm__)
__attribute__((import_module("credman_v4"), import_name("SelfDeclarePackageInfo")))
#endif
void SelfDeclarePackageInfo(const char* package_display_name, const char* package_icon, size_t package_icon_len);

#if defined(__wasm__)
__attribute__((import_module("credman_v5"), import_name("AddMetadataDisplayTextToEntrySet")))
#endif
void AddMetadataDisplayTextToEntrySet(const char *cred_id, const char *metadata_display_text, const char *set_id, int set_index);

#ifdef __cplusplus
}
#endif

#endif