#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <map>
#include <cstring>
#include <iostream>
#include <algorithm>
#include <cmath>
#include <fstream>
#include <iomanip>

extern "C" {
#include "cJSON/cJSON.h"
#include "dcql.h"
#include "base64.h"
#include "credentialmanager.h"
int openid4vp_main();
}

using json = nlohmann::json;

// --- FakeCredman Implementation ---
enum class EntryType {
    Verification,
    InlineIssuance,
    Payment,
    UserInfo,
    Export
};

NLOHMANN_JSON_SERIALIZE_ENUM(EntryType, {
    {EntryType::Verification, "Verification"},
    {EntryType::InlineIssuance, "InlineIssuance"},
    {EntryType::Payment, "Payment"},
    {EntryType::UserInfo, "UserInfo"},
    {EntryType::Export, "Export"}
})

struct FakeEntry {
    std::string credId;
    EntryType type;
    std::string title;
    std::string subtitle;
    std::string disclaimer;
    std::string warning;
    std::string metadata_display_text;
    std::vector<std::pair<std::string, std::string>> fields;
    std::string merchant_name;
    std::string transaction_amount;
    std::string additional_info;
};

void to_json(json& j, const FakeEntry& e) {
    j = json{
        {"credId", e.credId},
        {"type", e.type},
        {"title", e.title},
        {"subtitle", e.subtitle},
        {"disclaimer", e.disclaimer},
        {"warning", e.warning},
        {"metadata_display_text", e.metadata_display_text},
        {"fields", e.fields},
        {"merchant_name", e.merchant_name},
        {"transaction_amount", e.transaction_amount},
        {"additional_info", e.additional_info}
    };
}

struct FakeEntrySet {
    std::string setId;
    int setLength;
    // setIndex -> credId -> entry
    std::map<std::string, std::map<std::string, FakeEntry>> entries;
};

void to_json(json& j, const FakeEntrySet& s) {
    j = json{
        {"setId", s.setId},
        {"setLength", s.setLength},
        {"entries", s.entries}
    };
}

class FakeCredman {
public:
    static FakeCredman& GetInstance() {
        static FakeCredman instance;
        return instance;
    }

    void Reset() {
        entrySets.clear();
        standaloneEntries.clear();
        wasmVersion = 9999;
        requestJson = "";
        credentialsBlob.clear();
    }

    std::map<std::string, FakeEntrySet> entrySets;
    std::vector<FakeEntry> standaloneEntries;
    uint32_t wasmVersion = 9999;
    std::string requestJson;
    std::vector<uint8_t> credentialsBlob;

private:
    FakeCredman() = default;
};

void to_json(json& j, const FakeCredman& c) {
    j = json{
        {"entrySets", c.entrySets},
        {"standaloneEntries", c.standaloneEntries}
    };
}

std::string ReadFileToString(const std::string& path) {
    std::ifstream t(path);
    if (!t.is_open()) return "";
    std::string str((std::istreambuf_iterator<char>(t)),
                    std::istreambuf_iterator<char>());
    return str;
}

void WriteStringToFile(const std::string& path, const std::string& content) {
    std::ofstream out(path);
    out << content;
}

// --- Mocked ACM APIs (extern "C") ---
extern "C" {
void GetWasmVersion(uint32_t* version) {
    *version = FakeCredman::GetInstance().wasmVersion;
}

void GetRequestSize(uint32_t* size) {
    *size = FakeCredman::GetInstance().requestJson.size();
}

void GetRequestBuffer(void* buffer) {
    memcpy(buffer, FakeCredman::GetInstance().requestJson.c_str(), FakeCredman::GetInstance().requestJson.size());
}

void GetCredentialsSize(uint32_t* size) {
    *size = FakeCredman::GetInstance().credentialsBlob.size();
}

size_t ReadCredentialsBuffer(void* buffer, size_t offset, size_t len) {
    if (offset >= FakeCredman::GetInstance().credentialsBlob.size()) return 0;
    size_t toRead = std::min(len, (size_t)(FakeCredman::GetInstance().credentialsBlob.size() - offset));
    memcpy(buffer, FakeCredman::GetInstance().credentialsBlob.data() + offset, toRead);
    return toRead;
}

void AddEntrySet(const char* set_id, int set_length) {
    std::string s_id = set_id ? set_id : "";
    FakeCredman::GetInstance().entrySets[s_id] = {s_id, set_length, {}};
}

void AddEntryToSet(const char* cred_id, const char* /*icon*/, size_t /*icon_len*/, const char* title, const char* subtitle, const char* disclaimer, const char* warning, const char* /*metadata*/, const char* set_id, int set_index) {
    FakeEntry entry;
    entry.credId = cred_id ? cred_id : "";
    entry.type = EntryType::Verification;
    entry.title = title ? title : "";
    entry.subtitle = subtitle ? subtitle : "";
    entry.disclaimer = disclaimer ? disclaimer : "";
    entry.warning = warning ? warning : "";
    std::string s_id = set_id ? set_id : "";
    FakeCredman::GetInstance().entrySets[s_id].entries[std::to_string(set_index)][entry.credId] = entry;
}

void AddFieldToEntrySet(const char* cred_id, const char* field_display_name, const char* field_display_value, const char* set_id, int set_index) {
    std::string c_id = cred_id ? cred_id : "";
    std::string f_name = field_display_name ? field_display_name : "";
    std::string f_val = field_display_value ? field_display_value : "";
    std::string s_id = set_id ? set_id : "";
    FakeCredman::GetInstance().entrySets[s_id].entries[std::to_string(set_index)][c_id].fields.push_back({f_name, f_val});
}

void AddPaymentEntryToSetV2(const char* cred_id, const char* merchant_name, const char* /*payment_method_name*/, const char* /*payment_method_subtitle*/, const char* /*payment_method_icon*/, size_t /*payment_method_icon_len*/, const char* transaction_amount, const char* /*bank_icon*/, size_t /*bank_icon_len*/, const char* /*payment_provider_icon*/, size_t /*payment_provider_icon_len*/, const char* additional_info, const char* /*metadata*/, const char* set_id, int set_index) {
    FakeEntry entry;
    entry.credId = cred_id ? cred_id : "";
    entry.type = EntryType::Payment;
    entry.merchant_name = merchant_name ? merchant_name : "";
    entry.transaction_amount = transaction_amount ? transaction_amount : "";
    entry.additional_info = additional_info ? additional_info : "";
    std::string s_id = set_id ? set_id : "";
    FakeCredman::GetInstance().entrySets[s_id].entries[std::to_string(set_index)][entry.credId] = entry;
}

void AddPaymentEntryToSet(const char* cred_id, const char* merchant_name, const char* payment_method_name, const char* payment_method_subtitle, const char* payment_method_icon, size_t payment_method_icon_len, const char* transaction_amount, const char* bank_icon, size_t bank_icon_len, const char* payment_provider_icon, size_t payment_provider_icon_len, const char* metadata, const char* set_id, int set_index) {
    AddPaymentEntryToSetV2(cred_id, merchant_name, payment_method_name, payment_method_subtitle, payment_method_icon, payment_method_icon_len, transaction_amount, bank_icon, bank_icon_len, payment_provider_icon, payment_provider_icon_len, "", metadata, set_id, set_index);
}

void AddMetadataDisplayTextToEntrySet(const char *cred_id, const char *metadata_display_text, const char *set_id, int set_index) {
    std::string c_id = cred_id ? cred_id : "";
    std::string m_text = metadata_display_text ? metadata_display_text : "";
    std::string s_id = set_id ? set_id : "";
    FakeCredman::GetInstance().entrySets[s_id].entries[std::to_string(set_index)][c_id].metadata_display_text = m_text;
}

void AddInlineIssuanceEntry(const char* cred_id, const char* /*icon*/, size_t /*icon_len*/, const char* title, const char* subtitle) {
    FakeEntry entry;
    entry.credId = cred_id ? cred_id : "";
    entry.type = EntryType::InlineIssuance;
    entry.title = title ? title : "";
    entry.subtitle = subtitle ? subtitle : "";
    FakeCredman::GetInstance().standaloneEntries.push_back(entry);
}

// Deprecated or unused stubs
void AddEntry(long long, const char*, size_t, const char*, const char*, const char*, const char*) {}
void AddField(long long, const char*, const char*) {}
void AddStringIdEntry(const char*, const char*, size_t, const char*, const char*, const char*, const char*) {}
void AddFieldForStringIdEntry(const char*, const char*, const char*) {}
void AddPaymentEntry(const char*, const char*, const char*, const char*, const char*, size_t, const char*, const char*, size_t, const char*, size_t) {}
void SetAdditionalDisclaimerAndUrlForVerificationEntry(const char*, const char*, const char*, const char*) {}
void SetAdditionalDisclaimerAndUrlForVerificationEntryInCredentialSet(const char*, const char*, const char*, const char*, const char*, int) {}
void GetCallingAppInfo(CallingAppInfo*) {}
void SelfDeclarePackageInfo(const char*, const char*, size_t) {}
}

// --- Helper for creating registry blob ---
std::vector<uint8_t> CreateRegistryBlob(const std::string& jsonStr) {
    std::vector<uint8_t> blob;
    int offset = 4 + 10; // 4 bytes header + 10 bytes mock icon
    blob.resize(offset + jsonStr.size());
    memcpy(blob.data(), &offset, 4);
    for (int i = 0; i < 10; ++i) blob[4 + i] = (uint8_t)i;
    memcpy(blob.data() + offset, jsonStr.c_str(), jsonStr.size());
    return blob;
}

void RunTest(const std::string& test_name, const std::string& custom_registry = "") {
    FakeCredman::GetInstance().Reset();
    std::string registry_json_str = custom_registry.empty() ? ReadFileToString("testdata/registry.json") : custom_registry;
    FakeCredman::GetInstance().credentialsBlob = CreateRegistryBlob(registry_json_str);
    
    std::string loaded_request = ReadFileToString("testdata/" + test_name + "_request.json");
    // Ensure we parse and dump to normalize, or just use it directly. The original code used dump()
    FakeCredman::GetInstance().requestJson = json::parse(loaded_request).dump();
    
    const char* generate_env = std::getenv("GENERATE_TESTDATA");
    bool generate = generate_env && std::string(generate_env) == "1";

    openid4vp_main();
    
    json result_json = FakeCredman::GetInstance();
    if (generate) {
        WriteStringToFile("testdata/" + test_name + "_expected.json", result_json.dump(2));
    } else {
        std::string loaded_expected = ReadFileToString("testdata/" + test_name + "_expected.json");
        CHECK(json::parse(loaded_expected) == result_json);
    }
}



// --- Group 1: Base64-URL Decoding ---
TEST_CASE("TC01_DecodeEmptyString") {
    char* output = nullptr;
    int len = B64DecodeURL((char*)"", &output);
    CHECK(len == 0);
    if (output) free(output);
}

TEST_CASE("TC02_DecodeNoPadding") {
    char* output = nullptr;
    int len = B64DecodeURL((char*)"SGVsbG8", &output);
    CHECK(len == 5);
    CHECK(std::string(output, len) == "Hello");
    if (output) free(output);
}

TEST_CASE("TC03_DecodeOnePadding") {
    char* output = nullptr;
    int len = B64DecodeURL((char*)"SGVsbG8=", &output);
    CHECK(len == 5);
    CHECK(std::string(output, len) == "Hello");
    if (output) free(output);
}

TEST_CASE("TC04_DecodeTwoPaddings") {
    char* output = nullptr;
    int len = B64DecodeURL((char*)"SGVsbA==", &output);
    CHECK(len == 4);
    CHECK(std::string(output, len) == "Hell");
    if (output) free(output);
}

TEST_CASE("TC05_DecodeUrlSafeChars") {
    char* output = nullptr;
    int len = B64DecodeURL((char*)"-_-_", &output);
    CHECK(len == 3);
    CHECK((uint8_t)output[0] == 0xFB);
    CHECK((uint8_t)output[1] == 0xFF);
    CHECK((uint8_t)output[2] == 0xBF);
    if (output) free(output);
}

TEST_CASE("TC06_DecodeInvalidChars") {
    char* output = nullptr;
    B64DecodeURL((char*)"SGV@#G8", &output);
    if (output) free(output);
}

// --- Group 2: DCQL Query & Matching ---
TEST_CASE("TC07_MdocMatch") {
    RunTest("TC07_MdocMatch");
}

TEST_CASE("TC08_MdocMismatch") {
    RunTest("TC08_MdocMismatch");
}

TEST_CASE("TC09_SdjwtMatch") {
    RunTest("TC09_SdjwtMatch");
}

TEST_CASE("TC10_SdjwtMismatch") {
    RunTest("TC10_SdjwtMismatch");
}

TEST_CASE("TC11_InlineIssuanceFallback") {
    RunTest("TC11_InlineIssuanceFallback");
}

TEST_CASE("TC12_MissingFormat") {
    RunTest("TC12_MissingFormat");
}

TEST_CASE("TC13_ReturnAllClaims") {
    RunTest("TC13_ReturnAllClaims");
}

TEST_CASE("TC14_MatchSpecificClaims") {
    RunTest("TC14_MatchSpecificClaims");
}

TEST_CASE("TC15_MatchNestedClaims") {
    RunTest("TC15_MatchNestedClaims");
}

TEST_CASE("TC16_FailMissingClaims") {
    RunTest("TC16_FailMissingClaims");
}

TEST_CASE("TC17_MatchClaimValuesBool") {
    RunTest("TC17_MatchClaimValuesBool");
}

TEST_CASE("TC18_FailClaimValuesBool") {
    RunTest("TC18_FailClaimValuesBool");
}

TEST_CASE("TC19_MatchClaimValuesInt") {
    RunTest("TC19_MatchClaimValuesInt");
}

TEST_CASE("TC20_FailClaimValuesInt") {
    RunTest("TC20_FailClaimValuesInt");
}

TEST_CASE("TC21_MatchFirstClaimSet") {
    RunTest("TC21_MatchFirstClaimSet");
}

TEST_CASE("TC22_MatchSecondClaimSet") {
    RunTest("TC22_MatchSecondClaimSet");
}

TEST_CASE("TC23_FailAllClaimSets") {
    RunTest("TC23_FailAllClaimSets");
}

TEST_CASE("TC24_DcqlQuerySingle") {
    RunTest("TC24_DcqlQuerySingle");
}

TEST_CASE("TC25_DcqlQuerySetMatch") {
    RunTest("TC25_DcqlQuerySetMatch");
}

TEST_CASE("TC26_DcqlQuerySetFailRequired") {
    RunTest("TC26_DcqlQuerySetFailRequired");
}

TEST_CASE("TC27_DcqlQuerySetFailOptional") {
    RunTest("TC27_DcqlQuerySetFailOptional");
}

TEST_CASE("TC28_DcqlQueryComplexOverlappingSets") {
    RunTest("TC28_DcqlQueryComplexOverlappingSets");
}

TEST_CASE("TC29_DcqlQueryOpenID4VPSpecExample") {
    RunTest("TC29_DcqlQueryOpenID4VPSpecExample");
}

// --- Group 3: Protocol Parsing & Integration ---
TEST_CASE("TC30_ParseV1Unsigned") {
    RunTest("TC30_ParseV1Unsigned");
}

TEST_CASE("TC31_ParseV1Signed") {
    RunTest("TC31_ParseV1Signed");
}

TEST_CASE("TC32_ExtractPaymentSca1") {
    RunTest("TC32_ExtractPaymentSca1");
}

TEST_CASE("TC33_ExtractPaymentDetails") {
    RunTest("TC33_ExtractPaymentDetails");
}

TEST_CASE("TC34_ExtractPaymentGeneric") {
    RunTest("TC34_ExtractPaymentGeneric");
}

TEST_CASE("TC35_WasmAddEntryToSet") {
    RunTest("TC35_WasmAddEntryToSet");
}

TEST_CASE("TC36_WasmPaymentV2") {
    RunTest("TC36_WasmPaymentV2");
}

TEST_CASE("TC37_WasmMetadataText") {
    std::string registry_with_meta = ReadFileToString("testdata/registry.json");
    size_t pos = registry_with_meta.find("\"title\": \"John's Driving License\"");
    if (pos != std::string::npos) {
        registry_with_meta.insert(pos, "\"metadata_display_text\": \"Verified Member\", ");
    }
    
    RunTest("TC37_WasmMetadataText", registry_with_meta);
}

TEST_CASE("TC39_MatchMostPreferredSupportedProtocolAvailable") {
    json reg = json::parse(ReadFileToString("testdata/registry.json"));
    reg["supported_protocols"] = {"openid4vp-v1-signed", "openid4vp-v1-unsigned"};
    RunTest("TC39_MatchMostPreferredSupportedProtocolAvailable", reg.dump());
}

TEST_CASE("TC40_NoMatchIfNoRequestsForSupportedProtocols") {
    json reg = json::parse(ReadFileToString("testdata/registry.json"));
    reg["supported_protocols"] = {"openid4vp-v1-signed"};
    RunTest("TC40_NoMatchIfNoRequestsForSupportedProtocols", reg.dump());
}