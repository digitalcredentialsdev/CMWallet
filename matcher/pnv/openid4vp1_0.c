#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../cJSON/cJSON.h"
#include "../credentialmanager.h"

#include "../base64.h"
#include "../dcql.h"
#include "../icon.h"

#define PROTOCOL_OPENID4VP_1_0_UNSIGNED "openid4vp-v1-unsigned"
#define PROTOCOL_OPENID4VP_1_0_SIGNED "openid4vp-v1-signed"
// TODO: #define PROTOCOL_OPENID4VP_1_0_MULTISIGNED "openid4vp-v1-multisigned"

cJSON *GetDCRequestJson()
{
    uint32_t request_size;
    GetRequestSize(&request_size);
    char *request_json = malloc(request_size);
    GetRequestBuffer(request_json);
    return cJSON_Parse(request_json);
}

cJSON *GetCredsJson()
{
    uint32_t credentials_size;
    GetCredentialsSize(&credentials_size);
    char *creds_json = malloc(credentials_size);
    ReadCredentialsBuffer(creds_json, 0, credentials_size);
    return cJSON_Parse(creds_json);
}

void report_credential_set_length(char* set_id, int curr_length, int curr_set_idx, cJSON *matched_credential_sets, int credential_sets_length) {
    if (curr_set_idx == credential_sets_length) {
        AddEntrySet(set_id, curr_length);
    } else if (curr_set_idx < credential_sets_length) {
        cJSON *matched_credential_set = cJSON_GetArrayItem(matched_credential_sets, curr_set_idx);
        cJSON *matched_option;
        cJSON_ArrayForEach(matched_option, matched_credential_set) {
            cJSON *matched_credential_ids = cJSON_GetObjectItemCaseSensitive(matched_option, "matched_credential_ids");
            int option_size = cJSON_GetArraySize(matched_credential_ids);
            report_credential_set_length(set_id, option_size + curr_length, curr_set_idx + 1, matched_credential_sets, credential_sets_length);
        }
    } else {
        printf("Unexpected curr_set_idx %d\n", curr_set_idx);
    }
}

void report_matched_credential(uint32_t wasm_version, cJSON* matched_doc, cJSON* matched_credential_id, int doc_idx, int request_id, char* set_id, char* dcql_set_idx, char* dcql_option_idx, char *creds_blob, cJSON* transaction_credential_ids, char* merchant_name, char* transaction_amount, char* additional_info) {
    cJSON *matched_credential = cJSON_GetObjectItem(matched_doc, "matched");
    cJSON *c;
    cJSON_ArrayForEach(c, matched_credential)
    {
        printf("cred %s\n", cJSON_Print(c));
        cJSON *metadata_object = cJSON_CreateObject();
        char *matched_id = cJSON_GetStringValue(cJSON_GetObjectItem(c, "id"));

        cJSON_AddItemReferenceToObject(metadata_object, "claims", cJSON_GetObjectItem(c, "matched_claim_metadata"));
        cJSON_AddItemReferenceToObject(metadata_object, "dc_request_index", cJSON_CreateNumber(request_id));
        cJSON_AddItemReferenceToObject(metadata_object, "dcql_cred_id", matched_credential_id);
        if (dcql_set_idx != NULL && strlen(dcql_set_idx) > 0) {
            cJSON_AddStringToObject(metadata_object, "dcql_credential_set_index", dcql_set_idx);
            cJSON_AddStringToObject(metadata_object, "dcql_option_index", dcql_option_idx);
        }
        char *metadata = cJSON_PrintUnformatted(metadata_object);

        // if (transaction_credential_ids != NULL)
        // {
        //     printf("transaction cred ids %s\n", cJSON_Print(transaction_credential_ids));
        //     cJSON *transaction_credential_id;
        //     cJSON_ArrayForEach(transaction_credential_id, transaction_credential_ids)
        //     {
        //         printf("comparing cred id %s with transaction cred id %s.\n", cJSON_Print(matched_credential_id), cJSON_Print(transaction_credential_id));
        //         if (cJSON_Compare(transaction_credential_id, matched_credential_id, cJSON_True))
        //         {
        //             cJSON* c_display = cJSON_GetObjectItem(cJSON_GetObjectItem(c, "display"), "verification");
        //             char *title = cJSON_GetStringValue(cJSON_GetObjectItem(c_display, "title"));
        //             char *subtitle = cJSON_GetStringValue(cJSON_GetObjectItem(c_display, "subtitle"));
        //             cJSON *icon = cJSON_GetObjectItem(c_display, "icon");
        //             printf("transaction cred ids %s\n", cJSON_Print(transaction_credential_ids));

        //             double icon_start = (cJSON_GetNumberValue(cJSON_GetObjectItem(icon, "start")));
        //             int icon_start_int = icon_start;
        //             printf("icon_start int %d, double %f\n", icon_start_int, icon_start);
        //             int icon_len = (int)(cJSON_GetNumberValue(cJSON_GetObjectItem(icon, "length")));

        //             if (wasm_version >= 3)
        //             {
        //                 AddPaymentEntryToSetV2(matched_id, merchant_name, title, subtitle, creds_blob + icon_start_int, icon_len, transaction_amount, NULL, 0, NULL, 0, additional_info, metadata, set_id, doc_idx);
        //             }
        //             else if (wasm_version == 2)
        //             {
        //                 AddPaymentEntryToSet(matched_id, merchant_name, title, subtitle, creds_blob + icon_start_int, icon_len, transaction_amount, NULL, 0, NULL, 0, metadata, set_id, doc_idx);
        //             }
        //             else
        //             { // TODO: remove
        //                 cJSON *id_obj = cJSON_CreateObject();
        //                 cJSON_AddItemReferenceToObject(id_obj, "id", cJSON_GetObjectItem(c, "id"));
        //                 cJSON_AddItemReferenceToObject(id_obj, "dcql_cred_id", cJSON_GetObjectItem(matched_doc, "id"));
        //                 cJSON_AddItemReferenceToObject(id_obj, "provider_idx", cJSON_CreateNumber(request_id));
        //                 char *id = cJSON_PrintUnformatted(id_obj);
        //                 AddPaymentEntry(matched_id, merchant_name, title, subtitle, creds_blob + icon_start_int, icon_len, transaction_amount, NULL, 0, NULL, 0);
        //             }
        //         }
        //         break;
        //     }
        // }
        // else
        // {
            char *title = cJSON_GetStringValue(cJSON_GetObjectItem(c, "title"));
            char *subtitle = cJSON_GetStringValue(cJSON_GetObjectItem(c, "subtitle"));
            char *disclaimer = cJSON_GetStringValue(cJSON_GetObjectItem(c, "disclaimer"));
            char *verifier_terms_prefix = cJSON_GetStringValue(cJSON_GetObjectItem(c, "verifier_terms_prefix"));
            char *aggregator_consent = cJSON_GetStringValue(cJSON_GetObjectItem(c, "aggregator_consent"));
            char *aggregator_policy_url = cJSON_GetStringValue(cJSON_GetObjectItem(c, "aggregator_policy_url"));
            char *aggregator_policy_text = cJSON_GetStringValue(cJSON_GetObjectItem(c, "aggregator_policy_text"));
            cJSON *icon = cJSON_GetObjectItem(c, "icon");
            int icon_start_int = 0;
            int icon_len = 0;
            if (icon != NULL)
            {
                cJSON *start = cJSON_GetObjectItem(icon, "start");
                cJSON *length = cJSON_GetObjectItem(icon, "length");
                if (start != NULL && length != NULL)
                {
                    double icon_start = (cJSON_GetNumberValue(start));
                    icon_start_int = icon_start;
                    icon_len = (int)(cJSON_GetNumberValue(length));
                }
            }
            printf("Adding entry with id: %s\n", matched_id);
            AddEntryToSet(matched_id, creds_blob + icon_start_int, icon_len, title, subtitle, disclaimer, NULL, metadata, set_id, doc_idx);

            if (aggregator_consent != NULL && verifier_terms_prefix != NULL)
            {
                size_t prefix_len = strlen(verifier_terms_prefix);
                size_t aggregator_consent_len = strlen(aggregator_consent);
                char *consent_msg = (char *)malloc(prefix_len + aggregator_consent_len + 1);
                strcpy(consent_msg, verifier_terms_prefix);
                strcat(consent_msg, aggregator_consent);
                consent_msg[prefix_len + aggregator_consent_len] = '\0';
                SetAdditionalDisclaimerAndUrlForVerificationEntryInCredentialSet(matched_id, consent_msg, aggregator_policy_text, aggregator_policy_url, set_id, doc_idx);
            }
            else
            {
                SetAdditionalDisclaimerAndUrlForVerificationEntryInCredentialSet(matched_id, aggregator_consent, aggregator_policy_text, aggregator_policy_url, set_id, doc_idx);
            }
            cJSON *matched_claim_names = cJSON_GetObjectItem(c, "matched_claim_names");
            cJSON *claim;
            cJSON_ArrayForEach(claim, matched_claim_names)
            {
                printf("Add field for id %s, claim value: %s\n", matched_id, cJSON_Print(claim));
                AddFieldToEntrySet(matched_id, cJSON_GetStringValue(claim), NULL, set_id, doc_idx);
            }
        // }
    }
}

void report_matched_credential_set(char* set_id, int curr_set_idx, cJSON *matched_credential_sets, int curr_doc_idx, int credential_sets_length, uint32_t wasm_version, cJSON* matched_docs, int request_id, char *creds_blob, cJSON* transaction_credential_ids, char* merchant_name, char* transaction_amount, char* additional_info) {
    if (curr_set_idx < credential_sets_length) {
        cJSON *matched_credential_set = cJSON_GetArrayItem(matched_credential_sets, curr_set_idx);
        cJSON *matched_option;
        cJSON_ArrayForEach(matched_option, matched_credential_set) {
            cJSON *curr_matched_credential_ids = cJSON_GetObjectItemCaseSensitive(matched_option, "matched_credential_ids");
            char *dcql_set_idx = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(matched_option, "set_id")); // TODO
            char *dcql_option_idx = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(matched_option, "option_id"));
            cJSON *matched_doc;
            cJSON *matched_credential_id;
            int new_doc_idx = curr_doc_idx;
            cJSON_ArrayForEach(matched_credential_id, curr_matched_credential_ids)
            {
                printf("matched_credential_id %s\n", cJSON_GetStringValue(matched_credential_id));
                matched_doc = cJSON_GetObjectItemCaseSensitive(matched_docs, cJSON_GetStringValue(matched_credential_id));
                report_matched_credential(wasm_version, matched_doc, matched_credential_id, new_doc_idx, request_id, set_id, dcql_set_idx, dcql_option_idx, creds_blob, transaction_credential_ids, merchant_name, transaction_amount, additional_info);
                ++new_doc_idx;
            }

            ++curr_set_idx;
            report_matched_credential_set(set_id, curr_set_idx, matched_credential_sets, new_doc_idx, credential_sets_length, wasm_version, matched_docs, request_id, creds_blob, transaction_credential_ids, merchant_name, transaction_amount, additional_info);
        }
    }
}

#if defined(__wasm__)
int main()
#else
int openid_main()
#endif
{
    printf("Telephony matcher\n");
    uint32_t credentials_size;
    GetCredentialsSize(&credentials_size);

    char *creds_blob = malloc(credentials_size);
    ReadCredentialsBuffer(creds_blob, 0, credentials_size);

    int json_offset = *((int *)creds_blob);
    printf("Creds JSON offset %d\n", json_offset);

    cJSON *creds = cJSON_Parse(creds_blob + json_offset);
    cJSON *credential_store = cJSON_GetObjectItem(creds, "credentials");
    printf("Creds JSON %s\n", cJSON_Print(credential_store));

    cJSON *dc_request = GetDCRequestJson();
    printf("Request JSON %s\n", cJSON_Print(dc_request));

    uint32_t wasm_version;
    GetWasmVersion(&wasm_version);
    printf("Wasm version %u\n", wasm_version);

    // Parse each top level request looking for OpenID4VP requests
    cJSON_bool is_modern_request = cJSON_HasObjectItem(dc_request, "requests");
    cJSON *requests;
    if (is_modern_request)
    {
        requests = cJSON_GetObjectItem(dc_request, "requests");
    }
    else
    {
        requests = cJSON_GetObjectItem(dc_request, "providers");
    }
    int requests_size = cJSON_GetArraySize(requests);

    int matched = 0;
    int should_offer_issuance = 0;
    char *merchant_name = NULL;
    char *transaction_amount = NULL;
    char *additional_info = NULL;
    for (int i = 0; i < requests_size; i++)
    {
        cJSON *request = cJSON_GetArrayItem(requests, i);
        // printf("Request %s\n", cJSON_Print(request));

        char *protocol = cJSON_GetStringValue(cJSON_GetObjectItem(request, "protocol"));
        if (strcmp(protocol, PROTOCOL_OPENID4VP_1_0_UNSIGNED) == 0 || strcmp(protocol, PROTOCOL_OPENID4VP_1_0_SIGNED) == 0)
        {
            // We have an OpenID4VP request
            cJSON *data_json;
            if (is_modern_request)
            {
                data_json = cJSON_GetObjectItem(request, "data");
                if (cJSON_IsString(data_json))
                { // Legacy spec
                    char *data_json_string = cJSON_GetStringValue(data_json);
                    data_json = cJSON_Parse(data_json_string);
                }
            }
            else
            { // Legacy spec
                cJSON *data = cJSON_GetObjectItem(request, "request");
                char *data_json_string = cJSON_GetStringValue(data);
                data_json = cJSON_Parse(data_json_string);
            }

            if (strcmp(protocol, PROTOCOL_OPENID4VP_1_0_SIGNED) == 0)
            {
                cJSON *signed_request = cJSON_GetObjectItem(data_json, "request");
                char *signed_request_string = cJSON_GetStringValue(signed_request);
                int delimiter = '.';
                char *payload_start = strchr(signed_request_string, delimiter);
                payload_start++;
                char *payload_end = strchr(payload_start, delimiter);
                *payload_end = '\0';
                char *decoded_request_json;
                int decoded_request_json_len = B64DecodeURL(payload_start, &decoded_request_json);
                data_json = cJSON_Parse(decoded_request_json);
            }
            cJSON *query = cJSON_GetObjectItem(data_json, "dcql_query");
            if (cJSON_HasObjectItem(data_json, "offer"))
            {
                should_offer_issuance = 1;
            }

            // For now we only support one transaction data item

            cJSON *transaction_data_list = cJSON_GetObjectItem(data_json, "transaction_data");

            cJSON *transaction_data = NULL;
            cJSON *transaction_credential_ids = NULL;
            if (transaction_data_list != NULL)
            {
                if (cJSON_GetArraySize(transaction_data_list) == 1)
                {
                    cJSON *transaction_data_encoded = cJSON_GetArrayItem(transaction_data_list, 0);
                    char *transaction_data_encoded_str = cJSON_GetStringValue(transaction_data_encoded);
                    char *transaction_data_json;
                    int transaction_data_json_len = B64DecodeURL(transaction_data_encoded_str, &transaction_data_json);
                    transaction_data = cJSON_Parse(transaction_data_json);
                    transaction_credential_ids = cJSON_GetObjectItem(transaction_data, "credential_ids");
                    merchant_name = cJSON_GetStringValue(cJSON_GetObjectItem(transaction_data, "merchant_name"));
                    transaction_amount = cJSON_GetStringValue(cJSON_GetObjectItem(transaction_data, "amount"));
                }
            }

            cJSON *matched_result = dcql_query(query, credential_store);
            cJSON *matched_credential_sets = cJSON_GetObjectItemCaseSensitive(matched_result, "matched_credential_sets");
            cJSON *matched_docs = cJSON_GetObjectItemCaseSensitive(matched_result, "matched_credentials");
            // printf("matched_creds %d\n", cJSON_GetArraySize(matched_creds));
            //            printf("matched_creds %s\n", cJSON_Print(cJSON_GetArrayItem(matched_creds,0)));

            int matched_credential_sets_size = cJSON_GetArraySize(matched_credential_sets);
            if (matched_credential_sets_size > 0) { // Some credential(s) matched
                cJSON *first_matched_credential_set = cJSON_GetArrayItem(matched_credential_sets, 0);
                cJSON *matched_option;
                cJSON_ArrayForEach(matched_option, first_matched_credential_set) {
                    cJSON *matched_credential_ids = cJSON_GetObjectItemCaseSensitive(matched_option, "matched_credential_ids");
                    int credential_set_size = cJSON_GetArraySize(matched_credential_ids);
                    char set_id_buffer[26];
                    
                    if (cJSON_HasObjectItem(matched_option, "set_id")) {
                        char *set_idx = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(matched_option, "set_id"));
                        char *option_idx = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(matched_option, "option_id"));
                        int chars_written = sprintf(set_id_buffer, "req:%d;set:%s;option:%s", i, set_idx, option_idx);
                        if (wasm_version > 1) { // Report set length
                            report_credential_set_length(set_id_buffer, credential_set_size, 1, matched_credential_sets, matched_credential_sets_size);
                        }
                        cJSON *matched_doc;
                        cJSON *matched_credential_id;
                        int doc_idx = 0;
                        cJSON_ArrayForEach(matched_credential_id, matched_credential_ids)
                        {
                            printf("matched_credential_id %s\n", cJSON_GetStringValue(matched_credential_id));
                            matched_doc = cJSON_GetObjectItemCaseSensitive(matched_docs, cJSON_GetStringValue(matched_credential_id));
                            report_matched_credential(wasm_version, matched_doc, matched_credential_id, doc_idx, i, set_id_buffer, set_idx, option_idx, creds_blob, transaction_credential_ids, merchant_name, transaction_amount, additional_info);
                            ++doc_idx;
                        }
                        report_matched_credential_set(set_id_buffer, 1, matched_credential_sets, doc_idx, matched_credential_sets_size, wasm_version, matched_docs, i, creds_blob, transaction_credential_ids, merchant_name, transaction_amount, additional_info);
                    } else { // No credential_sets present in dcql
                        int chars_written = sprintf(set_id_buffer, "req:%d;null", i);
                        if (wasm_version > 1) { // Report set length
                            AddEntrySet(set_id_buffer, credential_set_size);
                        }

                        cJSON *matched_doc;
                        cJSON *matched_credential_id;
                        int doc_idx = 0;
                        cJSON_ArrayForEach(matched_credential_id, matched_credential_ids)
                        {
                            printf("matched_credential_id %s\n", cJSON_GetStringValue(matched_credential_id));
                            matched_doc = cJSON_GetObjectItemCaseSensitive(matched_docs, cJSON_GetStringValue(matched_credential_id));
                            report_matched_credential(wasm_version, matched_doc, matched_credential_id, doc_idx, i, set_id_buffer, NULL, NULL, creds_blob, transaction_credential_ids, merchant_name, transaction_amount, additional_info);
                            ++doc_idx;
                        }
                    }
                }
            }
        }
    }
    return 0;
}