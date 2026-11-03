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
#define PROTOCOL_OPENID4VP_1_0_MULTISIGNED "openid4vp-v1-multisigned"

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

static int is_user_verification_requested(cJSON *data_json, cJSON *query, cJSON *matched_credential_id) {
    if (data_json != NULL) {
        cJSON *uv = cJSON_GetObjectItemCaseSensitive(data_json, "user_verification");
        if (uv != NULL) {
            if (cJSON_IsString(uv) && uv->valuestring != NULL && strcmp(uv->valuestring, "discouraged") != 0) {
                return 1;
            }
            if (cJSON_IsTrue(uv)) {
                return 1;
            }
        }
    }

    if (query != NULL) {
        cJSON *credentials = cJSON_GetObjectItemCaseSensitive(query, "credentials");
        if (credentials != NULL && cJSON_IsArray(credentials)) {
            cJSON *cred;
            const char *matched_id_str = cJSON_IsString(matched_credential_id) ? matched_credential_id->valuestring : NULL;
            cJSON_ArrayForEach(cred, credentials) {
                cJSON *cred_id = cJSON_GetObjectItemCaseSensitive(cred, "id");
                if (matched_id_str != NULL && cred_id != NULL && cJSON_IsString(cred_id)) {
                    if (strcmp(cred_id->valuestring, matched_id_str) != 0) {
                        continue;
                    }
                }

                cJSON *cred_uv = cJSON_GetObjectItemCaseSensitive(cred, "user_verification");
                if (cred_uv != NULL) {
                    if (cJSON_IsString(cred_uv) && cred_uv->valuestring != NULL && strcmp(cred_uv->valuestring, "discouraged") != 0) {
                        return 1;
                    }
                    if (cJSON_IsTrue(cred_uv)) {
                        return 1;
                    }
                }

                cJSON *claims = cJSON_GetObjectItemCaseSensitive(cred, "claims");
                if (claims != NULL && cJSON_IsArray(claims)) {
                    cJSON *claim;
                    cJSON_ArrayForEach(claim, claims) {
                        cJSON *path = cJSON_GetObjectItemCaseSensitive(claim, "path");
                        if (path != NULL) {
                            if (cJSON_IsArray(path)) {
                                cJSON *path_elem;
                                cJSON_ArrayForEach(path_elem, path) {
                                    if (cJSON_IsString(path_elem) && path_elem->valuestring != NULL) {
                                        if (strcmp(path_elem->valuestring, "user_verification_hint") == 0) {
                                            return 1;
                                        }
                                    }
                                }
                            } else if (cJSON_IsString(path) && path->valuestring != NULL) {
                                if (strcmp(path->valuestring, "user_verification_hint") == 0) {
                                    return 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    return 0;
}

// Effective delegation type of a matched registry credential: FULL only if the runtime supports
// delegation (wasm >= 7), the credential was registered with delegation_type FULL (1) and the
// verifier did not request user verification (which forces the provider UI).
static int is_entry_fully_delegated(cJSON *c, uint32_t wasm_version, cJSON *data_json, cJSON *query, cJSON *matched_credential_id) {
    if (wasm_version < 7) {
        return 0;
    }
    cJSON *del_type_item = cJSON_GetObjectItemCaseSensitive(c, "delegation_type");
    int entry_del_type = (del_type_item != NULL && cJSON_IsNumber(del_type_item)) ? del_type_item->valueint : 0;
    if (entry_del_type != 1) {
        return 0;
    }
    return !is_user_verification_requested(data_json, query, matched_credential_id);
}

// Returns 1 if the option contributes at least one entry to an entry set, given whether only
// fully delegated entries may be reported.
static int option_has_reportable_entry(cJSON *matched_option, cJSON *matched_docs, int only_fully_delegated, uint32_t wasm_version, cJSON *data_json, cJSON *query) {
    cJSON *matched_credential_ids = cJSON_GetObjectItemCaseSensitive(matched_option, "matched_credential_ids");
    cJSON *matched_credential_id;
    cJSON_ArrayForEach(matched_credential_id, matched_credential_ids) {
        cJSON *matched_doc = cJSON_GetObjectItemCaseSensitive(matched_docs, cJSON_GetStringValue(matched_credential_id));
        if (matched_doc == NULL) {
            continue;
        }
        cJSON *c;
        cJSON_ArrayForEach(c, cJSON_GetObjectItem(matched_doc, "matched")) {
            if (!only_fully_delegated || is_entry_fully_delegated(c, wasm_version, data_json, query, matched_credential_id)) {
                return 1;
            }
        }
    }
    return 0;
}

void report_matched_credential(uint32_t wasm_version, cJSON* matched_doc, cJSON* matched_credential_id, int doc_idx, int request_id, char* set_id, char* dcql_set_idx, char* dcql_option_idx, char *creds_blob, cJSON* transaction_credential_ids, char* merchant_name, char* transaction_amount, char* additional_info, int only_fully_delegated, cJSON *data_json, cJSON *query) {
    if (matched_doc == NULL) {
        return;
    }
    cJSON *matched_credential = cJSON_GetObjectItem(matched_doc, "matched");
    cJSON *c;
    cJSON_ArrayForEach(c, matched_credential)
    {
        printf("cred %s\n", cJSON_Print(c));
        char *matched_id = cJSON_GetStringValue(cJSON_GetObjectItem(c, "id"));
        int fully_delegated = is_entry_fully_delegated(c, wasm_version, data_json, query, matched_credential_id);
        if (only_fully_delegated && !fully_delegated) {
            // The entry set is partial: this entry could only be fulfilled through our own UI,
            // which Credential Manager cannot combine with other providers' entries.
            printf("Skipping entry %s: not fully delegated and the entry set is partial\n", matched_id);
            continue;
        }
        cJSON *metadata_object = cJSON_CreateObject();

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
        //
        //             double icon_start = (cJSON_GetNumberValue(cJSON_GetObjectItem(icon, "start")));
        //             int icon_start_int = icon_start;
        //             printf("icon_start int %d, double %f\n", icon_start_int, icon_start);
        //             int icon_len = (int)(cJSON_GetNumberValue(cJSON_GetObjectItem(icon, "length")));
        //
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
            if (fully_delegated) {
                SetDelegationTypeForEntryInSet(matched_id, 1, set_id, doc_idx);
            }
            char *dedup_id = cJSON_GetStringValue(cJSON_GetObjectItem(c, "dedupId"));
            cJSON *rank_item = cJSON_GetObjectItem(c, "rank");
            int rank = rank_item != NULL ? (int)cJSON_GetNumberValue(rank_item) : 0;
            if (wasm_version >= 10 && (dedup_id != NULL || rank_item != NULL)) {
                SetDedupIdAndRankForEntryInSet(matched_id, dedup_id, rank, set_id, doc_idx);
            }
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

#define MAX_CREDENTIAL_SETS 16

static int get_option_length(cJSON *matched_option) {
    return cJSON_HasObjectItem(matched_option, "option_length") ?
        cJSON_GetObjectItem(matched_option, "option_length")->valueint :
        cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(matched_option, "matched_credential_ids"));
}

// Reports one combination of options (one option per matched credential set) as a single entry
// set. The set is declared with the sum of the verifier's option lengths and every credential is
// placed at its requested index, so that a partial match leaves gaps for other providers.
//
// If this provider matched every credential of the combination, the entry set is complete and all
// entries are reported, regardless of delegation type. Otherwise only fully delegated entries are
// reported: the missing slots can only be filled by other providers, which Credential Manager does
// exclusively for fully delegated entries, so this provider's non-delegated entries (which would
// need its own UI) could never be combined with them. If nothing remains, the entry set is not
// declared at all.
static void report_option_combination(int request_id, cJSON **selected_options, int num_sets, uint32_t wasm_version, cJSON *matched_docs, char *creds_blob, cJSON *transaction_credential_ids, char *merchant_name, char *transaction_amount, char *additional_info, cJSON *data_json, cJSON *query) {
    char set_id_buffer[256];
    int pos = snprintf(set_id_buffer, sizeof(set_id_buffer), "req:%d", request_id);
    int has_explicit_set = 0;
    int is_partial = 0;
    int total_length = 0;
    for (int s = 0; s < num_sets; ++s) {
        cJSON *matched_option = selected_options[s];
        if (cJSON_HasObjectItem(matched_option, "set_id")) {
            has_explicit_set = 1;
            pos += snprintf(set_id_buffer + pos, sizeof(set_id_buffer) - pos, ";set:%s;option:%s",
                cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(matched_option, "set_id")),
                cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(matched_option, "option_id")));
            if (pos >= (int)sizeof(set_id_buffer)) {
                printf("Credential set id too long, skipping combination\n");
                return;
            }
        }
        if (cJSON_IsTrue(cJSON_GetObjectItem(matched_option, "is_partial"))) {
            is_partial = 1;
        }
        total_length += get_option_length(matched_option);
    }
    if (!has_explicit_set) { // No credential_sets present in dcql
        snprintf(set_id_buffer + pos, sizeof(set_id_buffer) - pos, ";null");
    }

    int only_fully_delegated = is_partial;
    int reportable = 0;
    for (int s = 0; s < num_sets && !reportable; ++s) {
        reportable = option_has_reportable_entry(selected_options[s], matched_docs, only_fully_delegated, wasm_version, data_json, query);
    }
    if (!reportable) {
        printf("Skipping partial entry set %s: no fully delegated entries\n", set_id_buffer);
        return;
    }

    if (wasm_version > 1) { // Report set length
        AddEntrySet(set_id_buffer, total_length);
    }

    int option_offset = 0;
    for (int s = 0; s < num_sets; ++s) {
        cJSON *matched_option = selected_options[s];
        cJSON *matched_credential_ids = cJSON_GetObjectItemCaseSensitive(matched_option, "matched_credential_ids");
        cJSON *matched_indices = cJSON_GetObjectItem(matched_option, "matched_indices");
        char *dcql_set_idx = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(matched_option, "set_id"));
        char *dcql_option_idx = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(matched_option, "option_id"));
        cJSON *matched_credential_id;
        int k = 0;
        cJSON_ArrayForEach(matched_credential_id, matched_credential_ids)
        {
            int doc_idx = option_offset + (matched_indices ? cJSON_GetArrayItem(matched_indices, k)->valueint : k);
            printf("matched_credential_id %s\n", cJSON_GetStringValue(matched_credential_id));
            cJSON *matched_doc = cJSON_GetObjectItemCaseSensitive(matched_docs, cJSON_GetStringValue(matched_credential_id));
            report_matched_credential(wasm_version, matched_doc, matched_credential_id, doc_idx, request_id, set_id_buffer, dcql_set_idx, dcql_option_idx, creds_blob, transaction_credential_ids, merchant_name, transaction_amount, additional_info, only_fully_delegated, data_json, query);
            ++k;
        }
        option_offset += get_option_length(matched_option);
    }
}

// Enumerates the Cartesian product of the matched options across all credential sets and reports
// each combination as its own entry set.
static void report_option_combinations(int request_id, cJSON *matched_credential_sets, int num_sets, int set_idx, cJSON **selected_options, uint32_t wasm_version, cJSON *matched_docs, char *creds_blob, cJSON *transaction_credential_ids, char *merchant_name, char *transaction_amount, char *additional_info, cJSON *data_json, cJSON *query) {
    if (set_idx == num_sets) {
        report_option_combination(request_id, selected_options, num_sets, wasm_version, matched_docs, creds_blob, transaction_credential_ids, merchant_name, transaction_amount, additional_info, data_json, query);
        return;
    }
    cJSON *matched_credential_set = cJSON_GetArrayItem(matched_credential_sets, set_idx);
    cJSON *matched_option;
    cJSON_ArrayForEach(matched_option, matched_credential_set) {
        selected_options[set_idx] = matched_option;
        report_option_combinations(request_id, matched_credential_sets, num_sets, set_idx + 1, selected_options, wasm_version, matched_docs, creds_blob, transaction_credential_ids, merchant_name, transaction_amount, additional_info, data_json, query);
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
        if (strcmp(protocol, PROTOCOL_OPENID4VP_1_0_UNSIGNED) == 0 || strcmp(protocol, PROTOCOL_OPENID4VP_1_0_SIGNED) == 0 || strcmp(protocol, PROTOCOL_OPENID4VP_1_0_MULTISIGNED) == 0)
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
            else if (strcmp(protocol, PROTOCOL_OPENID4VP_1_0_MULTISIGNED) == 0)
            {
                cJSON *multisigned_request = cJSON_GetObjectItem(data_json, "request");
                cJSON *jws_json = multisigned_request;
                if (multisigned_request != NULL && cJSON_IsString(multisigned_request))
                {
                    jws_json = cJSON_Parse(cJSON_GetStringValue(multisigned_request));
                }
                if (jws_json == NULL)
                {
                    jws_json = data_json;
                }
                cJSON *payload_obj = cJSON_GetObjectItem(jws_json, "payload");
                if (payload_obj != NULL && cJSON_IsString(payload_obj))
                {
                    char *payload_string = cJSON_GetStringValue(payload_obj);
                    char *decoded_request_json;
                    int decoded_request_json_len = B64DecodeURL(payload_string, &decoded_request_json);
                    data_json = cJSON_Parse(decoded_request_json);
                }
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

            int num_sets = cJSON_GetArraySize(matched_credential_sets);
            if (num_sets > MAX_CREDENTIAL_SETS) {
                printf("Too many credential sets (%d), skipping request\n", num_sets);
            } else if (num_sets > 0) { // Some credential(s) matched
                cJSON *selected_options[MAX_CREDENTIAL_SETS];
                report_option_combinations(i, matched_credential_sets, num_sets, 0, selected_options, wasm_version, matched_docs, creds_blob, transaction_credential_ids, merchant_name, transaction_amount, additional_info, data_json, query);
            }
        }
    }
    return 0;
}