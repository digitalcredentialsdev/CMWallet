#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "cJSON/cJSON.h"
#include "credentialmanager.h"

#include "base64.h"
#include "dcql.h"
#include "icon.h"

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

        if (transaction_credential_ids != NULL)
        {
            printf("transaction cred ids %s\n", cJSON_Print(transaction_credential_ids));
            cJSON *transaction_credential_id;
            cJSON_ArrayForEach(transaction_credential_id, transaction_credential_ids)
            {
                printf("comparing cred id %s with transaction cred id %s.\n", cJSON_Print(matched_credential_id), cJSON_Print(transaction_credential_id));
                if (cJSON_Compare(transaction_credential_id, matched_credential_id, cJSON_True))
                {
                    cJSON* c_display = cJSON_GetObjectItem(cJSON_GetObjectItem(c, "display"), "verification");
                    char *title = cJSON_GetStringValue(cJSON_GetObjectItem(c_display, "title"));
                    char *subtitle = cJSON_GetStringValue(cJSON_GetObjectItem(c_display, "subtitle"));
                    cJSON *icon = cJSON_GetObjectItem(c_display, "icon");
                    printf("transaction cred ids %s\n", cJSON_Print(transaction_credential_ids));

                    double icon_start = (cJSON_GetNumberValue(cJSON_GetObjectItem(icon, "start")));
                    int icon_start_int = icon_start;
                    printf("icon_start int %d, double %f\n", icon_start_int, icon_start);
                    int icon_len = (int)(cJSON_GetNumberValue(cJSON_GetObjectItem(icon, "length")));

                    if (wasm_version >= 3)
                    {
                        printf("[MATCHER] MATCH SUCCESS! Calling AddPaymentEntryToSetV2 for ID: %s, Merchant: %s, Amount: %s\n",
                               matched_id ? matched_id : "NULL",
                               merchant_name ? merchant_name : "NULL",
                               transaction_amount ? transaction_amount : "NULL");
                        AddPaymentEntryToSetV2(matched_id, merchant_name, title, subtitle, creds_blob + icon_start_int, icon_len, transaction_amount, NULL, 0, NULL, 0, additional_info, metadata, set_id, doc_idx);
                    }
                    else if (wasm_version == 2)
                    {
                        AddPaymentEntryToSet(matched_id, merchant_name, title, subtitle, creds_blob + icon_start_int, icon_len, transaction_amount, NULL, 0, NULL, 0, metadata, set_id, doc_idx);
                    }
                    else
                    {
                        AddPaymentEntry(matched_id, merchant_name, title, subtitle, creds_blob + icon_start_int, icon_len, transaction_amount, NULL, 0, NULL, 0);
                    }
                }
                break;
            }
        }
        else
        {
            cJSON* c_display = cJSON_GetObjectItem(cJSON_GetObjectItem(c, "display"), "verification");
            char *title = cJSON_GetStringValue(cJSON_GetObjectItem(c_display, "title"));
            char *subtitle = cJSON_GetStringValue(cJSON_GetObjectItem(c_display, "subtitle"));
            char *explainer = cJSON_GetStringValue(cJSON_GetObjectItem(c_display, "explainer"));
            char *metadata_display_text = cJSON_GetStringValue(cJSON_GetObjectItem(c_display, "metadata_display_text"));
            cJSON *icon = cJSON_GetObjectItem(c_display, "icon");
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
            if (wasm_version > 1)
            {
                printf("AddEntryToSet %s, metadata: %s\n", matched_id, metadata);
                AddEntryToSet(matched_id, creds_blob + icon_start_int, icon_len, title, subtitle, explainer, NULL, metadata, set_id, doc_idx);
            }
            else
            {
                AddStringIdEntry(matched_id, creds_blob + icon_start_int, icon_len, title, subtitle, NULL, NULL);
            }
            cJSON *matched_claim_names = cJSON_GetObjectItem(c, "matched_claim_names");
            cJSON *claim;
            cJSON_ArrayForEach(claim, matched_claim_names)
            {
                char *claim_display = cJSON_GetStringValue(cJSON_GetObjectItem(cJSON_GetObjectItem(claim, "verification"), "display"));
                char *claim_value = cJSON_GetStringValue(cJSON_GetObjectItem(cJSON_GetObjectItem(claim, "verification"), "display_value"));
                if (wasm_version > 1)
                {
                    printf("AddFieldToEntrySet %s\n", matched_id);
                    AddFieldToEntrySet(matched_id, claim_display, claim_value, set_id, doc_idx);
                }
                else
                {
                    AddFieldForStringIdEntry(matched_id, claim_display, claim_value);
                }
            }
            if (wasm_version >= 5) {
                AddMetadataDisplayTextToEntrySet(matched_id, metadata_display_text, set_id, doc_idx);
            }
        }
    }
}

void report_matched_credential_set(char* set_id, int curr_set_idx, cJSON *matched_credential_sets, int curr_doc_idx, int credential_sets_length, uint32_t wasm_version, cJSON* matched_docs, int request_id, char *creds_blob, cJSON* transaction_credential_ids, char* merchant_name, char* transaction_amount, char* additional_info) {
    if (curr_set_idx < credential_sets_length) {
        cJSON *matched_credential_set = cJSON_GetArrayItem(matched_credential_sets, curr_set_idx);
        cJSON *matched_option;
        cJSON_ArrayForEach(matched_option, matched_credential_set) {
            cJSON *curr_matched_credential_ids = cJSON_GetObjectItemCaseSensitive(matched_option, "matched_credential_ids");
            char *dcql_set_idx = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(matched_option, "set_id"));
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

int main()
{
    uint32_t credentials_size;
    GetCredentialsSize(&credentials_size);
    printf("[OPENID_DEBUG] 1. Total credentials_size from host: %u\n", credentials_size);

    char *creds_blob = malloc(credentials_size);
    if (creds_blob == NULL) {
        printf("[OPENID_DEBUG] Error: Failed to allocate memory for creds_blob\n");
        return 1;
    }
    ReadCredentialsBuffer(creds_blob, 0, credentials_size);

    int json_offset = *((int *)creds_blob);
    printf("[OPENID_DEBUG] 2. Creds JSON offset calculated: %d\n", json_offset);

    if (json_offset >= credentials_size || json_offset < 0) {
        printf("[OPENID_DEBUG] FATAL ERROR: json_offset (%d) goes past buffer size (%u)!\n", json_offset, credentials_size);
        return 1;
    }

    printf("[OPENID_DEBUG] 3. Target address is valid. Attempting cJSON_Parse...\n");

    char* json_string_ptr = creds_blob + json_offset;

    char snapshot[21];
    strncpy(snapshot, json_string_ptr, 20);
    snapshot[20] = '\0';
    printf("[OPENID_DEBUG] 4. String snapshot at offset: %s\n", snapshot);

    cJSON *creds = cJSON_Parse(json_string_ptr);
    if (creds == NULL) {
        printf("[OPENID_DEBUG] FATAL ERROR: cJSON_Parse failed (Invalid JSON or missing null terminator)\n");
        return 1;
    }
    cJSON *credential_store = cJSON_GetObjectItem(creds, "credentials");
    printf("[OPENID_DEBUG] 5. Creds parsed successfully. Size: %d\n", cJSON_GetArraySize(credential_store));

    cJSON *dc_request = GetDCRequestJson();
    printf("[OPENID_DEBUG] 6. Request JSON fetched and parsed.\n");

    uint32_t wasm_version;
    GetWasmVersion(&wasm_version);
    printf("Wasm version %u\n", wasm_version);

    cJSON_bool is_modern_request = cJSON_HasObjectItem(dc_request, "requests");
    cJSON *requests;
    if (is_modern_request)
    {
        printf("[OPENID_DEBUG] 7. is_modern_requestd.\n");
        requests = cJSON_GetObjectItem(dc_request, "requests");
    }
    else
    {
        printf("[OPENID_DEBUG] 8. NOT is_modern_requestd.\n");
        requests = cJSON_GetObjectItem(dc_request, "providers");
    }
    int requests_size = cJSON_GetArraySize(requests);
    printf("[OPENID_DEBUG] request size %d\n", requests_size);

    int matched = 0;
    int should_offer_issuance = 0;
    char *merchant_name = NULL;
    char *transaction_amount = NULL;
    char *additional_info = NULL;

    for (int i = 0; i < requests_size; i++)
    {
        cJSON *request = cJSON_GetArrayItem(requests, i);
        printf("[OPENID_DEBUG] Request %s\n", cJSON_Print(request));

        char *protocol = cJSON_GetStringValue(cJSON_GetObjectItem(request, "protocol"));
        if (strcmp(protocol, PROTOCOL_OPENID4VP_1_0_UNSIGNED) == 0 || strcmp(protocol, PROTOCOL_OPENID4VP_1_0_SIGNED) == 0)
        {
            printf("[OPENID_DEBUG] 10. Protocol match 1.\n");

            cJSON *data_json;
            if (is_modern_request)
            {
                data_json = cJSON_GetObjectItem(request, "data");
                if (cJSON_IsString(data_json))
                {
                    char *data_json_string = cJSON_GetStringValue(data_json);
                    data_json = cJSON_Parse(data_json_string);
                }
            }
            else
            {
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

            cJSON *transaction_data_list = cJSON_GetObjectItem(data_json, "transaction_data");

            cJSON *transaction_data = NULL;
            cJSON *transaction_credential_ids = NULL;

            if (transaction_data_list == NULL) {
                printf("[OPENID_DEBUG] Transaction data null.\n");
            }

            if (transaction_data_list != NULL)
            {
                int td_count = cJSON_GetArraySize(transaction_data_list);
                printf("[OPENID_DEBUG] Found %d transaction_data items to decode.\n", td_count);

                for (int td_i = 0; td_i < td_count; td_i++)
                {
                    cJSON *transaction_data_encoded = cJSON_GetArrayItem(transaction_data_list, td_i);
                    char *transaction_data_encoded_str = cJSON_GetStringValue(transaction_data_encoded);

                    if (transaction_data_encoded_str == NULL) {
                        printf("[OPENID_DEBUG] Error: transaction_data[%d] is not a string.\n", td_i);
                        continue;
                    }
                    char *transaction_data_json = NULL;
                    printf("[OPENID_DEBUG] Attempting B64DecodeURL on item %d...\n", td_i);
                    int transaction_data_json_len = B64DecodeURL(transaction_data_encoded_str, &transaction_data_json);
                    printf("transaction data [%d] %s\n", td_i, transaction_data_json);

                    if (transaction_data_json == NULL || transaction_data_json_len <= 0) {
                        printf("[OPENID_DEBUG] Error: B64DecodeURL failed or returned empty on item %d.\n", td_i);
                        continue;
                    }
                    printf("[OPENID_DEBUG] Decode successful. Attempting cJSON_Parse...\n");

                    cJSON *td_item = cJSON_Parse(transaction_data_json);
                    if (td_item == NULL) {
                        printf("[OPENID_DEBUG] Error: cJSON_Parse failed on decoded string for item %d.\n", td_i);
                        free(transaction_data_json);
                        continue;
                    }
                    char *transaction_data_type = cJSON_GetStringValue(cJSON_GetObjectItem(td_item, "type"));
                    printf("[OPENID_DEBUG] Parsed transaction type: %s\n", transaction_data_type ? transaction_data_type : "NULL");

                    if (td_i == 0) {
                        transaction_data = td_item;
                        transaction_credential_ids = cJSON_GetObjectItem(td_item, "credential_ids");
                    }

                    if (transaction_data_type == NULL) {
                        // skip malformed item
                    } else if (strcmp(transaction_data_type, "urn:eudi:sca:payment:1") == 0) {
                        cJSON *payload = cJSON_GetObjectItem(td_item, "payload");
                        if (merchant_name == NULL)
                            merchant_name = cJSON_GetStringValue(cJSON_GetObjectItem(cJSON_GetObjectItem(payload, "payee"), "name"));
                        if (transaction_amount == NULL) {
                            transaction_amount = cJSON_GetStringValue(cJSON_GetObjectItem(payload, "amount_display"));
                            if (transaction_amount == NULL) {
                                double amount = cJSON_GetNumberValue(cJSON_GetObjectItem(payload, "amount"));
                                int length_for_amount = (int)log10(amount) + 1;
                                char *currency = cJSON_GetStringValue(cJSON_GetObjectItem(payload, "currency"));
                                int total_length = length_for_amount + 4 + (currency ? strlen(currency) : 3) + 2;
                                transaction_amount = malloc(total_length);
                                sprintf(transaction_amount, "%s %f", currency ? currency : "USD", amount);
                            }
                        }
                        if (additional_info == NULL)
                            additional_info = cJSON_GetStringValue(cJSON_GetObjectItem(td_item, "additional_info"));
                    } else if (strcmp(transaction_data_type, "payment_details") == 0) {
                        if (merchant_name == NULL)
                            merchant_name = cJSON_GetStringValue(cJSON_GetObjectItem(td_item, "payee_name"));
                        if (transaction_amount == NULL) {
                            char *amount = cJSON_GetStringValue(cJSON_GetObjectItem(td_item, "payment_amount"));
                            char *currency = cJSON_GetStringValue(cJSON_GetObjectItem(td_item, "payment_currency"));
                            if (amount && currency) {
                                transaction_amount = malloc(strlen(amount) + strlen(currency) + 2);
                                sprintf(transaction_amount, "%s %s", currency, amount);
                            }
                        }
                        if (additional_info == NULL)
                            additional_info = cJSON_GetStringValue(cJSON_GetObjectItem(td_item, "additional_info"));
                    } else if (strcmp(transaction_data_type, "delegate") == 0) {
                        // Handle delegate transaction data (AP2 flow).
                        // We extract mandate information and build additional_info for the UI.
                        cJSON *delegate_payload_arr = cJSON_GetObjectItem(td_item, "delegate_payload");
                        char *payee_name_val      = NULL;
                        char *amt_value_val       = NULL;
                        char *amt_currency_val    = NULL;
                        cJSON *checkout_jwt_payload = NULL;
                        int amt_value_allocated = 0;

                        if (delegate_payload_arr != NULL) {
                            int dp_count = cJSON_GetArraySize(delegate_payload_arr);
                            for (int dp_i = 0; dp_i < dp_count; dp_i++) {
                                cJSON *dp = cJSON_GetArrayItem(delegate_payload_arr, dp_i);
                                char *vct = cJSON_GetStringValue(cJSON_GetObjectItem(dp, "vct"));
                                if (vct == NULL) continue;

                                // Extract payment mandate details if present
                                if (strcmp(vct, "mandate.payment") == 0) {
                                    printf("[OPENID_DEBUG] Found mandate.payment\n");
                                    cJSON *payee = cJSON_GetObjectItem(dp, "payee");
                                    if (payee != NULL && payee_name_val == NULL)
                                        payee_name_val = cJSON_GetStringValue(cJSON_GetObjectItem(payee, "name"));
                                    cJSON *amount_obj = cJSON_GetObjectItem(dp, "payment_amount");
                                    if (amount_obj != NULL) {
                                        cJSON *amt_item = cJSON_GetObjectItem(amount_obj, "amount");
                                        if (amt_item != NULL && amt_value_val == NULL) {
                                            if (cJSON_IsNumber(amt_item)) {
                                                double amt = cJSON_GetNumberValue(amt_item);
                                                amt_value_val = malloc(32);
                                                snprintf(amt_value_val, 32, "%.0f", amt);
                                                amt_value_allocated = 1;
                                            } else {
                                                amt_value_val = cJSON_GetStringValue(amt_item);
                                            }
                                        }
                                        if (amt_currency_val == NULL)
                                            amt_currency_val = cJSON_GetStringValue(cJSON_GetObjectItem(amount_obj, "currency"));
                                    }
                                }
                                // Extract checkout mandate and decode checkout JWT if present
                                else if (strcmp(vct, "mandate.checkout") == 0) {
                                    printf("[OPENID_DEBUG] Found mandate.checkout\n");
                                    char *checkout_jwt_str = cJSON_GetStringValue(cJSON_GetObjectItem(dp, "checkout_jwt"));
                                    if (checkout_jwt_str != NULL) {
                                        // Extract payload from compact JWT (header.payload.signature)
                                        char *dot1 = strchr(checkout_jwt_str, '.');
                                        if (dot1 != NULL) {
                                            char *payload_start = dot1 + 1;
                                            char *dot2 = strchr(payload_start, '.');
                                            int payload_len = dot2 ? (int)(dot2 - payload_start) : (int)strlen(payload_start);
                                            char *payload_b64 = malloc(payload_len + 1);
                                            memcpy(payload_b64, payload_start, payload_len);
                                            payload_b64[payload_len] = '\0';

                                            char *decoded_json = NULL;
                                            int decoded_len = B64DecodeURL(payload_b64, &decoded_json);
                                            free(payload_b64);

                                            if (decoded_len > 0 && decoded_json != NULL) {
                                                printf("[OPENID_DEBUG] Decoded checkout JWT successfully.\n");
                                                checkout_jwt_payload = cJSON_Parse(decoded_json);
                                                free(decoded_json);
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // Populate merchant_name and transaction_amount for card picker header
                        if (merchant_name == NULL && payee_name_val != NULL)
                            merchant_name = payee_name_val;
                        if (transaction_amount == NULL && amt_value_val != NULL && amt_currency_val != NULL) {
                            transaction_amount = malloc(strlen(amt_value_val) + strlen(amt_currency_val) + 2);
                            sprintf(transaction_amount, "%s %s", amt_currency_val, amt_value_val);
                        }
                        
                        if (amt_value_allocated) {
                            free(amt_value_val);
                        }

                        // Build additional_info JSON for picker UI (table with line items)
                        if (additional_info == NULL) {
                            printf("[OPENID_DEBUG] Building table headers for additional_info...\n");
                            cJSON *ai_obj = cJSON_CreateObject();

                            cJSON *header_arr = cJSON_CreateArray();
                            cJSON_AddItemToArray(header_arr, cJSON_CreateString("Item"));
                            cJSON_AddItemToArray(header_arr, cJSON_CreateString("Qty"));
                            cJSON_AddItemToArray(header_arr, cJSON_CreateString("Price"));
                            cJSON_AddItemToObject(ai_obj, "tableHeader", header_arr);

                            cJSON *rows_arr = cJSON_CreateArray();
                            if (checkout_jwt_payload != NULL) {
                                printf("[OPENID_DEBUG] Pulling cart line items from checkout payload...\n");
                                cJSON *line_items = cJSON_GetObjectItem(checkout_jwt_payload, "line_items");
                                if (line_items != NULL) {
                                    int li_count = cJSON_GetArraySize(line_items);
                                    for (int li = 0; li < li_count; li++) {
                                        cJSON *item = cJSON_GetArrayItem(line_items, li);
                                        char *title      = cJSON_GetStringValue(cJSON_GetObjectItem(item, "title"));
                                        char *unit_price = cJSON_GetStringValue(cJSON_GetObjectItem(item, "unit_price"));
                                        double qty_num   = cJSON_GetNumberValue(cJSON_GetObjectItem(item, "quantity"));
                                        char qty_str[16] = {0};
                                        snprintf(qty_str, sizeof(qty_str), "%.0f", qty_num);
                                        cJSON *row = cJSON_CreateArray();
                                        cJSON_AddItemToArray(row, cJSON_CreateString(title      ? title      : ""));
                                        cJSON_AddItemToArray(row, cJSON_CreateString(qty_str));
                                        cJSON_AddItemToArray(row, cJSON_CreateString(unit_price ? unit_price : ""));
                                        cJSON_AddItemToArray(rows_arr, row);
                                    }
                                }
                            } else {
                                printf("[OPENID_DEBUG] Warning: checkout_jwt_payload was NULL, tableRows will be empty.\n");
                            }
                            cJSON_AddItemToObject(ai_obj, "tableRows", rows_arr);

                            char footer_str[64] = {0};
                            if (checkout_jwt_payload != NULL) {
                                cJSON *totals = cJSON_GetObjectItem(checkout_jwt_payload, "totals");
                                char *total_val  = totals ? cJSON_GetStringValue(cJSON_GetObjectItem(totals, "total")) : NULL;
                                char *cur = cJSON_GetStringValue(cJSON_GetObjectItem(checkout_jwt_payload, "currency"));
                                if (total_val && cur)
                                    snprintf(footer_str, sizeof(footer_str), "Total: %s %s", cur, total_val);
                                else if (total_val)
                                    snprintf(footer_str, sizeof(footer_str), "Total: %s", total_val);
                            }
                            cJSON_AddItemToObject(ai_obj, "footer", cJSON_CreateString(footer_str));

                            additional_info = cJSON_PrintUnformatted(ai_obj);
                            cJSON_Delete(ai_obj);
                            if (checkout_jwt_payload != NULL) {
                                cJSON_Delete(checkout_jwt_payload);
                                checkout_jwt_payload = NULL;
                            }
                        }
                    } else {
                        if (merchant_name == NULL)
                            merchant_name = cJSON_GetStringValue(cJSON_GetObjectItem(td_item, "merchant_name"));
                        if (transaction_amount == NULL)
                            transaction_amount = cJSON_GetStringValue(cJSON_GetObjectItem(td_item, "amount"));
                        if (additional_info == NULL)
                            additional_info = cJSON_GetStringValue(cJSON_GetObjectItem(td_item, "additional_info"));
                    }
                    if (td_i > 0) {
                        cJSON_Delete(td_item);
                    }
                }
            }

            printf("[OPENID_DEBUG] Reached the line before dcql_query!\n");

            cJSON *matched_result = dcql_query(query, credential_store);
            printf("match result %s\n", cJSON_Print(matched_result));
            cJSON *matched_credential_sets = cJSON_GetObjectItemCaseSensitive(matched_result, "matched_credential_sets");
            cJSON *matched_docs = cJSON_GetObjectItemCaseSensitive(matched_result, "matched_credentials");

            int matched_credential_sets_size = cJSON_GetArraySize(matched_credential_sets);
            if (matched_credential_sets_size > 0) {
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
                        if (wasm_version > 1) {
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
                    } else {
                        int chars_written = sprintf(set_id_buffer, "req:%d;null", i);
                        if (wasm_version > 1) {
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

            cJSON *inline_issuance = cJSON_GetObjectItemCaseSensitive(matched_result, "inline_issuance");
            if (inline_issuance != NULL) {
                char *cred_id = cJSON_GetStringValue(cJSON_GetObjectItem(inline_issuance, "id"));
                char *title = cJSON_GetStringValue(cJSON_GetObjectItem(inline_issuance, "title"));
                char *subtitle = cJSON_GetStringValue(cJSON_GetObjectItem(inline_issuance, "subtitle"));
                cJSON *icon = cJSON_GetObjectItem(inline_issuance, "icon");
                if (icon == NULL) {
                    AddInlineIssuanceEntry(cred_id, 0, 0, title, subtitle);
                } else {
                    double icon_start = cJSON_GetNumberValue(cJSON_GetObjectItem(icon, "start"));
                    int icon_start_int = icon_start;
                    int icon_len = (int)(cJSON_GetNumberValue(cJSON_GetObjectItem(icon, "length")));
                    AddInlineIssuanceEntry(cred_id, creds_blob + icon_start_int, icon_len, title, subtitle);
                }
            }
        }
    }

    return 0;
}