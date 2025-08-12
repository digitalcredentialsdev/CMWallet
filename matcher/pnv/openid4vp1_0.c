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

int main()
{
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

            cJSON *matched_docs = dcql_query(i, query, credential_store);
            // printf("matched_creds %d\n", cJSON_GetArraySize(matched_creds));
            //            printf("matched_creds %s\n", cJSON_Print(cJSON_GetArrayItem(matched_creds,0)));

            // Only support one doc
            cJSON *matched_doc;
            cJSON_ArrayForEach(matched_doc, matched_docs)
            {
                cJSON *matched_cred = cJSON_GetObjectItem(matched_doc, "matched");
                cJSON *doc_id = cJSON_GetObjectItem(matched_doc, "id");
                cJSON *c;
                cJSON_ArrayForEach(c, matched_cred)
                {
                    printf("Attempting to add cred %s\n", cJSON_Print(c));
                    cJSON *id_obj = cJSON_CreateObject();
                    cJSON *matched_id = cJSON_GetObjectItem(c, "id");

                    cJSON_AddItemReferenceToObject(id_obj, "entry_id", matched_id);
                    cJSON_AddItemReferenceToObject(id_obj, "dcql_cred_id", doc_id);
                    cJSON_AddItemReferenceToObject(id_obj, "req_idx", cJSON_CreateNumber(i));
                    char *id = cJSON_PrintUnformatted(id_obj);

                    if (transaction_credential_ids != NULL)
                    {
                        printf("transaction cred ids %s\n", cJSON_Print(transaction_credential_ids));
                        cJSON *transaction_credential_id;
                        cJSON_ArrayForEach(transaction_credential_id, transaction_credential_ids)
                        {
                            printf("comparing cred id %s with transaction cred id %s.\n", cJSON_Print(doc_id), cJSON_Print(transaction_credential_id));
                            if (cJSON_Compare(transaction_credential_id, doc_id, cJSON_True))
                            {

                                char *title = cJSON_GetStringValue(cJSON_GetObjectItem(c, "title"));
                                char *subtitle = cJSON_GetStringValue(cJSON_GetObjectItem(c, "subtitle"));
                                cJSON *icon = cJSON_GetObjectItem(c, "icon");
                                printf("transaction cred ids %s\n", cJSON_Print(transaction_credential_ids));

                                double icon_start = (cJSON_GetNumberValue(cJSON_GetObjectItem(icon, "start")));
                                int icon_start_int = icon_start;
                                printf("icon_start int %d, double %f\n", icon_start_int, icon_start);
                                int icon_len = (int)(cJSON_GetNumberValue(cJSON_GetObjectItem(icon, "length")));

                                AddPaymentEntry(id, merchant_name, title, subtitle, creds_blob + icon_start_int, icon_len, transaction_amount, NULL, 0, NULL, 0);
                                matched = 1;
                                break;
                            }
                        }
                    }
                    else
                    {
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
                        matched = 1;
                        printf("AddStringIdEntry %s\n", id);
                        AddStringIdEntry(id, creds_blob + icon_start_int, icon_len, title, subtitle, disclaimer, NULL);

                        if (aggregator_consent != NULL && verifier_terms_prefix != NULL)
                        {
                            size_t prefix_len = strlen(verifier_terms_prefix);
                            size_t aggregator_consent_len = strlen(aggregator_consent);
                            char *consent_msg = (char *)malloc(prefix_len + aggregator_consent_len + 1);
                            strcpy(consent_msg, verifier_terms_prefix);
                            strcat(consent_msg, aggregator_consent);
                            consent_msg[prefix_len + aggregator_consent_len] = '\0';
                            SetAdditionalDisclaimerAndUrlForVerificationEntry(id, consent_msg, aggregator_policy_text, aggregator_policy_url);
                        }
                        else
                        {
                            SetAdditionalDisclaimerAndUrlForVerificationEntry(id, aggregator_consent, aggregator_policy_text, aggregator_policy_url);
                        }
                        cJSON *matched_claim_names = cJSON_GetObjectItem(c, "matched_claim_names");
                        cJSON *claim;
                        cJSON_ArrayForEach(claim, matched_claim_names)
                        {
                            printf("AddFieldForStringIdEntry %s, claim value: %s\n", id, cJSON_Print(claim));
                            AddFieldForStringIdEntry(id, cJSON_GetStringValue(claim), NULL);
                        }
                    }
                }
            }
        }
    }

    if (matched == 0 && should_offer_issuance != 0 && merchant_name != NULL)
    {
        AddPaymentEntry("ISSUANCE", merchant_name, "Verify this transaction and save your card in CMWallet", NULL, _icons_Wallet_Rounded_png, sizeof(_icons_Wallet_Rounded_png), transaction_amount, NULL, 0, NULL, 0);
    }

    return 0;
}