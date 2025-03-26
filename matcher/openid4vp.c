#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON/cJSON.h"
#include "credentialmanager.h"

#include "base64.h"
#include "dcql.h"
#include "icon.h"

// Following [draft 24](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#name-protocol)
// Note that the latest spec has this changed to urn based, versioned values.
#define PROTOCOL_OPENID4VP_1_0 "openid4vp"

cJSON* GetDCRequestJson() {
    uint32_t request_size;
    GetRequestSize(&request_size);
    char* request_json = malloc(request_size);
    GetRequestBuffer(request_json);
    return cJSON_Parse(request_json);
}

cJSON* GetCredsJson() {
    uint32_t credentials_size;
    GetCredentialsSize(&credentials_size);
    char* creds_json = malloc(credentials_size);
    ReadCredentialsBuffer(creds_json, 0, credentials_size);
    return cJSON_Parse(creds_json);
}

int main() {
    uint32_t credentials_size;
    GetCredentialsSize(&credentials_size);

    char* creds_blob = malloc(credentials_size);
    ReadCredentialsBuffer(creds_blob, 0, credentials_size);

    int json_offset = *((int*)creds_blob);
    printf("Creds JSON offset %d\n", json_offset);

    cJSON* creds = cJSON_Parse(creds_blob + json_offset);
    cJSON* credential_store = cJSON_GetObjectItem(creds, "credentials");
    printf("Creds JSON %s\n", cJSON_Print(credential_store));

    cJSON* dc_request = GetDCRequestJson();
    printf("Request JSON %s\n", cJSON_Print(dc_request));

    // Parse each top level request looking for OpenID4VP requests
    cJSON* requests = cJSON_GetObjectItem(dc_request, "requests");
    int requests_size = cJSON_GetArraySize(requests);

    int matched = 0;
    int should_offer_issuance = 0;
    char* merchant_name = NULL;
    char* transaction_amount = NULL;
    for(int i=0; i<requests_size; i++) {
        cJSON* request = cJSON_GetArrayItem(requests, i);
        //printf("Request %s\n", cJSON_Print(request));

        char* protocol = cJSON_GetStringValue(cJSON_GetObjectItem(request, "protocol"));
        if (strcmp(protocol, PROTOCOL_OPENID4VP_1_0) == 0) {
            // We have an OpenID4VP request
            cJSON* data = cJSON_GetObjectItem(request, "data");

            // TODO: Won't need to do this conversion in the latest spec.
            char* data_json_string = cJSON_GetStringValue(data);
            cJSON* data_json = cJSON_Parse(data_json_string);
            if (cJSON_HasObjectItem(data_json, "request")) {
                // Until the spec has an official definition, treat the "request" key as the identifier for a signed request 
                cJSON* signed_request = cJSON_GetObjectItem(data_json, "request");
                char* signed_request_string = cJSON_GetStringValue(signed_request);
                int delimiter = '.';
                char* payload_start = strchr(signed_request_string, delimiter);
                payload_start++;
                char* payload_end = strchr(payload_start, delimiter);
                *payload_end = '\0';
                char* decoded_request_json;
                int decoded_request_json_len = B64DecodeURL(payload_start, &decoded_request_json);
                data_json = cJSON_Parse(decoded_request_json);
            }
            cJSON* query = cJSON_GetObjectItem(data_json, "dcql_query");
            if (cJSON_HasObjectItem(data_json, "offer")) {
                should_offer_issuance = 1;
            }

            // For now we only support one transaction data item

            cJSON* transaction_data_list = cJSON_GetObjectItem(data_json, "transaction_data");

            cJSON* transaction_data = NULL;
            cJSON* transaction_credential_ids = NULL;
            if (transaction_data_list != NULL) {
                if(cJSON_GetArraySize(transaction_data_list) == 1) {
                    cJSON* transaction_data_encoded = cJSON_GetArrayItem(transaction_data_list, 0);
                    char* transaction_data_encoded_str = cJSON_GetStringValue(transaction_data_encoded);
                    char* transaction_data_json;
                    int transaction_data_json_len = B64DecodeURL(transaction_data_encoded_str, &transaction_data_json);
                    transaction_data = cJSON_Parse(transaction_data_json);
                    transaction_credential_ids = cJSON_GetObjectItem(transaction_data, "credential_ids");
                    merchant_name = cJSON_GetStringValue(cJSON_GetObjectItem(transaction_data, "merchant_name"));
                    transaction_amount = cJSON_GetStringValue(cJSON_GetObjectItem(transaction_data, "amount"));
                }
                
            }

            cJSON* matched_docs = dcql_query(query, credential_store);
            //printf("matched_creds %d\n", cJSON_GetArraySize(matched_creds));
//            printf("matched_creds %s\n", cJSON_Print(cJSON_GetArrayItem(matched_creds,0)));

            // Only support one doc

            cJSON* matched_doc = cJSON_GetArrayItem(matched_docs,0);
            cJSON* matched_cred = cJSON_GetObjectItem(matched_doc, "matched");
            cJSON* doc_id = cJSON_GetObjectItem(matched_doc, "id");
            cJSON* c;
            cJSON_ArrayForEach(c, matched_cred) {
//                printf("cred %s\n", cJSON_Print(c));
                cJSON* id_obj = cJSON_CreateObject();
                cJSON* matched_id = cJSON_GetObjectItem(c, "id");

                cJSON_AddItemReferenceToObject(id_obj, "id", matched_id);
                cJSON_AddItemReferenceToObject(id_obj, "provider_idx", cJSON_CreateNumber(i));
                char* id = cJSON_PrintUnformatted(id_obj);

                if (transaction_credential_ids != NULL) {
                    printf("transaction cred ids %s\n", cJSON_Print(transaction_credential_ids));
                    cJSON* transaction_credential_id;
                    cJSON_ArrayForEach(transaction_credential_id, transaction_credential_ids) {
                        printf("comparing cred id %s with transaction cred id %s.\n", cJSON_Print(doc_id), cJSON_Print(transaction_credential_id));
                        if (cJSON_Compare(transaction_credential_id, doc_id, cJSON_True)) {

                            char *title = cJSON_GetStringValue(cJSON_GetObjectItem(c, "title"));
                            char *subtitle = cJSON_GetStringValue(cJSON_GetObjectItem(c, "subtitle"));
                            cJSON* icon = cJSON_GetObjectItem(c, "icon");
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
                } else {
                    char *title = cJSON_GetStringValue(cJSON_GetObjectItem(c, "title"));
                    char *subtitle = cJSON_GetStringValue(cJSON_GetObjectItem(c, "subtitle"));
                    matched = 1;
                    AddStringIdEntry(id, NULL, 0, title, subtitle, NULL, NULL);
                    cJSON *matched_claim_names = cJSON_GetObjectItem(c, "matched_claim_names");
                    cJSON *claim;
                    cJSON_ArrayForEach(claim, matched_claim_names) {
                        AddFieldForStringIdEntry(id, cJSON_GetStringValue(claim), NULL);
                    }
                }
            }


        }
    }

    if (matched == 0 && should_offer_issuance != 0 && merchant_name != NULL) {
        AddPaymentEntry("ISSUANCE", merchant_name, "Verify this transaction and save your card in CMWallet", NULL, _icons_Wallet_Rounded_png, sizeof(_icons_Wallet_Rounded_png), transaction_amount, NULL, 0, NULL, 0);
    }

    return 0;
}