#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "../base64.h"
#include "../dcql.h"

#include "../cJSON/cJSON.h"

int AddAllClaims(cJSON* matched_claim_names, cJSON* candidate_paths)
{
    cJSON* curr_path;
    cJSON_ArrayForEach(curr_path, candidate_paths)
    {
        cJSON* attr;
        if (cJSON_HasObjectItem(curr_path, "display"))
        {
            cJSON_AddItemReferenceToArray(matched_claim_names, cJSON_GetObjectItem(curr_path, "display"));
        }
        else if (cJSON_IsObject(curr_path))
        {
            AddAllClaims(matched_claim_names, curr_path);
        }
    }
    return 0;
}

cJSON *CreateSingleStringArrayJson(char *string)
{
    cJSON *array = cJSON_CreateArray();
    cJSON_AddItemReferenceToArray(array, cJSON_CreateString(string));
    return array;
}

enum ClaimMatchResult
{
    CLAIM_MATCH_UNKNOWN = 0,
    CLAIM_MATCH_YES = 1,
    CLAIM_MATCH_NO = -1,
};

cJSON *
MatchCredential(cJSON *credential, cJSON *credential_store)
{
    cJSON* result = cJSON_CreateObject();

    cJSON* inline_issuance = NULL;
    cJSON *matched_credentials = cJSON_CreateArray();
    char *format = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(credential, "format"));

    // check for optional params
    cJSON *meta = cJSON_GetObjectItemCaseSensitive(credential, "meta");
    cJSON *claims = cJSON_GetObjectItemCaseSensitive(credential, "claims");
    cJSON *claim_sets = cJSON_GetObjectItemCaseSensitive(credential, "claim_sets");

    cJSON *candidates = cJSON_GetObjectItemCaseSensitive(credential_store, format);
    cJSON* inline_issuance_candidates = cJSON_GetObjectItemCaseSensitive(credential_store, "issuance");
    inline_issuance_candidates = cJSON_GetObjectItemCaseSensitive(inline_issuance_candidates, format);

    if (candidates == NULL && inline_issuance_candidates == NULL) {
        cJSON_AddItemReferenceToObject(result, "matched_creds", matched_credentials);
        cJSON_AddItemReferenceToObject(result, "inline_issuance", inline_issuance);
        return result;
    }

    // Filter by meta
    cJSON *aggregator_consent = NULL;
    cJSON *aggregator_policy_url = NULL;
    cJSON *aggregator_policy_text = NULL;
    if (meta != NULL)
    {
        if (strcmp(format, "dc-authorization+sd-jwt") == 0)
        {
            if (!cJSON_HasObjectItem(meta, "credential_authorization_jwt"))
            {
                return matched_credentials;
            }
            char *cred_auth_jwt = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(meta, "credential_authorization_jwt"));
            int delimiter = '.';
            char *payload_start = strchr(cred_auth_jwt, delimiter);
            payload_start++;
            char *payload_end = strchr(payload_start, delimiter);
            *payload_end = '\0';
            char *decoded_cred_auth_json;
            int decoded_cred_auth_json_len = B64DecodeURL(payload_start, &decoded_cred_auth_json);
            cJSON *cred_auth_json = cJSON_Parse(decoded_cred_auth_json);
            if (!cJSON_HasObjectItem(cred_auth_json, "iss"))
            {
                printf("The dcql request has no iss value. No match. \n");
                return matched_credentials;
            }
            cJSON *iss_value = cJSON_GetObjectItemCaseSensitive(cred_auth_json, "iss");

            cJSON *vct_values_obj = cJSON_GetObjectItemCaseSensitive(meta, "vct_values");
            cJSON *cred_candidates = candidates;
            candidates = cJSON_CreateArray();
            cJSON *vct_value;
            cJSON_ArrayForEach(vct_value, vct_values_obj)
            {
                cJSON *vct_candidates = cJSON_GetObjectItemCaseSensitive(cred_candidates, cJSON_GetStringValue(vct_value));
                cJSON *curr_candidate;
                cJSON_ArrayForEach(curr_candidate, vct_candidates)
                {
                    cJSON *iss_allowlist = cJSON_GetObjectItemCaseSensitive(curr_candidate, "iss_allowlist");
                    if (iss_allowlist == NULL)
                    {
                        printf("A candidate credential of type %s passed null iss allowlist check.\n", cJSON_GetStringValue(vct_value));
                        cJSON_AddItemReferenceToArray(candidates, curr_candidate);
                    }
                    else
                    {
                        cJSON *allowed_iss;
                        cJSON_ArrayForEach(allowed_iss, iss_allowlist)
                        {
                            if (cJSON_Compare(allowed_iss, iss_value, cJSON_True))
                            {
                                printf("A candidate credential of type %s passed iss allowlist check.\n", cJSON_GetStringValue(vct_value));
                                cJSON_AddItemReferenceToArray(candidates, curr_candidate);
                                break;
                            }
                        }
                    }
                }
            }
            if (cJSON_HasObjectItem(cred_auth_json, "consent_data"))
            {
                printf("Request has consent data\n");
                char *consent_data = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(cred_auth_json, "consent_data"));
                char *decoded_consent_data_json;
                int decoded_consent_data_json_len = B64DecodeURL(consent_data, &decoded_consent_data_json);
                cJSON *consent_data_json = cJSON_Parse(decoded_consent_data_json);
                aggregator_consent = cJSON_GetObjectItemCaseSensitive(consent_data_json, "consent_text");
                printf("aggregator_consent %s\n", cJSON_Print(aggregator_consent));
                // Deprecated: to remove
                aggregator_policy_url = cJSON_GetObjectItemCaseSensitive(consent_data_json, "policy_link");
                printf("aggregator_policy_url %s\n", cJSON_Print(aggregator_policy_url));
                aggregator_policy_text = cJSON_GetObjectItemCaseSensitive(consent_data_json, "policy_text");
                printf("aggregator_policy_text %s\n", cJSON_Print(aggregator_policy_text));
            }
        }
        else
        {
            cJSON_AddItemReferenceToObject(result, "matched_creds", matched_credentials);
            cJSON_AddItemReferenceToObject(result, "inline_issuance", inline_issuance);
            return result;
        }
    }
    else
    {
        cJSON_AddItemReferenceToObject(result, "matched_creds", matched_credentials);
        cJSON_AddItemReferenceToObject(result, "inline_issuance", inline_issuance);
        return result;
    }

    if (candidates == NULL)
    {
        cJSON_AddItemReferenceToObject(result, "matched_creds", matched_credentials);
        cJSON_AddItemReferenceToObject(result, "inline_issuance", inline_issuance);
        return result;
    }

    // Match on the claims
    if (claims == NULL)
    {
        printf("No claims provided, matching on the whole credential.\n");
        // Match every candidate
        cJSON *candidate;
        cJSON_ArrayForEach(candidate, candidates)
        {
            cJSON *matched_credential = cJSON_CreateObject();
            cJSON_AddItemReferenceToObject(matched_credential, "id", cJSON_GetObjectItemCaseSensitive(candidate, "id"));
            cJSON_AddItemReferenceToObject(matched_credential, "title", cJSON_GetObjectItemCaseSensitive(candidate, "title"));
            cJSON_AddItemReferenceToObject(matched_credential, "subtitle", cJSON_GetObjectItemCaseSensitive(candidate, "subtitle"));
            cJSON_AddItemReferenceToObject(matched_credential, "verifier_terms_prefix", cJSON_GetObjectItemCaseSensitive(candidate, "verifier_terms_prefix"));
            cJSON_AddItemReferenceToObject(matched_credential, "disclaimer", cJSON_GetObjectItemCaseSensitive(candidate, "disclaimer"));
            cJSON_AddItemReferenceToObject(matched_credential, "icon", cJSON_GetObjectItemCaseSensitive(candidate, "icon"));
            cJSON_AddItemReferenceToObject(matched_credential, "aggregator_consent", aggregator_consent);
            cJSON_AddItemReferenceToObject(matched_credential, "aggregator_policy_text", aggregator_policy_text);
            cJSON_AddItemReferenceToObject(matched_credential, "aggregator_policy_url", aggregator_policy_url);
            cJSON *matched_claim_names = cJSON_CreateArray();
            // printf("candidate %s\n", cJSON_Print(candidate));
            cJSON_AddItemReferenceToArray(matched_claim_names, cJSON_GetObjectItemCaseSensitive(candidate, "shared_attribute_display_name"));
            cJSON_AddItemReferenceToObject(matched_credential, "matched_claim_names", matched_claim_names);
            cJSON_AddItemReferenceToObject(matched_credential, "matched_claim_metadata", cJSON_CreateArray()); // Don't care for Telephony
            cJSON_AddItemReferenceToArray(matched_credentials, matched_credential);
        }
    }
    else
    {
        cJSON *matched_claim_paths = cJSON_CreateArray();

        cJSON *phone_number_matched_candidates = cJSON_CreateArray();
        cJSON *carrier_and_subscription_matched_candidates = cJSON_CreateArray();
        cJSON *carrier_matched_candidates = cJSON_CreateArray();
        cJSON *sub_matched_candidates = cJSON_CreateArray();
        cJSON *other_candidates = cJSON_CreateArray();

        cJSON *phone_number_hint_paths = CreateSingleStringArrayJson("phone_number_hint");
        cJSON *subscription_hint_paths = CreateSingleStringArrayJson("subscription_hint");
        cJSON *carrier_hint_paths = CreateSingleStringArrayJson("carrier_hint");
        cJSON *android_carrier_hint_paths = CreateSingleStringArrayJson("android_carrier_hint");
        cJSON *disallow_carriers_paths = CreateSingleStringArrayJson("disallow_carriers");

        if (claim_sets == NULL)
        {
            printf("Matching based on provided claims\n");
            cJSON *candidate;
            cJSON_ArrayForEach(candidate, candidates)
            {
                cJSON *matched_credential = cJSON_CreateObject();
                cJSON_AddItemReferenceToObject(matched_credential, "id", cJSON_GetObjectItemCaseSensitive(candidate, "id"));
                cJSON_AddItemReferenceToObject(matched_credential, "title", cJSON_GetObjectItemCaseSensitive(candidate, "title"));
                cJSON_AddItemReferenceToObject(matched_credential, "subtitle", cJSON_GetObjectItemCaseSensitive(candidate, "subtitle"));
                cJSON_AddItemReferenceToObject(matched_credential, "verifier_terms_prefix", cJSON_GetObjectItemCaseSensitive(candidate, "verifier_terms_prefix"));
                cJSON_AddItemReferenceToObject(matched_credential, "disclaimer", cJSON_GetObjectItemCaseSensitive(candidate, "disclaimer"));
                cJSON_AddItemReferenceToObject(matched_credential, "icon", cJSON_GetObjectItemCaseSensitive(candidate, "icon"));
                cJSON_AddItemReferenceToObject(matched_credential, "aggregator_consent", aggregator_consent);
                cJSON_AddItemReferenceToObject(matched_credential, "aggregator_policy_text", aggregator_policy_text);
                cJSON_AddItemReferenceToObject(matched_credential, "aggregator_policy_url", aggregator_policy_url);
                cJSON *matched_claim_names = cJSON_CreateArray();
                cJSON_AddItemReferenceToArray(matched_claim_names, cJSON_GetObjectItemCaseSensitive(candidate, "shared_attribute_display_name"));

                cJSON *claim;
                cJSON *candidate_claims = cJSON_GetObjectItemCaseSensitive(candidate, "paths");
                enum ClaimMatchResult phone_number_matched = CLAIM_MATCH_UNKNOWN;
                enum ClaimMatchResult carrier_matched = CLAIM_MATCH_UNKNOWN;
                enum ClaimMatchResult android_carrier_matched = CLAIM_MATCH_UNKNOWN;
                enum ClaimMatchResult subscription_matched = CLAIM_MATCH_UNKNOWN;
                int exclude_candidate_credential = 0;
                cJSON_ArrayForEach(claim, claims)
                {
                    cJSON *claim_values = cJSON_GetObjectItemCaseSensitive(claim, "values");
                    cJSON *paths = cJSON_GetObjectItemCaseSensitive(claim, "path");
                    cJSON *curr_path;
                    cJSON *curr_claim = candidate_claims;
                    int matched = 1;
                    printf("Credential claim: %s ", cJSON_Print(curr_claim));
                    cJSON_ArrayForEach(curr_path, paths)
                    {
                        printf("- requested path %s ", cJSON_Print(curr_path));
                        char *path_value = cJSON_GetStringValue(curr_path);
                        if (cJSON_HasObjectItem(curr_claim, path_value))
                        {
                            printf("- path found ");
                            curr_claim = cJSON_GetObjectItemCaseSensitive(curr_claim, path_value);
                        }
                        else
                        {
                            printf("- path not found ");
                            matched = 0;
                            break;
                        }
                    }
                    bool match_claim = 0;
                    if (matched != 0 && curr_claim != NULL)
                    {
                        if (claim_values != NULL)
                        {
                            cJSON *v;
                            cJSON_ArrayForEach(v, claim_values)
                            {
                                if (cJSON_Compare(v, cJSON_GetObjectItemCaseSensitive(curr_claim, "value"), cJSON_True))
                                {
                                    printf("- claim value matched.\n");
                                    match_claim = 1;
                                    break;
                                }
                            }
                        }
                        else
                        {
                            printf("- claim matched.\n");
                            match_claim = 1;
                        }
                    }
                    else
                    {
                        printf("- claim did not match\n.");
                    }
                    if (matched)
                    {
                        enum ClaimMatchResult result = match_claim ? CLAIM_MATCH_YES : CLAIM_MATCH_NO;
                        if (cJSON_Compare(paths, phone_number_hint_paths, cJSON_True))
                        {
                            phone_number_matched = result;
                        }
                        else if (cJSON_Compare(paths, subscription_hint_paths, cJSON_True))
                        {
                            subscription_matched = result;
                        }
                        else if (cJSON_Compare(paths, carrier_hint_paths, cJSON_True))
                        {
                            carrier_matched = result;
                        }
                        else if (cJSON_Compare(paths, android_carrier_hint_paths, cJSON_True))
                        {
                            android_carrier_matched = result;
                        }
                    }
                    else if (cJSON_Compare(paths, disallow_carriers_paths, cJSON_True) && claim_values != NULL)
                    {   // If the carrier ID matches any value in the disallow carrier list, then we don't show this option.
                        cJSON *candidate_carrier_id = cJSON_GetObjectItem(candidate_claims, "carrier_hint");
                        cJSON *v;
                        cJSON_ArrayForEach(v, claim_values)
                        {
                            if (cJSON_Compare(v, cJSON_GetObjectItemCaseSensitive(candidate_carrier_id, "value"), cJSON_True))
                            {
                                printf("Credential matching the disallow list.\n");
                                exclude_candidate_credential = 1;
                                break;
                            }
                        }
                        if (exclude_candidate_credential != 0) {
                            break;
                        }
                    }
                }
                bool carrier_matched_final = carrier_matched + android_carrier_matched >= 1;
                cJSON_AddItemReferenceToObject(matched_credential, "matched_claim_names", matched_claim_names);
                cJSON_AddItemReferenceToObject(matched_credential, "matched_claim_metadata", cJSON_CreateArray()); // Don't care for Telephony
                if (exclude_candidate_credential != 0)
                {
                    // Skip this credential
                }
                else if (phone_number_matched == CLAIM_MATCH_YES)
                {
                    cJSON_AddItemReferenceToArray(phone_number_matched_candidates, matched_credential);
                }
                else if (carrier_matched_final && subscription_matched == CLAIM_MATCH_YES)
                {
                    cJSON_AddItemReferenceToArray(carrier_and_subscription_matched_candidates, matched_credential);
                }
                else if (carrier_matched_final)
                {
                    cJSON_AddItemReferenceToArray(carrier_matched_candidates, matched_credential);
                }
                else if (subscription_matched == CLAIM_MATCH_YES)
                {
                    cJSON_AddItemReferenceToArray(sub_matched_candidates, matched_credential);
                }
                else
                {
                    cJSON_AddItemReferenceToArray(other_candidates, matched_credential);
                }
            }
        }
        else
        {
            printf("PNV does not support matching based on claim_sets\n");
        }

        cJSON *c;
        cJSON_ArrayForEach(c, phone_number_matched_candidates)
        {
            cJSON_AddItemReferenceToArray(matched_credentials, c);
        }
        cJSON_ArrayForEach(c, carrier_and_subscription_matched_candidates)
        {
            cJSON_AddItemReferenceToArray(matched_credentials, c);
        }
        cJSON_ArrayForEach(c, carrier_matched_candidates)
        {
            cJSON_AddItemReferenceToArray(matched_credentials, c);
        }
        cJSON_ArrayForEach(c, sub_matched_candidates)
        {
            cJSON_AddItemReferenceToArray(matched_credentials, c);
        }
        cJSON_ArrayForEach(c, other_candidates)
        {
            cJSON_AddItemReferenceToArray(matched_credentials, c);
        }
    }


    cJSON_AddItemReferenceToObject(result, "matched_creds", matched_credentials);
    cJSON_AddItemReferenceToObject(result, "inline_issuance", inline_issuance);
    return result;
}

cJSON *dcql_query(cJSON *query, cJSON *credential_store)
{
    cJSON* match_result = cJSON_CreateObject();
    cJSON* matched_credential_sets = cJSON_CreateArray();
    cJSON* candidate_matched_credentials = cJSON_CreateObject();
    cJSON* candidate_inline_issuance_credentials = cJSON_CreateObject();
    cJSON* credentials = cJSON_GetObjectItemCaseSensitive(query, "credentials");
    cJSON* credential_sets = cJSON_GetObjectItemCaseSensitive(query, "credential_sets");

    cJSON* credential;
    cJSON_ArrayForEach(credential, credentials) {
        char* id = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(credential, "id"));
        cJSON* match_result = MatchCredential(credential, credential_store);
        cJSON* matched = cJSON_GetObjectItem(match_result, "matched_creds");
        if (cJSON_GetArraySize(matched) > 0) {
            cJSON* m = cJSON_CreateObject();
            cJSON_AddItemReferenceToObject(m, "id", cJSON_GetObjectItemCaseSensitive(credential, "id"));
            cJSON_AddItemReferenceToObject(m, "matched", matched);
            cJSON_AddItemReferenceToObject(candidate_matched_credentials, id, m);
        }
        cJSON_AddItemReferenceToObject(candidate_inline_issuance_credentials, id, cJSON_GetObjectItem(match_result, "inline_issuance"));
    }

    if (credential_sets == NULL) {
        if (cJSON_GetArraySize(credentials) == cJSON_GetArraySize(candidate_matched_credentials)) {
            cJSON* single_matched_credential_set = cJSON_CreateObject();
            cJSON* matched_cred_ids = cJSON_CreateArray();
            cJSON* matched_credential;
            cJSON_ArrayForEach(matched_credential, credentials) {
                cJSON_AddItemReferenceToArray(matched_cred_ids, cJSON_GetObjectItemCaseSensitive(matched_credential, "id"));
            }
            char set_id_buffer[16];
            cJSON_AddItemReferenceToObject(single_matched_credential_set, "matched_credential_ids", matched_cred_ids);
            cJSON* curr_matched_credential_sets = cJSON_CreateArray(); // For consistency with the credential_sets case
            cJSON_AddItemReferenceToArray(curr_matched_credential_sets, single_matched_credential_set);
            cJSON_AddItemReferenceToArray(matched_credential_sets, curr_matched_credential_sets);
            cJSON_AddItemReferenceToObject(match_result, "matched_credential_sets", matched_credential_sets);
            cJSON_AddItemReferenceToObject(match_result, "matched_credentials", candidate_matched_credentials);
        }
        if (cJSON_GetArraySize(credentials) == cJSON_GetArraySize(candidate_inline_issuance_credentials)) {
            cJSON* inline_issuance_credential;
            // For now, just use the first inline issuance entry that matched
            cJSON_ArrayForEach(inline_issuance_credential, candidate_inline_issuance_credentials) {
                cJSON_AddItemReferenceToObject(match_result, "inline_issuance", inline_issuance_credential);
                break;
            }
        }
    } else {
        // TODO: support inline issuance
        cJSON* credential_set;
        int matched = 1;
        int set_idx = 0;
        cJSON_ArrayForEach(credential_set, credential_sets) {
            if (cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(credential_set, "required"))) {
                ++set_idx;
                continue;
            }
            cJSON* curr_matched_credential_sets = cJSON_CreateArray();
            cJSON* options = cJSON_GetObjectItemCaseSensitive(credential_set, "options");
            cJSON* option;
            int credential_set_matched = 0;
            int option_idx = 0;
            cJSON_ArrayForEach(option, options) {
                cJSON* matched_cred_ids = cJSON_CreateArray();
                cJSON* cred_id;
                credential_set_matched = 1;
                cJSON_ArrayForEach(cred_id, option) {
                    if (cJSON_GetObjectItemCaseSensitive(candidate_matched_credentials, cJSON_GetStringValue(cred_id)) == NULL) {
                        credential_set_matched = 0;
                        break;
                    }  // Remove for multi-provider support
                    cJSON_AddItemReferenceToArray(matched_cred_ids, cred_id);
                }
                if (credential_set_matched != 0) {
                    cJSON* cred_set_info = cJSON_CreateObject();
                    char set_id_buffer[4];
                    char option_id_buffer[4];
                    int chars_written = sprintf(set_id_buffer, "%d", set_idx);
                    chars_written = sprintf(option_id_buffer, "%d", option_idx);
                    cJSON_AddStringToObject(cred_set_info, "set_id", set_id_buffer);
                    cJSON_AddStringToObject(cred_set_info, "option_id", option_id_buffer);
                    cJSON_AddItemReferenceToObject(cred_set_info, "matched_credential_ids", matched_cred_ids);
                    cJSON_AddItemReferenceToArray(curr_matched_credential_sets, cred_set_info);
                }
                ++option_idx;
            }
            if (cJSON_GetArraySize(curr_matched_credential_sets) == 0) {
                matched = 0;
                break;
            } else {
                cJSON_AddItemReferenceToArray(matched_credential_sets, curr_matched_credential_sets);
            }
            ++set_idx;
        }
        if (matched != 0) {
            cJSON_AddItemReferenceToObject(match_result, "matched_credential_sets", matched_credential_sets);
            cJSON_AddItemReferenceToObject(match_result, "matched_credentials", candidate_matched_credentials);
        }
    }

    printf("dcql_query return: %s\n", cJSON_Print(match_result));
    return match_result;
}