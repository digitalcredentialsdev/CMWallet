#include <stdio.h>
#include <string.h>

#include "dcql.h"

#include "cJSON/cJSON.h"

int AddAllClaims(cJSON* matched_claim_names, cJSON* candidate_paths) {
    cJSON* curr_path;
    cJSON_ArrayForEach(curr_path, candidate_paths) {
        cJSON* attr;
        if (cJSON_HasObjectItem(curr_path, "display")) {
            cJSON_AddItemReferenceToArray(matched_claim_names, cJSON_GetObjectItem(curr_path, "display"));
        } else if (cJSON_IsObject(curr_path)) {
            AddAllClaims(matched_claim_names, curr_path);
        }
    }
    return 0;
}

cJSON* MatchCredential(cJSON* credential, cJSON* credential_store) {
    cJSON* result = cJSON_CreateObject();

    cJSON* inline_issuance = NULL;
    cJSON* matched_credentials = cJSON_CreateArray();
    char* format = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(credential, "format"));

    // check for optional params
    cJSON* meta = cJSON_GetObjectItemCaseSensitive(credential, "meta");
    cJSON* claims = cJSON_GetObjectItemCaseSensitive(credential, "claims");
    cJSON* claim_sets = cJSON_GetObjectItemCaseSensitive(credential, "claim_sets");

    cJSON* candidates = cJSON_GetObjectItemCaseSensitive(credential_store, format);
    cJSON* inline_issuance_candidates = cJSON_GetObjectItemCaseSensitive(credential_store, "issuance");
    inline_issuance_candidates = cJSON_GetObjectItemCaseSensitive(inline_issuance_candidates, format);

    if (candidates == NULL && inline_issuance_candidates == NULL) {
        cJSON_AddItemReferenceToObject(result, "matched_creds", matched_credentials);
        cJSON_AddItemReferenceToObject(result, "inline_issuance", inline_issuance);
        return result;
    }

    // Filter by meta
    if (meta != NULL) {
        if (strcmp(format, "mso_mdoc") == 0) {
            cJSON* doctype_value_obj = cJSON_GetObjectItemCaseSensitive(meta, "doctype_value");
            if (doctype_value_obj != NULL) {
                char* doctype_value = cJSON_GetStringValue(doctype_value_obj);
                candidates = cJSON_GetObjectItemCaseSensitive(candidates, doctype_value);
                //printf("candidates %s\n", cJSON_Print(candidates));

                if (inline_issuance_candidates != NULL) {
                    cJSON* inline_issuance_candidate;
                    cJSON_ArrayForEach(inline_issuance_candidate, inline_issuance_candidates) {
                        if (inline_issuance != NULL) {
                            break;
                        }
                        cJSON* supported = cJSON_GetObjectItemCaseSensitive(inline_issuance_candidate, "supported");
                        cJSON* supported_doctype;
                        cJSON_ArrayForEach(supported_doctype, supported) {
                            if (cJSON_Compare(supported_doctype, doctype_value_obj, cJSON_True)) {
                                inline_issuance = inline_issuance_candidate;
                                break;
                            }
                        }
                    }
                }
            }
        } else if (strcmp(format, "dc+sd-jwt") == 0) {
            cJSON* vct_values_obj = cJSON_GetObjectItemCaseSensitive(meta, "vct_values");
            cJSON* cred_candidates = candidates;
            candidates = cJSON_CreateArray();
            cJSON* vct_value;
            cJSON_ArrayForEach(vct_value, vct_values_obj) {
                cJSON* vct_candidates = cJSON_GetObjectItemCaseSensitive(cred_candidates, cJSON_GetStringValue(vct_value));
                cJSON* curr_candidate;
                cJSON_ArrayForEach(curr_candidate, vct_candidates) {
                    cJSON_AddItemReferenceToArray(candidates, curr_candidate);
                }
            }

            if (inline_issuance_candidates != NULL) {
                cJSON* inline_issuance_candidate;
                cJSON_ArrayForEach(inline_issuance_candidate, inline_issuance_candidates) {
                    if (inline_issuance != NULL) {
                        break;
                    }
                    cJSON* supported = cJSON_GetObjectItemCaseSensitive(inline_issuance_candidate, "supported");
                    cJSON* supported_vct;
                    cJSON_ArrayForEach(vct_value, vct_values_obj) {
                        cJSON_ArrayForEach(supported_vct, supported) {
                            if (cJSON_Compare(supported_vct, vct_value, cJSON_True)) {
                                inline_issuance = inline_issuance_candidate;
                                break;
                            }
                        }
                    }
                }
            }
        } else  {
            cJSON_AddItemReferenceToObject(result, "matched_creds", matched_credentials);
            cJSON_AddItemReferenceToObject(result, "inline_issuance", inline_issuance);
            return result;
        }
    }

    if (candidates == NULL) {
        cJSON_AddItemReferenceToObject(result, "matched_creds", matched_credentials);
        cJSON_AddItemReferenceToObject(result, "inline_issuance", inline_issuance);
        return result;
    }

    // Match on the claims
    if (claims == NULL) {
        // Match every candidate
        cJSON* candidate;
        cJSON_ArrayForEach(candidate, candidates) {
            cJSON* matched_credential = cJSON_CreateObject();
            cJSON_AddItemReferenceToObject(matched_credential, "id", cJSON_GetObjectItemCaseSensitive(candidate, "id"));
            cJSON_AddItemReferenceToObject(matched_credential, "display", cJSON_GetObjectItemCaseSensitive(candidate, "display"));
            cJSON* matched_claim_names = cJSON_CreateArray();
            cJSON* matched_claim_metadata = cJSON_CreateArray();
            //printf("candidate %s\n", cJSON_Print(candidate));
            AddAllClaims(matched_claim_names, cJSON_GetObjectItemCaseSensitive(candidate, "paths"));
            cJSON_AddItemReferenceToObject(matched_credential, "matched_claim_names", matched_claim_names);
            cJSON_AddItemReferenceToObject(matched_credential, "matched_claim_metadata", matched_claim_metadata); // Empty array represents all matched
            cJSON_AddItemReferenceToArray(matched_credentials, matched_credential);
        }
    } else {
        if (claim_sets == NULL) {
            cJSON* candidate;
            cJSON_ArrayForEach(candidate, candidates) {
                cJSON* matched_credential = cJSON_CreateObject();
                cJSON_AddItemReferenceToObject(matched_credential, "id", cJSON_GetObjectItemCaseSensitive(candidate, "id"));
                cJSON_AddItemReferenceToObject(matched_credential, "display", cJSON_GetObjectItemCaseSensitive(candidate, "display"));
                cJSON* matched_claim_names = cJSON_CreateArray();
                cJSON* matched_claim_metadata = cJSON_CreateArray();

                cJSON* claim;
                cJSON* candidate_claims = cJSON_GetObjectItemCaseSensitive(candidate, "paths");
                cJSON_ArrayForEach(claim, claims) {
                    cJSON* claim_values = cJSON_GetObjectItemCaseSensitive(claim, "values");
                    cJSON* paths = cJSON_GetObjectItemCaseSensitive(claim, "path");
                    cJSON* curr_path;
                    cJSON* curr_claim = candidate_claims;
                    int matched = 1;
                    cJSON_ArrayForEach(curr_path, paths) {
                        char* path_value = cJSON_GetStringValue(curr_path);
                        if (cJSON_HasObjectItem(curr_claim, path_value)) {
                            curr_claim = cJSON_GetObjectItemCaseSensitive(curr_claim, path_value);
                        } else {
                            matched = 0;
                            break;
                        }
                    }
                    if (matched != 0 && curr_claim != NULL && cJSON_HasObjectItem(curr_claim, "display")) {
                        if (claim_values != NULL) {
                            cJSON* v;
                            cJSON_ArrayForEach(v, claim_values) {
                                if (cJSON_Compare(v, cJSON_GetObjectItemCaseSensitive(curr_claim, "value"), cJSON_True)) {
                                    cJSON_AddItemReferenceToArray(matched_claim_metadata, paths);
                                    cJSON_AddItemReferenceToArray(matched_claim_names, cJSON_GetObjectItem(curr_claim, "display"));
                                    break;
                                }
                            }
                        } else {
                            cJSON_AddItemReferenceToArray(matched_claim_metadata, paths);
                            cJSON_AddItemReferenceToArray(matched_claim_names, cJSON_GetObjectItem(curr_claim, "display"));
                        }
                    }
                }
                cJSON_AddItemReferenceToObject(matched_credential, "matched_claim_names", matched_claim_names);
                cJSON_AddItemReferenceToObject(matched_credential, "matched_claim_metadata", matched_claim_metadata);
                if (cJSON_GetArraySize(matched_claim_names) == cJSON_GetArraySize(claims)) {
                    cJSON_AddItemReferenceToArray(matched_credentials, matched_credential);
                }
            }
        } else {
            cJSON* candidate;
            cJSON_ArrayForEach(candidate, candidates) {
                cJSON* matched_credential = cJSON_CreateObject();
                cJSON_AddItemReferenceToObject(matched_credential, "id", cJSON_GetObjectItemCaseSensitive(candidate, "id"));
                cJSON_AddItemReferenceToObject(matched_credential, "display", cJSON_GetObjectItemCaseSensitive(candidate, "display"));
                cJSON* matched_claim_ids = cJSON_CreateObject();

                cJSON* claim;
                cJSON* candidate_claims = cJSON_GetObjectItemCaseSensitive(candidate, "paths");
                cJSON_ArrayForEach(claim, claims) {
                    cJSON* claim_values = cJSON_GetObjectItemCaseSensitive(claim, "values");
                    char* claim_id = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(claim, "id"));
                    cJSON* paths = cJSON_GetObjectItemCaseSensitive(claim, "path");
                    cJSON* curr_path;
                    cJSON* curr_claim = candidate_claims;
                    int matched = 1;
                    cJSON_ArrayForEach(curr_path, paths) {
                        char* path_value = cJSON_GetStringValue(curr_path);
                        if (cJSON_HasObjectItem(curr_claim, path_value)) {
                            curr_claim = cJSON_GetObjectItemCaseSensitive(curr_claim, path_value);
                        } else {
                            matched = 0;
                            break;
                        }
                    }
                    if (matched != 0 && curr_claim != NULL && cJSON_HasObjectItem(curr_claim, "display")) {
                        if (claim_values != NULL) {
                            cJSON* v;
                            cJSON_ArrayForEach(v, claim_values) {
                                if (cJSON_Compare(v, cJSON_GetObjectItemCaseSensitive(curr_claim, "value"), cJSON_True)) {
                                    cJSON* matched_claim_info = cJSON_CreateObject();
                                    cJSON_AddItemReferenceToObject(matched_claim_info, "claim_display", cJSON_GetObjectItem(curr_claim, "display"));
                                    cJSON_AddItemReferenceToObject(matched_claim_info, "claim_path", paths);
                                    cJSON_AddItemReferenceToObject(matched_claim_ids, claim_id, matched_claim_info);
                                    break;
                                }
                            }
                        } else {
                            cJSON* matched_claim_info = cJSON_CreateObject();
                            cJSON_AddItemReferenceToObject(matched_claim_info, "claim_display", cJSON_GetObjectItem(curr_claim, "display"));
                            cJSON_AddItemReferenceToObject(matched_claim_info, "claim_path", paths);
                            cJSON_AddItemReferenceToObject(matched_claim_ids, claim_id, matched_claim_info);
                        }
                    }
                }
                cJSON* claim_set;
                cJSON_ArrayForEach(claim_set, claim_sets) {
                    cJSON* matched_claim_names = cJSON_CreateArray();
                    cJSON* matched_claim_metadata = cJSON_CreateArray();
                    cJSON* c;
                    cJSON_ArrayForEach(c, claim_set) {
                        if (cJSON_HasObjectItem(matched_claim_ids, cJSON_GetStringValue(c))) {
                            cJSON* matched_claim_info = cJSON_GetObjectItemCaseSensitive(matched_claim_ids, cJSON_GetStringValue(c));
                            cJSON_AddItemReferenceToArray(matched_claim_metadata, cJSON_GetObjectItemCaseSensitive(matched_claim_info, "claim_path"));
                            cJSON_AddItemReferenceToArray(matched_claim_names, cJSON_GetObjectItemCaseSensitive(matched_claim_info, "claim_display"));
                        }
                    }
                    if (cJSON_GetArraySize(matched_claim_names) == cJSON_GetArraySize(claim_set)) {
                        cJSON_AddItemReferenceToObject(matched_credential, "matched_claim_names", matched_claim_names);
                        cJSON_AddItemReferenceToObject(matched_credential, "matched_claim_metadata", matched_claim_metadata);
                        cJSON_AddItemReferenceToArray(matched_credentials, matched_credential);
                        break;
                    }
                }
            }
        }
    }

    cJSON_AddItemReferenceToObject(result, "matched_creds", matched_credentials);
    cJSON_AddItemReferenceToObject(result, "inline_issuance", inline_issuance);
    return result;
}

cJSON* dcql_query(cJSON* query, cJSON* credential_store) {
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