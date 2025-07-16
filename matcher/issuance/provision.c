#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <unistd.h>
#include "../cJSON/cJSON.h"
#include "../credentialmanager.h"

#include "launcher_icon.h"

#define PROTOCOL_OPENID4VCI "openid4vci1.0"
#define PROTOCOL_OPENID4VCI_V1 "openid4vci-v1"

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

int main() {uint32_t credentials_size;
    GetCredentialsSize(&credentials_size);

    char* creds_blob = malloc(credentials_size);
    ReadCredentialsBuffer(creds_blob, 0, credentials_size);

    int json_offset = *((int*)creds_blob);
    printf("Creds JSON offset %d\n", json_offset);

    cJSON* creds = cJSON_Parse(creds_blob + json_offset);
    printf("Creds JSON %s\n", cJSON_Print(creds));
    /* 
      {
        "display": {
            "icon": {...},
            "title": "...",
            "subtitle": "..."
        },
        capability: {
            "issuer1": {},
            "issuer2": {}
        }
      }
    */

    cJSON* dc_request = GetDCRequestJson();
    printf("Request JSON %s\n", cJSON_Print(dc_request));

    cJSON* requests = cJSON_GetObjectItem(dc_request, "requests");
    int requests_size = cJSON_GetArraySize(requests);
    for(int i=0; i<requests_size; i++) {
        cJSON* request = cJSON_GetArrayItem(requests, i);
        char* protocol = cJSON_GetStringValue(cJSON_GetObjectItem(request, "protocol"));
        if (strcmp(protocol, PROTOCOL_OPENID4VCI) == 0 || strcmp(protocol, PROTOCOL_OPENID4VCI_V1) == 0) {
            // We have an OpenID4VCI request
            cJSON* cred_offer = cJSON_GetObjectItem(request, "data");
            cJSON* credential_issuer = cJSON_GetObjectItem(cred_offer, "credential_issuer");
        
            cJSON* capabilities = cJSON_GetObjectItem(creds, "capabilities");
            if(capabilities == NULL || cJSON_HasObjectItem(capabilities, cJSON_GetStringValue(credential_issuer))) {
                cJSON* display = cJSON_GetObjectItem(creds, "display");
                cJSON* icon = cJSON_GetObjectItem(display, "icon");
                int icon_start_int = 0;
                int icon_len = 0;
                if (icon != NULL) {
                    cJSON* start = cJSON_GetObjectItem(icon, "start");
                    cJSON* length = cJSON_GetObjectItem(icon, "length");
                    if (start != NULL && length != NULL) {
                        double icon_start = (cJSON_GetNumberValue(start));
                        icon_start_int = icon_start;
                        icon_len = (int)(cJSON_GetNumberValue(length));
                    }
                }
                cJSON* title = cJSON_GetObjectItem(display, "title");
                cJSON* subtitle = cJSON_GetObjectItem(display, "subtitle");
                
                AddStringIdEntry("0", creds_blob + icon_start_int, icon_len, cJSON_GetStringValue(title), cJSON_GetStringValue(subtitle), NULL, NULL);
            }
        }
    }
	return 0;
}