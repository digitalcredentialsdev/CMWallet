#include <stdio.h>
#include <sys/stat.h>

#include "credentialmanager.h"

#define REQUEST_PATH "request.json"
#define CREDS_PATH "testcreds.json"

void GetFileSize(const char* path, uint32_t* size) {
    struct stat s;
    stat(path, &s);
    *size = s.st_size;
}

void GetRequestSize(uint32_t* size) {
    GetFileSize(REQUEST_PATH, size);
}

void GetRequestBuffer(void* buffer) {
    uint32_t len;
    GetRequestSize(&len);
    FILE* f = fopen(REQUEST_PATH, "r");
    fread(buffer, len, 1, f);
    fclose(f);
}

void GetCredentialsSize(uint32_t* size) {
    GetFileSize(CREDS_PATH, size);
}

size_t ReadCredentialsBuffer(void* buffer, size_t offset, size_t len) {
    FILE* f = fopen(CREDS_PATH, "r");
    fseek(f, offset, SEEK_SET);
    size_t bytes_read = fread(buffer, 1, len, f);
    fclose(f);
    return bytes_read;
}

void AddStringIdEntry(const char* cred_id, const char* icon, size_t icon_len, const char* title, const char* subtitle, const char* disclaimer, const char* warning) {
    printf("AddStringIdEntry id:%s title:%s subtitle:%s\n", cred_id, title, subtitle);
}

void AddFieldForStringIdEntry(const char* cred_id, const char* field_display_name, const char* field_display_value) {
    printf("AddFieldForStringIdEntry id:%s field_display_name:%s\n", cred_id, field_display_name);
}
