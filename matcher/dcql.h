#ifndef DCQL_H
#define DCQL_H

#include "cJSON/cJSON.h"

cJSON* dcql_query(const int request_id, cJSON* query, cJSON* credential_store);

#endif