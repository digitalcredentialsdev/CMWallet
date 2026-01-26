#ifndef DCQL_H
#define DCQL_H

#ifdef __cplusplus
extern "C" {
#endif

#include "cJSON/cJSON.h"

cJSON* dcql_query(cJSON* query, cJSON* credential_store);

#ifdef __cplusplus
}
#endif

#endif
