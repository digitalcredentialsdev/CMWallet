# Objective
Add comprehensive unit testing for the C-based OpenID4VP / DCQL matcher in `matcher/`. The tests will cover Base64 decoding, DCQL query execution, credential filtering, and OpenID4VP protocol handling, including Android Credential Manager (ACM) WASM bindings.

# Proposed Solution
We will design 38 distinct test cases spanning `base64.c`, `dcql.c`, and `openid4vp1_0.c`. The test suite will be written in **C++** using the **`doctest`** testing framework and **`nlohmann/json`** for JSON payload mocking, built via a simple **Makefile** or **CMakeLists.txt**. We are not constrained by Wasm binary size in the test suite.

## Credential Store Mocking
We will use the following explicit, hardcoded mock registry JSON that covers all permutations tested below. It includes standard `mso_mdoc` credentials, deeply nested `dc+sd-jwt` credentials, issuance fallbacks, and the exact VCT targets needed to execute the complex credential sets from the OpenID4VP DCQL spec example.

```json
{
  "credentials": {
    "mso_mdoc": {
      "org.iso.18013.5.1.mDL": [
        {
          "id": "mdoc_cred_1",
          "display": {
            "verification": {
              "title": "John's Driving License",
              "icon": { "start": 4, "length": 10 }
            }
          },
          "paths": {
            "org.iso.18013.5.1": {
              "family_name": { "value": "Doe", "display": { "verification": { "display": "Family Name", "display_value": "Doe" } } },
              "given_name": { "value": "John", "display": { "verification": { "display": "Given Name", "display_value": "John" } } },
              "age": { "value": 21, "display": { "verification": { "display": "Age", "display_value": "Yes" } } },
              "age_over_21": { "value": true, "display": { "verification": { "display": "Over 21" } } }
            }
          }
        },
        {
          "id": "mdoc_cred_underage",
          "display": {
            "verification": {
              "title": "Underage License",
              "icon": { "start": 4, "length": 10 }
            }
          },
          "paths": {
            "org.iso.18013.5.1": {
              "age": { "value": 18, "display": { "verification": { "display": "Age" } } },
              "age_over_21": { "value": false, "display": { "verification": { "display": "Over 21", "display_value": "Yes"  } } }
            }
          }
        },
        {
          "id": "mdoc_cred_3",
          "display": {
            "verification": {
              "title": "Alice's Driving License",
              "icon": { "start": 4, "length": 10 }
            }
          },
          "paths": {
            "org.iso.18013.5.1": {
              "family_name": { "value": "Smith", "display": { "verification": { "display": "Family Name" } } },
              "given_name": { "value": "Alice", "display": { "verification": { "display": "Given Name" } } },
              "age": { "value": 25, "display": { "verification": { "display": "Age" } } },
              "age_over_21": { "value": true, "display": { "verification": { "display": "Over 21" } } }
            }
          }
        },
        {
          "id": "mdoc_cred_4",
          "display": {
            "verification": {
              "title": "Jane's Driving License",
              "icon": { "start": 4, "length": 10 }
            }
          },
          "paths": {
            "org.iso.18013.5.1": {
              "family_name": { "value": "Doe", "display": { "verification": { "display": "Family Name" } } },
              "given_name": { "value": "Jane", "display": { "verification": { "display": "Given Name" } } },
              "age": { "value": 30, "display": { "verification": { "display": "Age" } } },
              "age_over_21": { "value": true, "display": { "verification": { "display": "Over 21" } } }
            }
          }
        }
      ]
    },
    "dc+sd-jwt": {
      "urn:eu.europa.ec.eudi:pid:1": [
        {
          "id": "sdjwt_cred_1",
          "display": {
            "verification": {
              "title": "My EU PID",
              "icon": { "start": 4, "length": 10 }
            }
          },
          "paths": {
            "user": {
              "address": {
                "locality": { "value": "Brussels", "display": { "verification": { "display": "City" } } },
                "country": { "value": "BE", "display": { "verification": { "display": "Country" } } }
              },
              "name": {
                "first": { "value": "Jane", "display": { "verification": { "display": "First Name" } } }
              }
            }
          }
        }
      ],
      "https://credentials.example.com/identity_credential": [
        {
          "id": "sdjwt_spec_pid",
          "display": { "verification": { "title": "Spec PID", "icon": { "start": 4, "length": 10 } } },
          "paths": {
            "given_name": { "value": "Alice", "display": { "verification": { "display": "Given Name" } } },
            "family_name": { "value": "Smith", "display": { "verification": { "display": "Family Name" } } },
            "address": {
              "street_address": { "value": "123 Spec St", "display": { "verification": { "display": "Street" } } }
            }
          }
        }
      ],
      "https://othercredentials.example/pid": [
        {
          "id": "sdjwt_spec_other_pid",
          "display": { "verification": { "title": "Other PID", "icon": { "start": 4, "length": 10 } } },
          "paths": {
            "given_name": { "value": "Bob", "display": { "verification": { "display": "Given Name" } } },
            "family_name": { "value": "Jones", "display": { "verification": { "display": "Family Name" } } },
            "address": {
              "street_address": { "value": "456 Other St", "display": { "verification": { "display": "Street" } } }
            }
          }
        }
      ],
      "https://credentials.example.com/reduced_identity_credential": [
        {
          "id": "sdjwt_spec_reduced_1",
          "display": { "verification": { "title": "Reduced PID", "icon": { "start": 4, "length": 10 } } },
          "paths": {
            "given_name": { "value": "Charlie", "display": { "verification": { "display": "Given Name" } } },
            "family_name": { "value": "Brown", "display": { "verification": { "display": "Family Name" } } }
          }
        }
      ],
      "https://cred.example/residence_credential": [
        {
          "id": "sdjwt_spec_reduced_2",
          "display": { "verification": { "title": "Residence Cred", "icon": { "start": 4, "length": 10 } } },
          "paths": {
            "postal_code": { "value": "12345", "display": { "verification": { "display": "Zip" } } },
            "locality": { "value": "Townsville", "display": { "verification": { "display": "City" } } },
            "region": { "value": "State", "display": { "verification": { "display": "Region" } } }
          }
        }
      ],
      "https://company.example/company_rewards": [
        {
          "id": "sdjwt_spec_rewards",
          "display": { "verification": { "title": "Rewards", "icon": { "start": 4, "length": 10 } } },
          "paths": {
            "rewards_number": { "value": "9999", "display": { "verification": { "display": "Rewards No" } } }
          }
        }
      ]
    },
    "issuance": {
      "mso_mdoc": [
        {
          "id": "issuance_mdl_1",
          "title": "Get a New mDL",
          "subtitle": "From your local DMV",
          "icon": { "start": 4, "length": 10 },
          "supported": [ "org.iso.18013.5.1.mDL" ]
        }
      ],
      "dc+sd-jwt": [
        {
          "id": "issuance_pid_1",
          "title": "Get a New EU PID",
          "subtitle": "Official Digital ID",
          "icon": { "start": 4, "length": 10 },
          "supported": [ "urn:eu.europa.ec.eudi:pid:1" ]
        }
      ]
    }
  }
}
```

*Note: The test suite will construct a raw binary blob containing a mock 4-byte header and icon section prepended to this JSON string.*

## Fake Credential Manager Design (FakeCredman)
Based on the real Android Credential Manager's host implementation (`RegistryRuntime.kt` and `RegistryRuntimeExt.kt`), the test suite requires a stateful C++ mock to capture WASM import calls. The matcher communicates its results via functions like `AddEntrySet`, `AddEntryToSet`, and `AddFieldToEntrySet`.

The `FakeCredman` will be a global singleton tracking these invocations:
- **Data Structures**:
  - `EntryType`: Enum (`Verification`, `InlineIssuance`, `Payment`, `UserInfo`, `Export`) to distinguish between the types of entries added by the matcher.
  - `FakeEntry`: Struct storing `credId`, `type` (of `EntryType`), `title`, `subtitle`, `disclaimer`, `warning`, `metadata_display_text`, a vector of `fields` (key-value pairs), and payment details (`merchant_name`, `transaction_amount`).
  - `FakeEntrySet`: Struct storing `setId`, `setLength`, and a nested map `std::map<int, std::map<std::string, FakeEntry>> entries` (keyed by `setIndex` and `credId`).
  - `FakeStandaloneEntries`: For entries not in a set (e.g., `AddInlineIssuanceEntry`).
- **Mocks**: It will export `extern "C"` functions mimicking the host bindings, routing arguments into the `FakeCredman` state and assigning the appropriate `EntryType`:
  - `AddEntrySet(setId, setLength)`
  - `AddEntryToSet(...)` -> Creates `FakeEntry` with `type = Verification`.
  - `AddFieldToEntrySet(...)` -> Appends to `fields` of the matching entry.
  - `AddPaymentEntryToSetV2(...)` -> Creates `FakeEntry` with `type = Payment`.
  - `AddMetadataDisplayTextToEntrySet(...)` -> Updates `metadata_display_text`.
  - `AddInlineIssuanceEntry(...)` -> Creates `FakeEntry` in `FakeStandaloneEntries` with `type = InlineIssuance`.
- **Verification**: Tests will reset `FakeCredman` before each run and assert on its final state (e.g., verifying `FakeCredman::GetInstance().entrySets["my_set"].entries[0]["cred_123"].type == Verification`).

## Test Cases & Assertions

For every test case that executes a matcher query, we will assert not only the internal C structures (e.g., `matched_creds`) but also the exact state pushed to the `FakeCredman` about the added entry set (ID), the entries contained in each set, and their correct `EntryType`.

### Group 1: Base64-URL Decoding (`base64.c`)
1. **TC01_DecodeEmptyString**: Input `""`. Assert output length is 0, buffer is empty.
2. **TC02_DecodeNoPadding**: Input `"SGVsbG8"`. Assert output length is 5, buffer matches `"Hello"`.
3. **TC03_DecodeOnePadding**: Input `"SGVsbG8="`. Assert output length is 5.
4. **TC04_DecodeTwoPaddings**: Input `"SGVsbA=="`. Assert output length is 4.
5. **TC05_DecodeUrlSafeChars**: Input `"-_-_"`. Assert output length is 3, buffer matches raw binary conversion.
6. **TC06_DecodeInvalidChars**: Input `"SGV@#G8"`. Assert function handles gracefully (outputs mapped zeros based on `B64Lookup`).

### Group 2: DCQL Query & Matching (`dcql.c`)
7. **TC07_MdocMatch**: Request `mso_mdoc` with `doctype_value: org.iso.mDL`. Assert `MatchCredential` returns candidate in `matched_creds`. Assert `FakeCredman` receives `AddEntrySet` and `AddEntryToSet` with the expected `credId` and `type = Verification`.
8. **TC08_MdocMismatch**: Request `mso_mdoc` with `doctype_value: UNKNOWN`. Assert `matched_creds` is empty. Assert `FakeCredman.entrySets` is empty.
9. **TC09_SdjwtMatch**: Request `dc+sd-jwt` with `vct_values: ["urn:eu.europa.ec.eudi:pid:1"]`. Assert candidate match. Assert `FakeCredman` registers the `dc+sd-jwt` entry in the expected set index with `type = Verification`.
10. **TC10_SdjwtMismatch**: Request `dc+sd-jwt` with `vct_values: ["UNKNOWN"]`. Assert `matched_creds` is empty.
11. **TC11_InlineIssuanceFallback**: Request `mso_mdoc` where credentials don't match, but `issuance` list has matching supported doctype. Assert `FakeCredman` receives `AddInlineIssuanceEntry`, creating an entry with `type = InlineIssuance`, correct `title`/`subtitle`, and empty `fields`.
12. **TC12_MissingFormat**: Request `w3c_vc`. Store has no `w3c_vc` candidates. Assert `matched_creds` is empty.
13. **TC13_ReturnAllClaims**: Query has no `claims` array. Assert `AddAllClaims` populates `matched_claim_names`. Assert `FakeCredman` receives `AddFieldToEntrySet` for *all* candidate claims on the Verification entry.
14. **TC14_MatchSpecificClaims**: Query asks for `["family_name"]`. Assert `FakeCredman` receives exactly 1 `AddFieldToEntrySet` call for "Family Name".
15. **TC15_MatchNestedClaims**: Query asks for path `["address", "locality"]`. Assert deep traversal resolves the claim and pushes it to `FakeCredman`.
16. **TC16_FailMissingClaims**: Query asks for path `["unknown", "claim"]`. Assert credential does not append to `matched_creds`.
17. **TC17_MatchClaimValuesBool**: Query specifies claim `age_over_21` with `values: [true]`. Candidate has boolean `true`. Assert `FakeCredman` registers the entry.
18. **TC18_FailClaimValuesBool**: Query specifies claim `age_over_21` with `values: [true]`. Candidate has boolean `false`. Assert `FakeCredman.entrySets` is empty.
19. **TC19_MatchClaimValuesInt**: Query specifies integer claim `age` with `values: [21, 22]`. Candidate has integer `21`. Assert `FakeCredman` registers the entry.
20. **TC20_FailClaimValuesInt**: Query specifies integer claim `age` with `values: [21, 22]`. Candidate has integer `18`. Assert `FakeCredman.entrySets` is empty.
21. **TC21_MatchFirstClaimSet**: Query specifies two `claim_sets`. Candidate satisfies set 1. Assert `FakeCredman` registers the entry.
22. **TC22_MatchSecondClaimSet**: Candidate lacks claims for set 1, but satisfies set 2. Assert `FakeCredman` registers the entry.
23. **TC23_FailAllClaimSets**: Candidate satisfies neither claim set. Assert mismatch.
24. **TC24_DcqlQuerySingle**: Run `dcql_query` with one required credential. Assert `FakeCredman` populates `entrySets["request_id_0"]` with `setLength=1`.
25. **TC25_DcqlQuerySetMatch**: `dcql_query` with `credential_sets` where `required: true` set is matched. Assert `FakeCredman` registers the matched Verification entries under the correctly assigned `setId`.
26. **TC26_DcqlQuerySetFailRequired**: `credential_sets` where `required: true` set fails. Assert `FakeCredman` remains empty.
27. **TC27_DcqlQuerySetFailOptional**: `credential_sets` where `required: false` set fails, but `required: true` matches. Assert overall match succeeds in `FakeCredman`.
28. **TC28_DcqlQueryComplexOverlappingSets**: Execute a `dcql_query` using `credential_sets` that define 3 options/sets, where each option requires at least 2 credentials. Design the mock credentials such that the same `credId` fulfills requirements across multiple sets. Assert `FakeCredman` populates 3 distinct entry sets (i.e. length of `entrySets` is 3), each containing at least 2 entries, and verify that the overlapping `credId` (like `mdoc_cred_4`) is correctly registered in the overlapping sets without errors.
29. **TC29_DcqlQueryOpenID4VPSpecExample**: Execute the specific DCQL query from the OpenID4VP spec (detailed below) containing multiple `dc+sd-jwt` requests and complex `credential_sets` (Required Set: `[pid]`, `[other_pid]`, `[pid_reduced_cred_1, pid_reduced_cred_2]`; Optional Set: `[nice_to_have]`). Assert `FakeCredman` successfully processes the combinations and populates the expected discrete entry sets matching the registry data.

```json
{
  "credentials": [
    {
      "id": "pid",
      "format": "dc+sd-jwt",
      "meta": {
        "vct_values": ["https://credentials.example.com/identity_credential"]
      },
      "claims": [
        {"path": ["given_name"]},
        {"path": ["family_name"]},
        {"path": ["address", "street_address"]}
      ]
    },
    {
      "id": "other_pid",
      "format": "dc+sd-jwt",
      "meta": {
        "vct_values": ["https://othercredentials.example/pid"]
      },
      "claims": [
        {"path": ["given_name"]},
        {"path": ["family_name"]},
        {"path": ["address", "street_address"]}
      ]
    },
    {
      "id": "pid_reduced_cred_1",
      "format": "dc+sd-jwt",
      "meta": {
        "vct_values": ["https://credentials.example.com/reduced_identity_credential"]
      },
      "claims": [
        {"path": ["family_name"]},
        {"path": ["given_name"]}
      ]
    },
    {
      "id": "pid_reduced_cred_2",
      "format": "dc+sd-jwt",
      "meta": {
        "vct_values": ["https://cred.example/residence_credential"]
      },
      "claims": [
        {"path": ["postal_code"]},
        {"path": ["locality"]},
        {"path": ["region"]}
      ]
    },
    {
      "id": "nice_to_have",
      "format": "dc+sd-jwt",
      "meta": {
        "vct_values": ["https://company.example/company_rewards"]
      },
      "claims": [
        {"path": ["rewards_number"]}
      ]
    }
  ],
  "credential_sets": [
    {
      "options": [
        [ "pid" ],
        [ "other_pid" ],
        [ "pid_reduced_cred_1", "pid_reduced_cred_2" ]
      ]
    },
    {
      "required": false,
      "options": [
        [ "nice_to_have" ]
      ]
    }
  ]
}
```

### Group 3: Protocol Parsing & Integration (`openid4vp1_0.c` & ACM bindings)
30. **TC30_ParseV1Unsigned**: Mock `dc_request` with `openid4vp-v1-unsigned`. Assert JSON payload parsed correctly.
31. **TC31_ParseV1Signed**: Mock `dc_request` with `openid4vp-v1-signed` (JWS). Assert payload extracted, split by '.', and Base64-decoded into JSON.
32. **TC32_ExtractPaymentSca1**: Mock `transaction_data` type `urn:eudi:sca:payment:1`. Assert `FakeCredman` receives `AddPaymentEntryToSetV2`, creating an entry with `type = Payment`, `merchant_name` from `payload.payee.name` and correctly calculated amount.
33. **TC33_ExtractPaymentDetails**: Mock `transaction_data` type `payment_details`. Assert `FakeCredman` Payment entry receives amount concatenated with currency.
34. **TC34_ExtractPaymentGeneric**: Mock `transaction_data` lacking type. Assert fallback to `merchant_name` and `amount` keys on the Payment entry in `FakeCredman`.
35. **TC35_WasmAddEntryToSet**: Mock WASM version 2 (non-payment). Assert `AddEntryToSet` invoked. Assert `FakeCredman` captures correct title, subtitle, and icon offset/len with `type = Verification`.
36. **TC36_WasmPaymentV2**: Mock WASM version 3 (payment). Assert `FakeCredman` verifies `AddPaymentEntryToSetV2` created a `Payment` entry and parsed transaction amount/merchant accurately.
37. **TC37_WasmPaymentV1**: Mock WASM version 2 (payment). Assert `FakeCredman` receives `AddPaymentEntryToSet` (legacy) instead of V2, creating a `Payment` entry.
38. **TC38_WasmMetadataText**: Mock WASM version 5. Assert `FakeCredman` receives `AddMetadataDisplayTextToEntrySet` appending the expected `metadata_display_text` string to the correct Verification entry.

# Implementation Plan
1. **Mock Setup**: Instantiate the explicit `cJSON` or `nlohmann/json` string payload from the plan inside `test_runner.cc`.
2. **Fake Credman**: Implement the `FakeCredman` global state (including `EntryType` distinguishing logic) and the `extern "C"` functions mimicking `RegistryRuntime.kt` (e.g. `AddEntrySet`, `AddEntryToSet`, `AddFieldToEntrySet`).
3. **Framework & Build**: Create a `Makefile` or `CMakeLists.txt` using the system-installed `doctest.h` and `nlohmann/json.hpp`.
4. **C++ Interop**: Write `test_runner.cc`, including the C headers (`extern "C"`) and linking the mock APIs so `openid4vp1_0.c` and `dcql.c` execute correctly.
5. **Tests Implementation**: Implement `TEST_CASE` blocks in `test_runner.cc` covering TC01 through TC38. Ensure every matcher test asserts `FakeCredman` state (e.g., set IDs, entry counts, `EntryType`, field names, and values).