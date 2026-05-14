# OpenID4VP Matcher: Comprehensive Code Index

## 1. Registry Binary Format
The registry blob is a custom binary format:
- **Header**: 4 bytes (Little-endian `int`) representing the offset from the start of the blob to the beginning of the JSON metadata.
- **Icon Section**: Raw PNG bytes located between the header and the JSON metadata.
- **Metadata Section**: UTF-8 encoded JSON string starting at the specified offset.

The source of truth lives in the [Jetpack library](https://cs.android.com/androidx/platform/frameworks/support/+/androidx-main:credentials/registry/registry-digitalcredentials-openid/src/main/java/androidx/credentials/registry/digitalcredentials/openid4vp/OpenId4VpRegistry.kt). Specifically, the current impl is compatible with [this commit](https://cs.android.com/androidx/platform/frameworks/support/+/androidx-main:credentials/registry/registry-digitalcredentials-openid/src/main/java/androidx/credentials/registry/digitalcredentials/openid4vp/OpenId4VpRegistry.kt;drc=c9d1a56029af57bab736319f1612e3f09953010b).

## 2. Registry JSON Schema
Root structure: `{"credentials": { ... }}`

### 2.1 mso_mdoc (credentials.mso_mdoc)
- **Key**: Document Type (e.g., "org.iso.18013.5.1.mDL")
- **Value**: Array of Credential Objects:
  - `id`: String.
  - `display`:
    - `verification`:
      - `title`: String.
      - `subtitle`: String (optional).
      - `explainer`: String (optional).
      - `warning`: String (optional).
      - `metadata_display_text`: String (optional).
      - `icon`: `{"start": <int>, "length": <int>}`.
  - `paths`: Map of Namespace -> Map of ClaimName -> Claim object:
    - `value`: Any (raw value).
    - `display`:
      - `verification`:
        - `display`: String (localized name).
        - `display_value`: String (optional localized value).

### 2.2 dc+sd-jwt (credentials.dc+sd-jwt)
- **Key**: Verifiable Credential Type (VCT) string.
- **Value**: Array of Credential Objects.
- **Paths Construction**: The Kotlin `SdJwtEntry.claims` (a list) is flattened into a nested `paths` object. Each `SdJwtClaim.path` (an array of strings) defines the nesting.
- **Example**: A claim with `path = ["user", "name", "first"]` becomes:
  ```json
  "paths": {
    "user": {
      "name": {
        "first": {
          "value": "John",
          "display": { "verification": { "display": "First Name", ... } }
        }
      }
    }
  }
  ```
- **Structure**:
  - `id`: String.
  - `display`: (same as mso_mdoc).
  - `paths`: Recursive nested object. Leaf nodes are Claim objects (same structure as mso_mdoc).

### 2.3 Issuance (credentials.issuance)
- **mso_mdoc**: Array of MdocInlineIssuanceEntry objects:
  - `id`: String.
  - `subtitle`: String (optional).
  - `title`: String (optional hint).
  - `icon`: `{"start": <int>, "length": <int>}` (optional).
  - `supported`: Array of DocType Strings.
- **dc+sd-jwt**: Array of SdJwtInlineIssuanceEntry objects:
  - `id`: String.
  - `subtitle`: String (optional).
  - `title`: String (optional hint).
  - `icon`: `{"start": <int>, "length": <int>}` (optional).
  - `supported`: Array of VCT Strings.

---

## 3. C Function Index

### base64.c / base64.h
- `static int B64Lookup(char x)`: Helper function that maps Base64-URL characters to their corresponding 6-bit integer values.
- `int B64DecodeURL(char* input, char** output)`: Takes a Base64-URL encoded string and decodes it. It allocates a new buffer for the output using `malloc` and returns the decoded length. It correctly handles base64url specific characters ('-' and '_') as well as standard padding ('=').

### credentialmanager.c / credentialmanager.h
- Provides ACM (Android Credential Manager) environment bindings to interface with the Android OS.
- `void* GetRequest()`: Fetches the buffer containing the ACM request JSON.
- `void* GetCredentials()`: Fetches the buffer containing the Registry binary blob.
- Also exposes WASM imports for ACM reporting: `AddEntrySet`, `AddEntryToSet`, `AddFieldToEntrySet`, `AddPaymentEntryToSetV2`, `GetWasmVersion`, `AddInlineIssuanceEntry`, etc.

### dcql.c / dcql.h
- `int AddAllClaims(cJSON* matched_claim_names, cJSON* candidate_paths)`: Recursively traverses a JSON object representing candidate claim paths. For every object containing a "display" key, it adds that "display" object to the `matched_claim_names` array. This is used when a request doesn't specify specific claims, so the matcher must collect all available claims from the credential to show to the user.
- `cJSON* MatchCredential(cJSON* credential, cJSON* credential_store)`: Evaluates a single DCQL `credential` requirement against the registry `credential_store`.
  - Determines if the requested format is `mso_mdoc` or `dc+sd-jwt`.
  - Checks if the credential candidate matches the `meta` criteria (e.g., matching `doctype_value` for `mso_mdoc`, or `vct_values` for `dc+sd-jwt`).
  - Iterates over candidates that matched the `meta` criteria.
  - If specific `claims` are requested, it traverses the `paths` of the candidate using the requested JSON paths array. It matches claim values if `values` are specified in the request.
  - If `claim_sets` are specified, it verifies that at least one logical group of claims is fully satisfied by the matched claims.
  - Identifies matching inline issuance options by comparing `supported` DocTypes or VCTs against the `meta` requirements.
  - Returns a JSON object with `matched_creds` (list of matched credentials containing `id`, `display`, `matched_claim_names`, and `matched_claim_metadata`) and an `inline_issuance` entry if applicable.
- `cJSON* dcql_query(cJSON* query, cJSON* credential_store)`: High-level function that orchestrates DCQL evaluation.
  - Iterates over all `credentials` in the DCQL query and calls `MatchCredential` for each.
  - If `credential_sets` are defined in the query, it iterates over these sets and their options to find valid combinations of matched credentials that satisfy the query logic (handling `required` flags).
  - If no `credential_sets` are defined, it requires all requested credentials to match.
  - Returns a final `match_result` JSON containing `matched_credential_sets` (valid combinations of credentials) and `matched_credentials` (the actual credential details).

### openid4vp1_0.c
- `void report_credential_set_length(...)`: Recursively calculates the total number of credentials across all options in a matched credential set and reports this total length to the ACM using `AddEntrySet`.
- `void report_matched_credential(...)`: Reports a specific matched credential to the ACM.
  - Constructs a JSON metadata string containing the matched claims, request index, and DCQL IDs.
  - Checks if the credential is a payment transaction (if `transaction_credential_ids` match). If so, it reports it as a payment entry via `AddPaymentEntryToSetV2` or `AddPaymentEntryToSet` (depending on the WASM version).
  - Otherwise, it reports it as a standard entry via `AddEntryToSet`, providing title, subtitle, explainer, and icon offsets.
  - Iterates through `matched_claim_names` to report each individual matched claim via `AddFieldToEntrySet`.
  - Reports `metadata_display_text` via `AddMetadataDisplayTextToEntrySet` if present.
- `void report_matched_credential_set(...)`: Recursively iterates through the complex `matched_credential_sets` structure returned by `dcql_query` and calls `report_matched_credential` for each valid credential in each option.
- `int main()`: The global entry point for the WASM module.
  - Fetches the credentials binary blob and finds the JSON metadata offset.
  - Parses the registry JSON and the DCQL request JSON.
  - Determines if the request is OpenID4VP (signed or unsigned) and decodes the payload via `B64DecodeURL` if it's signed (JWS).
  - Handles transaction data extraction for payments (merchant name, amount, additional info).
  - Calls `dcql_query` to perform the actual matching.
  - Extracts the matched results and uses the `report_*` functions to format and send the results back to the Android OS via the ACM API.
  - Handles inline issuance fallback by calling `AddInlineIssuanceEntry` if no regular credentials match but inline issuance is supported.

### testharness.c
- Provides mock implementations for ACM APIs (`GetRequestSize`, `GetRequestBuffer`, `GetCredentialsSize`, `ReadCredentialsBuffer`, etc.) to allow for local execution of the `main()` function.
- Reads test inputs from local files like `request.json` and `testcreds.json`.
