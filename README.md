# CMWallet - Android Digital Credentials Sample Wallet

CMWallet is a developer-focused Android sample application demonstrating integration with Android's
**Credential Manager API** to support **Verifiable Digital Credentials**.

This project demonstrates a referenceable Holder (Wallet), supporting **issuance** of credentials
from issuers through the **OpenID4VCI** standard and **presentation** of credentials to Verifiers (
apps) through the **OpenID4VP** standard.

## Try it out

* Navigate to https://github.com/digitalcredentialsdev/CMWallet/actions.
* Select the latest build and download the `app-debug.apk` file.
* Deploy the app on your Android device.
* Open the `CMWallet` app once to register the metadata with Credential Manager.
* Now the wallet is ready to handle a verifier Digital Credentials request.
    * You can navigate to the demo verifier site https://digital-credentials.dev/ and try it out.

---

## Architectural Design & System Flow

CMWallet is built on Jetpack Compose, using Room for storage and Ktor for networking.

CMWallet handles requests for credential presentation from **Verifiers** following
the [Android developer
website on displaying credentials](https://developer.android.com/identity/digital-credentials/credential-holder/credential-holder).

CMWallet handles requests to store credentials from **issuers** following the [Android developer
website on handling issuance](https://developer.android.com/identity/digital-credentials/credential-holder/issue-credential).

### 1. Credential Presentation

Presents user-selected credential claims to verifiers. Holders must first register their
credentials' metadata with Credential Manager to displayed to the user. When verifier websites or
apps request digital credential claims, Credential Manager will display relevant options for the
user to select. After the user selects a credential, the corresponding holder application will be
invoked, and then the credential will be presented to the verifier:

```
[Holder(wallet) app] ──► Registers presentation metadata with Credential Manager
                                                                   
[Verifier app / website] ──► Requests digital credential(s) ──► Credential Manager matches credentials and displays options to user ──► User selects credential(s) ──► Holder is invoked ──► Holder returns signed presentation to verifier
```

* **Matchers (WASM matching)**: In order to match a verifier's requested claims with registered
  metadata, Credential Manager runs the wallet's compiled WebAssembly (WASM) matching module (e.g.,
  `openid4vp1_0.wasm`) in an offline, secure system sandbox. The matcher evaluates the verifier's
  query against the stored credentials without revealing any private user details to the calling
  app. Credential Manager comes with a robust matcher that supports OpenID4VP, including the sd-jwt
  VC and the mdoc credential types, by default.
* **Holder invocation**: If matching credential(s) are found, Android displays a credential selector
  with the matched credentials to the user. The user selects the credential they want, which then
  invokes the holder and launches the holder activity. CMWallet launches an additional
  `BiometricPrompt` during invocation for additional user consent.
* **Presentation Assembly**: The wallet extracts the requested claims, signs the response using the
  private key stored in secure hardware, packages the payload, and returns it to the calling
  verifier.

Additional features: 

* **Multi-credential presentation**: Credential Manager supports requesting multiple credentials (e.g. age + payment) in a single request.
* **User-friendly UI**: The credential selector UI automatically adapts to different use cases, such as verification or payment confirmation, displaying the most appropriate layout for the request.

### 2. Credential Issuance

Normally a user can trigger credential issuance in two ways:

* Issuer-initiated flow: the user triggers a request to issue a VDC from an issuer application or
  website. For example, a website may offer its users an option to "Add your passport to your
  wallet". The issuer calls the [Credential Manager issuance API](https://developer.android.com/identity/digital-credentials/credential-issuer/issue-credentials)
  to make an OpenID4VCI Credential Offer request. To handle such requests, a wallet must first
  integrate with Credential Manager to register its metadata. Credential Manager will display
  relevant options for a user to select. After the user selects a wallet option, the wallet
  application will be invoked and can proceed with the steps needed to complete the issuance.

* Wallet-initiated flow: the user requests to add a VDC from their wallet application. For example,
  a wallet may offer a button to "Add your passport". In this case, the wallet maintains its
  supported issuer list and metadata. It does not need to integrate with the Android Credential
  Manager to complete this function.

CMWallet supports the issuer initiated flow, allowing arbitrary types of credentials in the SD-JWT
VC or mdoc format.

The credential issuance flow works similar to the presentation flow: 

```
[Holder(wallet) app] ──► Registers issuance metadata with Credential Manager
                                                                   
[Issuer app / website] ──► Requests credential issuance ──► Credential Manager matches and displays holder options to user ──► User selects holder ──► Holder is invoked ──► Holder completes the issuance operation
```

* **Key Generation and Attestation**: CMWallet supports [Android key attestation](https://developer.android.com/identity/digital-credentials/credential-issuer/keystore-attestation) for credential
binding keys. It provides a direct Android hardware backed key attestation and is the recommended key proof approach on Android.
* **Asynchronous issuance fulfillment**: Unlike presentation fulfillment, where the holder always returns a completed presentation result to the caller, issuance fulfillment involves multiple server interactions and sometimes a user verification process that can take hours to complete. Therefore, the holder may return a default response indicating the successful receipt of the issuance request. This does not necessarily mean that the issuance has completed; instead, it signals to the calling issuer that they can transition the user to an appropriate next step in the UI.

---

## Directory & Module Guide

```
CMWallet/
├── app/
│   └── src/main/java/com/credman/cmwallet/
│       ├── CmWalletApplication.kt       # App startup, registry synchronization
│       ├── MainActivity.kt              # Main launcher dashboard UI
│       ├── ui/                          # Compose views and home ViewModel
│       ├── getcred/                     # Presentation flow (GET_CREDENTIAL intent)
│       ├── createcred/                  # Issuance flow (CREATE_CREDENTIAL intent)
│       ├── data/                        # Repository and Room SQLite persistence
│       ├── openid4vci/                  # Issuance client implementation
│       ├── openid4vp/                   # Presentation parser and matching engine
│       ├── mdoc/                        # ISO 18013-5 mdoc formatting and signatures
│       ├── sdjwt/                       # sd-jwt VC format presentation and verification
│       └── cbor/                        # CBOR encoding helpers
├── matcher/                             # C implementation of wasm matcher
├── matcher-rs/                          # Rust implementation of wasm matcher
├── testdata/                            # Offline test credential generator & key material
│   ├── create_database.py               # Python script to sign & generate mdoc and SD-JWT test credentials
│   ├── helpers.py                       # Utilities for parsing SD-JWT claim paths and display metadata
│   ├── database_in.json                 # Raw unsigned input credentials (claims, namespaces, and display info)
│   ├── database.json                    # Output database containing signed test credentials & device keys
│   ├── ds_cert_mdoc.pem                 # Document Signer (DS) certificate for mdoc test credentials
│   ├── ds_private_key_mdoc.pem          # Private key for signing mdoc test credentials
│   ├── ds_cert_sdjwt.pem                # Document Signer (DS) certificate for SD-JWT test credentials
│   ├── ds_private_key_sdjwt.json        # JWK private key for signing SD-JWT test credentials
│   ├── issuer_cert_mdoc.pem             # Issuer Root CA certificate for mdoc
│   ├── issuer_cert_sdjwt.pem            # Issuer Root CA certificate for SD-JWT
│   ├── issuer_private_key_mdoc.pem      # Issuer root private key for mdoc
│   ├── issuer_private_key_sdjwt.json    # Issuer root private key for SD-JWT
│   └── issuance_wallet_attestation_cert.pem # Certificate used for wallet client attestation
│   ├── README.md                        # Instructions for building and deploying test database

```

### Detailed Directory Mapping

#### 1. App Configuration and Lifecycle

* **`CmWalletApplication.kt`**
    * **Role**: The application initialization class.
    * **Usage**: On startup, it configures the database and loads the compiled WASM matcher files (
      `openid4vp1_0.wasm`, `pnv.wasm`) from the app's `assets/`. It establishes a reactive Kotlin
      Flow that collects active credentials from the repository, transforms them into a
      `OpenId4VpRegistry` model, and updates Credential Manager's `RegistryManager` dynamically in
      the background.

#### 2. UI, Credential Presentation, and Handling Credential Issuance

* **`HomeScreen.kt` and `HomeViewModel.kt` (`/ui`)**
    * **Role**: Renders the wallet's main dashboard.
    * **Usage**: Displays stored digital cards in a swipeable wallet visual. Selecting a card opens
      the `CredentialDialog` for more detailed viewing.
* **`GetCredentialActivity.kt` (`/getcred`)**
    * **Role**: Entry point for Android's `GET_CREDENTIAL` flow.
    * **Usage**: This activity extracts the request JSON. It calls
      `processDigitalCredentialOption()` to filter matched claims, triggers the system's biometric
      lock, compiles the cryptographic response, and calls
      `PendingIntentHandler.setGetCredentialResponse()` to deliver it to the calling verifier app.
* **`CreateCredentialActivity.kt` and `CreateCredentialViewModel.kt` (`/createcred`)**
    * **Role**: Entry point for Android's `CREATE_CREDENTIAL` system provider flow.
    * **Usage**: Initiated during an issuance request. Displays a sheet presenting the issuer
      authentication flow (`AuthWebView`), manages network state steps, triggers key generation,
      requests the credential, and updates the Room DB upon approval.

#### 3. Protocol Implementations

* **`/openid4vci`**
    * **`OpenId4VCI.kt`**: Orchestrates HTTP communication with the Issuer. Uses **Ktor** to fetch
      OAuth2 authorization endpoints, post **PAR** (Pushed Authorization Requests), and retrieve
      issued credentials.
    * **`class DeviceKey`**: Contains `SoftwareKey` and `HardwareKey` classes representing device
      keys.
* **`/openid4vp`**
    * **`OpenId4VP.kt`**: Parses verifier presentation requests. Evaluates incoming nonces, extracts
      client metadata, parses query formats, and encrypts final payloads using JWE (JSON Web
      Encryption).
    * **`DCQL.kt`**: A pure Kotlin parser for the **Digital Credential Query Language**
      specification, allowing the app to perform query evaluations inside its own execution thread.

#### 4. Digital Credential Formats

* **`/mdoc`**
    * **`MDoc.kt`**: A parser for **ISO 18013-5** mobile driving license documents, converting
      binary CBOR namespaces and elements into structured Kotlin maps (`issuerSignedNamespaces`).
    * **`mdoc/Utils.kt`**: Cryptographic helper functions:
        * `generateDeviceResponse()`: Generates a standard-compliant COSE Sign1 signature utilizing
          the device private key, binding it to the verified claims.
        * `createSessionTranscript()`: Binds handover parameters (like domains and session nonces)
          into a SHA-256 byte array prevent replay attacks.
        * `filterIssuerSigned()`: Filters out the raw, verified issuer-signed claims to reveal only
          the elements the user chose to share.
* **`/sdjwt`**
    * **`SdJwt.kt`**: Integrates Selective Disclosure JSON Web Tokens.
    * **Key Function - `present()`**: Collects the verifier-selected claims, gathers their
      corresponding salt disclosures (formatted as base64 hashes), builds a **Key-Bound JWT** signed
      by the holder's private key, and joins them into a tilde (`~`) delimited string format for
      submission.

#### 5. Database and Storage (`/data`)

* **`repository/CredentialRepository.kt`**
    * **Role**: Synchronizes persistence layers.
    * **Usage**: Combines dynamic sqlite database records (`CredentialDatabaseDataSource`) and test
      credentials (`TestCredentialsDataSource`) into unified flows. It is responsible for
      transforming standard database items into Android System-level `DigitalCredentialEntry`
      structures (like `MdocEntry` and `SdJwtEntry`) including display properties and titles.

---

## The WASM Query Matchers (`/matcher` and `/matcher-rs`)

These folders contain the source code for the default WASM matchers, which support all OpenID4VP and OpenID4VCI use cases.

Note that the Credential Manager API already includes these default matchers, so you will most likely not need to create any custom matchers yourself.