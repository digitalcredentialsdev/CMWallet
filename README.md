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

To learn about handling requests for credentials from other applications, or **Verifiers**,
see [Credential Presentation](#1-credential-presentation). Learn more on
the [Android developer
website on displaying credentials](https://developer.android.com/identity/digital-credentials/credential-holder/credential-holder).

To learn about handling requests to store credentials from credential **issuers**,
see [Credential Issuance](#2-credential-issuance). Learn more on
the [Android developer
website on handling issuance](https://developer.android.com/identity/digital-credentials/credential-holder/issue-credential).

### 1. Credential Presentation

Presents user-selected credential claims to verifiers. Holders must first register their
credentials' metadata with Credential Manager to displayed to the user. When verifier websites or
apps request digital credential claims, Credential Manager will display relevant options for the
user to select. After the user selects a credential, the corresponding holder application will be
invoked, and then the credential will be presented to the verifier:

```
[Holder(wallet) app] ──► Registers metadata with Credential Manager
                                                                   
[Verifier app] ──► Requests digital credential claim(s) ──► Credential Manager matches claims and displays options to user ──► User selects credential ──► Holder is invoked ──► Holder returns signed presentation to verifier
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

### 2. Credential Issuance

Handles credential issuance requests from issuers. When a user initiates getting a credential from
an issuer by scanning a QR code or opening a link, the issuer calls the Android Credential Manager
API that launches the credential creation and storage process:

```
[Issuer app] ──► Triggers system intent: CREATE_CREDENTIAL ──► calls Credential Manater's CreateCredentialActivity
                                                                                                 │
       Save issued credential ◄── Hardware-backed attestation process ◄── Request credential from Issuer 
```

* **Issuer triggers intent**: The issuer triggers Android's `CREATE_CREDENTIAL` system intent,
  launching `CreateCredentialActivity`.
* **Progress bottom sheet**: The wallet displays a Compose bottom sheet showing a progress bar while
  it parses the Credential Offer.
* **Key Generation and Attestation**: The wallet generates a secure cryptographic EC P-256 key pair
  in the phone's hardware-backed **Android KeyStore**. It creates a signed **DPoP Proof** and an *
  *Android Keystore Key Attestation** to prove the key is tied to a genuine physical device.
* **Hardware-backed attestation process**: The wallet sends the key proofs to the issuer's endpoint
  and receives the signed credential payload (in mDoc or sd-jwt format)
* **Saving the credential**: The wallet decrypts the signed credential payload if it is encrypted,
  and persists it in the Room Database.

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
└── matcher-rs/                          # Rust implementation of wasm matcher
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

Credential matching does not happen directly in the main wallet app code. Instead:

1. Matcher code is written in C/C++ (`matcher/`) or Rust (`matcher-rs/`).
2. It implements DCQL parser rules and format-specific validation.
3. It compiles directly to a WebAssembly binary target in `build.sh`
4. The resulting `.wasm` files are placed in `app/src/main/assets/`.
5. When a request arrives, Credential Manager loads these WASM binaries into an isolated system
   sandbox for query matching.

Note that matches are not required to be separately defined; Credential Manager already includes a
default matcher.