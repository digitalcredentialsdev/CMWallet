package com.credman.cmwallet.openid4vci

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import androidx.compose.ui.input.key.Key
import com.credman.cmwallet.CmWalletApplication.Companion.TAG
import com.credman.cmwallet.createJWTES256
import com.credman.cmwallet.jweSerialization
import com.credman.cmwallet.loadECPrivateKey
import com.credman.cmwallet.openid4vci.data.CredentialOffer
import com.credman.cmwallet.openid4vci.data.CredentialRequest
import com.credman.cmwallet.openid4vci.data.CredentialResponse
import com.credman.cmwallet.openid4vci.data.NonceResponse
import com.credman.cmwallet.openid4vci.data.OauthAuthorizationServer
import com.credman.cmwallet.openid4vci.data.ParResponse
import com.credman.cmwallet.openid4vci.data.Proofs
import com.credman.cmwallet.openid4vci.data.TokenRequest
import com.credman.cmwallet.openid4vci.data.TokenResponse
import com.credman.cmwallet.toBase64UrlNoPadding
import com.credman.cmwallet.toJWK
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.forms.submitForm
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.http.parameters
import io.ktor.serialization.kotlinx.json.json
import io.ktor.util.encodeBase64
import kotlinx.coroutines.delay
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.json.JSONObject
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.interfaces.ECPrivateKey
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.security.cert.Certificate
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

@OptIn(ExperimentalUuidApi::class)
class OpenId4VCI(val credentialOfferJson: String) {

    companion object {
        const val WALLET_CLIENT_ID = "https://cmwallet.example.org"
        const val WALLET_NAME = "CMWallet"

        /** Priv key for [WALLET_CERT] */
        /** Should be generated server side. Only use this for testing purpose */
        val WALLET_CERT_PRV_KEY =
            loadECPrivateKey(Base64.decode(
                "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgp7MvoXLpeRcEjKdUETZNjqCkAtU86ER2cesSDYRwTcqhRANCAAQIr_o2Q9PaiQg7AOsJD4jLvhr0x_i_JrwhNKAF6WQDty3QKaMZlYZIabS9wTpUkEPMOYJ7sqwTS81okBqoYGG2", Base64.URL_SAFE)) as ECPrivateKey


        const val WALLET_CERT = "-----BEGIN CERTIFICATE-----\n" +
                "MIICrTCCAlOgAwIBAgIUMfoUOsCwoUcR5adonlnZTfcIw1owCgYIKoZIzj0EAwIw\n" +
                "dTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1v\n" +
                "dW50YWluIFZpZXcxETAPBgNVBAoMCENNV2FsbGV0MSYwJAYDVQQDDB1jbXdhbGxl\n" +
                "dC1wcm92aWRlci5leGFtcGxlLmNvbTAeFw0yNjAyMTMwMTM2MzNaFw0zNjAyMDEw\n" +
                "MTM2MzNaMHUxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYD\n" +
                "VQQHDA1Nb3VudGFpbiBWaWV3MREwDwYDVQQKDAhDTVdhbGxldDEmMCQGA1UEAwwd\n" +
                "Y213YWxsZXQtcHJvdmlkZXIuZXhhbXBsZS5jb20wWTATBgcqhkjOPQIBBggqhkjO\n" +
                "PQMBBwNCAAQIr/o2Q9PaiQg7AOsJD4jLvhr0x/i/JrwhNKAF6WQDty3QKaMZlYZI\n" +
                "abS9wTpUkEPMOYJ7sqwTS81okBqoYGG2o4HAMIG9MB0GA1UdDgQWBBRiENDlrMNA\n" +
                "dBU2zs4tK6Yuyp6/6jAfBgNVHSMEGDAWgBRiENDlrMNAdBU2zs4tK6Yuyp6/6jAP\n" +
                "BgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIHgDAwBgNVHRIEKTAnhiVodHRw\n" +
                "czovL2Ntd2FsbGV0LXByb3ZpZGVyLmV4YW1wbGUuY29tMCgGA1UdEQQhMB+CHWNt\n" +
                "d2FsbGV0LXByb3ZpZGVyLmV4YW1wbGUuY29tMAoGCCqGSM49BAMCA0gAMEUCICDU\n" +
                "6quuv/9kP90eDaZs6hZsmYOh1UA37qHg6n7Lom4FAiEAvfaJE4YylFDXdyF7YgB2\n" +
                "FddC70oU1mVNrH6WlLmdQxY=\n" +
                "-----END CERTIFICATE-----"
    }
    private val json = Json {
        explicitNulls = false
        ignoreUnknownKeys = true
    }
    val credentialOffer: CredentialOffer = json.decodeFromString(credentialOfferJson)
    private val authServerCache = mutableMapOf<String, OauthAuthorizationServer>()
    private val httpClient = HttpClient(CIO) {
        install(ContentNegotiation) {
            json()
        }
    }

    val codeVerifier = ByteArray(33).let {
        SecureRandom().nextBytes(it)
        return@let it
    }.toBase64UrlNoPadding()

    private val kp: KeyPair

    init {
        val kpg =  KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))
        kp = kpg.genKeyPair()
    }

    suspend fun requestAuthServerMetadata(server: String): OauthAuthorizationServer {
        if (credentialOffer.authorizationServerMetadata != null) {
            delay(50)
            return credentialOffer.authorizationServerMetadata
        }
        if (server !in authServerCache) {
            authServerCache[server] =
                httpClient.get("$server/.well-known/oauth-authorization-server").body()
        }
        return authServerCache[server]!!
    }

    fun authServerIdentifier(): String = if (credentialOffer.issuerMetadata.authorizationServers == null) {
        credentialOffer.issuerMetadata.credentialIssuer
    } else {
        "Can't do this yet"
    }

    suspend fun authEndpoint(authServer: String): String {
        return requestAuthServerMetadata(authServer).authorizationEndpoint!!
    }

    suspend fun requestNonceFromEndpoint(): NonceResponse {
        require(credentialOffer.issuerMetadata.nonceEndpoint != null) { "nonce_endpoint must be set when requesting a nonce" }
        return httpClient.post(credentialOffer.issuerMetadata.nonceEndpoint).body()
    }

    /** Returns null if par endpoint isn't specified in the authorization server metadata. */
    @OptIn(ExperimentalUuidApi::class)
    suspend fun requestParEndpoint(): ParResponse? {
        val clientAttestation = getClientAttestationJwt()
        val clientAttestationPop = getClientAttestationJwt()

        val parEndpoint = credentialOffer.authorizationServerMetadata?.mtlsEndpointAliases?.pushedAuthorizationRequestEndpoint ?:
            credentialOffer.authorizationServerMetadata?.pushedAuthorizationRequestEndpoint ?: return null
        val credId = credentialOffer.credentialConfigurationIds.first()
        val md = MessageDigest.getInstance("SHA256")
        val codeChallenge = md.digest(codeVerifier.toByteArray()).toBase64UrlNoPadding()

        val result = httpClient.submitForm(
            url = parEndpoint,
            formParameters = parameters {
                append("client_id", WALLET_CLIENT_ID)
                append("response_type", "code")
                append("state", Uuid.random().toString())
                append(
                    "issuer_state",
                    credentialOffer.grants!!.authorizationCode!!.issuerState ?: ""
                )
                append("redirect_uri", "http://localhost")
                append("scope", credId)
                append("code_challenge", codeChallenge)
                append("code_challenge_method", "S256")
            }
        ) {
            header("oauth-client-attestation", clientAttestation)
            header("oauth-client-attestation-pop", clientAttestationPop)
        }

        if (result.status == HttpStatusCode.BadRequest) {
            throw IllegalStateException("PAR endpoint returns error: ${result.bodyAsText()}")
        }

        return result.body()
    }

    /**
     * The client (wallet) attestation should have been generated from the wallet server. We only
     * do this device side for the ease of demoing.
     */
    suspend fun getClientAttestationJwt(): String {
        val clientAttestationHeader = buildJsonObject {
            put("typ", "oauth-client-attestation+jwt")
            put("alg", "ES256")
        }
        val clientAttestationPayload = buildJsonObject {
            put("sub", WALLET_CLIENT_ID)
            put("wallet_name", WALLET_NAME)
            put("exp", Instant.now().epochSecond + 3000)
            put("cnf", buildJsonObject {
                put("jwk", kp.public.toJWK())
            })
        }
        return createJWTES256(clientAttestationHeader, clientAttestationPayload, WALLET_CERT_PRV_KEY)
    }

    fun generateClientAttestationPopJwt(): String {
        val clientAttestationPopHeader = buildJsonObject {
            put("typ", "oauth-client-attestation-pop+jwt")
            put("alg", "ES256")
        }
        val clientAttestationPopPayload = buildJsonObject {
            put("aud", authServerIdentifier())
            put("jti", Uuid.random().toByteArray().encodeBase64())
            put("iat", Instant.now().epochSecond)
            // TODO: support challenge
//            put("challenge", "5c1a9e10-29ff-4c2b-ae73-57c0957c09c4")
        }
        return createJWTES256(clientAttestationPopHeader, clientAttestationPopPayload, kp.private)
    }

    fun generateDpopJwt(method: String, endpoint: String, dpopNonce: String?, ath: String? = null): String {
        val dpopHeader = buildJsonObject {
            put("typ", "dpop+jwt")
            put("alg", "ES256")
            put("jwk", kp.public.toJWK())
        }
        val dpopPayload = buildJsonObject {
            put("jti", Uuid.random().toByteArray().encodeBase64())
            put("htm", method)
            put("htu", endpoint)
            put("iat", Instant.now().epochSecond)
            ath?.let { put("ath", ath) }
            dpopNonce?.let { put("nonce", dpopNonce) }
        }
        return createJWTES256(dpopHeader, dpopPayload, kp.private)
    }

    suspend fun requestTokenFromEndpoint(
        authServer: String,
        tokenRequest: TokenRequest,
        dpopNonce: String? = null,
        codeVerifier: String? = null
    ): TokenResponse {
        Log.d(TAG, "TokenRequest: $tokenRequest")
        val endpoint = requestAuthServerMetadata(authServer).tokenEndpoint
        require(endpoint != null) { "Token Endpoint Missed from Auth Server metadata" }

        val clientAttestation = getClientAttestationJwt()
        val clientAttestationPop = generateClientAttestationPopJwt()
        val dpop = generateDpopJwt("POST", endpoint, dpopNonce)

        val result = httpClient.submitForm(
            url = endpoint,
            formParameters = parameters {
                json.encodeToJsonElement(tokenRequest).jsonObject.forEach { key, element ->
                    when (element) {
                        is JsonPrimitive -> append(key, element.jsonPrimitive.content)
                        is JsonArray ->  append(key, element.jsonArray.toString())
                        is JsonObject -> append(key, element.jsonObject.toString())
                        else -> {}
                    }
                }
            }
        ) {
            header("oauth-client-attestation", clientAttestation)
            header("oauth-client-attestation-pop", clientAttestationPop)
            header("dpop", dpop)
        }

        Log.d(TAG, "Token response ${result.bodyAsText()}")

        if (result.status == HttpStatusCode.BadRequest) {
            val body = JSONObject(result.bodyAsText())
            if ("use_dpop_nonce" == body.optString("error")) {
                val dpopNonce = result.headers.get("dpop-nonce")!!
                return requestTokenFromEndpoint(authServer, tokenRequest, dpopNonce)
            }
            throw IllegalStateException("Token endpoint returns error: $body")
        }

        return result.body()
    }

    fun requireCredentialRequestEncryption(): Boolean = credentialOffer.issuerMetadata.credentialRequestEncryption?.encryptionRequired ?: false
    fun getCredentialRequestEncryptionKey(): JSONObject {
        require(credentialOffer.issuerMetadata.credentialRequestEncryption!!.encValuesSupported.contains("A128GCM")) {
            "Don't support the credential request encryption method yet"
        }
        val keys = credentialOffer.issuerMetadata.credentialRequestEncryption.jwks.keys
        val key = keys.firstOrNull{
            it.alg == "ECDH-ES"
        } ?: throw java.lang.UnsupportedOperationException("No supported encryption key")
        return JSONObject(Json.encodeToString(key))
    }
    fun requireCredentialResponseEncryption(): Boolean = credentialOffer.issuerMetadata.credentialResponseEncryption?.encryptionRequired ?: false

    @OptIn(ExperimentalUuidApi::class)
    suspend fun requestCredentialFromEndpoint(
        accessToken: String,
        credentialRequest: CredentialRequest,
        nonce: String? = null,
    ): CredentialResponse {
        Log.d(TAG, "Credential request: $credentialRequest")
        val endpoint = credentialOffer.issuerMetadata.credentialEndpoint
        val md = MessageDigest.getInstance("SHA256")
        val accessTokenHash = md.digest(accessToken.toByteArray()).toBase64UrlNoPadding()
        val dpop = generateDpopJwt("POST", endpoint, nonce, accessTokenHash)

        val result = httpClient.post(endpoint) {
            header(HttpHeaders.Authorization, "Dpop $accessToken")
            header("dpop", dpop)

            if (requireCredentialRequestEncryption()) {
                contentType(ContentType("application", "jwt"))
                setBody(jweSerialization(
                    recipientKeyJwk = getCredentialRequestEncryptionKey(),
                    plainText = json.encodeToJsonElement(credentialRequest).toString()
                ))
            } else {
                contentType(ContentType.Application.Json)
                setBody(
                    json.encodeToJsonElement(credentialRequest)
                )
            }
        }

        if (result.status == HttpStatusCode.Unauthorized) {
            val dpopNonce = result.headers.get("dpop-nonce")
            if (dpopNonce != null) {
                return requestCredentialFromEndpoint(accessToken, credentialRequest, dpopNonce)
            }
            throw IllegalStateException("Token endpoint returns error: $result")
        }
        Log.d(TAG, "Credential response status: ${result.status}")
        Log.d(TAG, "Credential response: ${result.bodyAsText()}")

        return result.body()
    }

    suspend fun createJwt(publicKey: PublicKey, privateKey: PrivateKey): String {
        val nonceResponse = requestNonceFromEndpoint()
        return createJWTES256(
            header = buildJsonObject {
                put("typ", "openid4vci-proof+jwt")
                put("alg", "ES256")
                put("jwk", publicKey.toJWK())
            },
            payload = buildJsonObject {
                put("aud", credentialOffer.credentialIssuer)
                put("iat", Instant.now().epochSecond)
                put("nonce", nonceResponse.cNonce)
            },
            privateKey = privateKey
        )
    }

    suspend fun createKeyProofs(credentialConfigurationId: String): Pair<Proofs, List<DeviceKey>> {
        val proofTypesSupported = credentialOffer.issuerMetadata.credentialConfigurationsSupported[credentialConfigurationId]?.proofTypesSupported!!
        return if (proofTypesSupported.containsKey("android_keystore_attestation")) {
            createAndroidAttestationProofJwt()
        } else if (proofTypesSupported.containsKey("jwt")) {
            createProofJwt()
        } else {
            throw UnsupportedOperationException("Can handle proof types $proofTypesSupported")
        }
    }

    private suspend fun createAndroidAttestationProofJwt(): Pair<Proofs, List<DeviceKey>> {
        val nonceResponse = requestNonceFromEndpoint()
        val certificates: MutableList<Array<Certificate>> = mutableListOf()
        val deviceKeys: MutableList<HardwareKey> = mutableListOf()
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null) // Load the default Android keystore
        for (i in 0..<(credentialOffer.issuerMetadata.batchCredentialIssuance?.batchSize ?: 1)) {
            val keyAlias = Uuid.random().toHexString()
            val kpg = KeyPairGenerator.getInstance("EC", "AndroidKeyStore")
            val spec = KeyGenParameterSpec.Builder(
                keyAlias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(nonceResponse.cNonce.toByteArray(Charsets.UTF_8))
                .build()
            kpg.initialize(spec)
            val kp = kpg.genKeyPair()
            deviceKeys.add(HardwareKey(keyAlias, kp.public))
            val certificateChain = keyStore.getCertificateChain(keyAlias)
            certificates.add(certificateChain)
        }

        return Pair(
            first = Proofs(
                androidKeystoreAttestation = certificates.map { certificateArray ->
                    certificateArray.map { certificate -> certificate.encoded.toBase64UrlNoPadding() }
                }
            ),
            second = deviceKeys
        )
    }

    private suspend fun createProofJwt(): Pair<Proofs, List<DeviceKey>> {
        val deviceKeys: MutableList<SoftwareKey> = mutableListOf()
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))
        for (i in 0..< (credentialOffer.issuerMetadata.batchCredentialIssuance?.batchSize ?: 1)) {
            val kp = kpg.genKeyPair()
            deviceKeys.add(SoftwareKey(publicKey = kp.public, privateKey = kp.private))
        }

        return Pair(
            first = Proofs(
                jwt = deviceKeys.map {
                    createJwt(it.publicKey, it.privateKey)
                }
            ),
            second = deviceKeys
        )
    }
}

sealed class DeviceKey(
    val publicKey: PublicKey
)

class SoftwareKey(
    val privateKey: PrivateKey,
    publicKey: PublicKey
) : DeviceKey(publicKey)

class HardwareKey(
    val keyAlias: String,
    publicKey: PublicKey
) : DeviceKey(publicKey)
