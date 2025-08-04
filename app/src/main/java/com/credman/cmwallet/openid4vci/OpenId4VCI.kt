package com.credman.cmwallet.openid4vci

import android.util.Base64
import android.util.Log
import com.credman.cmwallet.CmWalletApplication.Companion.TAG
import com.credman.cmwallet.CmWalletApplication.Companion.TEST_VCI_CLIENT_ID
import com.credman.cmwallet.createJWTES256
import com.credman.cmwallet.loadECPrivateKey
import com.credman.cmwallet.openid4vci.data.CredentialOffer
import com.credman.cmwallet.openid4vci.data.CredentialRequest
import com.credman.cmwallet.openid4vci.data.CredentialResponse
import com.credman.cmwallet.openid4vci.data.NonceResponse
import com.credman.cmwallet.openid4vci.data.OauthAuthorizationServer
import com.credman.cmwallet.openid4vci.data.ParResponse
import com.credman.cmwallet.openid4vci.data.Proof
import com.credman.cmwallet.openid4vci.data.TokenRequest
import com.credman.cmwallet.openid4vci.data.TokenResponse
import com.credman.cmwallet.toBase64UrlNoPadding
import com.credman.cmwallet.toJWK
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.bearerAuth
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
import io.ktor.http.headers
import io.ktor.http.parameters
import io.ktor.serialization.kotlinx.json.json
import io.ktor.util.encodeBase64
import io.ktor.util.reflect.TypeInfo
import kotlinx.coroutines.delay
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
import org.json.JSONArray
import org.json.JSONObject
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.interfaces.ECPrivateKey
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

class OpenId4VCI(val credentialOfferJson: String) {
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

    suspend fun authEndpoint(authServer: String): String {
        return requestAuthServerMetadata(authServer).authorizationEndpoint!!
    }

    suspend fun requestNonceFromEndpoint(): NonceResponse {
        require(credentialOffer.issuerMetadata.nonceEndpoint != null) { "nonce_endpoint must be set when requesting a nonce" }
        return httpClient.post(credentialOffer.issuerMetadata.nonceEndpoint).body()
    }

    /** Returns null if par endpoint isn't specified in the authorization server metadata. */
    @OptIn(ExperimentalUuidApi::class)
    suspend fun requestParEndpoint(
        clientId: String
    ): ParResponse? {
        val tmpKeyPriv =
            loadECPrivateKey(Base64.decode(
                "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgp71n8d_UOIJKQq7gyQcMZjWBzG1JhAg_bioIpOL-gU-hRANCAAQ6r-Jruh-EOpl3gG3buc9E6pKJ9IBj1AkPXTlkPWnNF3m6FdQyi7L7pfalCujcoid0rvbjq11dA5L5cpF-egpE", Base64.URL_SAFE)) as ECPrivateKey
        val clientAttestationHeader = buildJsonObject {
            put("typ", "oauth-client-attestation+jwt")
            put("alg", "ES256")
            put("kid", "11")
        }
        val clientAttestationPayload = buildJsonObject {
            put("iss", "https://digital-credentials.dev/")
            put("sub", TEST_VCI_CLIENT_ID)
            put("exp", Instant.now().epochSecond + 3000)
            put("cnf", buildJsonObject {
                put("jwk", kp.public.toJWK())
            })
        }
        val clientAttestation = createJWTES256(
            clientAttestationHeader,
            clientAttestationPayload,
            tmpKeyPriv
        )
        val clientAttestationPopHeader = buildJsonObject {
            put("typ", "oauth-client-attestation-pop")
            put("alg", "ES256")
        }
        val clientAttestationPopPayload = buildJsonObject {
            put("iss", TEST_VCI_CLIENT_ID)
            put("sub", "https://demo.certification.openid.net/test/a/vci-wallet-test-dc-api/")
            put("exp", Instant.now().epochSecond + 3000)
            put("jti", Uuid.random().toByteArray().encodeBase64())
        }
        val clientAttestationPop = createJWTES256(clientAttestationPopHeader, clientAttestationPopPayload, kp.private)

        val parEndpoint = credentialOffer.authorizationServerMetadata?.mtlsEndpointAliases?.pushedAuthorizationRequestEndpoint ?:
            credentialOffer.authorizationServerMetadata?.pushedAuthorizationRequestEndpoint ?: return null
        val credId = credentialOffer.credentialConfigurationIds.first()
        val md = MessageDigest.getInstance("SHA256")
        val codeChallenge = md.digest(codeVerifier.toByteArray()).toBase64UrlNoPadding()

        val result = httpClient.submitForm(
            url = parEndpoint,
            formParameters = parameters {
                append("client_id", clientId)
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

    @OptIn(ExperimentalUuidApi::class)
    suspend fun requestTokenFromEndpoint(
        authServer: String,
        tokenRequest: TokenRequest,
        dpopNonce: String? = null,
        codeVerifier: String? = null
    ): TokenResponse {
        Log.d(TAG, "TokenRequest: $tokenRequest")
        val endpoint = requestAuthServerMetadata(authServer).tokenEndpoint
        require(endpoint != null) { "Token Endpoint Missed from Auth Server metadata" }
        val tmpKeyPriv =
            loadECPrivateKey(Base64.decode(
                "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgp71n8d_UOIJKQq7gyQcMZjWBzG1JhAg_bioIpOL-gU-hRANCAAQ6r-Jruh-EOpl3gG3buc9E6pKJ9IBj1AkPXTlkPWnNF3m6FdQyi7L7pfalCujcoid0rvbjq11dA5L5cpF-egpE", Base64.URL_SAFE)) as ECPrivateKey
        val clientAttestationHeader = buildJsonObject {
            put("typ", "oauth-client-attestation+jwt")
            put("alg", "ES256")
            put("kid", "11")
        }
        val clientAttestationPayload = buildJsonObject {
            put("iss", "https://digital-credentials.dev/")
            put("sub", TEST_VCI_CLIENT_ID)
            put("exp", Instant.now().epochSecond + 3000)
            put("cnf", buildJsonObject {
                put("jwk", kp.public.toJWK())
            })
        }
        val clientAttestation = createJWTES256(clientAttestationHeader, clientAttestationPayload, tmpKeyPriv)
        val clientAttestationPopHeader = buildJsonObject {
            put("typ", "oauth-client-attestation-pop")
            put("alg", "ES256")
        }
        val clientAttestationPopPayload = buildJsonObject {
            put("iss", TEST_VCI_CLIENT_ID)
            put("sub", "https://demo.certification.openid.net/test/a/vci-wallet-test-dc-api/")
            put("exp", Instant.now().epochSecond + 3000)
            put("jti", Uuid.random().toByteArray().encodeBase64())
        }
        val clientAttestationPop = createJWTES256(clientAttestationPopHeader, clientAttestationPopPayload, kp.private)
        val dpopHeader = buildJsonObject {
            put("typ", "dpop+jwt")
            put("alg", "ES256")
            put("jwk", kp.public.toJWK())
        }
        val dpopPayload = buildJsonObject {
            put("jti", Uuid.random().toByteArray().encodeBase64())
            put("htm", "POST")
            put("htu", endpoint)
            put("iat", Instant.now().epochSecond)
            dpopNonce?.let { put("nonce", dpopNonce) }
        }
        val dpop = createJWTES256(dpopHeader, dpopPayload, kp.private)

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

    @OptIn(ExperimentalUuidApi::class)
    suspend fun requestCredentialFromEndpoint(
        accessToken: String,
        credentialRequest: CredentialRequest,
        nonce: String? = null,
    ): CredentialResponse {
        val endpoint = credentialOffer.issuerMetadata.credentialEndpoint
        val md = MessageDigest.getInstance("SHA256")
        val accessTokenHash = md.digest(accessToken.toByteArray()).toBase64UrlNoPadding()
        val dpopHeader = buildJsonObject {
            put("typ", "dpop+jwt")
            put("alg", "ES256")
            put("jwk", kp.public.toJWK())
        }
        val dpopPayload = buildJsonObject {
            put("jti", Uuid.random().toByteArray().encodeBase64())
            put("htm", "POST")
            put("htu", endpoint)
            put("iat", Instant.now().epochSecond)
            put("ath", accessTokenHash)
            nonce?.let { put("nonce", nonce) }
        }
        val dpop = createJWTES256(dpopHeader, dpopPayload, kp.private)

        val result = httpClient.post(endpoint) {
//            bearerAuth(accessToken)
            header(HttpHeaders.Authorization, "Dpop $accessToken")
            contentType(ContentType.Application.Json)
            setBody(json.encodeToJsonElement(credentialRequest))

            header("dpop", dpop)
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

    suspend fun createProofJwt(publicKey: PublicKey, privateKey: PrivateKey): Proof {
        return Proof(
            proofType = "jwt",
            jwt = createJwt(publicKey, privateKey)
        )
    }

//    fun generateCredentialToSave(
//        credentialEndpointResponse: CredentialResponse,
//        deviceKey: PrivateKey,
//        credentialConfigurationId: String = credentialOffer.credentialConfigurationIds.first(),
//    ): CredentialItem {
//        val credentialIssuerSigned = Base64.decode(
//            credentialEndpointResponse.credentials!!.first().credential,
//            Base64.URL_SAFE
//        )
//        return toCredentialItem(
//            credentialIssuerSigned,
//            deviceKey,
//            credentialOffer.issuerMetadata.credentialConfigurationsSupported[credentialConfigurationId]!!
//        )
//    }
}