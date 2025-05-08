package com.credman.cmwallet.openid4vp

import android.util.Base64
import com.credman.cmwallet.cbor.cborEncode
import com.credman.cmwallet.data.model.CredentialItem
import com.credman.cmwallet.decodeBase64UrlNoPadding
import com.credman.cmwallet.ecJwkThumbprintSha256
import com.credman.cmwallet.jweSerialization
import com.credman.cmwallet.jwsDeserialization
import org.json.JSONObject
import java.security.MessageDigest

data class TransactionData(
    val encodedData: String,
    val type: String,
    val credentialIds: List<String>,
    val data: JSONObject
)

class OpenId4VP(
    var requestJson: JSONObject,
    var clientId: String,
    val protocolIdentifier: String = "openid4vp",
) {

    fun getSdJwtKbAud(origin: String) = when (protocolIdentifier) {
        in IDENTIFIERS_1_0 -> "origin:$origin"
        IDENTIFIER_DRAFT_24 -> clientId
        else -> throw UnsupportedOperationException("Unsupported protocol idenfitier $protocolIdentifier")
    }

    val nonce: String

    val dcqlQuery: JSONObject
    val transactionData: List<TransactionData>
    val issuanceOffer: JSONObject?
    val clientMedtadata: JSONObject?
    val responseMode: String?
    var encryptionJwk: JSONObject? = null

    init {
        // TODO: support multisigned request
        // If the request is signed
        if (protocolIdentifier == IDENTIFIER_1_0_SIGNED || requestJson.has("request")) {
            val signedRequest = requestJson.getString("request")
            requestJson = jwsDeserialization(signedRequest).second
            clientId = requestJson.getString("client_id")
        }

        // Parse required params
        require(requestJson.has("nonce")) { "Authorization Request must contain a nonce" }
        require(requestJson.has("dcql_query")) { "Authorization Request must contain a dcql_query" }

        nonce = requestJson.getString("nonce")
        dcqlQuery = requestJson.getJSONObject("dcql_query")
        issuanceOffer = requestJson.optJSONObject("offer")
        clientMedtadata = requestJson.optJSONObject("client_metadata")
        responseMode = requestJson.optString("response_mode")

        if (responseMode == "dc_api.jwt") {
            val jwks = clientMedtadata?.getJSONObject("jwks")?.getJSONArray("keys")!!
            for (i in 0..<jwks.length()) {
                val jwk = jwks[i] as JSONObject
                if (jwk.has("use")
                    && jwk["use"] == "enc"
                    && jwk["kty"] == "EC"
                    && jwk["crv"] == "P-256"
                ) {
                    encryptionJwk = jwk
                }
            }
            requireNotNull(encryptionJwk) { "Could not find a valid encryption key (CMWallet only supports EC P256 key" }
        }

        val transactionDataJson = requestJson.optJSONArray("transaction_data")
        if (transactionDataJson != null) {
            val tempList = mutableListOf<TransactionData>()
            for (i in 0 until transactionDataJson.length()) {
                val transactionDataItemEncoded = transactionDataJson.getString(i)
                val transactionDataItemJson =
                    Base64.decode(transactionDataItemEncoded, Base64.URL_SAFE)
                        .toString(Charsets.UTF_8)
                val transactionDataItem = JSONObject(transactionDataItemJson)
                val credentialIds = mutableListOf<String>()
                val credentialIdsJson = transactionDataItem.getJSONArray("credential_ids")
                for (j in 0 until credentialIdsJson.length()) {
                    credentialIds.add(credentialIdsJson.getString(j))
                }

                tempList.add(
                    TransactionData(
                        transactionDataItemEncoded,
                        transactionDataItem.getString("type"),
                        credentialIds,
                        transactionDataItem
                    )
                )
            }
            transactionData = tempList
        } else {
            transactionData = emptyList()
        }

    }

    data class TransactionDataResult(
        val deviceSignedTransactionData: Map<String, List<ByteArray>>,
        val authenticationTitleAndSubtitle: Pair<CharSequence, CharSequence?>?,
    )

    fun generateDeviceSignedTransactionData(dcqlId: String): TransactionDataResult {
        if (transactionData.isEmpty()) {
            return TransactionDataResult(emptyMap(), null)
        }
        val transactionDataHashes = mutableListOf<ByteArray>()
        var authenticationTitleAndSubtitle: Pair<CharSequence, CharSequence?>? = null
        for (transactionDataItem in transactionData) {
            if (dcqlId in transactionDataItem.credentialIds) {
                val md = MessageDigest.getInstance("SHA-256")
                transactionDataHashes.add(md.digest(transactionDataItem.encodedData.encodeToByteArray()))
                val decoded = JSONObject(
                    String(
                        Base64.decode(
                            transactionDataItem.encodedData,
                            Base64.URL_SAFE
                        )
                    )
                )
                val merchantName = decoded.optString(MERCHANT_NAME)
                val amount = decoded.optString(AMOUNT)
                if (!merchantName.isNullOrBlank() && !amount.isNullOrBlank()) {
                    authenticationTitleAndSubtitle = Pair(
                        "Confirm transaction",
                        "Authorize payment of amount $amount to $merchantName."
                    )
                }
            }
        }
        return TransactionDataResult(
            mapOf(
                Pair(
                    "transaction_data_hashes",
                    transactionDataHashes.toList()
                )
            ),
            authenticationTitleAndSubtitle,
        )
    }

    fun matchCredentials(credentialStore: JSONObject): Map<String, List<MatchedCredential>> {
        return DCQLQuery(dcqlQuery, credentialStore)
    }

    fun performQueryOnCredential(selectedCredential: CredentialItem, dcqlCredId: String? = null): OpenId4VPMatchedCredential {
        return performQueryOnCredential(dcqlQuery, selectedCredential, dcqlCredId)
    }

    fun getHandover(origin: String): List<Any> {
        /**
         * Shape of `OpenID4VPDCAPIHandover[0]`
         *
         * See https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#appendix-B.3.4.1
         */
        val oid4vpHandoverIdentifier = "OpenID4VPDCAPIHandover";

        /**
         * Shape of `OpenID4VPDCAPIHandoverInfo`
         *
         * See https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#appendix-B.3.4.1
         */
        val handoverData = if (IDENTIFIERS_1_0.contains(protocolIdentifier)) {
            when (responseMode) {
                "dc_api" -> listOf(
                    origin,
                    nonce,
                    null
                )
                "dc_api.jwt" -> {
                    listOf(
                        origin,
                        nonce,
                        ecJwkThumbprintSha256(encryptionJwk!!)
                    )
                }
                else -> throw IllegalArgumentException("Unsupported response mode: $responseMode")
            }
        } else {
            listOf(
                origin,
                clientId,
                nonce
            )
        }

        val md = MessageDigest.getInstance("SHA-256")
        return listOf(
            oid4vpHandoverIdentifier,
            md.digest(cborEncode(handoverData))
        )
    }

    fun generateResponse(vpToken: JSONObject): String {
        val responseJson = JSONObject().put("vp_token", vpToken).toString()
        val response: String = if (responseMode == "dc_api.jwt") {
            // Encrypt response if applicable
            when (protocolIdentifier) {
                IDENTIFIER_DRAFT_24 -> {
                    val encryptionAgl = clientMedtadata?.opt("authorization_encrypted_response_alg")
                    val encryptionEnc = clientMedtadata?.opt("authorization_encrypted_response_enc")
                    val signAgl = clientMedtadata?.opt("authorization_signed_response_alg")
                    if (encryptionAgl != null && encryptionEnc != null && signAgl == null) {
                        require(encryptionAgl == "ECDH-ES" && encryptionEnc == "A128GCM") { "Unsupported encryption algorithm" }
                        val jwe = jweSerialization(encryptionJwk!!, responseJson)
                        JSONObject().put("response", jwe).toString()
                    } else {
                        throw UnsupportedOperationException("Response should be signed and / or encrypted but it's not supported yet")
                    }
                }
                in IDENTIFIERS_1_0 -> {
                    val jwe = jweSerialization(encryptionJwk!!, responseJson)
                    JSONObject().put("response", jwe).toString()
                }
                else -> throw UnsupportedOperationException("Invalid protocol identifier")
            }

        } else {
            responseJson
        }
        return response
    }

    companion object {
        const val MERCHANT_NAME = "merchant_name"
        const val AMOUNT = "amount"
        const val IDENTIFIER_DRAFT_24 = "openid4vp"
        const val IDENTIFIER_1_0_UNSIGNED = "openid4vp-v1-unsigned"
        const val IDENTIFIER_1_0_SIGNED = "openid4vp-v1-signed"
        const val IDENTIFIER_1_0_MULTISIGNED = "openid4vp-v1-multisigned"
        val IDENTIFIERS = setOf(
            IDENTIFIER_DRAFT_24, IDENTIFIER_1_0_UNSIGNED, IDENTIFIER_1_0_SIGNED, IDENTIFIER_1_0_MULTISIGNED)
        val IDENTIFIERS_1_0 = setOf(
            IDENTIFIER_1_0_UNSIGNED, IDENTIFIER_1_0_SIGNED, IDENTIFIER_1_0_MULTISIGNED)
    }
}