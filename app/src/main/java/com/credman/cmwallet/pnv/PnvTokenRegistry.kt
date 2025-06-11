package com.credman.cmwallet.pnv

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import androidx.credentials.provider.CallingAppInfo
import com.credman.cmwallet.CmWalletApplication.Companion.TAG
import com.credman.cmwallet.CmWalletApplication.Companion.computeClientId
import com.credman.cmwallet.createJWTES256
import com.credman.cmwallet.data.repository.CredentialRepository.Companion.ICON
import com.credman.cmwallet.data.repository.CredentialRepository.Companion.LENGTH
import com.credman.cmwallet.data.repository.CredentialRepository.Companion.START
import com.credman.cmwallet.data.repository.CredentialRepository.RegistryIcon
import com.credman.cmwallet.decodeBase64
import com.credman.cmwallet.getcred.GetCredentialActivity.DigitalCredentialRequestOptions
import com.credman.cmwallet.getcred.GetCredentialActivity.DigitalCredentialResult
import com.credman.cmwallet.jweSerialization
import com.credman.cmwallet.jwsDeserialization
import com.credman.cmwallet.loadECPrivateKey
import com.credman.cmwallet.openid4vp.OpenId4VP
import com.credman.cmwallet.openid4vp.OpenId4VP.Companion.IDENTIFIERS_1_0
import com.credman.cmwallet.pnv.PnvTokenRegistry.Companion.TEST_PNV_1_GET_PHONE_NUMBER
import com.credman.cmwallet.pnv.PnvTokenRegistry.Companion.TEST_PNV_1_VERIFY_PHONE_NUMBER
import com.credman.cmwallet.pnv.PnvTokenRegistry.Companion.TEST_PNV_2_VERIFY_PHONE_NUMBER
import com.credman.cmwallet.pnv.PnvTokenRegistry.Companion.VCT_GET_PHONE_NUMBER
import com.credman.cmwallet.pnv.PnvTokenRegistry.Companion.VCT_VERIFY_PHONE_NUMBER
import com.credman.cmwallet.toBase64UrlNoPadding
import com.credman.cmwallet.toJWK
import io.ktor.util.encodeBase64
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.interfaces.ECPrivateKey
import java.time.Instant
import java.util.Enumeration

/**
 * A phone number verification entry to be registered with the Credential Manager.
 *
 * @param tokenId The Securely generated ID that will be used to identify a user selection
 * @param title The display title for this TS43 token entry. Ideally this should be an obfuscated
 *   phone number, such as ***-***-1234, or some other information that allows the user to
 *   disambiguate this entry from others, especially in the multi-sim use case.
 * @param subscriptionId The subscription ID of the SIM card that this token is associated with.
 * @param carrierId The carrier ID of the SIM card that this token is associated with.
 * @param useCases The set of use cases that this token is. Allowed values are:
 *   [USE_CASE_VERIFY_PHONE_NUMBER], [USE_CASE_GET_PHONE_NUMBER], [USE_CASE_GET_SUBSCRIBER_INFO]
 */
data class PnvTokenRegistry(
    val tokenId: String,
    val vct: String,
    val title: String,
    val subtitle: String? = null,
    val providerConsent: String?,
    val subscriptionHint: Int,
    val carrierHint: String,
    val androidCarrierHint: Int,
    val phoneNumberHint: String?,
    val iss: String,
    val icon: String? = null,
    val phoneNumberAttributeDisplayName: String, // Should be localized
) {
    /** Converts this TS43 entry to the more generic SD-JWT registry item(s). */
    private fun toSdJwtRegistryItems(): SdJwtRegistryItem {
        return SdJwtRegistryItem(
                id = tokenId,
                vct = vct,
                claims =
                    listOf(
                        RegistryClaim("subscription_hint", null, subscriptionHint),
                        RegistryClaim("carrier_hint", null, carrierHint),
                        RegistryClaim("android_carrier_hint", null, androidCarrierHint),
                        RegistryClaim("phone_number_hint", null, phoneNumberHint),
                    ),
                displayData = ItemDisplayData(title = title, subtitle = subtitle, description = providerConsent),
            )
    }

    companion object {
        const val VCT_GET_PHONE_NUMBER = "number-verification/device-phone-number/ts43"
        const val VCT_VERIFY_PHONE_NUMBER = "number-verification/verify/ts43"
        const val PNV_CRED_FORMAT = "dc-authorization+sd-jwt"

        internal const val CREDENTIALS = "credentials"
        internal const val ID = "id"
        internal const val TITLE = "title"
        internal const val SUBTITLE = "subtitle"
        internal const val DISCLAIMER = "disclaimer"
        internal const val PATHS = "paths"
        internal const val VALUE = "value"
        internal const val DISPLAY = "display"
        internal const val SHARED_ATTRIBUTE_DISPLAY_NAME = "shared_attribute_display_name"

        val TEST_PNV_1_GET_PHONE_NUMBER = PnvTokenRegistry(
            tokenId = "pnv_1",
            vct = VCT_GET_PHONE_NUMBER,
            title = "Terrific Telecom",
            subtitle = "+1 (650) 215-4321",
            providerConsent = "CMWallet will enable your carrier (Terrific Telecom) to share your phone number",
            subscriptionHint = 1,
            carrierHint = "310250",
            androidCarrierHint = 3,
            phoneNumberHint = "+16502154321",
            iss = "https://example.terrific-telecom.dev",
            icon = "iVBORw0KGgoAAAANSUhEUgAAAA4AAAAWCAYAAADwza0nAAAACXBIWXMAAAsTAAALEwEAmpwYAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAACBSURBVHgB7ZTBDUVQEEXvff8VoITfC0YZatABHWiH6IUOaICHBCuReXbEWd1kcmZmMRmGIinhSpABFBDoJpqccSKtA/7wY7C71FQ1NUaUyKIg4Ba8MbiJ3YPnqvcnfuI7xAfdqr0qXjU9FTXTGUnca//NIYGdoflla1BbDsPIqZgBHcEomi+uUHMAAAAASUVORK5CYII=",
            phoneNumberAttributeDisplayName = "Phone number",
        )
        val TEST_PNV_1_VERIFY_PHONE_NUMBER = TEST_PNV_1_GET_PHONE_NUMBER.copy(
            vct = VCT_VERIFY_PHONE_NUMBER,
        )
        val TEST_PNV_2_VERIFY_PHONE_NUMBER = PnvTokenRegistry(
            tokenId = "pnv_2",
            vct = VCT_VERIFY_PHONE_NUMBER,
            title = "Work Number",
            subtitle = "Timely Telecom",
            providerConsent = "CMWallet will enable your carrier (Timely Telecom) to share your phone number",
            subscriptionHint = 2,
            carrierHint = "380250",
            androidCarrierHint = 3,
            phoneNumberHint = "+16502157890",
            iss = "https://example.timely-telecom.dev",
            icon = "iVBORw0KGgoAAAANSUhEUgAAAA4AAAAWCAYAAADwza0nAAAACXBIWXMAAAsTAAALEwEAmpwYAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAACBSURBVHgB7ZTBDUVQEEXvff8VoITfC0YZatABHWiH6IUOaICHBCuReXbEWd1kcmZmMRmGIinhSpABFBDoJpqccSKtA/7wY7C71FQ1NUaUyKIg4Ba8MbiJ3YPnqvcnfuI7xAfdqr0qXjU9FTXTGUnca//NIYGdoflla1BbDsPIqZgBHcEomi+uUHMAAAAASUVORK5CYII=",
            phoneNumberAttributeDisplayName = "Phone number",
        )

        fun buildRegistryDatabase(items: List<PnvTokenRegistry>): ByteArray {
            val out = ByteArrayOutputStream()

            val iconMap: Map<String, RegistryIcon> = items.associate {
                Pair(
                    it.tokenId,
                    RegistryIcon(it.icon?.decodeBase64() ?: ByteArray(0))
                )
            }

            // Write the offset to the json
            val jsonOffset = 4 + iconMap.values.sumOf { it.iconValue.size }
            val buffer = ByteBuffer.allocate(4)
            buffer.order(ByteOrder.LITTLE_ENDIAN)
            buffer.putInt(jsonOffset)
            out.write(buffer.array())

            // Write the icons
            var currIconOffset = 4
            iconMap.values.forEach {
                it.iconOffset = currIconOffset
                out.write(it.iconValue)
                currIconOffset += it.iconValue.size
            }

            val sdJwtCredentials = JSONObject()
            for (item in items) {
                val sdJwtRegistryItem = item.toSdJwtRegistryItems()
                val credJson = JSONObject()
                credJson.put(SHARED_ATTRIBUTE_DISPLAY_NAME, item.phoneNumberAttributeDisplayName)
                credJson.put(ID, sdJwtRegistryItem.id)
                credJson.put(TITLE, sdJwtRegistryItem.displayData.title)
                credJson.putOpt(SUBTITLE, sdJwtRegistryItem.displayData.subtitle)
                credJson.putOpt(DISCLAIMER, sdJwtRegistryItem.displayData.description)
                val iconJson = JSONObject().apply {
                    put(START, iconMap[sdJwtRegistryItem.id]!!.iconOffset)
                    put(LENGTH, iconMap[sdJwtRegistryItem.id]!!.iconValue.size)
                }
                credJson.putOpt(ICON, iconJson)
                val paths = JSONObject()
                for (claim in sdJwtRegistryItem.claims) {
                    paths.put(claim.path, JSONObject().putOpt(DISPLAY, claim.display).putOpt(VALUE, claim.value))
                }

                credJson.put(PATHS, paths)
                val vctType = item.vct
                when (val current = sdJwtCredentials.opt(vctType) ?: JSONArray()) {
                    is JSONArray -> sdJwtCredentials.put(vctType, current.put(credJson))
                    else -> throw IllegalStateException("Unexpected type ${current::class.java}")
                }
            }
            val registryCredentials = JSONObject()
            registryCredentials.put(PNV_CRED_FORMAT, sdJwtCredentials)
            val registryJson = JSONObject()
            registryJson.put(CREDENTIALS, registryCredentials)
            Log.d(TAG, "Phone Number to be registered:\n$registryJson")
            out.write(registryJson.toString().toByteArray())
            return out.toByteArray()
        }
    }
}

private class RegistryClaim(
    val path: String, // Single depth only
    val display: String?,
    val value: Any?,
)

private class ItemDisplayData(
    val title: String,
    val subtitle: String?,
    val description: String?,
    )

private class SdJwtRegistryItem(
    val id: String,
    val vct: String,
    val claims: List<RegistryClaim>,
    val displayData: ItemDisplayData,
)

private fun getDeviceKey(): KeyPair {
    val alias = "pnv"
    val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }
    if (ks.containsAlias(alias)) {
        val entry = ks.getEntry(alias, null)
        if (entry !is KeyStore.PrivateKeyEntry) {
            throw IllegalStateException("Not an instance of a PrivateKeyEntry")
        }
        val private = entry.privateKey
        val public = ks.getCertificate(alias).publicKey
        return KeyPair(public, private)
    } else {
        val kpg: KeyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            "AndroidKeyStore"
        )
        val parameterSpec: KeyGenParameterSpec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        ).run {
            setDigests(KeyProperties.DIGEST_SHA256)
            build()
        }
        kpg.initialize(parameterSpec)

        val kp = kpg.generateKeyPair()
        return kp
    }
}

fun maybeHandlePnv(
    requestJson: String,
    providerIdx: Int,
    selectedID: String,
    dcqlCredId: String,
    origin: String, // Either the web origin or the calling app sha
    callingAppInfo: CallingAppInfo
): DigitalCredentialResult? {
    if (selectedID != TEST_PNV_1_GET_PHONE_NUMBER.tokenId && selectedID != TEST_PNV_2_VERIFY_PHONE_NUMBER.tokenId) {
        return null
    }
    val digitalCredentialOptions = DigitalCredentialRequestOptions.createFrom(requestJson)
    val requestProtocol = DigitalCredentialRequestOptions.getRequestProtocolAtIndex(
        digitalCredentialOptions, providerIdx
    )
    val requestData: JSONObject = DigitalCredentialRequestOptions.getRequestDataAtIndex(
        digitalCredentialOptions, providerIdx
    )
    Log.i(PNV_TAG, "processDigitalCredentialOption protocol $requestProtocol")
    require(IDENTIFIERS_1_0.contains(requestProtocol)) {"Unsupported protocol identifier $requestProtocol"}
    val openId4VPRequest = OpenId4VP(requestData, computeClientId(callingAppInfo), requestProtocol)
    Log.i(PNV_TAG, "nonce ${openId4VPRequest.nonce}")

    val dcqlObject = openId4VPRequest.getDcqlCredentialObject(dcqlCredId)!!
    Log.i(PNV_TAG, "dqcl $dcqlObject")
    val vct = dcqlObject.getJSONObject("meta").getJSONArray("vct_values").let {
        for (i in 0..<it.length()) {
            val currVct = it.getString(i)
            if (currVct == VCT_GET_PHONE_NUMBER || currVct == VCT_VERIFY_PHONE_NUMBER) {
                return@let currVct
            }
        }
        throw IllegalStateException("Could not find a valid vct value for pnv")
    }

    val selectedCred = when (selectedID) {
        TEST_PNV_1_GET_PHONE_NUMBER.tokenId -> if (vct == TEST_PNV_1_GET_PHONE_NUMBER.vct) TEST_PNV_1_GET_PHONE_NUMBER else TEST_PNV_1_VERIFY_PHONE_NUMBER
        TEST_PNV_2_VERIFY_PHONE_NUMBER.tokenId -> TEST_PNV_2_VERIFY_PHONE_NUMBER
        else -> return null
    }

    val credAuthJwt = dcqlObject.getJSONObject("meta").getString("credential_authorization_jwt")
    val (credAuthJwtHeader, credAuthJwtpayload) = jwsDeserialization(credAuthJwt)

    require(credAuthJwtHeader.has("x5c")) { "Missing aggregator cert" }
    val aggregatorCertChain = credAuthJwtHeader.getJSONArray("x5c") // See the x5c cert chain defined at https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.6
    // TODO: validate the aggregator cert is allowed to request phone number verification for the given carrier

    val consentData = credAuthJwtpayload.optString("consent_data")
    val md = MessageDigest.getInstance("SHA-256")
    val consentDataHash: String? =
        if (consentData.isEmpty()) { null }
        else { md.digest(consentData.encodeToByteArray()).toBase64UrlNoPadding() }

    val aggregatorNonce = credAuthJwtpayload.getString("nonce")
    require(aggregatorNonce == openId4VPRequest.nonce) { "Aggregator nonce should match the verifier nonce" }

    val aggregatorJwks = credAuthJwtpayload.getJSONObject("jwks").getJSONArray("keys")
    val aggregatorEncKey = aggregatorJwks.let {
        for (i in 0..<it.length()) {
            val jwk = it[i] as JSONObject
            if (jwk.has("use")
                && jwk["use"] == "enc"
                && jwk["kty"] == "EC"
                && jwk["crv"] == "P-256"
            ) {
                return@let jwk
            }
        }
        throw IllegalArgumentException("Given aggregator did not provide a valid encryption key")
    }

    // Generate the phone number token SD-JWT
    val tempTokenJson = buildJsonObject {
        put("temp_token", getTempTokenForCredential(selectedCred))
    }
    val encryptedTempTokenJwe = jweSerialization(aggregatorEncKey, tempTokenJson.toString())

    val tmpDeviceTelModuleKey =
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg6ef4-enmfQHRWUW40-Soj3aFB0rsEOp3tYMW-HJPBvChRANCAAT5N1NLZcub4bOgWfBwF8MHPGkfJ8Dm300cioatq9XovaLgG205FEXUOuNMEMQuLbrn8oiOC0nTnNIVn-OtSmSb"
    val deviceTelModulePrivateKey =
        loadECPrivateKey(Base64.decode(tmpDeviceTelModuleKey, Base64.URL_SAFE)) as ECPrivateKey
    val deviceKp = getDeviceKey()

    val deviceTelModuleJwt = createJWTES256(
        header = buildJsonObject {
            put("alg", "ES256")
            put("typ", "dc-authorization+sd-jwt")
            put("x5c", buildJsonArray {
                add("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+TdTS2XLm+GzoFnwcBfDBzxpHyfA5t9NHIqGravV6L2i4BttORRF1DrjTBDELi265/KIjgtJ05zSFZ/jrUpkmw==")
            })
        },
        payload = buildJsonObject {
            put("iss", "https://example.com/issuer")
            put("vct", selectedCred.vct)
            put("cnf", buildJsonObject {
                put("jwk", deviceKp.public.toJWK())
            })
            put("exp", 1883000000)
            put("iat", 1683000000)
        },
        privateKey = deviceTelModulePrivateKey
    )
    val sdJwt = deviceTelModuleJwt + "~"

    md.reset()
    val digest = md.digest(sdJwt.encodeToByteArray()).toBase64UrlNoPadding()
    val kbJwt = createJWTES256(
        header = buildJsonObject {
            put("typ", "kb+jwt") // MUST be kb+jwt
            put("alg", "ES256")
        },
        payload = buildJsonObject {
            put("iat", Instant.now().epochSecond)
            put("aud", origin)
            put("nonce", openId4VPRequest.nonce)
            put("encrypted_credential", encryptedTempTokenJwe)
            put("consent_data_hash", consentDataHash)
            put("sd_hash", digest)
            put("subscription_hint", selectedCred.subscriptionHint)
            put("carrier_hint", selectedCred.carrierHint)
            put("android_carrier_hint", selectedCred.androidCarrierHint)
        },
        privateKey = deviceKp.private
    )

    val tempTokenDcSdJwt = "${deviceTelModuleJwt}~${kbJwt}"

    val vpToken = JSONObject().apply {
        put(dcqlCredId, tempTokenDcSdJwt)
    }
    val response = openId4VPRequest.generateResponse(vpToken)
    Log.d(PNV_TAG, "Returning $response")

    return DigitalCredentialResult(
        responseJsonLegacy = "",
        authenticationTitle = "",
        authenticationSubtitle = null,
        responseJsonModern = JSONObject().apply {
            put("protocol", openId4VPRequest.protocolIdentifier)
            put("data", JSONObject(response))
        }.toString()
    )
}

fun getTempTokenForCredential(cred: PnvTokenRegistry): String {
    return "TODO: generate temp token"
}

private const val PNV_TAG = "PnvHandler"