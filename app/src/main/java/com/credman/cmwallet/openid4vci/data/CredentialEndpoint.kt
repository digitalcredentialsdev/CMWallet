package com.credman.cmwallet.openid4vci.data

import android.net.Uri
import android.util.Log
import com.credman.cmwallet.CmWalletApplication.Companion.TAG
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class Proofs(
    @SerialName("jwt") val jwt: List<String>? = null,
    @SerialName("attestation") val attestation: String? = null
)

@Serializable
data class CredentialRequest(
    @SerialName("credential_identifier") val credentialIdentifier: String? = null,
    @SerialName("credential_configuration_id") val credentialConfigurationId: String? = null,
    @SerialName("proofs") val proofs: Proofs? = null
)

@Serializable
data class Credential(
    @SerialName("credential") val credential: String
)

@Serializable
data class CredentialResponse(
    @SerialName("credentials") val credentials: List<Credential>? = null,
    @SerialName("transaction_id") val transactionId: String? = null,
    @SerialName("notification_id") val notificationId: String? = null,
    @SerialName("display") val display: List<Display>? = null,
)

@Serializable
data class Display(
    @SerialName("locale") val locale: String? = null,
    @SerialName("name") val name: String? = null,
    @SerialName("description") val description: String? = null,
    @SerialName("logo") val logo: CredentialResponseLogo? = null,
)

@Serializable
data class CredentialResponseLogo(
    @SerialName("uri") val uri: String,
    @SerialName("alt_text") val altText: String?,
)

fun String?.imageUriToImageB64(): String? {
    val regex = "image/.*,".toRegex()
    return this?.let {
        val imageUri = Uri.parse(it)
        if (imageUri.scheme == "data") {
            val ssp = Uri.parse(it).schemeSpecificPart
            return@let ssp.replace(regex, "")
        } else {
            Log.w(TAG, "Unrecognized uri scheme: ${imageUri.scheme}")
            return@let null
        }
    }
}