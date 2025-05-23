package com.credman.cmwallet.data.model

import com.credman.cmwallet.decodeBase64UrlNoPadding
import com.credman.cmwallet.mdoc.MDoc
import com.credman.cmwallet.openid4vci.data.CredentialConfiguration
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class CredentialItem(
    val id: String,
    val config: CredentialConfiguration,
    val displayData: CredentialDisplayData,
    val credentials: List<Credential>
)

// TODO: This is kinda hardcoded to mdoc, fix this to support other types
@Serializable
data class Credential(
    val key: CredentialKey,
    val credential: String
) {
    val mdoc: MDoc  by lazy {
        MDoc(credential.decodeBase64UrlNoPadding())
    }
}

@Serializable
sealed class CredentialKey

@Serializable
@SerialName("SOFTWARE")
data class CredentialKeySoftware(
    val publicKey: String,
    val privateKey: String
) : CredentialKey()

@Serializable
@SerialName("HARDWARE")
data class CredentialKeyHardware(
    val publicKey: String,
    val privateKey: String
) : CredentialKey()

@Serializable
data class CredentialDisplayData(
    val title: String,
    val subtitle: String?,
    val icon: String?
)
