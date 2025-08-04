package com.credman.cmwallet.openid4vci.data

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

@Serializable
data class GrantPreAuthorizedCode(
    @SerialName("pre-authorized_code") val preAuthorizedCode: String,
)

@Serializable
data class GrantAuthorizationCode(
    @SerialName("issuer_state") val issuerState: String?,
    @SerialName("authorization_server") val authorizationServer: String?,
    @SerialName("vp_request") val vpRequest: String?
)

@Serializable
data class Grants(
    @SerialName("urn:ietf:params:oauth:grant-type:pre-authorized_code") val preAuthorizedCode: GrantPreAuthorizedCode?,
    @SerialName("authorization_code") val authorizationCode: GrantAuthorizationCode?,
)

@Serializable
data class CredentialResponseEncryption(
    @SerialName("alg_values_supported") val algValuesSupported: List<String>,
    @SerialName("enc_values_supported") val encValuesSupported: List<String>,
    @SerialName("encryption_required") val encryptionRequired: Boolean
)

@Serializable
data class BatchCredentialIssuance(
    @SerialName("batch_size") val batchSize: Int
)

@Serializable
data class Logo(
    @SerialName("uri") val uri: String,
    @SerialName("alt_text") val altText: String?,
)

@Serializable
data class CredentialIssuerDisplay(
    @SerialName("name") val name: String?,
    @SerialName("locale") val locale: String?,
    @SerialName("logo") val logo: Logo?,
)

@Serializable
data class BackgroundImage(
    @SerialName("uri") val uri: String,
)

@Serializable
data class CredentialConfigurationMetadataDisplay(
    @SerialName("name") val name: String,
    @SerialName("locale") val locale: String?,
    @SerialName("logo") val logo: Logo?,
    @SerialName("description") val description: String?,
    @SerialName("background_color") val backgroundColor: String?,
    @SerialName("background_image") val backgroundImage: BackgroundImage?,
    @SerialName("text_color") val textColor: String?,
)

@Serializable
data class KeyAttestations(
    @SerialName("key_storage") val keyStorage: List<String>?,
    @SerialName("user_authentication") val userAuthentication: List<String>?,
)

@Serializable
data class CredentialConfigurationProofType(
    @SerialName("proof_signing_alg_values_supported") val proofSigningAlgValuesSupported: List<String>,
    @SerialName("key_attestations_required") val keyAttestationsRequired: KeyAttestations?,
)

@Serializable(with = CredentialConfigurationSerializer::class)
sealed class CredentialConfiguration {
    abstract val format: String
    abstract val scope: String?
    abstract val cryptographicBindingMethodsSupported: List<String>?
    abstract val credentialSigningAlgValuesSupported: List<String>?
    abstract val proofTypesSupported: Map<String, CredentialConfigurationProofType>?
    abstract val credentialMetadata: CredentialMetadata?
}

@Serializable
data class MDocClaimDisplay(
    @SerialName("name") val name: String?,
    @SerialName("locale") val locale: String?,
)

@Serializable
data class MDocClaim(
    @SerialName("mandatory") val mandatory: Boolean?,
    @SerialName("value_type") val valueType: String?,
    @SerialName("display") val display: List<MDocClaimDisplay>?,
)

@Serializable
data class CredentialConfigurationMDoc(
    @SerialName("format") override val format: String,
    @SerialName("scope") override val scope: String?,
    @SerialName("cryptographic_binding_methods_supported") override val cryptographicBindingMethodsSupported: List<String>?,
    @SerialName("credential_signing_alg_values_supported") override val credentialSigningAlgValuesSupported: List<String>?,
    @SerialName("proof_types_supported") override val proofTypesSupported: Map<String, CredentialConfigurationProofType>?,
    @SerialName("credential_metadata") override val credentialMetadata: CredentialMetadata?,
    @SerialName("doctype") val doctype: String,
    @SerialName("claims") val claims: List<Claim>?,
) : CredentialConfiguration()

@Serializable
data class ClaimDisplay(
    @SerialName("name") val name: String?,
    @SerialName("locale") val locale: String?,
)

@Serializable
data class Claim(
    @SerialName("mandatory") val mandatory: Boolean?,
    @SerialName("path") val path: List<String>,
    @SerialName("display") val display: List<ClaimDisplay>?,
)

@Serializable
data class CredentialConfigurationSdJwtVc(
    @SerialName("format") override val format: String,
    @SerialName("scope") override val scope: String?,
    @SerialName("cryptographic_binding_methods_supported") override val cryptographicBindingMethodsSupported: List<String>?,
    @SerialName("credential_signing_alg_values_supported") override val credentialSigningAlgValuesSupported: List<String>?,
    @SerialName("proof_types_supported") override val proofTypesSupported: Map<String, CredentialConfigurationProofType>?,
    @SerialName("credential_metadata") override val credentialMetadata: CredentialMetadata?,
    @SerialName("vct") val vct: String,
    @SerialName("claims") val claims: List<Claim>?,
) : CredentialConfiguration()

@Serializable
data class CredentialConfigurationUnknownFormat(
    @SerialName("format") override val format: String,
    @SerialName("scope") override val scope: String?,
    @SerialName("cryptographic_binding_methods_supported") override val cryptographicBindingMethodsSupported: List<String>?,
    @SerialName("credential_signing_alg_values_supported") override val credentialSigningAlgValuesSupported: List<String>?,
    @SerialName("proof_types_supported") override val proofTypesSupported: Map<String, CredentialConfigurationProofType>?,
    @SerialName("credential_metadata") override val credentialMetadata: CredentialMetadata?
) : CredentialConfiguration()

@Serializable
data class CredentialMetadata(
    @SerialName("display") val display: List<CredentialConfigurationMetadataDisplay>?,
)

object CredentialConfigurationSerializer :
    JsonContentPolymorphicSerializer<CredentialConfiguration>(CredentialConfiguration::class) {
    override fun selectDeserializer(element: JsonElement) = when {
        element.jsonObject["format"]!!.jsonPrimitive.content == "mso_mdoc" -> CredentialConfigurationMDoc.serializer()
        element.jsonObject["format"]!!.jsonPrimitive.content == "dc+sd-jwt" -> CredentialConfigurationSdJwtVc.serializer()
        else -> CredentialConfigurationUnknownFormat.serializer()
    }
}

@Serializable
data class CredentialIssuerMetadata(
    @SerialName("credential_issuer") val credentialIssuer: String,
    @SerialName("authorization_servers") val authorizationServers: List<String>?,
    @SerialName("credential_endpoint") val credentialEndpoint: String,
    @SerialName("nonce_endpoint") val nonceEndpoint: String?,
    @SerialName("deferred_credential_endpoint") val deferredCredentialEndpoint: String?,
    @SerialName("notification_endpoint") val notificationEndpoint: String?,
    @SerialName("credential_response_encryption") val credentialResponseEncryption: CredentialResponseEncryption?,
    @SerialName("batch_credential_issuance") val batchCredentialIssuance: BatchCredentialIssuance?,
    @SerialName("signed_metadata") val signedMetadata: String?,
    @SerialName("display") val display: List<CredentialIssuerDisplay>?,
    @SerialName("credential_configurations_supported") val credentialConfigurationsSupported: Map<String, CredentialConfiguration>,
)

@Serializable
data class CredentialOffer(
    @SerialName("credential_issuer") val credentialIssuer: String,
    @SerialName("credential_configuration_ids") val credentialConfigurationIds: List<String>,
    @SerialName("grants") val grants: Grants?,
    @SerialName("credential_issuer_metadata") val issuerMetadata: CredentialIssuerMetadata,
    @SerialName("authorization_server_metadata") val authorizationServerMetadata: OauthAuthorizationServer?
)