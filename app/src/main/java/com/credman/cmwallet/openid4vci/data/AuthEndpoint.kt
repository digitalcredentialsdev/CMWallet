package com.credman.cmwallet.openid4vci.data

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class OauthAuthorizationServer(
    @SerialName("issuer") val issuer: String,
    @SerialName("authorization_endpoint") val authorizationEndpoint: String?,
    @SerialName("token_endpoint") val tokenEndpoint: String?,
    @SerialName("response_types_supported") val responseTypesSupported: List<String>?,
    @SerialName("grant_types_supported") val grantTypesSupported: List<String>?,
    @SerialName("pushed_authorization_request_endpoint") val pushedAuthorizationRequestEndpoint: String?,
    @SerialName("mtls_endpoint_aliases") val mtlsEndpointAliases: MtlsEndpointAliases?,
)


@Serializable
data class MtlsEndpointAliases(
    @SerialName("pushed_authorization_request_endpoint") val pushedAuthorizationRequestEndpoint: String?,
    @SerialName("token_endpoint") val tokenEndpoint: String?,
    @SerialName("registration_endpoint") val registrationEndpoint: String?,
    @SerialName("userinfo_endpoint") val userinfoEndpoint: String?,
)

@Serializable
sealed class AuthorizationDetailResponse {
    abstract val type: String
}

@Serializable
@SerialName("openid_credential")
data class AuthorizationDetailResponseOpenIdCredential(
    @SerialName("type") override val type: String,
    @SerialName("credential_configuration_id") val credentialConfigurationId: String,
    @SerialName("credential_identifiers") val credentialIdentifiers: List<String>
) : AuthorizationDetailResponse()

@Serializable
data class ParResponse(
    @SerialName("request_uri") val requestUri: String,
    @SerialName("expires_in") val expiresIn: Int,
)