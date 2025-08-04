package com.credman.cmwallet.openid4vci.data

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class TokenRequest(
    @SerialName("grant_type") val grantType: String,
    @SerialName("pre-authorized_code") val preAuthorizedCode: String? = null,
    @SerialName("code") val code: String? = null,
    @SerialName("code_verifier") val codeVerifier: String? = null,
    @SerialName("redirect_uri") val redirectUri: String? = null,
    @SerialName("authorization_details") val authorizationDetails: List<AuthorizationDetail>? = null,
    @SerialName("scope") val scope: String? = null,
    @SerialName("tx_code") val txCode: String? = null,
    @SerialName("client_id") val clientId: String? = null,
)

@Serializable
data class AuthorizationDetail(
    @SerialName("type") val type: String = "openid_credential",
    @SerialName("credential_configuration_id") val credentialConfigurationId: String? = null,
    @SerialName("credential_identifiers") val credentialIdentifiers: List<String>? = null,
)

@Serializable
data class TokenResponse(
    @SerialName("access_token") val accessToken: String,
    @SerialName("refresh_token") val refreshToken: String? = null,
    @SerialName("expires_in") val expiresInSeconds: Long? = null,
    @SerialName("token_type") val tokenType: String? = null,
    @SerialName("scope") val scopes: String? = null,
    @SerialName("authorization_details") val authorizationDetails: List<AuthorizationDetailResponse>? = null,
)