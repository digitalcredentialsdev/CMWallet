package com.credman.cmwallet.createcred

import android.net.Uri
import android.os.Bundle
import android.util.Base64
import android.util.Log
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.credentials.CreateCredentialResponse
import androidx.credentials.CreateCustomCredentialResponse
import androidx.credentials.DigitalCredential
import androidx.credentials.ExperimentalDigitalCredentialApi
import androidx.credentials.provider.ProviderCreateCredentialRequest
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.credman.cmwallet.CmWalletApplication
import com.credman.cmwallet.CmWalletApplication.Companion.TAG
import com.credman.cmwallet.CmWalletApplication.Companion.computeClientId
import com.credman.cmwallet.data.model.Credential
import com.credman.cmwallet.data.model.CredentialDisplayData
import com.credman.cmwallet.data.model.CredentialItem
import com.credman.cmwallet.data.model.CredentialKeySoftware
import com.credman.cmwallet.data.room.CredentialDatabaseItem
import com.credman.cmwallet.getcred.GetCredentialActivity
import com.credman.cmwallet.getcred.createOpenID4VPResponse
import com.credman.cmwallet.loadECPrivateKey
import com.credman.cmwallet.openid4vci.OpenId4VCI
import com.credman.cmwallet.openid4vci.data.AuthorizationDetailResponseOpenIdCredential
import com.credman.cmwallet.openid4vci.data.CredentialRequest
import com.credman.cmwallet.openid4vci.data.GrantAuthorizationCode
import com.credman.cmwallet.openid4vci.data.TokenRequest
import com.credman.cmwallet.openid4vci.data.TokenResponse
import com.credman.cmwallet.openid4vci.data.imageUriToImageB64
import com.credman.cmwallet.openid4vp.OpenId4VP
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.security.KeyFactory
import java.security.interfaces.ECPrivateKey
import java.security.spec.X509EncodedKeySpec
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

sealed class Result {
    data class Error(val msg: String? = null) : Result()
    data class Response(
        val response: CreateCredentialResponse,
        val newEntryId: String,
    ) : Result()
}

data class AuthServerUiState (
    val url: String,
    val redirectUrl: String,
    val state: String
)

data class CreateCredentialUiState(
    val credentialsToSave: List<CredentialItem>? = null,
    val state: Result? = null,
    val authServer: AuthServerUiState? = null,
    val vpResponse:  CredentialItem? = null,

    // hack
    val tmpCode: GrantAuthorizationCode? = null
)

@OptIn(ExperimentalDigitalCredentialApi::class)
class CreateCredentialViewModel : ViewModel() {
    var uiState by mutableStateOf(CreateCredentialUiState())
        private set

    private lateinit var openId4VCI: OpenId4VCI

    val tmpKey =
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg6ef4-enmfQHRWUW40-Soj3aFB0rsEOp3tYMW-HJPBvChRANCAAT5N1NLZcub4bOgWfBwF8MHPGkfJ8Dm300cioatq9XovaLgG205FEXUOuNMEMQuLbrn8oiOC0nTnNIVn-OtSmSb"
    val tmpPublicKey =
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE-TdTS2XLm-GzoFnwcBfDBzxpHyfA5t9NHIqGravV6L2i4BttORRF1DrjTBDELi265_KIjgtJ05zSFZ_jrUpkmw=="
    val privateKey =
        loadECPrivateKey(Base64.decode(tmpKey, Base64.URL_SAFE)) as ECPrivateKey
    val publicKeySpec = X509EncodedKeySpec(Base64.decode(tmpPublicKey, Base64.URL_SAFE))
    val kf = KeyFactory.getInstance("EC")
    val publicKey = kf.generatePublic(publicKeySpec)!!

    fun onNewRequest(request: ProviderCreateCredentialRequest) {
        viewModelScope.launch {
            processRequest(request)
        }
        Log.d(TAG, "Done")
    }

    fun onCode(code: String) {
        uiState = uiState.copy(authServer = null)
        viewModelScope.launch {
            // Figure out auth server
            val authServer =
                if (openId4VCI.credentialOffer.issuerMetadata.authorizationServers == null) {
                    openId4VCI.credentialOffer.issuerMetadata.credentialIssuer
                } else {
                    "Can't do this yet"
                }
            val tokenResponse = openId4VCI.requestTokenFromEndpoint(
                authServer, TokenRequest(
                    grantType = "authorization_code",
                    code  =  code
                )
            )
            Log.i(TAG, "tokenResponse $tokenResponse")
            processToken(tokenResponse)
        }
    }

    @OptIn(ExperimentalUuidApi::class)
    private suspend fun processToken(tokenResponse: TokenResponse) {
        tokenResponse.authorizationDetails?.forEach { authDetail ->
            when (authDetail) {
                is AuthorizationDetailResponseOpenIdCredential -> {
                    val newCredentials = mutableListOf<CredentialItem>()
                    authDetail.credentialIdentifiers.forEach { credentialId ->
                        val credentialResponse = openId4VCI.requestCredentialFromEndpoint(
                            accessToken = tokenResponse.accessToken,
                            credentialRequest = CredentialRequest(
                                credentialIdentifier = credentialId,
                                proof = openId4VCI.createProofJwt(publicKey, privateKey)
                            )
                        )
                        Log.i(TAG, "credentialResponse $credentialResponse")
                        val config = openId4VCI.credentialOffer.issuerMetadata.credentialConfigurationsSupported[authDetail.credentialConfigurationId]!!
                        val display = credentialResponse.display?.firstOrNull()
                        val newCredentialItem = CredentialItem(
                            id = Uuid.random().toHexString(),
                            config = config,
                            displayData = CredentialDisplayData(
                                title = display?.name ?:"Unknown",
                                subtitle = display?.description,
                                icon = display?.logo?.uri.imageUriToImageB64()
                            ),
                            credentials = credentialResponse.credentials!!.map {
                                Credential(
                                    key = CredentialKeySoftware(
                                        publicKey = tmpPublicKey,
                                        privateKey = tmpKey
                                    ),
                                    credential = it.credential
                                )
                            }
                        )
                        newCredentials.add(newCredentialItem)
                    }
                    uiState = uiState.copy(credentialsToSave = newCredentials, authServer = null)
                }
            }
        }
    }

    @OptIn(ExperimentalUuidApi::class)
    fun onApprove() {
        viewModelScope.launch {
            val authServer =
                if (openId4VCI.credentialOffer.issuerMetadata.authorizationServers == null) {
                    openId4VCI.credentialOffer.issuerMetadata.credentialIssuer
                } else {
                    "Can't do this yet"
                }
            val authServerUrl = Uri.parse(openId4VCI.authEndpoint(authServer))
                .buildUpon()
                .appendQueryParameter("response_type", "code")
                .appendQueryParameter("state", Uuid.random().toString())
                .appendQueryParameter("redirect_uri", "http://localhost")
                .appendQueryParameter("issuer_state", uiState.tmpCode?.issuerState ?: "")
                .appendQueryParameter("vp_response", "foo")
                .build()

            Log.d(TAG, "authServerUrl: $authServerUrl")
            uiState = uiState.copy(authServer = AuthServerUiState(
                url = authServerUrl.toString(),
                redirectUrl = "http://localhost",
                state = "state"
            ), vpResponse = null)
        }

    }

    @OptIn(ExperimentalUuidApi::class)
    private suspend fun processRequest(request: ProviderCreateCredentialRequest?) {
        uiState = CreateCredentialUiState()
        if (request == null) {
            //uiState = CreateCredentialUiState()
            return
        }
        try {
            // This will eventually be replaced by a structured Jetpack property,
            // as opposed to having to parse a raw data from Bundle.
            val requestJsonString: String = request.callingRequest.credentialData.getString(
                "androidx.credentials.BUNDLE_KEY_REQUEST_JSON"
            )!!
            Log.d(
                TAG,
                "Request json received: $requestJsonString"
            )
            
            val requestJson = JSONObject(requestJsonString)
            require(requestJson.has("requests")) { "request json missing required field `requests`" }
            val requestsJson =requestJson.getJSONArray("requests")

            for (i in 0..< requestsJson.length()) {
                val digitalCredentialCreateRequest = requestsJson.getJSONObject(i)
                require(digitalCredentialCreateRequest.has("protocol")) { "request json missing required field protocol" }
                require(digitalCredentialCreateRequest.has("data")) { "request json missing required field data" }

                if (setOf("openid4vci1.0", "openid4vci", "openid4vci-v1").contains(digitalCredentialCreateRequest.getString("protocol"))) {
                    openId4VCI =
                        OpenId4VCI(digitalCredentialCreateRequest.getJSONObject("data").toString())
                    // Figure out auth server
                    val authServer =
                        if (openId4VCI.credentialOffer.issuerMetadata.authorizationServers == null) {
                            openId4VCI.credentialOffer.issuerMetadata.credentialIssuer
                        } else {
                            "Can't do this yet"
                        }
                    require(openId4VCI.credentialOffer.grants != null)

                    if (openId4VCI.credentialOffer.grants!!.preAuthorizedCode != null) {
                        val grant = openId4VCI.credentialOffer.grants!!.preAuthorizedCode

                        val tokenResponse = openId4VCI.requestTokenFromEndpoint(
                            authServer, TokenRequest(
                                grantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                                preAuthorizedCode = grant?.preAuthorizedCode
                            )
                        )
                        Log.i(TAG, "tokenResponse $tokenResponse")
                        processToken(tokenResponse)

                    } else if (openId4VCI.credentialOffer.grants!!.authorizationCode != null) {
                        val grant = openId4VCI.credentialOffer.grants!!.authorizationCode!!
                        Log.d(TAG, "Grant: $grant")
                        if (grant.vpRequest != null) {
                            val openId4VPRequest = OpenId4VP(
                                JSONObject(grant.vpRequest),
                                computeClientId(request.callingAppInfo)
                            )
                            val selectedCredential = CmWalletApplication.credentialRepo.getCredential("id1")
                                ?: throw RuntimeException("Selected credential not found")
                            val matchedCredential =
                                openId4VPRequest.performQueryOnCredential(selectedCredential)
                            val vpResponse = createOpenID4VPResponse(
                                openId4VPRequest,
                                "wallet",
                                selectedCredential,
                                matchedCredential
                            )
                            uiState = uiState.copy(vpResponse = selectedCredential, tmpCode = grant)

                        } else {
                            val authServerUrl = Uri.parse(openId4VCI.authEndpoint(authServer))
                                .buildUpon()
                                .appendQueryParameter("response_type", "code")
                                .appendQueryParameter("state", Uuid.random().toString())
                                .appendQueryParameter("redirect_uri", "http://localhost")
                                .appendQueryParameter("issuer_state", grant?.issuerState ?: "")
                                .build()

                            Log.d(TAG, "authServerUrl: $authServerUrl")
                            uiState = uiState.copy(authServer = AuthServerUiState(
                                url = authServerUrl.toString(),
                                redirectUrl = "http://localhost",
                                state = "state"
                            ))
                        }
                    } else {
                        throw IllegalArgumentException("Missing grants")
                    }
                    return
                }
            }
            onError("Could not find any supported request protocol")
        } catch (e: Exception) {
            Log.e(TAG, "Exception processing request", e)
            onError("Invalid request")
        }
    }

    fun onConfirm() {
        val credentialsToSave = uiState.credentialsToSave
        if (credentialsToSave != null) {
            viewModelScope.launch {
                val insertedId = CmWalletApplication.database.credentialDao().insertAll(
                    credentialsToSave.map { CredentialDatabaseItem(it) }
                )[0]
                onResponse(insertedId.toString())
            }
        } else {
            Log.e(TAG, "Unexpected: null credential to save")
            onError("Internal error")
        }
    }

    private fun onResponse(newEntryId: String) {
        val testResponse = CreateCustomCredentialResponse(
            type = DigitalCredential.TYPE_DIGITAL_CREDENTIAL,
            data = Bundle().apply {
                putString(
                    "androidx.credentials.BUNDLE_KEY_RESPONSE_JSON",
                    JSONObject().put("protocol", "openid4vci").put("data", JSONObject()).toString()
                )
            },
        )
        uiState = uiState.copy(state = Result.Response(testResponse, newEntryId))
    }

    private fun onError(msg: String? = null) {
        uiState = uiState.copy(state = Result.Error(msg))
    }
}