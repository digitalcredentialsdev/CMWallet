package com.credman.cmwallet.getcred

import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.util.Log
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.credentials.CreateCredentialRequest
import androidx.credentials.CreateCustomCredentialRequest
import androidx.credentials.DigitalCredential
import androidx.credentials.ExperimentalDigitalCredentialApi
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetDigitalCredentialOption
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.provider.ProviderCreateCredentialRequest
import androidx.credentials.provider.ProviderGetCredentialRequest
import androidx.credentials.registry.provider.selectedEntryId
import androidx.fragment.app.FragmentActivity
import com.credman.cmwallet.CmWalletApplication
import com.credman.cmwallet.CmWalletApplication.Companion.TAG
import com.credman.cmwallet.CmWalletApplication.Companion.computeClientId
import com.credman.cmwallet.createcred.CreateCredentialActivity
import com.credman.cmwallet.data.model.CredentialItem
import com.credman.cmwallet.data.model.CredentialKeySoftware
import com.credman.cmwallet.decodeBase64UrlNoPadding
import com.credman.cmwallet.getcred.GetCredentialActivity.DigitalCredentialResult
import com.credman.cmwallet.loadECPrivateKey
import com.credman.cmwallet.mdoc.createSessionTranscript
import com.credman.cmwallet.mdoc.filterIssuerSigned
import com.credman.cmwallet.mdoc.generateDeviceResponse
import com.credman.cmwallet.mdoc.webOriginOrAppOrigin
import com.credman.cmwallet.openid4vci.data.CredentialConfigurationMDoc
import com.credman.cmwallet.openid4vci.data.CredentialConfigurationSdJwtVc
import com.credman.cmwallet.openid4vci.data.CredentialConfigurationUnknownFormat
import com.credman.cmwallet.openid4vp.OpenId4VP
import com.credman.cmwallet.openid4vp.OpenId4VPMatchedCredential
import com.credman.cmwallet.openid4vp.OpenId4VPMatchedMDocClaims
import com.credman.cmwallet.openid4vp.OpenId4VPMatchedSdJwtClaims
import com.credman.cmwallet.sdjwt.SdJwt
import com.credman.cmwallet.toBase64UrlNoPadding
import com.google.android.gms.identitycredentials.IntentHelper
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.json.JSONObject


fun createOpenID4VPResponse(
    openId4VPRequest: OpenId4VP,
    origin: String,
    selectedCredential: CredentialItem,
    matchedCredential: OpenId4VPMatchedCredential
): DigitalCredentialResult {
    var authenticationTitle: CharSequence = "Verify your identity"
    var authenticationSubtitle: CharSequence? = null
    // Create the response
    val vpToken = JSONObject()
    when (selectedCredential.config) {
        is CredentialConfigurationSdJwtVc -> {
            val claims =
                (matchedCredential.matchedClaims as OpenId4VPMatchedSdJwtClaims).claims
            val sdJwtVc = SdJwt(
                selectedCredential.credentials.first().credential,
                (selectedCredential.credentials.first().key as CredentialKeySoftware).privateKey
            )
            vpToken.put(
                matchedCredential.dcqlId,
                sdJwtVc.present(
                    claims,
                    nonce = openId4VPRequest.nonce,
                    clientId = openId4VPRequest.clientId
                )
            )
        }
        is CredentialConfigurationMDoc -> {
            val matchedClaims =
                matchedCredential.matchedClaims as OpenId4VPMatchedMDocClaims
            val filteredIssuerSigned = filterIssuerSigned(
                selectedCredential.credentials.first().credential.decodeBase64UrlNoPadding(),
                matchedClaims.claims
            )
            val deviceNamespaces = if (openId4VPRequest.transactionData.isEmpty()) {
                emptyMap<String, Any>()
            } else {
                val deviceSignedTransactionData =
                    openId4VPRequest.generateDeviceSignedTransactionData(
                        matchedCredential.dcqlId
                    )
                if (deviceSignedTransactionData.authenticationTitleAndSubtitle != null) {
                    authenticationTitle =
                        deviceSignedTransactionData.authenticationTitleAndSubtitle.first
                    authenticationSubtitle =
                        deviceSignedTransactionData.authenticationTitleAndSubtitle.second
                }
                mapOf(
                    Pair(
                        "net.openid.open4vc",
                        deviceSignedTransactionData.deviceSignedTransactionData
                    )
                )
            }
            val devicePrivateKey =
                loadECPrivateKey((selectedCredential.credentials.first().key as CredentialKeySoftware).privateKey.decodeBase64UrlNoPadding())
            val deviceResponse = generateDeviceResponse(
                doctype = selectedCredential.config.doctype,
                issuerSigned = filteredIssuerSigned,
                devicePrivateKey = devicePrivateKey,
                sessionTranscript = createSessionTranscript(
                    openId4VPRequest.getHandover(
                        origin
                    )
                ),
                deviceNamespaces = deviceNamespaces

            )
            val encodedDeviceResponse = deviceResponse.toBase64UrlNoPadding()
            vpToken.put(matchedCredential.dcqlId, encodedDeviceResponse)
        }

        is CredentialConfigurationUnknownFormat -> TODO()
    }

    // Create the openid4vp result
    val response = openId4VPRequest.generateResponse(vpToken)
    Log.d(TAG, "Returning $response")
    return DigitalCredentialResult(
        responseJson = response,
        authenticationTitle = authenticationTitle,
        authenticationSubtitle = authenticationSubtitle,
    )
}

class GetCredentialActivity : FragmentActivity() {
    private var request: ProviderGetCredentialRequest? = null

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        Log.d(TAG, "Got activity result from issuance")
        val newEntryId = data?.getStringExtra("newEntryId")!!
        handleRequest(
            JSONObject().put("provider_idx", 0).put("id", newEntryId).toString(),
            request!!
        )
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
        this.request = request
        if (request != null) {
            Log.i(TAG, "selectedEntryId ${request.selectedEntryId}")
            handleRequest(request.selectedEntryId, request)
        }
    }

    @OptIn(ExperimentalDigitalCredentialApi::class)
    fun handleRequest(entryId: String?, request: ProviderGetCredentialRequest) {
        var origin = request.callingAppInfo.getOrigin(
            CmWalletApplication.credentialRepo.privAppsJson
        )
        Log.i("GetCredentialActivity", "origin $origin")
        if (origin != null && origin.endsWith(":443")) {
            origin = origin.substringBefore(":443")
            Log.i("GetCredentialActivity", "new origin $origin")
        }

        request.credentialOptions.forEach {
            if (it is GetDigitalCredentialOption) {
                val resultData = Intent()
                Log.i(TAG, "Request ${it.requestJson}")

                try {
                    val digitalCredentialRequestOptions =
                        Json.decodeFromString<DigitalCredentialRequestOptions>(it.requestJson)
                    if (entryId == "ISSUANCE") {
                        val openId4VPRequest = OpenId4VP(
                            digitalCredentialRequestOptions.requests[0].data,
                            computeClientId(request.callingAppInfo)
                        )
                        startActivityForResult(
                            Intent(this, CreateCredentialActivity::class.java).apply {
                                val callingAppInfo = request.callingAppInfo
                                val providerRequest =
                                    ProviderCreateCredentialRequest(
                                        CreateCustomCredentialRequest(
                                            type = it.type,
                                            credentialData = Bundle().apply {
                                                putString(
                                                    "androidx.credentials.BUNDLE_KEY_REQUEST_JSON",
                                                    JSONObject()
                                                        .put("protocol", "openid4vci")
                                                        .putOpt("data", openId4VPRequest.issuanceOffer)
                                                        .toString()
                                                )
                                            },
                                            candidateQueryData = Bundle(),
                                            isSystemProviderRequired = false,
                                            displayInfo =
                                            CreateCredentialRequest.DisplayInfo("userid", "username"),
                                            origin = origin,
                                        ),
                                        callingAppInfo,
                                    )
                                if (Build.VERSION.SDK_INT >= 34) { // TODO: b/361100869 use the official Jetpack api
                                    putExtra(
                                        "android.service.credentials.extra.CREATE_CREDENTIAL_REQUEST",
                                        android.service.credentials.CreateCredentialRequest(
                                            android.service.credentials.CallingAppInfo(
                                                providerRequest.callingAppInfo.packageName,
                                                providerRequest.callingAppInfo.signingInfo,
                                                origin,
                                            ),
                                            providerRequest.callingRequest.type,
                                            Bundle(providerRequest.callingRequest.credentialData),
                                        ),
                                    )
                                    putExtra("androidx.credentials.registry.provider.extra.CREDENTIAL_ID", "0")
                                } else {
                                    val requestBundle = ProviderCreateCredentialRequest.asBundle(providerRequest)
                                    requestBundle.putString(
                                        "androidx.credentials.registry.provider.extra.CREDENTIAL_ID",
                                        "0",
                                    )
                                    putExtra("android.service.credentials.extra.CREATE_CREDENTIAL_REQUEST", requestBundle)
                                }
                            },
                            1111
                        )
                        return
                    }
                    val selectedEntryId = JSONObject(entryId!!)
                    val providerIdx = selectedEntryId.getInt("provider_idx")
                    val selectedId = selectedEntryId.getString("id")

                    val response = processDigitalCredentialOption(
                        digitalCredentialRequestOptions,
                        providerIdx,
                        selectedId,
                        webOriginOrAppOrigin(
                            origin,
                            request.callingAppInfo.signingInfoCompat.signingCertificateHistory[0].toByteArray()
                        )
                    )

                    val biometricPrompt = BiometricPrompt(
                        this@GetCredentialActivity,
                        object : BiometricPrompt.AuthenticationCallback() {
                            override fun onAuthenticationFailed() {
                                super.onAuthenticationFailed()
                                Log.d(TAG, "onAuthenticationFailed")
                            }

                            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                                Log.d(TAG, "onAuthenticationSucceeded")

                                // This is a temporary solution until Chrome migrate to use
                                // the top level DC DigitalCredential json structure.
                                // Long term, this should be replaced by a simple
                                // `PendingIntentHandler.setGetCredentialResponse(intent, DigitalCredential(response.responseJson))` call.
                                PendingIntentHandler.setGetCredentialResponse(
                                    resultData,
                                    GetCredentialResponse(DigitalCredential(response.responseJson))
                                )

                                setResult(RESULT_OK, resultData)
                                finish()
                            }

                            override fun onAuthenticationError(
                                errorCode: Int,
                                errString: CharSequence
                            ) {
                                Log.e(TAG, "onAuthenticationError $errorCode $errString")
                                PendingIntentHandler.setGetCredentialException(
                                    resultData,
                                    GetCredentialUnknownException()
                                )
                                setResult(RESULT_OK, resultData)
                                finish()
                            }
                        })
                    Log.d(TAG, "authenticating")
                    biometricPrompt.authenticate(
                        BiometricPrompt.PromptInfo.Builder()
                            .setTitle(response.authenticationTitle)
                            .setSubtitle(response.authenticationSubtitle)
                            .setConfirmationRequired(false)
                            .setStrongOrDeviceAuthenticators(this@GetCredentialActivity)
                            .build()
                    )
                    return
                } catch (e: Exception) {
                    Log.e(TAG, "exception", e)
                    PendingIntentHandler.setGetCredentialException(
                        resultData,
                        GetCredentialUnknownException()
                    )
                    setResult(RESULT_OK, resultData)
                    finish()
                }
            }
        }
        Log.w(TAG, "No request to handle, terminating")
        finish()
    }

    data class DigitalCredentialResult(
        val responseJson: String,
        val authenticationTitle: CharSequence,
        val authenticationSubtitle: CharSequence?
    )

    @Serializable
    data class DigitalCredentialRequestOptions(
        val requests: List<DigitalCredentialRequest>
    )

    @Serializable
    data class DigitalCredentialRequest(
        val protocol: String,
        val data: String
    )

    private fun processDigitalCredentialOption(
        digitalCredentialRequestOptions: DigitalCredentialRequestOptions,
        providerIdx: Int,
        selectedID: String,
        origin: String
    ): DigitalCredentialResult {
        val selectedCredential = CmWalletApplication.credentialRepo.getCredential(selectedID)
            ?: throw RuntimeException("Selected credential not found")

        Log.i(
            "GetCredentialActivity",
            "digitalCredentialRequestOptions $digitalCredentialRequestOptions"
        )

        val provider = digitalCredentialRequestOptions.requests[providerIdx]

        Log.i(
            "GetCredentialActivity",
            "processDigitalCredentialOption protocol ${provider.protocol}"
        )
        when (provider.protocol) {
            "openid4vp" -> {
                val openId4VPRequest = OpenId4VP(provider.data, computeClientId(request!!.callingAppInfo))
                Log.i("GetCredentialActivity", "nonce ${openId4VPRequest.nonce}")
                val matchedCredential =
                    openId4VPRequest.performQueryOnCredential(selectedCredential)
                Log.i("GetCredentialActivity", "matchedCredential $matchedCredential")



                return createOpenID4VPResponse(
                    openId4VPRequest,
                    origin,
                    selectedCredential,
                    matchedCredential
                );

            }

            else -> throw IllegalArgumentException()
        }
    }
}

/**
 * Returns biometric Strong only if it is available. Otherwise, also allows device credentials.
 */
fun BiometricPrompt.PromptInfo.Builder.setStrongOrDeviceAuthenticators(context: Context): BiometricPrompt.PromptInfo.Builder {
    val authenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG
    val biometricManager = BiometricManager.from(context)
    if (biometricManager.canAuthenticate(authenticators) == BiometricManager.BIOMETRIC_SUCCESS) {
        this.setAllowedAuthenticators(authenticators).setNegativeButtonText("Cancel")
    } else {
        this.setAllowedAuthenticators(
            authenticators or BiometricManager.Authenticators.DEVICE_CREDENTIAL
        )
    }
    return this
}

internal const val CHROME_RESPONSE_TOKEN_KEY_LEGACY = "identityToken"
