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
import androidx.credentials.registry.provider.SelectedCredentialSet
import androidx.credentials.registry.provider.selectedCredentialSet
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
import com.credman.cmwallet.mdoc.MDoc
import com.credman.cmwallet.mdoc.createSessionTranscript
import com.credman.cmwallet.mdoc.filterIssuerSigned
import com.credman.cmwallet.mdoc.generateDeviceResponse
import com.credman.cmwallet.mdoc.webOriginOrAppOrigin
import com.credman.cmwallet.openid4vci.data.CredentialConfigurationMDoc
import com.credman.cmwallet.openid4vci.data.CredentialConfigurationSdJwtVc
import com.credman.cmwallet.openid4vci.data.CredentialConfigurationUnknownFormat
import com.credman.cmwallet.openid4vp.OpenId4VP
import com.credman.cmwallet.openid4vp.OpenId4VP.Companion.IDENTIFIERS_1_0
import com.credman.cmwallet.openid4vp.OpenId4VP.Companion.IDENTIFIER_DRAFT_24
import com.credman.cmwallet.openid4vp.OpenId4VPMatchedCredential
import com.credman.cmwallet.openid4vp.OpenId4VPMatchedMDocClaims
import com.credman.cmwallet.openid4vp.OpenId4VPMatchedSdJwtClaims
import com.credman.cmwallet.pnv.maybeHandlePnv
import com.credman.cmwallet.sdjwt.SdJwt
import com.credman.cmwallet.toBase64UrlNoPadding
import org.json.JSONArray
import org.json.JSONObject


data class MatchedCredential(
    val selectedCredential: CredentialItem,
    val matchedCredential: OpenId4VPMatchedCredential
)

fun createOpenID4VPResponse(
    openId4VPRequest: OpenId4VP,
    origin: String,
    matchedCredentials: List<MatchedCredential>,
): DigitalCredentialResult {
    var authenticationTitle: CharSequence = "Verify your identity"
    var authenticationSubtitle: CharSequence? = null
    // Create the response
    val vpToken = JSONObject()
    var credentialResponse: String? = null
    for (matchedCred in matchedCredentials) {
        val selectedCredential = matchedCred.selectedCredential
        val matchedCredential = matchedCred.matchedCredential
        when (selectedCredential.config) {
            is CredentialConfigurationSdJwtVc -> {
                val claims =
                    (matchedCredential.matchedClaims as OpenId4VPMatchedSdJwtClaims).claimSets
                val sdJwtVc = SdJwt(
                    selectedCredential.credentials.first().credential,
                    (selectedCredential.credentials.first().key as CredentialKeySoftware).privateKey
                )
                credentialResponse =
                    sdJwtVc.present(
                        claims,
                        nonce = openId4VPRequest.nonce,
                        aud = openId4VPRequest.getSdJwtKbAud(origin)
                    )
            }

            is CredentialConfigurationMDoc -> {
                val matchedClaims =
                    matchedCredential.matchedClaims as OpenId4VPMatchedMDocClaims
                val filteredIssuerSigned = filterIssuerSigned(
                    selectedCredential.credentials.first().credential.decodeBase64UrlNoPadding(),
                    matchedClaims.claimSets
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
                credentialResponse = deviceResponse.toBase64UrlNoPadding()
            }

            is CredentialConfigurationUnknownFormat -> TODO()
        }

        vpToken.put(
            matchedCredential.dcqlId,
            when (openId4VPRequest.protocolIdentifier) {
                IDENTIFIER_DRAFT_24 -> credentialResponse
                in IDENTIFIERS_1_0 -> JSONArray().put(credentialResponse)
                else -> throw UnsupportedOperationException("Invalid protocol identifier")
            }
        )
    }
    // Create the openid4vp result
    val response = openId4VPRequest.generateResponse(vpToken)
    Log.d(TAG, "Returning $response")
    return DigitalCredentialResult(
        authenticationTitle = authenticationTitle,
        authenticationSubtitle = authenticationSubtitle,
        responseJson = JSONObject().apply {
            put("protocol", openId4VPRequest.protocolIdentifier)
            put("data", JSONObject(response))
        }.toString()
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
            selectedSet = null,
            request!!
        )
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
        this.request = request
        if (request != null) {
            Log.i(TAG, "selectedEntryId ${request.selectedEntryId}")
            Log.i(TAG, "selectedCredentialSet ${request.selectedCredentialSet}")
            handleRequest(request.selectedEntryId, selectedSet = request.selectedCredentialSet, request)
        }
    }

    @OptIn(ExperimentalDigitalCredentialApi::class)
    fun handleRequest(
        entryId: String?, // TODO: deprecate this usage
        selectedSet: SelectedCredentialSet?,
        request: ProviderGetCredentialRequest
    ) {
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
                    if (entryId == "ISSUANCE") {
                        val openId4VPRequest = OpenId4VP(
                            DigitalCredentialRequestOptions.createFrom(it.requestJson).let {
                                DigitalCredentialRequestOptions.getRequestDataAtIndex(it, 0)
                            },
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

                    val selectedEntryInfo = if (entryId != null) {
                        InternalSelectionInfo.fromEntryIdJson(entryId)
                    } else {
                        InternalSelectionInfo.fromSelectedSet(selectedSet!!)
                    }
                    Log.d(TAG, "Selected Entry Info:${selectedEntryInfo}")

                    val pnvResponse = maybeHandlePnv(
                        it.requestJson,
                        selectedEntryInfo.requestIdx,
                        selectedEntryInfo.creds.first().entryId,
                        selectedEntryInfo.creds.first().dcqlId,
                        webOriginOrAppOrigin(
                            origin,
                            request.callingAppInfo.signingInfoCompat.signingCertificateHistory[0].toByteArray()
                        ),
                        request.callingAppInfo
                    )
                    if (pnvResponse != null) {
                        PendingIntentHandler.setGetCredentialResponse(
                            resultData,
                            GetCredentialResponse(DigitalCredential(pnvResponse.responseJson))
                        )
                        setResult(RESULT_OK, resultData)
                        finish()
                        return
                    }

                    val response = processDigitalCredentialOption(
                        it.requestJson,
                        selectedEntryInfo,
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
        val authenticationTitle: CharSequence,
        val authenticationSubtitle: CharSequence?,
        val responseJson: String,
    )

    sealed class DigitalCredentialRequestOptions {
        companion object {
            fun getRequestProtocolAtIndex(digitalCredentialOptions: DigitalCredentialRequestOptions, index: Int): String {
                return when (digitalCredentialOptions) {
                    is DigitalCredentialRequestOptionsModern -> digitalCredentialOptions.requests[index].protocol
                    is DigitalCredentialRequestOptionsLegacy -> digitalCredentialOptions.providers[index].protocol
                }
            }

            fun getRequestDataAtIndex(digitalCredentialOptions: DigitalCredentialRequestOptions, index: Int): JSONObject {
                return when (digitalCredentialOptions) {
                    is DigitalCredentialRequestOptionsModern -> digitalCredentialOptions.requests[index].data
                    is DigitalCredentialRequestOptionsLegacy -> JSONObject(digitalCredentialOptions.providers[index].request)
                }
            }

            fun createFrom(request: String): DigitalCredentialRequestOptions {
                val requestJson = JSONObject(request)
                return if (requestJson.has("requests")) {
                    val requestsJson = requestJson.getJSONArray("requests")
                    DigitalCredentialRequestOptionsModern(
                        requests = mutableListOf<DigitalCredentialRequestModern>().apply {
                            for (i in 0..<requestsJson.length()) {
                                add(
                                    DigitalCredentialRequestModern(
                                        requestsJson.getJSONObject(i).getString("protocol"),
                                        requestsJson.getJSONObject(i).let {
                                            val data = it.get("data")
                                            return@let when (data) {
                                                is String -> JSONObject(data)
                                                else -> data as JSONObject
                                            }
                                        }
                                    )
                                )
                            }
                        }
                    )
                } else {
                    val providersJson = requestJson.getJSONArray("providers")
                    DigitalCredentialRequestOptionsLegacy(
                        providers = mutableListOf<DigitalCredentialRequestLegacy>().apply {
                            for (i in 0..<providersJson.length()) {
                                add(
                                    DigitalCredentialRequestLegacy(
                                        providersJson.getJSONObject(i).getString("protocol"),
                                        providersJson.getJSONObject(i).getString("request")
                                    )
                                )
                            }
                        }
                    )
                }
            }
        }
    }

    data class DigitalCredentialRequestOptionsLegacy(
        val providers: List<DigitalCredentialRequestLegacy>
    ) : DigitalCredentialRequestOptions()

    data class DigitalCredentialRequestLegacy(
        val protocol: String,
        val request: String
    )

    data class DigitalCredentialRequestOptionsModern(
        val requests: List<DigitalCredentialRequestModern>
    ): DigitalCredentialRequestOptions()

    data class DigitalCredentialRequestModern(
        val protocol: String,
        val data: JSONObject
    )

    private fun processDigitalCredentialOption(
        requestJson: String,
        selectionInfo: InternalSelectionInfo,
        origin: String
    ): DigitalCredentialResult {
        val digitalCredentialOptions = DigitalCredentialRequestOptions.createFrom(requestJson)

        val requestProtocol = DigitalCredentialRequestOptions.getRequestProtocolAtIndex(
            digitalCredentialOptions, selectionInfo.requestIdx
        )
        val requestData: JSONObject = DigitalCredentialRequestOptions.getRequestDataAtIndex(
            digitalCredentialOptions, selectionInfo.requestIdx
        )

        Log.i(
            "GetCredentialActivity",
            "processDigitalCredentialOption protocol ${requestProtocol}"
        )

        when (requestProtocol) {
            in OpenId4VP.IDENTIFIERS -> {
                val openId4VPRequest = OpenId4VP(
                    requestData,
                    computeClientId(request!!.callingAppInfo),
                    requestProtocol
                )
                Log.i("GetCredentialActivity", "nonce ${openId4VPRequest.nonce}")

                val matchedCredentials = mutableListOf<MatchedCredential>()
                for (cred in selectionInfo.creds) {
                    val selectedCredential =
                        CmWalletApplication.credentialRepo.getCredential(cred.entryId)
                            ?: throw RuntimeException("Selected credential \"${cred.entryId}\" not found")
                    val matchedCredential =
                        if (cred.matchedClaimPaths == null) {
                            openId4VPRequest.performQueryOnCredential(selectedCredential, cred.dcqlId)
                        } else {
                            OpenId4VPMatchedCredential(
                                cred.dcqlId,
                                if (selectedCredential.config.format == "dc+sd-jwt") {
                                    OpenId4VPMatchedSdJwtClaims(cred.matchedClaimPaths?.let { matchedClaimPaths ->
                                        val singleClaimSet = JSONArray()
                                        for (i in 0 until matchedClaimPaths.paths.length()) {
                                            val matchedPath = matchedClaimPaths.paths.getJSONArray(i)
                                            val pathObject = JSONObject().put("path", matchedPath)
                                            singleClaimSet.put(pathObject)
                                        }
                                        JSONArray().put(singleClaimSet)
                                    })
                                } else if (selectedCredential.config.format == "mso_mdoc") {
                                    OpenId4VPMatchedMDocClaims(
                                        cred.matchedClaimPaths?.let { matchedClaimPaths ->
                                            val ret = mutableMapOf<String, MutableList<String>>()
                                            for (i in 0 until matchedClaimPaths.paths.length()) {
                                                val matchedPath = matchedClaimPaths.paths.getJSONArray(i)
                                                val namespace = matchedPath.getString(0)
                                                val claimName = matchedPath.getString(1)
                                                if (ret.containsKey(namespace)) {
                                                    ret[namespace]?.add(claimName)
                                                } else {
                                                    ret[namespace] = mutableListOf(claimName)
                                                }
                                            }
                                            listOf(ret)
                                        } ?: selectedCredential.let {
                                            val mdoc =
                                                MDoc(it.credentials.first().credential.decodeBase64UrlNoPadding())
                                            val ret = mutableMapOf<String, List<String>>()
                                            mdoc.issuerSignedNamespaces.forEach { (namespace, elements) ->
                                                ret[namespace] = elements.keys.toList()
                                            }
                                            listOf(ret)
                                        }
                                    )
                                } else {
                                    throw UnsupportedOperationException("Unknown credential type")
                                }
                            )
                        }

                    Log.i("GetCredentialActivity", "matchedCredential $matchedCredential")
                    matchedCredentials.add(MatchedCredential(selectedCredential, matchedCredential))
                }
                return createOpenID4VPResponse(
                    openId4VPRequest,
                    origin,
                    matchedCredentials
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
