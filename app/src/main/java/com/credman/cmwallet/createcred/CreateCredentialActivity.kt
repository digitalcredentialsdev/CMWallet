package com.credman.cmwallet.createcred

import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.service.credentials.CredentialProviderService
import android.util.Log
import android.view.ViewGroup
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.BottomSheetDefaults
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.credentials.CreateCredentialRequest
import androidx.credentials.CreateCredentialRequest.DisplayInfo
import androidx.credentials.CreateCredentialResponse
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.provider.ProviderCreateCredentialRequest
import androidx.lifecycle.viewmodel.compose.viewModel
import com.credman.cmwallet.CmWalletApplication
import com.credman.cmwallet.CmWalletApplication.Companion.TAG
import com.credman.cmwallet.data.model.CredentialItem
import com.credman.cmwallet.getcred.GetCredentialActivity
import com.credman.cmwallet.ui.CredentialCard
import com.credman.cmwallet.ui.theme.CMWalletTheme

@Suppress("RestrictedApi")
class CreateCredentialActivity : ComponentActivity() {
    private val viewModel: CreateCredentialViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (savedInstanceState == null) {
            Log.d(TAG, "New CreateCredentialActivity")
            val request = toRequest(intent)
            if (request == null) {
                Log.e(TAG, "[CreateCredentialActivity] Got empty request!")
                finish()
                return
            }

            val origin = request.callingAppInfo.getOrigin(
                CmWalletApplication.credentialRepo.privAppsJson
            ) ?: ""
            Log.i(TAG, "[CreateCredentialActivity] origin $origin")

            viewModel.onNewRequest(request)
        }
        setContent {
            CMWalletTheme {
                CreateCredentialScreen(viewModel)
            }
        }
    }

    @OptIn(ExperimentalMaterial3Api::class)
    @Composable
    fun CreateCredentialScreen(viewModel: CreateCredentialViewModel) {
        println("color ${BottomSheetDefaults.ContainerColor.alpha} ${BottomSheetDefaults.ContainerColor.red} ${BottomSheetDefaults.ContainerColor.green} ${BottomSheetDefaults.ContainerColor.blue}")
        val uiState = viewModel.uiState
        val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
        LaunchedEffect(uiState.state) {
            handleUiResult(uiState.state)
        }


        ModalBottomSheet(
            onDismissRequest = {
                finishWithError(exception = CreateCredentialCancellationException())
            },
            sheetState = sheetState
        ) {
            val credentials = uiState.credentialsToSave

            if (uiState.authServer != null) {
                Column(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Row(
                        modifier = Modifier
                            .padding(10.dp)
                    ) {
                        Text(
                            text = "Verify your identity...",
                            textAlign = TextAlign.Center,
                            fontSize = 20.sp
                        )
                    }
                    Box(
                        modifier = Modifier.fillMaxWidth().height(500.dp)
                    ) {
                        AuthWebView(
                            url = uiState.authServer.url,
                            redirectUrl = uiState.authServer.redirectUrl,
                            onDone = { code ->
                                viewModel.onCode(code, uiState.authServer.redirectUrl)
                            }
                        )
                    }


                }
            } else if (uiState.vpResponse != null) {
                VpCredential(
                    vpResponse =  uiState.vpResponse,
                    onApprove = {
                        viewModel.onApprove()
                    }
                )
            } else if (credentials == null) {
                LinearProgressIndicator(
                    Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 2.dp)
                )
            } else {
                Column(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Row(
                        modifier = Modifier
                            .padding(10.dp)
                    ) {
                        Text(
                            text = "Add to CMWallet",
                            textAlign = TextAlign.Center,
                            fontSize = 20.sp
                        )
                    }
                    for (credential in credentials) {
                        Row(
                            modifier = Modifier
                                .padding(10.dp)
                        ) {
                            CredentialCard(credential, {})
                        }
                    }
//                    when (val credentialDetails = credential.credential) {
//                        is MdocCredential -> CredentialClaimList(credentialDetails)
//                    }
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        TextButton(
                            modifier = Modifier.padding(20.dp, 10.dp, 10.dp, 20.dp ),
                            onClick = {
                                viewModel.onConfirm()
                            }
                        ) {
                            Text("Cancel")
                        }
                        Button(
                            modifier = Modifier.padding(10.dp, 10.dp, 20.dp, 20.dp ),
                            onClick = {
                                viewModel.onConfirm()
                            }
                        ) {
                            Text("Add to wallet")
                        }
                    }

                }
            }

        }
    }

    private fun handleUiResult(r: Result?) {
        when (r) {
            is Result.Error -> finishWithError(r.msg)
            is Result.Response -> finishWithResponse(r.response, r.newEntryId)
            else -> {} // No-op
        }
    }

    private fun finishWithResponse(response: CreateCredentialResponse, newEntryId: String) {
        val resultData = Intent()
        PendingIntentHandler.setCreateCredentialResponse(resultData, response)

        // A bit hacky, for the inline issuance
        resultData.putExtra("newEntryId", newEntryId)

        setResult(RESULT_OK, resultData)
        finish()
    }

    private fun finishWithError(
        msg: String? = null,
        exception: CreateCredentialException = CreateCredentialUnknownException(msg)
    ) {
        val resultData = Intent()
        PendingIntentHandler.setCreateCredentialException(
            resultData,
            exception,
        )
        setResult(RESULT_OK, resultData)
        finish()
    }

    /**
     * Eventually this should be replaced as a single call
     * val request = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
     */
    fun toRequest(intent: Intent): ProviderCreateCredentialRequest? {
        val tmpRequestInto = DisplayInfo("userId")
        if (Build.VERSION.SDK_INT >= 34) {
            val request = intent.getParcelableExtra(
                CredentialProviderService.EXTRA_CREATE_CREDENTIAL_REQUEST,
                android.service.credentials.CreateCredentialRequest::class.java
            ) ?: return null
            return try {
                ProviderCreateCredentialRequest(
                    callingRequest =
                    CreateCredentialRequest.createFrom(
                        request.type,
                        request.data.apply {
                            putBundle(
                                DisplayInfo.BUNDLE_KEY_REQUEST_DISPLAY_INFO,
                                tmpRequestInto.toBundle(),
                            )
                        },
                        request.data,
                        requireSystemProvider = false,
                        request.callingAppInfo.origin
                    ),
                    callingAppInfo =
                    CallingAppInfo.create(
                        request.callingAppInfo.packageName,
                        request.callingAppInfo.signingInfo,
                        request.callingAppInfo.origin
                    ),
                    biometricPromptResult = null
                )
            } catch (e: IllegalArgumentException) {
                return null
            }
        } else {
            val requestBundle = intent.getBundleExtra(
                "android.service.credentials.extra.CREATE_CREDENTIAL_REQUEST"
            ) ?: return null
            val requestDataBundle = requestBundle.getBundle(
                "androidx.credentials.provider.extra.CREATE_REQUEST_CREDENTIAL_DATA"
            ) ?: Bundle()
            requestDataBundle.putBundle(
                DisplayInfo.BUNDLE_KEY_REQUEST_DISPLAY_INFO,
                tmpRequestInto.toBundle(),
            )
            requestBundle.putBundle(
                "androidx.credentials.provider.extra.CREATE_REQUEST_CREDENTIAL_DATA",
                requestDataBundle
            )
            return try {
                ProviderCreateCredentialRequest.fromBundle(requestBundle)
            } catch (e: Exception) {
                Log.e(TAG, "Parsing error", e)
                null
            }
        }
    }

    @Composable
    fun VpCredential(
        vpResponse: CredentialItem,
        onApprove: () -> Unit
    ) {
        Column(
            modifier = Modifier.fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Row(
                modifier = Modifier
                    .padding(10.dp)
            ) {
                Text(
                    text = "Verify your ID",
                    textAlign = TextAlign.Center,
                    fontSize = 20.sp
                )
            }
            Row(
                modifier = Modifier
                    .padding(10.dp)
            ) {
                CredentialCard(vpResponse, {})
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                TextButton(
                    modifier = Modifier.padding(20.dp, 10.dp, 10.dp, 20.dp ),
                    onClick = {

                    }
                ) {
                    Text("Cancel")
                }
                Button(
                    modifier = Modifier.padding(10.dp, 10.dp, 20.dp, 20.dp ),
                    onClick = {
                        onApprove()
                    }
                ) {
                    Text("Share")
                }
            }
        }
    }

    @Composable
    fun AuthWebView(
        url: String,
        redirectUrl: String,
        onDone: (String) -> Unit
    ) {
        LazyColumn {
            item {
                AndroidView(factory = {
                    WebView(it).apply {
                        clearCache(true)
                        settings.javaScriptEnabled = true
                        this.layoutParams = ViewGroup.LayoutParams(
                            ViewGroup.LayoutParams.MATCH_PARENT,
                            ViewGroup.LayoutParams.MATCH_PARENT
                        )
                        this.webViewClient = object : WebViewClient() {
                            override fun shouldOverrideUrlLoading(
                                view: WebView?,
                                request: WebResourceRequest?
                            ): Boolean {

                                request?.let {

                                    if (request.url.toString().startsWith("$redirectUrl/")) {
                                        request.url.getQueryParameter("code")?.let { code ->
                                            onDone(code)
                                        }
                                    }
                                }
                                return super.shouldOverrideUrlLoading(view, request)
                            }
                        }
                    }
                }, update = {
                    it.loadUrl(url)
                })
            }
        }
    }
}

@Composable
fun CredentialClaimList(
//    cred: MdocCredential,
) {
//    cred.nameSpaces.forEach { namespacedData ->
//        namespacedData.value.data.forEach { field ->
//            Row(
//                modifier = Modifier.fillMaxWidth().padding(10.dp),
//                horizontalArrangement = Arrangement.SpaceBetween,
//            ) {
//                Text(field.value.display)
//                Text(field.value.displayValue ?: " " /*placeholder*/)
//            }
//        }
//    }
}