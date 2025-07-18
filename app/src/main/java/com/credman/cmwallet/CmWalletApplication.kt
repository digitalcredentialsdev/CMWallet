package com.credman.cmwallet

import android.app.Application
import android.graphics.Bitmap
import android.util.Log
import androidx.core.graphics.drawable.toBitmap
import androidx.credentials.DigitalCredential
import androidx.credentials.ExperimentalDigitalCredentialApi
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.registry.provider.RegisterCredentialsRequest
import androidx.credentials.registry.provider.RegistryManager
import androidx.room.Room
import com.credman.cmwallet.data.repository.CredentialRepository
import com.credman.cmwallet.data.repository.CredentialRepository.Companion.ICON
import com.credman.cmwallet.data.repository.CredentialRepository.Companion.ID
import com.credman.cmwallet.data.repository.CredentialRepository.Companion.LENGTH
import com.credman.cmwallet.data.repository.CredentialRepository.Companion.START
import com.credman.cmwallet.data.repository.CredentialRepository.Companion.SUBTITLE
import com.credman.cmwallet.data.repository.CredentialRepository.Companion.TITLE
import com.credman.cmwallet.data.repository.CredentialRepository.RegistryIcon
import com.credman.cmwallet.data.room.CredentialDatabase
import com.credman.cmwallet.mdoc.MDoc
import com.google.android.gms.identitycredentials.IdentityCredentialClient
import com.google.android.gms.identitycredentials.IdentityCredentialManager
import com.google.android.gms.identitycredentials.RegisterCreationOptionsRequest
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.io.encoding.ExperimentalEncodingApi


class CmWalletApplication : Application() {
    companion object {
        lateinit var database: CredentialDatabase
        lateinit var credentialRepo: CredentialRepository

        fun computeClientId(callingAppInfo: CallingAppInfo): String {
            val origin = callingAppInfo.getOrigin(credentialRepo.privAppsJson)
            return if (origin == null) {
                "android-origin:${callingAppInfo.packageName}"
            } else {
                "web-origin:$origin"
            }
        }

        const val TAG = "CmWalletApplication"
    }

    private val registryManager = RegistryManager.create(this)
    private lateinit var identityCredentialClient: IdentityCredentialClient
    private val applicationScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    @OptIn(ExperimentalDigitalCredentialApi::class, ExperimentalEncodingApi::class)
    override fun onCreate() {
        super.onCreate()

        val testIssuerSignedString =
            "ompuYW1lU3BhY2VzoXFvcmcuaXNvLjE4MDEzLjUuMYPYGFhUpGhkaWdlc3RJRABmcmFuZG9tUKRsGD3aPLpwu_wGZyvuvdxxZWxlbWVudElkZW50aWZpZXJrZmFtaWx5X25hbWVsZWxlbWVudFZhbHVlZVNtaXRo2BhYUaRoZGlnZXN0SUQBZnJhbmRvbVAQwZXPLt5ybFSqRvFVCnPocWVsZW1lbnRJZGVudGlmaWVyamdpdmVuX25hbWVsZWxlbWVudFZhbHVlY0pvbtgYWE-kaGRpZ2VzdElEAmZyYW5kb21QPNysOvdkUbmuOPhvyXsrAHFlbGVtZW50SWRlbnRpZmllcmthZ2Vfb3Zlcl8yMWxlbGVtZW50VmFsdWX1amlzc3VlckF1dGiEQ6EBJqEYIVkCSzCCAkcwggHtoAMCAQICFHStD_3VcEOVnxRIW57aoGfaMp7FMAoGCCqGSM49BAMCMHkxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1Nb3VudGFpbiBWaWV3MRwwGgYDVQQKDBNEaWdpdGFsIENyZWRlbnRpYWxzMR8wHQYDVQQDDBZkaWdpdGFsY3JlZGVudGlhbHMuZGV2MB4XDTI0MTExMDAxMDgwM1oXDTM0MTAyOTAxMDgwM1oweTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxHDAaBgNVBAoME0RpZ2l0YWwgQ3JlZGVudGlhbHMxHzAdBgNVBAMMFmRpZ2l0YWxjcmVkZW50aWFscy5kZXYwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATrQ6h60nar2xgrGpTMbRRYLBtWyfkHw2k4QzZc40EsBJNeDp-WXKz85dJjNloCsC7Ckb1spirxQdKVPWy2eRBpo1MwUTAdBgNVHQ4EFgQUCyxw_AMcbG8Lp1EwUuOaRBk527AwHwYDVR0jBBgwFoAUCyxw_AMcbG8Lp1EwUuOaRBk527AwDwYDVR0TAQH_BAUwAwEB_zAKBggqhkjOPQQDAgNIADBFAiEA_JW68hhRYz9l2scu8yW55xi7yyq7ycHg6arTH4b75zMCIG5DADVEbdGnoh6rzTKUdXEh2EnsgjERk6vH6u25Y4fLWQG62BhZAbWmZ3ZlcnNpb25jMS4wb2RpZ2VzdEFsZ29yaXRobWdTSEEtMjU2Z2RvY1R5cGV1b3JnLmlzby4xODAxMy41LjEubURMbHZhbHVlRGlnZXN0c6Fxb3JnLmlzby4xODAxMy41LjGjAFgg-TGk78sfX6xxEfdjckEmDSfiVWzOGIIwTqm0oQetoR8BWCAcX3iJNwCyYOy1Bfl9sAjv1lEuD7iXI5dJbkwPUB6-RwJYIGFOQ5HGtkmhrJWuJ6eTdM2PC_lAIDR5_9pWUiRogpWwbWRldmljZUtleUluZm-haWRldmljZUtleaQBAiABIVggdO8Xw9vvSFlJ9WC7Jd69A_jZ8fbaDi54X92jIbkJmxoiWCAMTMw-ipf52P1MpCfqncpCKgmnEXVhBruNhKLUYs3VhWx2YWxpZGl0eUluZm-jZnNpZ25lZMB4GzIwMjQtMTEtMTdUMjA6NTI6MjIuOTE5NzgyWml2YWxpZEZyb23AeBsyMDI0LTExLTE3VDIwOjUyOjIyLjkxOTc4OVpqdmFsaWRVbnRpbMB4GzIwMzQtMTEtMDVUMjA6NTI6MjIuOTE5Nzg5WlhAl1Lt2d0SSsbuMizlTkVeLR7wucamVyUhyHm6PdG1W0YWXIxfLGwP0rG7Zhpuomh5kpItM7lRdR_FdkJHXO81MQ"
        val testIssuerSigned = testIssuerSignedString.decodeBase64UrlNoPadding()
        val mdoc = MDoc(testIssuerSigned)
        println(mdoc.issuerSignedNamespaces)

        identityCredentialClient = IdentityCredentialManager.getClient(applicationContext)
        database = Room.databaseBuilder(
            applicationContext,
            CredentialDatabase::class.java, "credential-database"
        ).allowMainThreadQueries().fallbackToDestructiveMigration().build()
        credentialRepo = CredentialRepository()

        val openId4VPDraft24Matcher = loadOpenId4VPDraft24Matcher()
        val openId4VP1_0Matcher = loadOpenId4VP1_0Matcher()
        val testCredentialsJson = loadTestCredentialsNew().decodeToString()

        // Add the test credentials from the included json
        credentialRepo.addCredentialsFromJson(testCredentialsJson)
        credentialRepo.setPrivAppsJson(loadAppsJson().decodeToString())
        credentialRepo.openId4VCITestRequestJson = loadOpenId4VCIRequestJson().decodeToString()

        // Listen for new credentials and update the registry.
        applicationScope.launch {
            credentialRepo.credentialRegistryDatabase.collect { credentialDatabase ->
                Log.i(TAG, "Credentials changed $credentialDatabase")
                // Oid4vp draft 24
                // For backward compatibility with Chrome
                registryManager.registerCredentials(
                    request = object : RegisterCredentialsRequest(
                        "com.credman.IdentityCredential",
                        "openid4vp",
                        credentialDatabase,
                        openId4VPDraft24Matcher
                    ) {}
                )
                // In the future, should only register this type
                registryManager.registerCredentials(
                    request = object : RegisterCredentialsRequest(
                        DigitalCredential.TYPE_DIGITAL_CREDENTIAL,
                        "openid4vp",
                        credentialDatabase,
                        openId4VPDraft24Matcher
                    ) {}
                )

                // Oid4vp 1.0 Candidate
                // For backward compatibility with Chrome
                registryManager.registerCredentials(
                    request = object : RegisterCredentialsRequest(
                        "com.credman.IdentityCredential",
                        "openid4vp1.0",
                        credentialDatabase,
                        openId4VP1_0Matcher
                    ) {}
                )
                // In the future, should only register this type
                registryManager.registerCredentials(
                    request = object : RegisterCredentialsRequest(
                        DigitalCredential.TYPE_DIGITAL_CREDENTIAL,
                        "openid4vp1.0",
                        credentialDatabase,
                        openId4VP1_0Matcher
                    ) {}
                )

                // Phone number verification demo
                credentialRepo.registerPhoneNumberVerification(registryManager, loadPhoneNumberMatcher())
            }
        }

        identityCredentialClient.registerCreationOptions(
            RegisterCreationOptionsRequest(
                createOptions = buildIssuanceData(),
                matcher = loadIssuanceMatcher(),
                type = DigitalCredential.TYPE_DIGITAL_CREDENTIAL,
                id = "openid4vci",
                fulfillmentActionName = "",
            )
        ).addOnSuccessListener {
            Log.i(TAG, "Issuance registration succeeded.")
        }.addOnFailureListener { e ->
            Log.e(TAG, "Issuance registration failed.", e)
        }

//        TODO: delete: this is only for testing.
//        CoroutineScope(Dispatchers.IO).launch {
//            delay(5000)
//            val json = readAsset("test.json").toString(Charsets.UTF_8)
//            database.credentialDao().insertAll(Credential(2000L, json))
////            delay(5000)
////            database.credentialDao().delete(Credential(2000L, json))
//        }
    }

    private fun readAsset(fileName: String): ByteArray {
        val stream = assets.open(fileName)
        val data = ByteArray(stream.available())
        stream.read(data)
        stream.close()
        return data
    }

    private fun loadOpenId4VPDraft24Matcher(): ByteArray {
        return readAsset("openid4vp.wasm")
    }

    private fun loadOpenId4VP1_0Matcher(): ByteArray {
        return readAsset("openid4vp1_0.wasm")
    }

    private fun buildIssuanceData(): ByteArray {
        val walletIcon = resources.getDrawable(R.mipmap.ic_launcher, theme).toBitmap()
        val iconBuffer = ByteArrayOutputStream()
        walletIcon.compress(Bitmap.CompressFormat.PNG, 100, iconBuffer)

        val data = CredentialRepository.IssuanceRegistryData(
            icon = iconBuffer.toByteArray(),
            title = resources.getString(R.string.app_name),
            subtitle = "Save your document to CMWallet",
            issuerAllowlist = null
        )

        return data.toRegistryDatabase()
    }

    private fun loadIssuanceMatcher(): ByteArray {
        return readAsset("provision_hardcoded.wasm")
    }

    private fun loadPhoneNumberMatcher(): ByteArray {
        return readAsset("pnv.wasm")
    }

    private fun loadTestCredentialsNew(): ByteArray {
        return readAsset("databasenew.json")
    }

    private fun loadAppsJson(): ByteArray {
        return readAsset("apps.json")
    }

    private fun loadOpenId4VCIRequestJson(): ByteArray {
        return readAsset("openid4vci_request.json")
    }
}