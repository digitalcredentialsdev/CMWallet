package com.credman.cmwallet.data.repository

import android.graphics.BitmapFactory
import android.util.Log
import androidx.credentials.DigitalCredential
import androidx.credentials.ExperimentalDigitalCredentialApi
import androidx.credentials.registry.digitalcredentials.mdoc.MdocEntry
import androidx.credentials.registry.digitalcredentials.mdoc.MdocField
import androidx.credentials.registry.digitalcredentials.mdoc.MdocInlineIssuanceEntry
import androidx.credentials.registry.digitalcredentials.openid4vp.OpenId4VpRegistry
import androidx.credentials.registry.digitalcredentials.sdjwt.SdJwtClaim
import androidx.credentials.registry.digitalcredentials.sdjwt.SdJwtEntry
import androidx.credentials.registry.digitalcredentials.sdjwt.SdJwtInlineIssuanceEntry
import androidx.credentials.registry.provider.RegisterCredentialsRequest
import androidx.credentials.registry.provider.RegistryManager
import androidx.credentials.registry.provider.digitalcredentials.DigitalCredentialEntry
import androidx.credentials.registry.provider.digitalcredentials.InlineIssuanceEntry
import androidx.credentials.registry.provider.digitalcredentials.VerificationEntryDisplayProperties
import androidx.credentials.registry.provider.digitalcredentials.VerificationFieldDisplayProperties
import com.credman.cmwallet.CmWalletApplication
import com.credman.cmwallet.data.model.CredentialDisplayData
import com.credman.cmwallet.data.model.CredentialItem
import com.credman.cmwallet.data.model.CredentialKeySoftware
import com.credman.cmwallet.data.source.CredentialDatabaseDataSource
import com.credman.cmwallet.data.source.TestCredentialsDataSource
import com.credman.cmwallet.decodeBase64
import com.credman.cmwallet.decodeBase64UrlNoPadding
import com.credman.cmwallet.mdoc.MDoc
import com.credman.cmwallet.openid4vci.OpenId4VCI
import com.credman.cmwallet.openid4vci.data.CredentialConfigurationMDoc
import com.credman.cmwallet.openid4vci.data.CredentialConfigurationSdJwtVc
import com.credman.cmwallet.openid4vci.data.CredentialConfigurationUnknownFormat
import com.credman.cmwallet.pnv.PnvTokenRegistry
import com.credman.cmwallet.sdjwt.SdJwt
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.emitAll
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.map
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.io.encoding.ExperimentalEncodingApi

class CredentialRepository {
    //val json = Json { classDiscriminatorMode = ClassDiscriminatorMode.NONE }

    var privAppsJson = "{}"
        private set

    var openId4VCITestRequestJson = "{}"

    private val testCredentialsDataSource = TestCredentialsDataSource()
    private val credentialDatabaseDataSource = CredentialDatabaseDataSource()

    private fun combinedCredentials(): Flow<List<CredentialItem>> = flow {
        emitAll(
            combine(
                testCredentialsDataSource.credentials,
                credentialDatabaseDataSource.credentials
            ) { list1, list2 ->
                list1 + list2
            })
    }

    val credentials: Flow<List<CredentialItem>> = combinedCredentials()

    val credentialRegistryDatabase: Flow<OpenId4VpRegistry> = flow {
        emitAll(combinedCredentials().map { credentials ->
            Log.i("CredentialRepository", "Updating flow with ${credentials.size}")
            createRegistry(credentials)
        })
    }

    fun addCredentialsFromJson(credentialJson: String) {
        testCredentialsDataSource.initWithJson(credentialJson)
    }

    fun getCredential(id: String): CredentialItem? {
        return testCredentialsDataSource.getCredential(id)
            ?: credentialDatabaseDataSource.getCredential(id)
    }

    fun deleteCredential(id: String) {
        credentialDatabaseDataSource.deleteCredential(id)
    }

    fun setPrivAppsJson(appsJson: String) {
        privAppsJson = appsJson
    }

    @OptIn(ExperimentalDigitalCredentialApi::class)
    suspend fun registerPhoneNumberVerification(registryManager: RegistryManager, pnvMatcher: ByteArray) {
        val testPhoneNumberTokens = listOf(
            PnvTokenRegistry.TEST_PNV_1_GET_PHONE_NUMBER,
            PnvTokenRegistry.TEST_PNV_1_VERIFY_PHONE_NUMBER,
            PnvTokenRegistry.TEST_PNV_2_VERIFY_PHONE_NUMBER
        )

        registryManager.registerCredentials(
            request = object : RegisterCredentialsRequest(
                DigitalCredential.TYPE_DIGITAL_CREDENTIAL,
                "openid4vp1.0-pnv",
                PnvTokenRegistry.buildRegistryDatabase(testPhoneNumberTokens),
                pnvMatcher
            ) {}
        )
    }

    suspend fun issueCredential(requestJson: String) {
        val openId4VCI = OpenId4VCI(requestJson)

    }

    class IssuanceRegistryData(
        val icon: ByteArray, // Entry icon for display
        val title: String, // Entry subtitle for display
        val subtitle: String?, // Entry subtitle for display
        val issuerAllowlist: List<String>?,
    ) {
        fun toRegistryDatabase(): ByteArray {
            val out = ByteArrayOutputStream()

            // Write the offset to the json
            val jsonOffset = 4 + icon.size
            val buffer = ByteBuffer.allocate(4)
            buffer.order(ByteOrder.LITTLE_ENDIAN)
            buffer.putInt(jsonOffset)
            out.write(buffer.array())

            // Write the icons, currently write just one, being the wallet logo
            out.write(icon)

            val json = JSONObject().apply {
                put("display", JSONObject().apply {
                    put(TITLE, title)
                    putOpt(SUBTITLE, subtitle)
                    val iconJson = JSONObject().apply {
                        put(START, 4)
                        put(LENGTH, icon.size)
                    } // Hardcoded for now
                    put(ICON, iconJson)
                })
                if (issuerAllowlist != null) {
                    val capabilities = JSONObject()
                    for (iss in issuerAllowlist) {
                        capabilities.put(iss, JSONObject())
                    }
                    put("capabilities", capabilities)
                }
            }
            out.write(json.toString().toByteArray())
            return out.toByteArray()
        }
    }

    class RegistryIcon(
        val iconValue: ByteArray,
        var iconOffset: Int = 0
    )

    private fun JSONObject.putCommon(itemId: String, itemDisplayData: CredentialDisplayData, iconMap: Map<String, RegistryIcon>) {
        put(ID, itemId)
        put(TITLE, itemDisplayData.title)
        putOpt(SUBTITLE, itemDisplayData.subtitle)
        val iconJson = JSONObject().apply {
            put(START, iconMap[itemId]!!.iconOffset)
            put(LENGTH, iconMap[itemId]!!.iconValue.size)
        }
        put(ICON, iconJson)
    }

    private fun constructJwtClaims(
        rawJwt: JSONObject,
        displayConfig: CredentialConfigurationSdJwtVc?,
        claims: MutableList<SdJwtClaim>,
        path: List<String>
    ) {
        for (key in rawJwt.keys()) {
            val v = rawJwt[key]
            val currPath = path.toMutableList() // Make a copy
            currPath.add(key)
            if (v is JSONObject) {
                val displayName = displayConfig?.claims?.firstOrNull{
                    JSONArray(it.path) == currPath
                }?.display?.first()?.name ?: currPath.joinToString(separator = ".")
                claims.add(
                    SdJwtClaim(
                        path = currPath,
                        value = null,
                        fieldDisplayPropertySet = setOf(VerificationFieldDisplayProperties(
                            displayName = displayName,
                        )),
//                        isSelectivelyDisclosable = TODO()
                    )
                )
                constructJwtClaims(
                    v,
                    displayConfig,
                    claims,
                    currPath
                )
            } else {
                val displayName = displayConfig?.claims?.firstOrNull{
                    JSONArray(it.path) == currPath
                }?.display?.first()?.name ?: currPath.joinToString(separator = ".")
                claims.add(
                    SdJwtClaim(
                        path = currPath,
                        value = v,
                        fieldDisplayPropertySet = setOf(VerificationFieldDisplayProperties(
                            displayName = displayName,
                        )),
//                        isSelectivelyDisclosable = TODO()
                    )
                )
            }
        }
    }

    @OptIn(ExperimentalEncodingApi::class)
    private fun createRegistry(items: List<CredentialItem>): OpenId4VpRegistry {
        val credentialEntries: MutableList<DigitalCredentialEntry> = mutableListOf()

        items.forEach { item ->
            when (item.config) {
                is CredentialConfigurationSdJwtVc -> {
                    val sdJwtVc = SdJwt(item.credentials.first().credential, (item.credentials.first().key as CredentialKeySoftware).privateKey)
                    val rawJwt = sdJwtVc.verifiedResult.processedJwt
                    val claims = mutableListOf<SdJwtClaim>()
                    constructJwtClaims(rawJwt, item.config, claims, emptyList())
                    credentialEntries.add(SdJwtEntry(
                        verifiableCredentialType = rawJwt["vct"] as String,
                        claims = claims,
                        entryDisplayPropertySet = setOf(VerificationEntryDisplayProperties(
                            title = item.displayData.title,
                            subtitle = item.displayData.subtitle,
                            icon = item.displayData.icon?.decodeBase64()?.let {
                                BitmapFactory.decodeByteArray(it, 0, it.size)
                            } ?: CmWalletApplication.walletIcon
                        )),
                        id = item.id,
                    ))
                }
                is CredentialConfigurationMDoc -> {
                    val mdoc = MDoc(item.credentials.first().credential.decodeBase64UrlNoPadding())
                    val mdocFields = mutableListOf<MdocField>()
                    if (mdoc.issuerSignedNamespaces.isNotEmpty()) {
                        mdoc.issuerSignedNamespaces.forEach { (namespace, elements) ->
                            elements.forEach { (element, value) ->
                                val displayName = item.config.claims?.firstOrNull{
                                    it.path[0] == namespace && it.path[1] == element
                                }?.display?.first()?.name!!
                                val namespaceData = mdoc.issuerSignedNamespaces[namespace]?.get(element)
                                mdocFields.add(
                                    MdocField(
                                        namespace = namespace,
                                        identifier = element,
                                        fieldValue = value,
                                        fieldDisplayPropertySet = setOf(
                                            VerificationFieldDisplayProperties(
                                                displayName = displayName,
                                                displayValue = namespaceData as? String
                                            )
                                        )
                                    )
                                )
                            }
                        }
                    }
                    credentialEntries.add(MdocEntry(
                        docType = item.config.doctype,
                        fields = mdocFields,
                        entryDisplayPropertySet = setOf(VerificationEntryDisplayProperties(
                            title = item.displayData.title,
                            subtitle = item.displayData.subtitle,
                            icon = item.displayData.icon?.decodeBase64()?.let {
                                BitmapFactory.decodeByteArray(it, 0, it.size)
                            } ?: CmWalletApplication.walletIcon,
                            explainer = item.displayData.explainer,
                            metadataDisplayText = item.displayData.metadataDisplayText
                        )),
                        id = item.id,
                    ))
                }

                is CredentialConfigurationUnknownFormat -> TODO()
            }
        }
        return OpenId4VpRegistry(
            credentialEntries = credentialEntries,
            inlineIssuanceEntries = emptyList(),
//                listOf(
//                MdocInlineIssuanceEntry(
//                    id = "Issuance",
//                    display = InlineIssuanceEntry.InlineIssuanceDisplayProperties(
//                        subtitle = "Mobile Drivers License, State Id, and Others",
//                    ),
//                    supportedMdocs = setOf(
//                        MdocInlineIssuanceEntry.SupportedMdoc(
//                        "eu.europa.ec.eudi.pid.1"
//                        ),
//                        MdocInlineIssuanceEntry.SupportedMdoc(
//                        "org.iso.18013.5.1.mDL1"
//                        ),
//                    )
//                ),
//                SdJwtInlineIssuanceEntry(
//                    id = "sd-jwt-issuance",
//                    display = InlineIssuanceEntry.InlineIssuanceDisplayProperties(
//                        subtitle = "Mobile Drivers License, State Id, and Others",
//                    ),
//                    supportedSdJwts = setOf(
//                        SdJwtInlineIssuanceEntry.SupportedSdJwt("urn:openid:interop:id:1")
//                    )
//                )
//            ),
            id = "openid4vp1.0",
        )
    }

    companion object {
        const val TAG = "CredentialRepository"

        // Wasm database json keys
        const val CREDENTIALS = "credentials"
        const val ID = "id"
        const val TITLE = "title"
        const val SUBTITLE = "subtitle"
        const val ICON = "icon"
        const val START = "start"
        const val LENGTH = "length"
        const val NAMESPACES = "namespaces"
        const val PATHS = "paths"
        const val VALUE = "value"
        const val DISPLAY = "display"
        const val DISPLAY_VALUE = "display_value"
    }
}