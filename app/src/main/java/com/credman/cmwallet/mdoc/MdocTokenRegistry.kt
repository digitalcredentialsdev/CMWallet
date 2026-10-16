package com.credman.cmwallet.mdoc

import android.graphics.Bitmap
import android.util.Log
import com.credman.cmwallet.CmWalletApplication
import com.credman.cmwallet.data.model.CredentialItem
import com.credman.cmwallet.data.repository.CredentialRepository.Companion.CREDENTIALS
import com.credman.cmwallet.data.repository.CredentialRepository.Companion.DISPLAY
import com.credman.cmwallet.data.repository.CredentialRepository.Companion.DISPLAY_VALUE
import com.credman.cmwallet.data.repository.CredentialRepository.Companion.ICON
import com.credman.cmwallet.data.repository.CredentialRepository.Companion.ID
import com.credman.cmwallet.data.repository.CredentialRepository.Companion.LENGTH
import com.credman.cmwallet.data.repository.CredentialRepository.Companion.PATHS
import com.credman.cmwallet.data.repository.CredentialRepository.Companion.START
import com.credman.cmwallet.data.repository.CredentialRepository.Companion.SUBTITLE
import com.credman.cmwallet.data.repository.CredentialRepository.Companion.TITLE
import com.credman.cmwallet.data.repository.CredentialRepository.Companion.VALUE
import com.credman.cmwallet.data.repository.CredentialRepository.RegistryIcon
import com.credman.cmwallet.decodeBase64
import com.credman.cmwallet.decodeBase64UrlNoPadding
import com.credman.cmwallet.openid4vci.data.CredentialConfigurationMDoc
import com.credman.cmwallet.pnv.PnvTokenRegistry.Companion.DEDUP_ID
import com.credman.cmwallet.pnv.PnvTokenRegistry.Companion.RANK
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Custom builder for mDoc / mDL (ISO/IEC 18013-5) registry binary database.
 *
 * This builder serializes mDoc credential entries directly to the binary registry byte array
 * (JSON offset + icon bytes + registry JSON) and injects [DEDUP_ID] and [RANK] fields.
 *
 * It is used for testing credential deduplication and ranking prioritization directly in the wallet
 * without having to modify the upstream AndroidX Jetpack library (`androidx.credentials.registry.*`).
 */
object MdocTokenRegistry {
    private const val TAG = "MdocTokenRegistry"

    private const val MSO_MDOC = "mso_mdoc"
    private const val VERIFICATION = "verification"
    private const val EXPLAINER = "explainer"
    private const val METADATA_DISPLAY_TEXT = "metadata_display_text"
    private const val SUPPORTED_PROTOCOLS = "supported_protocols"

    private val DEFAULT_SUPPORTED_PROTOCOLS = listOf(
        "openid4vp-v1-signed",
        "openid4vp-v1-unsigned",
        "openid4vp-v1-multisigned"
    )

    /**
     * Builds the binary registry payload for mDoc credentials from a list of [CredentialItem]s.
     * Injects dedupId and rank directly into the credential JSON.
     */
    fun buildRegistryDatabase(
        items: List<CredentialItem>,
        supportedProtocols: List<String> = DEFAULT_SUPPORTED_PROTOCOLS
    ): ByteArray {
        val out = ByteArrayOutputStream()

        val iconMap: Map<String, RegistryIcon> = items.associate { item ->
            val iconBytes = item.displayData.icon?.decodeBase64() ?: getWalletIconBytes()
            Pair(item.id, RegistryIcon(iconBytes))
        }

        // Calculate JSON offset (4 bytes header + icons size)
        val jsonOffset = 4 + iconMap.values.sumOf { it.iconValue.size }
        val buffer = ByteBuffer.allocate(4).apply {
            order(ByteOrder.LITTLE_ENDIAN)
            putInt(jsonOffset)
        }
        out.write(buffer.array())

        // Write icons
        var currIconOffset = 4
        iconMap.values.forEach { registryIcon ->
            registryIcon.iconOffset = currIconOffset
            out.write(registryIcon.iconValue)
            currIconOffset += registryIcon.iconValue.size
        }

        val mdocCredentials = JSONObject()

        items.forEach { item ->
            val config = item.config
            if (config is CredentialConfigurationMDoc) {
                val mdoc = MDoc(item.credentials.first().credential.decodeBase64UrlNoPadding())
                val credJson = JSONObject().apply {
                    put(ID, item.id)
                    putOpt(DEDUP_ID, item.displayData.dedupId)
                    putOpt(RANK, item.displayData.rank)

                    val verificationDisplay = JSONObject().apply {
                        put(TITLE, item.displayData.title)
                        putOpt(SUBTITLE, item.displayData.subtitle)
                        putOpt(EXPLAINER, item.displayData.explainer)
                        putOpt(METADATA_DISPLAY_TEXT, item.displayData.metadataDisplayText)
                        val icon = iconMap[item.id]
                        if (icon != null) {
                            val iconJson = JSONObject().apply {
                                put(START, icon.iconOffset)
                                put(LENGTH, icon.iconValue.size)
                            }
                            put(ICON, iconJson)
                        }
                    }
                    put(DISPLAY, JSONObject().apply {
                        put(VERIFICATION, verificationDisplay)
                    })

                    val pathJson = JSONObject()
                    if (mdoc.issuerSignedNamespaces.isNotEmpty()) {
                        mdoc.issuerSignedNamespaces.forEach { (namespace, elements) ->
                            val namespaceJson = pathJson.optJSONObject(namespace) ?: JSONObject()
                            elements.forEach { (element, value) ->
                                val displayName = config.credentialMetadata?.claims?.firstOrNull {
                                    it.path.size >= 2 && it.path[0] == namespace && it.path[1] == element
                                }?.display?.firstOrNull()?.name ?: element

                                val fieldJson = JSONObject().apply {
                                    val fieldDisplay = JSONObject().apply {
                                        put(DISPLAY, displayName)
                                        putOpt(DISPLAY_VALUE, value as? String)
                                    }
                                    put(DISPLAY, JSONObject().apply {
                                        put(VERIFICATION, fieldDisplay)
                                    })
                                    putOpt(VALUE, value)
                                }
                                namespaceJson.put(element, fieldJson)
                            }
                            pathJson.put(namespace, namespaceJson)
                        }
                    }
                    put(PATHS, pathJson)
                }

                addCredentialJson(mdocCredentials, credJson, config.doctype)
            }
        }

        val registryCredentials = JSONObject().apply {
            put(MSO_MDOC, mdocCredentials)
        }
        val registryJson = JSONObject().apply {
            put(CREDENTIALS, registryCredentials)
            put(SUPPORTED_PROTOCOLS, JSONArray(supportedProtocols))
        }

        Log.d(TAG, "mDoc Registry to be registered:\n$registryJson")
        out.write(registryJson.toString().toByteArray())
        return out.toByteArray()
    }

    private fun addCredentialJson(
        collection: JSONObject,
        newCredJson: JSONObject,
        key: String
    ) {
        val current = collection.optJSONArray(key) ?: JSONArray().also { collection.put(key, it) }
        current.put(newCredJson)
    }

    private fun getWalletIconBytes(): ByteArray {
        val stream = ByteArrayOutputStream()
        CmWalletApplication.walletIcon.compress(Bitmap.CompressFormat.PNG, 100, stream)
        return stream.toByteArray()
    }
}
