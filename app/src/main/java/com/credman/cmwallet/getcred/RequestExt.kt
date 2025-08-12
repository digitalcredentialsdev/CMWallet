package com.credman.cmwallet.getcred

import androidx.annotation.VisibleForTesting
import androidx.credentials.provider.ProviderGetCredentialRequest
import androidx.credentials.registry.provider.digitalcredentials.DigitalCredentialEntry
import com.credman.cmwallet.getcred.SelectionInfo.SelectedCredential
import org.json.JSONArray
import org.json.JSONObject

data class SelectedClaims(
    val paths: JSONArray
)

data class SelectedCred(
    val entryId: String,
    val dcqlId: String,
    val matchedClaimPaths: SelectedClaims?
)

data class InternalSelectionInfo(
    val requestIdx: Int,
    val creds: List<SelectedCred>
) {
    companion object {
        fun fromSelectionInfo(selectionInfo: SelectionInfo): InternalSelectionInfo {
            val requestId = selectionInfo.setId.substringBefore(";").substringAfter("req:").toInt()
            val credList = mutableListOf<SelectedCred>()
            for (credential in selectionInfo.credentials) {
                val entryId = credential.credId
                val metadata = JSONObject(credential.metadata!!)

                val claims = metadata.getJSONArray("claims")
                val dqclId = metadata.getString("dcql_cred_id")
                credList.add(SelectedCred(entryId, dqclId, SelectedClaims(claims)))
            }
            return InternalSelectionInfo(requestId, credList)
        }

        fun fromEntryIdJson(entryId: String): InternalSelectionInfo {
            val entryIdJson = JSONObject(entryId)
            val requestIdx =
                if (entryIdJson.has("req_idx")) entryIdJson.getInt("req_idx") else entryIdJson.getInt(
                    "provider_idx"
                )
            val selectedId =
                if (entryIdJson.has("entry_id")) entryIdJson.getString("entry_id") else entryIdJson.getString(
                    "id"
                )
            val dqclCredId = entryIdJson.getString("dcql_cred_id")
            return InternalSelectionInfo(
                requestIdx,
                listOf(SelectedCred(selectedId, dqclCredId, null))
            )
        }
    }
}

/** Classes below belong to Jetpack */
data class SelectionInfo(
    val setId: String,
    val credentials: List<SelectedCredential>,
) {
    data class SelectedCredential(
        val credId: String,
        val metadata: String?,
    )
}

public val ProviderGetCredentialRequest.selectionInfo: SelectionInfo?
    get() = this.sourceBundle?.let {
        val setId = it.getString(EXTRA_CREDENTIAL_SET_ID) ?: return null
        val credentials = mutableListOf<SelectedCredential>()
        val setLength = it.getInt(EXTRA_CREDENTIAL_SET_ELEMENT_LENGTH, 0)
        for (i in 0 until setLength) {
            val credId = it.getString("${EXTRA_CREDENTIAL_SET_ELEMENT_ID_PREFIX}$i") ?: return null
            val metadata = it.getString("${EXTRA_CREDENTIAL_SET_ELEMENT_METADATA_PREFIX}$i")
            credentials.add(SelectedCredential(credId, metadata))
        }
        SelectionInfo(setId, credentials)
    }


private const val EXTRA_CREDENTIAL_SET_ID =
    "androidx.credentials.registry.provider.extra.CREDENTIAL_SET_ID"
private const val EXTRA_CREDENTIAL_SET_ELEMENT_LENGTH =
    "androidx.credentials.registry.provider.extra.CREDENTIAL_SET_ELEMENT_LENGTH"
private const val EXTRA_CREDENTIAL_SET_ELEMENT_ID_PREFIX =
    "androidx.credentials.registry.provider.extra.CREDENTIAL_SET_ELEMENT_ID_"
private const val EXTRA_CREDENTIAL_SET_ELEMENT_METADATA_PREFIX =
    "androidx.credentials.registry.provider.extra.CREDENTIAL_SET_ELEMENT_METADATA_"