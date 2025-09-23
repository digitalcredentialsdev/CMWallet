package com.credman.cmwallet.getcred

import androidx.credentials.registry.provider.SelectedCredentialSet
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
        fun fromSelectedSet(selectionInfo: SelectedCredentialSet): InternalSelectionInfo {
            val requestId = selectionInfo.credentialSetId.substringBefore(";").substringAfter("req:").toInt()
            val credList = mutableListOf<SelectedCred>()
            for (credential in selectionInfo.credentials) {
                val entryId = credential.credentialId
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