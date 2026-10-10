package com.credman.cmwallet.ui

import android.util.Log
import androidx.credentials.CreateDigitalCredentialRequest
import androidx.credentials.CreateDigitalCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.ExperimentalDigitalCredentialApi
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.credman.cmwallet.CmWalletApplication
import com.credman.cmwallet.CmWalletApplication.Companion.TAG
import com.credman.cmwallet.MainActivity
import com.credman.cmwallet.data.model.CredentialItem
import com.credman.cmwallet.pnv.PnvTokenRegistry
import com.credman.cmwallet.pnv.PnvTelephonyProbe
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import org.json.JSONObject

data class HomeScreenUiState(
    val credentials: List<CredentialItem>
)

class HomeViewModel : ViewModel() {
    private val _uiState = MutableStateFlow(HomeScreenUiState(emptyList()))
    val uiState: StateFlow<HomeScreenUiState> = _uiState.asStateFlow()

    init {
        viewModelScope.launch {
            CmWalletApplication.credentialRepo.credentials.collect { credentials ->
                _uiState.update { currentState ->
                    currentState.copy(
                        credentials = credentials
                    )
                }
            }
        }
    }

    fun deleteCredential(id: String) {
        CmWalletApplication.credentialRepo.deleteCredential(id)
    }

    fun getPnvProfile(): PnvTokenRegistry.Companion.EditablePnvProfile {
        return PnvTokenRegistry.loadEditableProfile(CmWalletApplication.appContext)
    }

    fun savePnvProfile(profile: PnvTokenRegistry.Companion.EditablePnvProfile) {
        PnvTokenRegistry.saveEditableProfile(CmWalletApplication.appContext, profile)
    }

    fun importPnvProfileFromDevice(current: PnvTokenRegistry.Companion.EditablePnvProfile): Pair<PnvTokenRegistry.Companion.EditablePnvProfile, String> {
        val result = PnvTelephonyProbe.deriveProfile(CmWalletApplication.appContext, current)
        return Pair(result.profile, result.message)
    }
}