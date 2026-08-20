package com.credman.cmwallet.pnv

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.telephony.SubscriptionManager
import android.telephony.TelephonyManager
import androidx.core.content.ContextCompat

object PnvTelephonyProbe {
    data class ProbeResult(
        val profile: PnvTokenRegistry.Companion.EditablePnvProfile,
        val message: String,
    )

    fun deriveProfile(
        context: Context,
        current: PnvTokenRegistry.Companion.EditablePnvProfile,
    ): ProbeResult {
        val tm = context.getSystemService(TelephonyManager::class.java)
        val hasPhoneState = ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.READ_PHONE_STATE,
        ) == PackageManager.PERMISSION_GRANTED

        val hasPhoneNumbers = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.READ_PHONE_NUMBERS,
            ) == PackageManager.PERMISSION_GRANTED
        } else {
            true
        }

        val simOperator = tm?.simOperator?.takeIf { it.isNotBlank() }
        val carrierHint = simOperator ?: current.carrierHint

        val subManager = context.getSystemService(SubscriptionManager::class.java)
        val activeSubs = try {
            if (hasPhoneState) subManager?.activeSubscriptionInfoList.orEmpty() else emptyList()
        } catch (_: SecurityException) {
            emptyList()
        }

        val subscriptionHint1 = activeSubs.getOrNull(0)?.subscriptionId ?: current.subscriptionHint1
        val subscriptionHint2 = activeSubs.getOrNull(1)?.subscriptionId ?: current.subscriptionHint2

        val numberFromSub = activeSubs.firstOrNull()?.number?.trim()?.takeIf { it.isNotBlank() }
        val numberFromLine1 = try {
            if (hasPhoneNumbers) tm?.line1Number?.trim()?.takeIf { it.isNotBlank() } else null
        } catch (_: SecurityException) {
            null
        }
        val phoneNumber = numberFromSub ?: numberFromLine1 ?: current.phoneNumberHint

        val message = if (simOperator == null && numberFromSub == null && numberFromLine1 == null) {
            "Could not fully read telephony details (permissions/carrier restrictions). Kept previous values where needed."
        } else {
            "Imported telephony details from device SIM/subscriptions."
        }

        return ProbeResult(
            profile = current.copy(
                phoneNumberHint = phoneNumber,
                carrierHint = carrierHint,
                subscriptionHint1 = subscriptionHint1,
                subscriptionHint2 = subscriptionHint2,
            ),
            message = message,
        )
    }
}
