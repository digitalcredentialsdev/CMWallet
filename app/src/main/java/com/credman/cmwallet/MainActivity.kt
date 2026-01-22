package com.credman.cmwallet

import android.app.PendingIntent
import android.os.Bundle
import android.util.Log
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.IntentSenderRequest
import androidx.activity.result.contract.ActivityResultContracts
import com.credman.cmwallet.CmWalletApplication.Companion.TAG
import com.credman.cmwallet.ui.HomeScreen
import com.credman.cmwallet.ui.theme.CMWalletTheme


class MainActivity : ComponentActivity() {
    val launcher = registerForActivityResult(ActivityResultContracts.StartIntentSenderForResult()) { result ->
        Log.d(TAG, "Received result ${result.data}")
        // Check for whether the issuance operation has finished or not. At this point, the new card
        // should already have been added to the database (notice the card issuance happen through
        // backend calls so the actual credential will not be propagated back here), or the issuance
        // has failed.
        // For demo purpose you can simply proceed your UI.
        Toast.makeText(this, "Issuance flow finished", Toast.LENGTH_SHORT).show()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            CMWalletTheme {
                HomeScreen()
            }
        }
    }

    fun launchIssuanceIntent(pendingIntent: PendingIntent) {
        launcher.launch(IntentSenderRequest.Builder(pendingIntent.intentSender).build())
    }
}
