package com.credman.cmwallet.ui

import android.graphics.BitmapFactory
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.paint
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.activity.compose.LocalActivity
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.credman.cmwallet.MainActivity
import com.credman.cmwallet.R
import com.credman.cmwallet.data.model.CredentialItem
import com.credman.cmwallet.data.model.CredentialKeySoftware
import com.credman.cmwallet.data.model.toPrivateKey
import com.credman.cmwallet.decodeBase64
import com.credman.cmwallet.openid4vci.data.CredentialConfigurationMDoc
import com.credman.cmwallet.openid4vci.data.CredentialConfigurationSdJwtVc
import com.credman.cmwallet.pnv.PnvTokenRegistry
import com.credman.cmwallet.sdjwt.SdJwt
import kotlin.io.encoding.ExperimentalEncodingApi

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(
    viewModel: HomeViewModel = viewModel()
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val openCredentialDialog = remember { mutableStateOf<CredentialItem?>(null) }
    Scaffold(
        modifier = Modifier.fillMaxSize(),
        topBar = {
            CenterAlignedTopAppBar(
                title = {
                    Text(text = "CMWallet")
                }
            )
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier.padding(innerPadding),
        ) {
            HorizontalDivider(thickness = 2.dp)
            CredentialList(
                viewModel = viewModel,
                uiState.credentials,
                onCredentialClick = { cred ->
                    openCredentialDialog.value = cred
                }
            )
        }
    }
    if (openCredentialDialog.value != null) {
        CredentialDialog(
            onDismissRequest = {
                openCredentialDialog.value = null
            },
            onDeleteCredential = {id ->
                openCredentialDialog.value = null
                viewModel.deleteCredential(id)
            },
            credentialItem = openCredentialDialog.value!!
        )
    }
}

@Composable
fun PnvIdentityEditor(viewModel: HomeViewModel) {
    val initialProfile = remember { viewModel.getPnvProfile() }
    var phoneNumber by remember { mutableStateOf(initialProfile.phoneNumberHint) }
    var carrierHint by remember { mutableStateOf(initialProfile.carrierHint) }
    var androidCarrierHint by remember { mutableStateOf(initialProfile.androidCarrierHint) }
    var subscriptionHint1 by remember { mutableStateOf(initialProfile.subscriptionHint1.toString()) }
    var subscriptionHint2 by remember { mutableStateOf(initialProfile.subscriptionHint2.toString()) }
    var saveMessage by remember { mutableStateOf<String?>(null) }
    var detailsVisible by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier.fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Card(
            modifier = Modifier.size(350.dp, 210.dp),
            shape = CardDefaults.shape,
            onClick = { detailsVisible = !detailsVisible }
        ) {
            Box(
                Modifier
                    .fillMaxSize()
                    .paint(
                        painterResource(id = R.drawable.card_art_dark),
                        contentScale = ContentScale.Crop,
                    )
            ) {
                Row(Modifier.fillMaxSize(), verticalAlignment = Alignment.CenterVertically) {
                    Column(
                        modifier = Modifier.padding(20.dp, 20.dp),
                        horizontalAlignment = Alignment.Start,
                        verticalArrangement = Arrangement.Center,
                    ) {
                        Text(
                            text = "PNV Identity",
                            fontSize = 20.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color.White,
                        )
                        Text(
                            text = "Tap to view and edit",
                            fontSize = 16.sp,
                            color = Color.White,
                        )
                    }
                }
            }
        }
        Text(
            text = if (detailsVisible) "PNV Identity selected. Edit details below." else "Tap the PNV card to view/edit details",
            color = Color.Gray
        )
        if (!detailsVisible) {
            return@Column
        }
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = Color(0xFFF6F6F6))
        ) {
            Column(
                modifier = Modifier.padding(12.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Text(
                    text = "PNV Details",
                    fontWeight = FontWeight.Bold,
                    fontSize = 18.sp,
                )
                HorizontalDivider()
                OutlinedTextField(
                    value = phoneNumber,
                    onValueChange = { phoneNumber = it.trim() },
                    label = { Text("Phone Number (E.164)") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true
                )
                OutlinedTextField(
                    value = carrierHint,
                    onValueChange = { carrierHint = it.trim() },
                    label = { Text("Carrier Hint (MCCMNC)") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true
                )
                OutlinedTextField(
                    value = androidCarrierHint,
                    onValueChange = { androidCarrierHint = it.trim() },
                    label = { Text("Android Carrier Hint") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true
                )
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.fillMaxWidth()) {
                    OutlinedTextField(
                        value = subscriptionHint1,
                        onValueChange = { subscriptionHint1 = it.trim() },
                        label = { Text("SIM1 Subscription") },
                        modifier = Modifier.weight(1f),
                        singleLine = true
                    )
                    OutlinedTextField(
                        value = subscriptionHint2,
                        onValueChange = { subscriptionHint2 = it.trim() },
                        label = { Text("SIM2 Subscription") },
                        modifier = Modifier.weight(1f),
                        singleLine = true
                    )
                }
                Button(
                    onClick = {
                        val current = PnvTokenRegistry.Companion.EditablePnvProfile(
                            phoneNumberHint = phoneNumber,
                            carrierHint = carrierHint,
                            androidCarrierHint = androidCarrierHint,
                            subscriptionHint1 = subscriptionHint1.toIntOrNull() ?: 1,
                            subscriptionHint2 = subscriptionHint2.toIntOrNull() ?: 2,
                        )
                        val (imported, message) = viewModel.importPnvProfileFromDevice(current)
                        phoneNumber = imported.phoneNumberHint
                        carrierHint = imported.carrierHint
                        androidCarrierHint = imported.androidCarrierHint
                        subscriptionHint1 = imported.subscriptionHint1.toString()
                        subscriptionHint2 = imported.subscriptionHint2.toString()
                        saveMessage = message
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Import Device Telephony")
                }
                Button(
                    onClick = {
                        val s1 = subscriptionHint1.toIntOrNull()
                        val s2 = subscriptionHint2.toIntOrNull()
                        if (phoneNumber.isBlank() || carrierHint.isBlank() || androidCarrierHint.isBlank() || s1 == null || s2 == null) {
                            saveMessage = "Enter valid values for all fields"
                            return@Button
                        }
                        viewModel.savePnvProfile(
                            PnvTokenRegistry.Companion.EditablePnvProfile(
                                phoneNumberHint = phoneNumber,
                                carrierHint = carrierHint,
                                androidCarrierHint = androidCarrierHint,
                                subscriptionHint1 = s1,
                                subscriptionHint2 = s2,
                            )
                        )
                        saveMessage = "Saved. Restart CMWallet to re-register PNV tokens."
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Save PNV Identity")
                }
                if (saveMessage != null) {
                    Text(text = saveMessage!!, color = Color.DarkGray)
                }
            }
        }
    }
}

@Composable
fun CredentialList(
    viewModel: HomeViewModel,
    credentials: List<CredentialItem>,
    onCredentialClick: (CredentialItem) -> Unit
) {
    Column(
        Modifier.fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        LazyColumn(
            modifier = Modifier.padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(15.dp)
        ) {
            item {
                PnvIdentityEditor(viewModel)
            }
            credentials.forEach {
                item {
                    CredentialCard(credential = it, onCredentialClick = onCredentialClick)
                }
            }
        }
    }
}

@Composable
fun CredentialDialog(
    onDismissRequest: () -> Unit,
    onDeleteCredential: (String) -> Unit,
    credentialItem: CredentialItem
) {
    Dialog(onDismissRequest = { onDismissRequest() }) {
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            shape = RoundedCornerShape(16.dp),
        ) {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                Text(
                    text = credentialItem.displayData.title,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(10.dp),
                    textAlign = TextAlign.Center,
                )
                if (credentialItem.config is CredentialConfigurationMDoc) {
                    credentialItem.credentials.first().mdoc.issuerSignedNamespaces.forEach { (namespace, elements) ->
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(10.dp)
                        ) {
                            Row(Modifier.background(Color.LightGray)) {
                                Text(
                                    text = namespace,
                                    modifier = Modifier
                                        .border(1.dp, Color.Black)
                                        .weight(1.0f)
                                        .padding(5.dp)
                                )
                            }
                            elements.forEach { (element, value) ->
                                Row() {
                                    Text(
                                        text = element,
                                        modifier = Modifier
                                            .border(1.dp, Color.Black)
                                            .weight(0.5f)
                                            .padding(5.dp)
                                    )
                                    Text(
                                        text = value.toString(),
                                        modifier = Modifier
                                            .border(1.dp, Color.Black)
                                            .weight(0.5f)
                                            .padding(5.dp),
                                        softWrap = false
                                    )
                                }
                            }
                        }
                    }
                } else if (credentialItem.config is CredentialConfigurationSdJwtVc) {
                    val sdJwtVc = SdJwt(
                        credentialItem.credentials.first().credential,
                        credentialItem.credentials.first().key.toPrivateKey()
                    )
                    val rawJwt = sdJwtVc.verifiedResult.processedJwt

                    // Show the vct values
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(10.dp)
                    ) {
                        Row(Modifier.background(Color.LightGray)) {
                            Text(
                                text = "vct",
                                modifier = Modifier
                                    .border(1.dp, Color.Black)
                                    .weight(1.0f)
                                    .padding(5.dp)
                            )
                        }
                        Row() {
                            Text(
                                text = rawJwt["vct"] as String,
                                modifier = Modifier
                                    .border(1.dp, Color.Black)
                                    .weight(0.5f)
                                    .padding(5.dp)
                            )
                        }
                    }

                    // Show the whole jwt
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(10.dp)
                    ) {
                        Row(Modifier.background(Color.LightGray)) {
                            Text(
                                text = "Full jwt details",
                                modifier = Modifier
                                    .border(1.dp, Color.Black)
                                    .weight(1.0f)
                                    .padding(5.dp)
                            )
                        }
                        Row() {
                            Text(
                                text = rawJwt.toString(2),
                                modifier = Modifier
                                    .border(1.dp, Color.Black)
                                    .weight(0.5f)
                                    .padding(5.dp)
                            )
                        }
                    }

                }
                Button(
                    modifier = Modifier.padding(10.dp),
                    onClick = {
                        onDeleteCredential(credentialItem.id)
                    }
                ) {
                    Text("Delete")
                }
            }
        }
    }
}

@OptIn(ExperimentalEncodingApi::class)
@Composable
fun CredentialCard(
    credential: CredentialItem,
    onCredentialClick: (CredentialItem) -> Unit
) {

    val cardArt = credential.displayData.icon?.decodeBase64() ?: ByteArray(0)
    Card(
        modifier = Modifier.size(350.dp, 210.dp),
        shape = CardDefaults.shape,
        onClick = {
            onCredentialClick(credential)
        }
    ) {
        if (cardArt.size > 0) {
            Image(
                contentScale = ContentScale.Crop,
                modifier = Modifier.fillMaxSize(),
                bitmap = BitmapFactory.decodeByteArray(cardArt, /*offset=*/0, cardArt.size)!!
                    .asImageBitmap(),
                contentDescription = null
            )
        } else {
            Box(
                Modifier
                    .fillMaxSize()
                    .paint(
                        painterResource(id = R.drawable.card_art_dark),
                        contentScale = ContentScale.Crop,
                    )
            ) {
                Row(Modifier.fillMaxSize(), verticalAlignment = Alignment.CenterVertically) {
                    Column(
                        modifier = Modifier.padding(20.dp, 20.dp),
                        horizontalAlignment = Alignment.Start,
                        verticalArrangement = Arrangement.Center,
                    ) {
                        Text(
                            text = credential.displayData.title,
                            fontSize = 20.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color.White,
                        )
                        Text(
                            text = credential.displayData.subtitle ?: "",
                            fontSize = 16.sp,
                            color = Color.White,
                        )
                    }
                }
            }
        }

    }

}