package com.credman.cmwallet

import android.app.Application
import android.util.Log
import androidx.credentials.registry.provider.RegisterCredentialsRequest
import androidx.credentials.registry.provider.RegistryManager
import androidx.room.Room
import com.credman.cmwallet.data.model.CredentialItem
import com.credman.cmwallet.data.repository.CredentialRepository
import com.credman.cmwallet.data.room.Credential
import com.credman.cmwallet.data.room.CredentialDatabase
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.json.JSONObject

class CmWalletApplication : Application() {
    companion object {
        lateinit var database: CredentialDatabase
        lateinit var credentialRepo: CredentialRepository

        const val TAG = "CmWalletApplication"
    }

    private val registryManager = RegistryManager.create(this)
    private val applicationScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    override fun onCreate() {
        super.onCreate()
        database = Room.databaseBuilder(
            applicationContext,
            CredentialDatabase::class.java, "credential-database"
        ).allowMainThreadQueries().fallbackToDestructiveMigration().build()
        credentialRepo = CredentialRepository()

        val openId4VPMatcher = loadOpenId4VPMatcher()
        val testCredentialsJson = loadTestCredentials().toString(Charsets.UTF_8)

        // Add the test credentials from the included json
        credentialRepo.addCredentialsFromJson(testCredentialsJson)
        credentialRepo.setPrivAppsJson(loadAppsJson().toString(Charsets.UTF_8))

        // Listen for new credentials and update the registry.
        applicationScope.launch {
            credentialRepo.credentialRegistryDatabase.collect { credentialDatabase ->
                Log.i("CmWalletApplication", "Credentials changed $credentialDatabase")
                registryManager.registerCredentials(
                    request = object : RegisterCredentialsRequest(
                        "com.credman.IdentityCredential",
                        "openid4vp",
                        credentialDatabase,
                        openId4VPMatcher
                    ) {}
                )
            }
        }

//        TODO: delete: this is only for testing.
        CoroutineScope(Dispatchers.IO).launch {
            delay(5000)
            val json = readAsset("test.json").toString(Charsets.UTF_8)
            val cred = Credential(2000L, json)
            database.credentialDao().insertAll(Credential(2000L, json))
//            delay(5000)
//            database.credentialDao().delete(Credential(2000L, json))
        }
    }

    private fun readAsset(fileName: String): ByteArray {
        val stream = assets.open(fileName);
        val data = ByteArray(stream.available())
        stream.read(data)
        stream.close()
        return data
    }

    private fun loadOpenId4VPMatcher(): ByteArray {
        return readAsset("openid4vp.wasm");
    }

    private fun loadTestCredentials(): ByteArray {
        return readAsset("database.json");
    }

    private fun loadAppsJson(): ByteArray {
        return readAsset("apps.json");
    }
}