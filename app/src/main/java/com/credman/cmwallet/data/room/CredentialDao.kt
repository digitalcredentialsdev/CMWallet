package com.credman.cmwallet.data.room

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import kotlinx.coroutines.flow.Flow

@Dao
interface CredentialDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAll(vararg creds: CredentialDatabaseItem)

    @Update
    suspend fun updateUsers(vararg creds: CredentialDatabaseItem)

    @Delete
    suspend fun delete(cred: CredentialDatabaseItem)

    @Query("SELECT * FROM credentials")
    fun getAll(): Flow<List<CredentialDatabaseItem>>

    @Query("SELECT * FROM credentials WHERE id = :id")
    fun loadCredById(id: String): CredentialDatabaseItem?
}