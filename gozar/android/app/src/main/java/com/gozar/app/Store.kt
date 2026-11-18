package com.gozar.app

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.runBlocking

private val Context.dataStore by preferencesDataStore(name = "gozar")

/** Persists profiles and settings as JSON in a Preferences DataStore. */
class Store(private val context: Context) {
    private val gson = Gson()
    private val kProfiles = stringPreferencesKey("profiles")
    private val kSettings = stringPreferencesKey("settings")

    val profiles: Flow<List<Profile>> = context.dataStore.data.map { p ->
        p[kProfiles]?.let {
            runCatching {
                gson.fromJson<List<Profile>>(it, object : TypeToken<List<Profile>>() {}.type)
            }.getOrNull()
        } ?: emptyList()
    }

    val settings: Flow<Settings> = context.dataStore.data.map { p ->
        p[kSettings]?.let {
            runCatching { gson.fromJson(it, Settings::class.java) }.getOrNull()
        } ?: Settings()
    }

    suspend fun saveProfiles(list: List<Profile>) {
        context.dataStore.edit { it[kProfiles] = gson.toJson(list) }
    }

    suspend fun saveSettings(s: Settings) {
        context.dataStore.edit { it[kSettings] = gson.toJson(s) }
    }

    /** Synchronous settings read for the VpnService (which has no composition scope). */
    fun settingsBlocking(): Settings = runCatching {
        runBlocking { settings.first() }
    }.getOrDefault(Settings())

    fun profilesBlocking(): List<Profile> = runCatching {
        runBlocking { profiles.first() }
    }.getOrDefault(emptyList())
}
