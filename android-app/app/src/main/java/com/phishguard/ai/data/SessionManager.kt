package com.phishguard.ai.data

import android.content.Context
import android.content.SharedPreferences
import com.phishguard.ai.data.db.UserRecord

class SessionManager(context: Context) {

    private val prefs: SharedPreferences = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)

    companion object {
        private const val PREF_NAME = "phishguard_user_session"
        private const val KEY_IS_LOGGED_IN = "is_logged_in"
        private const val KEY_USER_ID = "user_id"
        private const val KEY_USER_NAME = "user_name"
        private const val KEY_USER_EMAIL = "user_email"
        private const val KEY_USER_LANGUAGE = "user_language"
        private const val KEY_AUTH_TOKEN = "auth_token"

        @Volatile
        private var instance: SessionManager? = null

        fun getInstance(context: Context): SessionManager {
            return instance ?: synchronized(this) {
                instance ?: SessionManager(context.applicationContext).also { instance = it }
            }
        }
    }

    fun saveUserSession(user: UserRecord, token: String = "local_jwt_session") {
        prefs.edit().apply {
            putBoolean(KEY_IS_LOGGED_IN, true)
            putLong(KEY_USER_ID, user.id)
            putString(KEY_USER_NAME, user.name)
            putString(KEY_USER_EMAIL, user.email)
            putString(KEY_USER_LANGUAGE, user.language)
            putString(KEY_AUTH_TOKEN, token)
            apply()
        }
    }

    fun isLoggedIn(): Boolean = prefs.getBoolean(KEY_IS_LOGGED_IN, false)

    fun getUserId(): Long = prefs.getLong(KEY_USER_ID, -1L)

    fun getUserName(): String = prefs.getString(KEY_USER_NAME, "User") ?: "User"

    fun getUserEmail(): String = prefs.getString(KEY_USER_EMAIL, "") ?: ""

    fun getUserLanguage(): String = prefs.getString(KEY_USER_LANGUAGE, "English") ?: "English"

    fun setLanguage(language: String) {
        prefs.edit().putString(KEY_USER_LANGUAGE, language).apply()
    }

    fun logout() {
        prefs.edit().clear().apply()
    }
}
