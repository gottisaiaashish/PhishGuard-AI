package com.phishguard.ai.data.repository

import android.content.Context
import com.phishguard.ai.data.SessionManager
import com.phishguard.ai.data.db.AppDatabase
import com.phishguard.ai.data.db.UserRecord
import java.security.MessageDigest

class AuthRepository(private val context: Context) {

    private val db = AppDatabase.getInstance(context)
    private val sessionManager = SessionManager.getInstance(context)

    init {
        // Pre-seed default requested user
        if (db.getUserByEmail("gottisaiaashish@gmail.com") == null) {
            db.insertUser(
                name = "Sai Gotti",
                email = "gottisaiaashish@gmail.com",
                passwordHash = hashPassword("teamfmc123"),
                language = "English"
            )
        }
    }

    // Hash password with SHA-256
    private fun hashPassword(password: String): String {
        val bytes = MessageDigest.getInstance("SHA-256").digest(password.toByteArray())
        return bytes.joinToString("") { "%02x".format(it) }
    }

    /**
     * Register a new user.
     * [BACKEND API HOOK]: When your backend API (FastAPI / Supabase / Firebase) is ready,
     * call your remote POST /api/auth/register endpoint here and sync the returned user to SQLite.
     */
    fun register(name: String, email: String, password: String): Result<UserRecord> {
        val trimmedEmail = email.trim().lowercase()
        if (name.isBlank() || trimmedEmail.isBlank() || password.isBlank()) {
            return Result.failure(Exception("All fields are required."))
        }
        if (!android.util.Patterns.EMAIL_ADDRESS.matcher(trimmedEmail).matches()) {
            return Result.failure(Exception("Please enter a valid email address."))
        }
        if (password.length < 6) {
            return Result.failure(Exception("Password must be at least 6 characters."))
        }

        // Check if user already exists
        if (db.getUserByEmail(trimmedEmail) != null) {
            return Result.failure(Exception("An account with this email already exists."))
        }

        val passHash = hashPassword(password)
        val newId = db.insertUser(name, trimmedEmail, passHash)
        if (newId <= 0) {
            return Result.failure(Exception("Failed to create account. Please try again."))
        }

        val newUser = UserRecord(newId, name, trimmedEmail, "English", "Today")
        sessionManager.saveUserSession(newUser)
        return Result.success(newUser)
    }

    /**
     * Log in with email and password.
     * [BACKEND API HOOK]: When your backend API is ready, call POST /api/auth/login here.
     */
    fun login(email: String, password: String): Result<UserRecord> {
        val trimmedEmail = email.trim().lowercase()
        if (trimmedEmail.isBlank() || password.isBlank()) {
            return Result.failure(Exception("Please enter both email and password."))
        }

        val userPair = db.getUserByEmail(trimmedEmail)
            ?: return Result.failure(Exception("No account found with this email address."))

        val (user, storedHash) = userPair
        val inputHash = hashPassword(password)
        if (storedHash != inputHash) {
            return Result.failure(Exception("Incorrect password. Please try again."))
        }

        sessionManager.saveUserSession(user)
        return Result.success(user)
    }

    fun logout() {
        sessionManager.logout()
    }

    fun getCurrentUser(): UserRecord? {
        val userId = sessionManager.getUserId()
        if (userId <= 0) return null
        return db.getUserById(userId)
    }
}
