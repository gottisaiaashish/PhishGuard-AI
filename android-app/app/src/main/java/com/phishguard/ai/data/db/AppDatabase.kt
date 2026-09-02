package com.phishguard.ai.data.db

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

data class UserRecord(
    val id: Long,
    val name: String,
    val email: String,
    val language: String,
    val createdAt: String
)

data class ScanRecord(
    val id: Long,
    val userId: Long,
    val scanType: String, // "MESSAGE", "URL", "NOTIFICATION_INTERCEPT"
    val content: String,
    val riskScore: Int,
    val verdict: String, // "SAFE", "SUSPICIOUS", "HIGH_RISK"
    val details: String,
    val createdAt: String
)

data class ChatMessageRecord(
    val id: Long,
    val userId: Long,
    val sender: String, // "user", "assistant"
    val text: String,
    val language: String,
    val createdAt: String
)

data class UserStats(
    val totalScans: Int,
    val threatsBlocked: Int,
    val messagesMonitored: Int,
    val linksAnalyzed: Int
)

class AppDatabase(context: Context) : SQLiteOpenHelper(context, DATABASE_NAME, null, DATABASE_VERSION) {

    companion object {
        private const val DATABASE_NAME = "phishguard_secure.db"
        private const val DATABASE_VERSION = 1

        @Volatile
        private var instance: AppDatabase? = null

        fun getInstance(context: Context): AppDatabase {
            return instance ?: synchronized(this) {
                instance ?: AppDatabase(context.applicationContext).also { instance = it }
            }
        }
    }

    override fun onCreate(db: SQLiteDatabase) {
        // 1. Users Table
        db.execSQL("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                language TEXT DEFAULT 'English',
                created_at TEXT NOT NULL
            )
        """.trimIndent())

        // 2. Scan History Table
        db.execSQL("""
            CREATE TABLE scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                scan_type TEXT NOT NULL,
                content TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                verdict TEXT NOT NULL,
                details TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """.trimIndent())

        // 3. Chat Messages Table
        db.execSQL("""
            CREATE TABLE chat_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                sender TEXT NOT NULL,
                text TEXT NOT NULL,
                language TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """.trimIndent())
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        db.execSQL("DROP TABLE IF EXISTS chat_messages")
        db.execSQL("DROP TABLE IF EXISTS scan_history")
        db.execSQL("DROP TABLE IF EXISTS users")
        onCreate(db)
    }

    // ==================== USER OPERATIONS ====================

    fun insertUser(name: String, email: String, passwordHash: String, language: String = "English"): Long {
        val db = writableDatabase
        val values = ContentValues().apply {
            put("name", name.trim())
            put("email", email.trim().lowercase())
            put("password_hash", passwordHash)
            put("language", language)
            put("created_at", SimpleDateFormat("dd MMM yyyy", Locale.getDefault()).format(Date()))
        }
        return db.insert("users", null, values)
    }

    fun getUserByEmail(email: String): Pair<UserRecord, String>? {
        val db = readableDatabase
        val cursor = db.rawQuery("SELECT id, name, email, language, created_at, password_hash FROM users WHERE email = ? LIMIT 1", arrayOf(email.trim().lowercase()))
        cursor.use {
            if (it.moveToFirst()) {
                val user = UserRecord(
                    id = it.getLong(0),
                    name = it.getString(1),
                    email = it.getString(2),
                    language = it.getString(3),
                    createdAt = it.getString(4)
                )
                val passHash = it.getString(5)
                return Pair(user, passHash)
            }
        }
        return null
    }

    fun getUserById(userId: Long): UserRecord? {
        val db = readableDatabase
        val cursor = db.rawQuery("SELECT id, name, email, language, created_at FROM users WHERE id = ? LIMIT 1", arrayOf(userId.toString()))
        cursor.use {
            if (it.moveToFirst()) {
                return UserRecord(
                    id = it.getLong(0),
                    name = it.getString(1),
                    email = it.getString(2),
                    language = it.getString(3),
                    createdAt = it.getString(4)
                )
            }
        }
        return null
    }

    fun updateUserLanguage(userId: Long, language: String) {
        val db = writableDatabase
        val values = ContentValues().apply {
            put("language", language)
        }
        db.update("users", values, "id = ?", arrayOf(userId.toString()))
    }

    // ==================== SCAN HISTORY OPERATIONS ====================

    fun insertScan(userId: Long, scanType: String, content: String, riskScore: Int, verdict: String, details: String): Long {
        val db = writableDatabase
        val values = ContentValues().apply {
            put("user_id", userId)
            put("scan_type", scanType)
            put("content", content)
            put("risk_score", riskScore)
            put("verdict", verdict)
            put("details", details)
            put("created_at", SimpleDateFormat("dd MMM, HH:mm", Locale.getDefault()).format(Date()))
        }
        return db.insert("scan_history", null, values)
    }

    fun getUserScans(userId: Long, filterType: String? = null): List<ScanRecord> {
        val db = readableDatabase
        val query = if (filterType.isNullOrBlank() || filterType == "ALL") {
            "SELECT id, user_id, scan_type, content, risk_score, verdict, details, created_at FROM scan_history WHERE user_id = ? ORDER BY id DESC"
        } else {
            "SELECT id, user_id, scan_type, content, risk_score, verdict, details, created_at FROM scan_history WHERE user_id = ? AND scan_type = ? ORDER BY id DESC"
        }
        val args = if (filterType.isNullOrBlank() || filterType == "ALL") arrayOf(userId.toString()) else arrayOf(userId.toString(), filterType)
        val list = mutableListOf<ScanRecord>()
        val cursor = db.rawQuery(query, args)
        cursor.use {
            while (it.moveToNext()) {
                list.add(
                    ScanRecord(
                        id = it.getLong(0),
                        userId = it.getLong(1),
                        scanType = it.getString(2),
                        content = it.getString(3),
                        riskScore = it.getInt(4),
                        verdict = it.getString(5),
                        details = it.getString(6),
                        createdAt = it.getString(7)
                    )
                )
            }
        }
        return list
    }

    fun getUserStats(userId: Long): UserStats {
        val db = readableDatabase
        var total = 0
        var blocked = 0
        var messages = 0
        var links = 0

        val cursor = db.rawQuery("SELECT scan_type, verdict FROM scan_history WHERE user_id = ?", arrayOf(userId.toString()))
        cursor.use {
            while (it.moveToNext()) {
                total++
                val type = it.getString(0)
                val verdict = it.getString(1)
                if (verdict == "HIGH_RISK" || verdict == "SUSPICIOUS") {
                    blocked++
                }
                if (type == "MESSAGE" || type == "NOTIFICATION_INTERCEPT") {
                    messages++
                }
                if (type == "URL") {
                    links++
                }
            }
        }
        return UserStats(
            totalScans = total,
            threatsBlocked = blocked,
            messagesMonitored = messages,
            linksAnalyzed = links
        )
    }

    fun clearUserHistory(userId: Long) {
        val db = writableDatabase
        db.delete("scan_history", "user_id = ?", arrayOf(userId.toString()))
    }

    // ==================== CHATBOT OPERATIONS ====================

    fun insertChatMessage(userId: Long, sender: String, text: String, language: String): Long {
        val db = writableDatabase
        val values = ContentValues().apply {
            put("user_id", userId)
            put("sender", sender)
            put("text", text)
            put("language", language)
            put("created_at", SimpleDateFormat("HH:mm", Locale.getDefault()).format(Date()))
        }
        return db.insert("chat_messages", null, values)
    }

    fun getUserChatMessages(userId: Long): List<ChatMessageRecord> {
        val db = readableDatabase
        val list = mutableListOf<ChatMessageRecord>()
        val cursor = db.rawQuery("SELECT id, user_id, sender, text, language, created_at FROM chat_messages WHERE user_id = ? ORDER BY id ASC", arrayOf(userId.toString()))
        cursor.use {
            while (it.moveToNext()) {
                list.add(
                    ChatMessageRecord(
                        id = it.getLong(0),
                        userId = it.getLong(1),
                        sender = it.getString(2),
                        text = it.getString(3),
                        language = it.getString(4),
                        createdAt = it.getString(5)
                    )
                )
            }
        }
        return list
    }
}
