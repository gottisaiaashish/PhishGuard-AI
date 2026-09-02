package com.phishguard.ai.data.repository

import android.content.Context
import com.phishguard.ai.data.SessionManager
import com.phishguard.ai.data.db.AppDatabase
import com.phishguard.ai.data.db.ScanRecord
import com.phishguard.ai.data.db.UserStats

class ScanRepository(private val context: Context) {

    private val db = AppDatabase.getInstance(context)
    private val sessionManager = SessionManager.getInstance(context)

    fun saveScan(scanType: String, content: String, riskScore: Int, verdict: String, details: String): Long {
        val userId = sessionManager.getUserId().let { if (it > 0) it else 1L }
        return db.insertScan(userId, scanType, content, riskScore, verdict, details)
    }

    fun getHistory(filterType: String? = null): List<ScanRecord> {
        val userId = sessionManager.getUserId().let { if (it > 0) it else 1L }
        return db.getUserScans(userId, filterType)
    }

    fun getUserStats(): UserStats {
        val userId = sessionManager.getUserId().let { if (it > 0) it else 1L }
        return db.getUserStats(userId)
    }

    fun clearHistory() {
        val userId = sessionManager.getUserId().let { if (it > 0) it else 1L }
        db.clearUserHistory(userId)
    }
}
