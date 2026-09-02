package com.phishguard.ai

import android.app.Notification
import android.os.Build
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

data class InterceptedLog(
    val time: String,
    val app: String,
    val sender: String,
    val text: String,
    val isThreat: Boolean,
    val verdict: String
)

object LiveNotificationTracker {
    val logs = mutableListOf<InterceptedLog>()
    var onNewLog: ((InterceptedLog) -> Unit)? = null

    @Synchronized
    fun addLog(log: InterceptedLog) {
        logs.add(0, log)
        if (logs.size > 20) logs.removeAt(logs.lastIndex)
        onNewLog?.invoke(log)
    }
}

class PhishGuardNotificationService : NotificationListenerService() {

    companion object {
        private const val TAG = "PhishGuardService"
        var isConnected: Boolean = false
    }

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        super.onNotificationPosted(sbn)
        if (sbn == null) return

        val packageName = sbn.packageName ?: return

        // 1. Ignore notifications from our own app
        if (packageName == applicationContext.packageName) return

        // 2. Ignore non-messaging system packages
        if (packageName == "android" || packageName == "com.android.systemui" || packageName == "com.android.vending") {
            return
        }

        val notification = sbn.notification ?: return
        val extras = notification.extras ?: return

        // Extract title (WhatsApp uses CharSequence)
        val title = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString()
            ?: extras.getString(Notification.EXTRA_TITLE)
            ?: ""

        // Extract body text across all possible Android notification styles
        val text = extras.getCharSequence(Notification.EXTRA_TEXT)?.toString() ?: ""
        val bigText = extras.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString() ?: ""
        val subText = extras.getCharSequence(Notification.EXTRA_SUB_TEXT)?.toString() ?: ""
        val ticker = notification.tickerText?.toString() ?: ""

        // Extract multi-line texts (WhatsApp group chats & batched messages)
        val textLines = extras.getCharSequenceArray(Notification.EXTRA_TEXT_LINES)
        val linesJoined = textLines?.joinToString(" ") { it.toString() } ?: ""

        // Find the longest, most detailed text content
        val candidateTexts = listOf(bigText, linesJoined, text, ticker, subText)
        val fullContent = candidateTexts.filter { it.isNotBlank() }.maxByOrNull { it.length } ?: ""

        Log.e(TAG, "🟢 INTERCEPTED NOTIFICATION from [$packageName] Title: '$title' Body: '$fullContent'")

        if (fullContent.isNotBlank() || title.isNotBlank()) {
            val appLabel = when {
                packageName.contains("whatsapp", ignoreCase = true) -> "WhatsApp"
                packageName.contains("messaging", ignoreCase = true) || packageName.contains("mms", ignoreCase = true) -> "SMS"
                packageName.contains("telegram", ignoreCase = true) -> "Telegram"
                packageName.contains("instagram", ignoreCase = true) -> "Instagram"
                packageName.contains("gm", ignoreCase = true) -> "Gmail"
                else -> packageName.substringAfterLast('.')
            }

            val effectiveSender = if (title.isNotBlank()) "$appLabel ($title)" else appLabel
            val messageToScan = fullContent.ifBlank { title }

            // Scan with ThreatScanner
            ThreatScanner.scanNotification(
                context = applicationContext,
                sender = effectiveSender,
                messageText = messageToScan,
                packageName = packageName
            )
        }
    }

    override fun onListenerConnected() {
        super.onListenerConnected()
        isConnected = true
        Log.e(TAG, "🟢 PhishGuard NotificationListenerService CONNECTED to Android OS!")
    }

    override fun onListenerDisconnected() {
        super.onListenerDisconnected()
        isConnected = false
        Log.e(TAG, "🔴 PhishGuard NotificationListenerService DISCONNECTED.")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            requestRebind(android.content.ComponentName(this, PhishGuardNotificationService::class.java))
        }
    }
}
