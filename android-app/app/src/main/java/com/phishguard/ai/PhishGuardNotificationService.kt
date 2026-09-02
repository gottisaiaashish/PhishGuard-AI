package com.phishguard.ai

import android.app.Notification
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log

class PhishGuardNotificationService : NotificationListenerService() {

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        super.onNotificationPosted(sbn)
        if (sbn == null) return

        val packageName = sbn.packageName ?: return

        // Ignore notifications dispatched by our own app to avoid infinite loops
        if (packageName == applicationContext.packageName) return

        // Target messaging and communication apps
        val isTargetApp = packageName.contains("whatsapp", ignoreCase = true) ||
                packageName.contains("messaging", ignoreCase = true) ||
                packageName.contains("mms", ignoreCase = true) ||
                packageName.contains("telegram", ignoreCase = true) ||
                packageName.contains("gm", ignoreCase = true) ||
                packageName.contains("sms", ignoreCase = true)

        val extras = sbn.notification?.extras ?: return
        val title = extras.getString(Notification.EXTRA_TITLE) ?: ""
        val text = extras.getCharSequence(Notification.EXTRA_TEXT)?.toString() ?: ""
        val bigText = extras.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString() ?: ""

        val fullContent = if (bigText.isNotBlank()) bigText else text

        if (fullContent.isNotBlank()) {
            Log.d("PhishGuardService", "Intercepted notification from $packageName: $title -> $fullContent")
            ThreatScanner.scanNotification(
                context = applicationContext,
                sender = title,
                messageText = fullContent,
                packageName = packageName
            )
        }
    }

    override fun onListenerConnected() {
        super.onListenerConnected()
        Log.i("PhishGuardService", "PhishGuard Notification Listener successfully connected to Android OS.")
    }
}
