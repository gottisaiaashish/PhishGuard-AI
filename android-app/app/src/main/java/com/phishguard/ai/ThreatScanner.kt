package com.phishguard.ai

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.media.RingtoneManager
import android.os.Build
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.TimeUnit
import java.util.regex.Pattern

object ThreatScanner {

    private const val CHANNEL_ID = "phishguard_threat_alerts"
    private const val CHANNEL_NAME = "PhishGuard Threat Alerts"
    private const val API_URL = "https://phishguard-ai-mu.vercel.app"

    private val client = OkHttpClient.Builder()
        .connectTimeout(5, TimeUnit.SECONDS)
        .readTimeout(5, TimeUnit.SECONDS)
        .build()

    // Fast zero-day heuristic patterns for instant on-device detection (<30ms)
    private val URGENCY_PATTERN = Pattern.compile("(?i)(urgent|immediate|suspend|action required|freeze|unauthorized|blocked|kyc|pan card|aadhaar|debit card|credit card|lottery|kbc|winner|won|cashback|electricity|power cut|disconnect|part-time|salary|deposit|bonus|verify now|click here|apk)")
    private val SUSPICIOUS_DOMAINS = Pattern.compile("(?i)(micros0ft|paypa[il]|g00gle|netf[il]ix|azurepub\\.cc|\\.xyz|\\.top|\\.cc|\\.tk|\\.su|\\.online|\\.site|\\.club|\\.vip|\\.buzz|\\.link|\\.live|\\.work|\\.click|bit\\.ly|tinyurl|t\\.co|is\\.gd|rb\\.gy|cutt\\.ly)")
    private val URL_PATTERN = Pattern.compile("(?i)(https?://[^\\s\"'<>]+|www\\.[^\\s\"'<>]+|[a-zA-Z0-9-]+\\.(xyz|top|cc|tk|su|online|site|club|vip|buzz|link|live|work|click|info)[^\\s\"'<>]*)")

    fun scanNotification(context: Context, sender: String, messageText: String, packageName: String) {
        if (messageText.isBlank()) return

        // 1. Instant on-device heuristic detection
        val hasUrl = URL_PATTERN.matcher(messageText).find()
        val hasUrgency = URGENCY_PATTERN.matcher(messageText).find()
        val hasSuspiciousDomain = SUSPICIOUS_DOMAINS.matcher(messageText).find()

        val isHighRisk = (hasUrl && hasUrgency) || hasSuspiciousDomain || (hasUrl && messageText.contains("http://", ignoreCase = true))

        if (isHighRisk) {
            val appLabel = when {
                packageName.contains("whatsapp", ignoreCase = true) -> "WhatsApp"
                packageName.contains("mms", ignoreCase = true) || packageName.contains("messaging", ignoreCase = true) -> "SMS"
                packageName.contains("android.gm", ignoreCase = true) -> "Gmail"
                packageName.contains("telegram", ignoreCase = true) -> "Telegram"
                else -> "Message"
            }
            dispatchSecurityAlert(
                context = context,
                sender = sender.ifBlank { appLabel },
                summary = "Dangerous scam message intercepted! Do NOT click any links or share OTPs.",
                riskScore = 95
            )
            return
        }

        // 2. Cloud AI NLP deep scan (async coroutine)
        if (hasUrl) {
            CoroutineScope(Dispatchers.IO).launch {
                try {
                    val jsonBody = JSONObject().apply {
                        put("type", "sms")
                        put("sender", sender)
                        put("text", messageText)
                    }
                    val request = Request.Builder()
                        .url("$API_URL/api/analyze")
                        .post(jsonBody.toString().toRequestBody("application/json".toMediaType()))
                        .build()

                    val response = client.newCall(request).execute()
                    if (response.isSuccessful) {
                        val respBody = response.body?.string() ?: return@launch
                        val result = JSONObject(respBody)
                        val score = result.optInt("score", 0)
                        val status = result.optString("status", "Safe")

                        if (score >= 70) {
                            dispatchSecurityAlert(
                                context = context,
                                sender = sender,
                                summary = result.optString("aiExplanation", "Suspicious link detected in message."),
                                riskScore = score
                            )
                        }
                    }
                } catch (e: Exception) {
                    // Fallback to local heuristic already checked
                }
            }
        }
    }

    fun dispatchSecurityAlert(context: Context, sender: String, summary: String, riskScore: Int) {
        val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        // Create high-importance channel with sound and vibration
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                CHANNEL_NAME,
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "High-priority alerts for intercepted phishing and scam lures"
                enableVibration(true)
                vibrationPattern = longArrayOf(0, 350, 150, 350)
            }
            notificationManager.createNotificationChannel(channel)
        }

        val intent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        }
        val pendingIntent = PendingIntent.getActivity(
            context,
            0,
            intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val soundUri = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION)

        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle("🚨 PHISHGUARD ALERT: Scam Intercepted!")
            .setContentText("From: $sender (Threat Score: $riskScore/100)")
            .setStyle(NotificationCompat.BigTextStyle().bigText("⚠️ Dangerous link intercepted from $sender!\n\n$summary\n\n👉 ACTION: Do NOT click any links. Delete this message immediately."))
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setAutoCancel(true)
            .setSound(soundUri)
            .setVibrate(longArrayOf(0, 350, 150, 350))
            .setContentIntent(pendingIntent)
            .setColor(0xFFFF3366.toInt()) // Red danger banner
            .build()

        notificationManager.notify(System.currentTimeMillis().toInt(), notification)
    }
}
