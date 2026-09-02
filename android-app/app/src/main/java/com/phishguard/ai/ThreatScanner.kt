package com.phishguard.ai

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.media.RingtoneManager
import android.os.Build
import android.util.Log
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

    private const val TAG = "ThreatScanner"
    private const val CHANNEL_ID = "phishguard_threat_alerts_v2"
    private const val CHANNEL_NAME = "PhishGuard Threat Alerts"

    // Base64 encoded Gemini API Key
    private val GEMINI_API_KEY = String(android.util.Base64.decode("QVEuQWI4Uk42Sk9OUUlvWXRDa1JRbG5KUWlaZjF0V1F1dVJjNHRMN3pydDgzems0TkZfVEE=", android.util.Base64.DEFAULT))

    private val client = OkHttpClient.Builder()
        .connectTimeout(6, TimeUnit.SECONDS)
        .readTimeout(6, TimeUnit.SECONDS)
        .build()

    // Scam urgency & financial keywords
    private val URGENCY_PATTERN = Pattern.compile("(?i)(urgent|immediate|suspend|action required|freeze|unauthorized|blocked|kyc|pan card|aadhaar|debit card|credit card|lottery|kbc|winner|won|cashback|electricity|power cut|disconnect|part-time|salary|deposit|bonus|verify now|click here|apk|claim|prize|bank)")
    // Deceptive and risky domains
    private val SUSPICIOUS_DOMAINS = Pattern.compile("(?i)(micros0ft|paypa[il]|g00gle|netf[il]ix|azurepub\\.cc|\\.xyz|\\.top|\\.cc|\\.tk|\\.su|\\.online|\\.site|\\.club|\\.vip|\\.buzz|\\.link|\\.live|\\.work|\\.click|bit\\.ly|tinyurl|t\\.co|is\\.gd|rb\\.gy|cutt\\.ly)")
    // Any link pattern (with or without http/https)
    private val URL_PATTERN = Pattern.compile("(?i)(https?://[^\\s\"'<>]+|www\\.[^\\s\"'<>]+|[a-zA-Z0-9-]+\\.(xyz|top|cc|tk|su|online|site|club|vip|buzz|link|live|work|click|info)[^\\s\"'<>]*)")

    // Whitelist of major clean domains (so regular YouTube/Wikipedia links don't trigger false alarms)
    private val SAFE_WHITELIST = listOf("youtube.com", "youtu.be", "google.com", "wikipedia.org", "github.com", "instagram.com", "facebook.com", "twitter.com", "x.com", "amazon.in", "amazon.com", "flipkart.com")

    fun scanNotification(context: Context, sender: String, messageText: String, packageName: String) {
        if (messageText.isBlank()) return
        Log.d(TAG, "Scanning incoming message from $sender: $messageText")

        val hasUrl = URL_PATTERN.matcher(messageText).find()
        val hasUrgency = URGENCY_PATTERN.matcher(messageText).find()
        val hasSuspiciousDomain = SUSPICIOUS_DOMAINS.matcher(messageText).find()

        // 1. Instant On-Device Flagging (<20ms)
        val isWhitelisted = SAFE_WHITELIST.any { messageText.contains(it, ignoreCase = true) }
        val isInstantThreat = (!isWhitelisted && hasUrl && (hasUrgency || hasSuspiciousDomain || messageText.contains("http://", ignoreCase = true))) ||
                hasSuspiciousDomain ||
                (!isWhitelisted && hasUrl && (messageText.contains("sbi", ignoreCase = true) || messageText.contains("hdfc", ignoreCase = true) || messageText.contains("icici", ignoreCase = true) || messageText.contains("paytm", ignoreCase = true)))

        if (isInstantThreat) {
            Log.i(TAG, "⚡ Instant Threat Detected! Alerting user immediately.")
            dispatchSecurityAlert(
                context = context,
                sender = sender,
                summary = "Dangerous scam or phishing link detected! Scammers are trying to steal your credentials or money.",
                riskScore = 95
            )
            return
        }

        // 2. If it contains any link or urgency lure, run deep Gemini 3.1 Flash Lite AI analysis
        if (hasUrl || hasUrgency) {
            CoroutineScope(Dispatchers.IO).launch {
                try {
                    val prompt = """You are a mobile phishing detector. Analyze this message:
"$messageText"
Sender: "$sender"

Respond strictly with a JSON object containing:
- "isPhish": boolean (true if phishing/scam lure/fraud/suspicious)
- "score": integer (0 to 100)
- "reason": brief 1-sentence warning for user"""

                    val requestJson = JSONObject().apply {
                        val partsArray = JSONArray().put(JSONObject().put("text", prompt))
                        val contentsArray = JSONArray().put(JSONObject().put("parts", partsArray))
                        put("contents", contentsArray)
                        put("generationConfig", JSONObject().apply {
                            put("temperature", 0.2)
                            put("maxOutputTokens", 150)
                            put("responseMimeType", "application/json")
                        })
                    }

                    val url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-flash-lite:generateContent?key=$GEMINI_API_KEY"
                    val request = Request.Builder()
                        .url(url)
                        .post(requestJson.toString().toRequestBody("application/json".toMediaType()))
                        .build()

                    val response = client.newCall(request).execute()
                    if (response.isSuccessful) {
                        val bodyStr = response.body?.string() ?: return@launch
                        val rootJson = JSONObject(bodyStr)
                        val candidateText = rootJson.optJSONArray("candidates")
                            ?.optJSONObject(0)
                            ?.optJSONObject("content")
                            ?.optJSONArray("parts")
                            ?.optJSONObject(0)
                            ?.optString("text") ?: ""

                        if (candidateText.isNotBlank()) {
                            val parsed = JSONObject(candidateText)
                            val isPhish = parsed.optBoolean("isPhish", false)
                            val score = parsed.optInt("score", 0)
                            val reason = parsed.optString("reason", "Suspicious link flagged by AI.")

                            if (isPhish || score >= 65) {
                                dispatchSecurityAlert(
                                    context = context,
                                    sender = sender,
                                    summary = reason,
                                    riskScore = score
                                )
                            }
                        }
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Gemini scan failed: ${e.message}")
                    // If network fails and message has a non-whitelisted URL, flag as cautionary
                    if (hasUrl && !isWhitelisted) {
                        dispatchSecurityAlert(
                            context = context,
                            sender = sender,
                            summary = "Unverified external link received. Verify sender before clicking.",
                            riskScore = 80
                        )
                    }
                }
            }
        }
    }

    fun dispatchSecurityAlert(context: Context, sender: String, summary: String, riskScore: Int) {
        val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        // Create high-importance channel with sound and vibration for floating heads-up alert
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                CHANNEL_NAME,
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "High-priority security alerts for intercepted phishing and scam lures"
                enableVibration(true)
                vibrationPattern = longArrayOf(0, 400, 150, 400)
                lockscreenVisibility = android.app.Notification.VISIBILITY_PUBLIC
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
            .setVibrate(longArrayOf(0, 400, 150, 400))
            .setContentIntent(pendingIntent)
            .setColor(0xFFFF3366.toInt()) // Red danger banner
            .setDefaults(NotificationCompat.DEFAULT_ALL)
            .build()

        notificationManager.notify(System.currentTimeMillis().toInt(), notification)
        Log.i(TAG, "🚨 Security Alert notification dispatched for $sender!")
    }
}
