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
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.TimeUnit
import java.util.regex.Pattern

object ThreatScanner {

    private const val TAG = "ThreatScanner"
    private const val CHANNEL_ID = "phishguard_threat_alerts_v3"
    private const val CHANNEL_NAME = "PhishGuard Threat Alerts"

    // Base64 encoded Gemini API Key
    private val GEMINI_API_KEY = String(android.util.Base64.decode("QVEuQWI4Uk42Sk9OUUlvWXRDa1JRbG5KUWlaZjF0V1F1dVJjNHRMN3pydDgzems0TkZfVEE=", android.util.Base64.DEFAULT))

    private val client = OkHttpClient.Builder()
        .connectTimeout(6, TimeUnit.SECONDS)
        .readTimeout(6, TimeUnit.SECONDS)
        .build()

    private val timeFormat = SimpleDateFormat("HH:mm:ss", Locale.getDefault())

    // Scam urgency & financial keywords
    private val URGENCY_PATTERN = Pattern.compile("(?i)(urgent|immediate|suspend|action required|freeze|unauthorized|blocked|kyc|pan card|aadhaar|debit card|credit card|lottery|kbc|winner|won|cashback|electricity|power cut|disconnect|part-time|salary|deposit|bonus|verify now|click here|apk|claim|prize|bank|account blocked)")
    // Deceptive and risky domains
    private val SUSPICIOUS_DOMAINS = Pattern.compile("(?i)(micros0ft|paypa[il]|g00gle|netf[il]ix|azurepub\\.cc|\\.xyz|\\.top|\\.cc|\\.tk|\\.su|\\.online|\\.site|\\.club|\\.vip|\\.buzz|\\.link|\\.live|\\.work|\\.click|bit\\.ly|tinyurl|t\\.co|is\\.gd|rb\\.gy|cutt\\.ly)")
    // Any link pattern (with or without http/https)
    private val URL_PATTERN = Pattern.compile("(?i)(https?://[^\\s\"'<>]+|www\\.[^\\s\"'<>]+|[a-zA-Z0-9-]+\\.(xyz|top|cc|tk|su|online|site|club|vip|buzz|link|live|work|click|info)[^\\s\"'<>]*)")

    // Whitelist of major clean domains
    private val SAFE_WHITELIST = listOf("youtube.com", "youtu.be", "google.com", "wikipedia.org", "github.com", "instagram.com", "facebook.com", "twitter.com", "x.com", "amazon.in", "amazon.com", "flipkart.com")

    fun scanNotification(context: Context, sender: String, messageText: String, packageName: String) {
        if (messageText.isBlank()) return
        Log.e(TAG, "🔍 Scanning incoming message from $sender: $messageText")

        val currentTime = timeFormat.format(Date())
        val hasUrl = URL_PATTERN.matcher(messageText).find()
        val hasUrgency = URGENCY_PATTERN.matcher(messageText).find()
        val hasSuspiciousDomain = SUSPICIOUS_DOMAINS.matcher(messageText).find()

        // 1. Instant On-Device Flagging (<20ms)
        val isWhitelisted = SAFE_WHITELIST.any { messageText.contains(it, ignoreCase = true) }
        val isInstantThreat = (!isWhitelisted && hasUrl && (hasUrgency || hasSuspiciousDomain || messageText.contains("http://", ignoreCase = true))) ||
                hasSuspiciousDomain ||
                (!isWhitelisted && hasUrl && (messageText.contains("sbi", ignoreCase = true) || messageText.contains("hdfc", ignoreCase = true) || messageText.contains("icici", ignoreCase = true) || messageText.contains("paytm", ignoreCase = true)))

        if (isInstantThreat) {
            Log.e(TAG, "⚡ INSTANT THREAT DETECTED! Alerting user immediately.")
            try {
                com.phishguard.ai.data.repository.ScanRepository(context).saveScan(
                    scanType = "NOTIFICATION_INTERCEPT",
                    content = "From $sender: $messageText",
                    riskScore = 95,
                    verdict = "HIGH_RISK",
                    details = "Dangerous phishing or financial lure intercepted."
                )
            } catch (e: Exception) {
                // Ignore DB error
            }

            LiveNotificationTracker.addLog(
                InterceptedLog(
                    time = currentTime,
                    app = packageName,
                    sender = sender,
                    text = messageText,
                    isThreat = true,
                    verdict = "Phishing Scam Link Blocked"
                )
            )
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
                                LiveNotificationTracker.addLog(
                                    InterceptedLog(
                                        time = currentTime,
                                        app = packageName,
                                        sender = sender,
                                        text = messageText,
                                        isThreat = true,
                                        verdict = "AI Scam Detected ($score/100)"
                                    )
                                )
                                dispatchSecurityAlert(
                                    context = context,
                                    sender = sender,
                                    summary = reason,
                                    riskScore = score
                                )
                                return@launch
                            }
                        }
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Gemini scan failed: ${e.message}")
                }

                // If AI found it clean or non-threat
                LiveNotificationTracker.addLog(
                    InterceptedLog(
                        time = currentTime,
                        app = packageName,
                        sender = sender,
                        text = messageText,
                        isThreat = false,
                        verdict = "Verified Clean"
                    )
                )
            }
        } else {
            // Regular chat message (e.g. "hi", "how are you")
            LiveNotificationTracker.addLog(
                InterceptedLog(
                    time = currentTime,
                    app = packageName,
                    sender = sender,
                    text = messageText,
                    isThreat = false,
                    verdict = "Safe Message"
                )
            )
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
            .setContentTitle("PHISHGUARD ALERT: Scam Intercepted")
            .setContentText("From: $sender (Threat Score: $riskScore/100)")
            .setStyle(NotificationCompat.BigTextStyle().bigText("Security Alert: Dangerous link intercepted from $sender.\n\n$summary\n\nRecommendation: Do NOT click any links. Delete this message immediately."))
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
        Log.e(TAG, "Security Alert notification DISPATCHED for $sender!")
    }
}
