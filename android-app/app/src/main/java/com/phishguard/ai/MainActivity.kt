package com.phishguard.ai

import android.Manifest
import android.content.ComponentName
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.Typeface
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.google.android.material.card.MaterialCardView
import com.phishguard.ai.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Check for Android 13+ Notification Post Permission
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.POST_NOTIFICATIONS), 101)
            }
        }

        setupListeners()
        updatePermissionUI()
        setupLiveLogTracker()
    }

    override fun onResume() {
        super.onResume()
        updatePermissionUI()
        renderLiveLogs()
    }

    private fun setupListeners() {
        // Grant 1-Tap Notification Access Button
        binding.btnGrantPermission.setOnClickListener {
            val intent = Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)
            startActivity(intent)
            Toast.makeText(this, "Please enable 'PhishGuard AI' in Notification Access settings", Toast.LENGTH_LONG).show()
        }

        // Simulate Bank Scam SMS (Jury Demo)
        binding.btnSimulateBankScam.setOnClickListener {
            Toast.makeText(this, "Simulating incoming bank scam SMS...", Toast.LENGTH_SHORT).show()
            ThreatScanner.dispatchSecurityAlert(
                context = this,
                sender = "HDFC-BANK-ALERT",
                summary = "Your Debit Card is BLOCKED due to expired KYC! Verify now at http://hdfc-kyc-verify.xyz to avoid permanent suspension.",
                riskScore = 98
            )
            binding.tvStatBlocked.text = (binding.tvStatBlocked.text.toString().toIntOrNull() ?: 6 + 1).toString()
        }

        // Simulate WhatsApp Job Scam (Jury Demo)
        binding.btnSimulateWhatsAppScam.setOnClickListener {
            Toast.makeText(this, "Simulating WhatsApp job scam message...", Toast.LENGTH_SHORT).show()
            ThreatScanner.dispatchSecurityAlert(
                context = this,
                sender = "WhatsApp: Global HR Recruiter",
                summary = "Earn ₹5,000/hour doing simple YouTube likes! Pay ₹500 fee at http://telegram-task-bonus.top to activate your bonus.",
                riskScore = 95
            )
            binding.tvStatBlocked.text = (binding.tvStatBlocked.text.toString().toIntOrNull() ?: 6 + 1).toString()
        }
    }

    private fun setupLiveLogTracker() {
        LiveNotificationTracker.onNewLog = { logEntry ->
            runOnUiThread {
                renderLiveLogs()
                val currentMonitored = binding.tvStatMonitored.text.toString().toIntOrNull() ?: 48
                binding.tvStatMonitored.text = (currentMonitored + 1).toString()
                if (logEntry.isThreat) {
                    val currentBlocked = binding.tvStatBlocked.text.toString().toIntOrNull() ?: 6
                    binding.tvStatBlocked.text = (currentBlocked + 1).toString()
                }
            }
        }
        renderLiveLogs()
    }

    private fun renderLiveLogs() {
        val logs = LiveNotificationTracker.logs
        if (logs.isEmpty()) {
            binding.tvLiveLogEmpty.visibility = View.VISIBLE
            binding.containerLiveLogs.removeAllViews()
            return
        }

        binding.tvLiveLogEmpty.visibility = View.GONE
        binding.containerLiveLogs.removeAllViews()

        for (log in logs.take(6)) {
            val card = MaterialCardView(this).apply {
                radius = 12f * resources.displayMetrics.density
                strokeWidth = (1f * resources.displayMetrics.density).toInt()
                setCardBackgroundColor(Color.parseColor("#131B2E"))
                strokeColor = if (log.isThreat) Color.parseColor("#FF3366") else Color.parseColor("#1F2E4D")
                setContentPadding(18, 14, 18, 14)
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply {
                    setMargins(0, 0, 0, (6 * resources.displayMetrics.density).toInt())
                }
            }

            val layout = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
            }

            val topRow = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
            }

            val senderView = TextView(this).apply {
                text = "${log.time} • ${log.sender}"
                setTextColor(Color.parseColor("#E6EDF3"))
                textSize = 12f
                typeface = Typeface.DEFAULT_BOLD
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            }

            val verdictBadge = TextView(this).apply {
                text = if (log.isThreat) "🚨 THREAT" else "✅ CLEAN"
                setTextColor(if (log.isThreat) Color.parseColor("#FF3366") else Color.parseColor("#00E676"))
                textSize = 11f
                typeface = Typeface.DEFAULT_BOLD
            }

            topRow.addView(senderView)
            topRow.addView(verdictBadge)

            val snippet = TextView(this).apply {
                text = log.text.take(90) + if (log.text.length > 90) "..." else ""
                setTextColor(Color.parseColor("#8B949E"))
                textSize = 12f
                setPadding(0, 4, 0, 0)
            }

            layout.addView(topRow)
            layout.addView(snippet)
            card.addView(layout)

            binding.containerLiveLogs.addView(card)
        }
    }

    private fun updatePermissionUI() {
        val isGranted = isNotificationServiceEnabled()
        if (isGranted) {
            binding.tvPermissionState.text = "✅ Notification Listener Access Granted! PhishGuard is actively protecting incoming communications."
            binding.tvPermissionState.setTextColor(ContextCompat.getColor(this, R.color.threat_safe))
            binding.btnGrantPermission.isEnabled = false
            binding.btnGrantPermission.text = "Protection Enabled 🟢"
            binding.btnGrantPermission.setBackgroundColor(ContextCompat.getColor(this, R.color.card_stroke))
        } else {
            binding.tvPermissionState.text = "⚠️ Access Required: Enable notification access so PhishGuard can intercept deceptive scam links."
            binding.tvPermissionState.setTextColor(ContextCompat.getColor(this, R.color.text_secondary))
            binding.btnGrantPermission.isEnabled = true
            binding.btnGrantPermission.text = "Grant 1-Tap Notification Access"
        }
    }

    private fun isNotificationServiceEnabled(): Boolean {
        val pkgName = packageName
        val flat = Settings.Secure.getString(contentResolver, "enabled_notification_listeners") ?: return false
        val names = flat.split(":")
        for (name in names) {
            val cn = ComponentName.unflattenFromString(name)
            if (cn != null && cn.packageName == pkgName) {
                return true
            }
        }
        return false
    }
}
