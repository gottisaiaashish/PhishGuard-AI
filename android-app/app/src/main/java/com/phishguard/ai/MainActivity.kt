package com.phishguard.ai

import android.Manifest
import android.content.ComponentName
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
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
    }

    override fun onResume() {
        super.onResume()
        updatePermissionUI()
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
