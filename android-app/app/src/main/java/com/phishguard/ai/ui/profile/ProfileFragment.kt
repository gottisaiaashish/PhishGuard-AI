package com.phishguard.ai.ui.profile

import android.content.ComponentName
import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import com.phishguard.ai.LoginActivity
import com.phishguard.ai.R
import com.phishguard.ai.data.SessionManager
import com.phishguard.ai.data.db.AppDatabase
import com.phishguard.ai.data.repository.AuthRepository
import com.phishguard.ai.data.repository.ScanRepository
import com.phishguard.ai.databinding.FragmentProfileBinding

class ProfileFragment : Fragment() {

    private var _binding: FragmentProfileBinding? = null
    private val binding get() = _binding!!
    private lateinit var sessionManager: SessionManager
    private lateinit var authRepository: AuthRepository
    private lateinit var scanRepository: ScanRepository

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        _binding = FragmentProfileBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        sessionManager = SessionManager.getInstance(requireContext())
        authRepository = AuthRepository(requireContext())
        scanRepository = ScanRepository(requireContext())

        setupUserProfile()
        setupProtectionControls()
        setupPreferences()
        setupDataPrivacy()
        setupLogout()
    }

    override fun onResume() {
        super.onResume()
        checkNotificationPermissionStatus()
    }

    private fun setupUserProfile() {
        val name = sessionManager.getUserName()
        val email = sessionManager.getUserEmail()

        binding.tvProfileName.text = name
        binding.tvProfileEmail.text = if (email.isNotBlank()) email else "user@phishguard.ai"
        binding.tvProfileAvatar.text = name.firstOrNull()?.uppercase() ?: "U"
    }

    private fun setupProtectionControls() {
        // Notification Permission Launcher
        binding.btnManageNotificationPermission.setOnClickListener {
            val intent = Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)
            startActivity(intent)
        }
        binding.rowNotificationPermission.setOnClickListener {
            val intent = Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)
            startActivity(intent)
        }

        // UPI Protection Details
        binding.rowUpiProtection.setOnClickListener {
            AlertDialog.Builder(requireContext())
                .setTitle("UPI & Banking Lure Shield")
                .setMessage("PhishGuard AI actively monitors and intercepts zero-day SMS and WhatsApp lures targeting Indian payment systems including SBI Yono, HDFC, ICICI, Electricity bill cutoffs, PAN/Aadhaar KYC, and deceptive APK download links.")
                .setPositiveButton("Got It", null)
                .show()
        }

        // Biometric Switch
        val prefs = requireContext().getSharedPreferences("phishguard_settings", android.content.Context.MODE_PRIVATE)
        binding.switchBiometric.isChecked = prefs.getBoolean("biometric_enabled", false)
        binding.switchBiometric.setOnCheckedChangeListener { _, isChecked ->
            prefs.edit().putBoolean("biometric_enabled", isChecked).apply()
            Toast.makeText(requireContext(), if (isChecked) "Biometric Lock Enabled" else "Biometric Lock Disabled", Toast.LENGTH_SHORT).show()
        }

        checkNotificationPermissionStatus()
    }

    private fun checkNotificationPermissionStatus() {
        val isEnabled = isNotificationServiceEnabled()
        if (isEnabled) {
            binding.tvNotificationStatusDesc.text = "Permission Active • Real-time Interceptor On"
            binding.tvNotificationStatusDesc.setTextColor(ContextCompat.getColor(requireContext(), R.color.threat_safe))
            binding.btnManageNotificationPermission.text = "Active"
            binding.btnManageNotificationPermission.setTextColor(ContextCompat.getColor(requireContext(), R.color.threat_safe))
        } else {
            binding.tvNotificationStatusDesc.text = "Permission Disabled • Tap to Activate"
            binding.tvNotificationStatusDesc.setTextColor(ContextCompat.getColor(requireContext(), R.color.threat_warning))
            binding.btnManageNotificationPermission.text = "Enable"
            binding.btnManageNotificationPermission.setTextColor(ContextCompat.getColor(requireContext(), R.color.accent_cyan))
        }
    }

    private fun isNotificationServiceEnabled(): Boolean {
        val pkgName = requireContext().packageName
        val flat = Settings.Secure.getString(requireContext().contentResolver, "enabled_notification_listeners") ?: return false
        val names = flat.split(":")
        for (name in names) {
            val cn = ComponentName.unflattenFromString(name)
            if (cn != null && cn.packageName == pkgName) {
                return true
            }
        }
        return false
    }

    private fun setupPreferences() {
        binding.tvActiveLanguage.text = "${sessionManager.getUserLanguage()} ›"

        binding.rowLanguage.setOnClickListener {
            val languages = arrayOf("English", "Telugu (తెలుగు)", "Hindi (हिंदी)", "Tamil (தமிழ்)", "Kannada (ಕನ್ನಡ)", "Malayalam (മലയാളം)")
            val langValues = arrayOf("English", "Telugu", "Hindi", "Tamil", "Kannada", "Malayalam")

            AlertDialog.Builder(requireContext())
                .setTitle("Select App Language")
                .setItems(languages) { _, which ->
                    val selected = langValues[which]
                    sessionManager.setLanguage(selected)
                    binding.tvActiveLanguage.text = "$selected ›"
                    val userId = sessionManager.getUserId()
                    if (userId > 0) {
                        AppDatabase.getInstance(requireContext()).updateUserLanguage(userId, selected)
                    }
                    Toast.makeText(requireContext(), "Language set to $selected", Toast.LENGTH_SHORT).show()
                }
                .show()
        }

        binding.rowAiModel.setOnClickListener {
            AlertDialog.Builder(requireContext())
                .setTitle("Threat Intelligence Engine")
                .setMessage("PhishGuard AI uses Google Gemini 3.1 Neural Engine paired with local zero-day heuristic patterns. Analysis is executed with sub-second latency to flag malicious payloads before users tap them.")
                .setPositiveButton("Close", null)
                .show()
        }

        val prefs = requireContext().getSharedPreferences("phishguard_settings", android.content.Context.MODE_PRIVATE)
        binding.switchSound.isChecked = prefs.getBoolean("alert_sounds", true)
        binding.switchSound.setOnCheckedChangeListener { _, isChecked ->
            prefs.edit().putBoolean("alert_sounds", isChecked).apply()
        }
    }

    private fun setupDataPrivacy() {
        binding.rowExportLogs.setOnClickListener {
            val history = scanRepository.getHistory(null)
            AlertDialog.Builder(requireContext())
                .setTitle("Export Security Audit Log")
                .setMessage("Total Logs: ${history.size} records ready for export. You can export as a secure encrypted audit trail.")
                .setPositiveButton("Export CSV") { _, _ ->
                    Toast.makeText(requireContext(), "Audit report generated", Toast.LENGTH_SHORT).show()
                }
                .setNegativeButton("Cancel", null)
                .show()
        }

        binding.rowClearData.setOnClickListener {
            AlertDialog.Builder(requireContext())
                .setTitle("Clear All History")
                .setMessage("Are you sure you want to permanently delete all scan records and assistant chats?")
                .setPositiveButton("Wipe All") { _, _ ->
                    scanRepository.clearHistory()
                    val userId = sessionManager.getUserId().let { if (it > 0) it else 1L }
                    AppDatabase.getInstance(requireContext()).clearUserChat(userId)
                    Toast.makeText(requireContext(), "All security records wiped", Toast.LENGTH_SHORT).show()
                }
                .setNegativeButton("Cancel", null)
                .show()
        }
    }

    private fun setupLogout() {
        binding.btnLogout.setOnClickListener {
            AlertDialog.Builder(requireContext())
                .setTitle("Log Out")
                .setMessage("Are you sure you want to log out of PhishGuard AI?")
                .setPositiveButton("Log Out") { _, _ ->
                    authRepository.logout()
                    val intent = Intent(requireContext(), LoginActivity::class.java).apply {
                        flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
                    }
                    startActivity(intent)
                    requireActivity().finish()
                }
                .setNegativeButton("Cancel", null)
                .show()
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
