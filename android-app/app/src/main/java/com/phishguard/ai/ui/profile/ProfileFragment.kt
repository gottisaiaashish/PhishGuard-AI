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
import com.phishguard.ai.AuthActivity
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
        setupNotificationSettings()
        setupLanguagePreference()
        setupClearData()
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

        val user = authRepository.getCurrentUser()
        binding.tvProfileCreated.text = "Member since: ${user?.createdAt ?: "Today"}"
    }

    private fun setupNotificationSettings() {
        binding.btnManageNotificationPermission.setOnClickListener {
            val intent = Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)
            startActivity(intent)
        }
        checkNotificationPermissionStatus()
    }

    private fun checkNotificationPermissionStatus() {
        val isEnabled = isNotificationServiceEnabled()
        if (isEnabled) {
            binding.tvNotificationStatusDesc.text = "Permission Active • Intercepting threats"
            binding.tvNotificationStatusDesc.setTextColor(ContextCompat.getColor(requireContext(), R.color.threat_safe))
            binding.btnManageNotificationPermission.text = "Active"
            binding.btnManageNotificationPermission.setTextColor(ContextCompat.getColor(requireContext(), R.color.threat_safe))
        } else {
            binding.tvNotificationStatusDesc.text = "Permission Disabled • Tap Settings to Enable"
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

    private fun setupLanguagePreference() {
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
    }

    private fun setupClearData() {
        binding.rowClearData.setOnClickListener {
            AlertDialog.Builder(requireContext())
                .setTitle("Clear All History")
                .setMessage("Are you sure you want to permanently delete all scan records and assistant chats?")
                .setPositiveButton("Wipe All") { _, _ ->
                    scanRepository.clearHistory()
                    Toast.makeText(requireContext(), "Scan history cleared", Toast.LENGTH_SHORT).show()
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
                    val intent = Intent(requireContext(), AuthActivity::class.java).apply {
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
