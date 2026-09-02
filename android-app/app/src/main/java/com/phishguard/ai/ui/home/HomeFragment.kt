package com.phishguard.ai.ui.home

import android.graphics.Color
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import com.google.android.material.card.MaterialCardView
import com.phishguard.ai.LiveNotificationTracker
import com.phishguard.ai.MainActivity
import com.phishguard.ai.R
import com.phishguard.ai.data.SessionManager
import com.phishguard.ai.data.repository.ScanRepository
import com.phishguard.ai.databinding.FragmentHomeBinding

class HomeFragment : Fragment() {

    private var _binding: FragmentHomeBinding? = null
    private val binding get() = _binding!!
    private lateinit var scanRepository: ScanRepository
    private lateinit var sessionManager: SessionManager

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        _binding = FragmentHomeBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        scanRepository = ScanRepository(requireContext())
        sessionManager = SessionManager.getInstance(requireContext())

        setupUserGreeting()
        loadStats()
        setupActions()
        setupLiveFeed()
    }

    override fun onResume() {
        super.onResume()
        loadStats()
        renderLiveFeed()
    }

    private fun setupUserGreeting() {
        val name = sessionManager.getUserName()
        binding.tvHomeUserGreeting.text = "Hello, $name"
    }

    private fun loadStats() {
        val stats = scanRepository.getUserStats()
        binding.tvStatScans.text = stats.totalScans.toString()
        binding.tvStatThreats.text = stats.threatsBlocked.toString()
        binding.tvStatMonitored.text = stats.messagesMonitored.toString()
    }

    private fun setupActions() {
        binding.btnCardRunScan.setOnClickListener {
            (activity as? MainActivity)?.navigateToTab(R.id.nav_scan, 0)
        }

        binding.tvClearHomeFeed.setOnClickListener {
            LiveNotificationTracker.clearLogs()
            renderLiveFeed()
        }
    }

    private fun setupLiveFeed() {
        LiveNotificationTracker.onNewLog = {
            activity?.runOnUiThread {
                loadStats()
                renderLiveFeed()
            }
        }
        renderLiveFeed()
    }

    private fun renderLiveFeed() {
        val logs = LiveNotificationTracker.logs
        if (logs.isEmpty()) {
            binding.layoutHomeFeedEmpty.visibility = View.VISIBLE
            binding.tvClearHomeFeed.visibility = View.GONE
            binding.containerHomeFeed.removeAllViews()
            return
        }

        binding.layoutHomeFeedEmpty.visibility = View.GONE
        binding.tvClearHomeFeed.visibility = View.VISIBLE
        binding.containerHomeFeed.removeAllViews()

        val dangerColor = ContextCompat.getColor(requireContext(), R.color.threat_danger)
        val safeColor = ContextCompat.getColor(requireContext(), R.color.threat_safe)
        val cyanColor = ContextCompat.getColor(requireContext(), R.color.accent_cyan)
        val mutedColor = ContextCompat.getColor(requireContext(), R.color.text_secondary)

        for (log in logs.take(10)) {
            val itemView = LayoutInflater.from(requireContext()).inflate(R.layout.item_live_feed, binding.containerHomeFeed, false)

            val card = itemView.findViewById<MaterialCardView>(R.id.cardFeedItem)
            val tvAppBadge = itemView.findViewById<TextView>(R.id.tvFeedAppBadge)
            val tvSender = itemView.findViewById<TextView>(R.id.tvFeedSender)
            val tvTime = itemView.findViewById<TextView>(R.id.tvFeedTime)
            val tvVerdictBadge = itemView.findViewById<TextView>(R.id.tvFeedVerdictBadge)
            val tvSnippet = itemView.findViewById<TextView>(R.id.tvFeedMessageSnippet)
            val layoutAdvice = itemView.findViewById<View>(R.id.layoutFeedThreatAdvice)
            val tvAdvice = itemView.findViewById<TextView>(R.id.tvFeedThreatAdvice)

            // Dynamic app badge resolution across all notifications
            val appDisplayName = try {
                val pm = requireContext().packageManager
                val appInfo = pm.getApplicationInfo(log.app, 0)
                pm.getApplicationLabel(appInfo).toString()
            } catch (e: Exception) {
                val appLower = log.app.lowercase()
                when {
                    appLower.contains("whatsapp") -> "WhatsApp"
                    appLower.contains("snapchat") -> "Snapchat"
                    appLower.contains("telegram") -> "Telegram"
                    appLower.contains("sms") || appLower.contains("mms") || appLower.contains("messaging") -> "SMS"
                    appLower.contains("gmail") || appLower.contains("mail") -> "Email"
                    appLower.contains("instagram") -> "Instagram"
                    else -> log.app.substringAfterLast('.').replaceFirstChar { it.uppercase() }
                }
            }
            tvAppBadge.text = appDisplayName
            tvAppBadge.setTextColor(cyanColor)

            tvSender.text = log.sender.ifBlank { appDisplayName }
            tvTime.text = log.time
            tvSnippet.text = log.text

            if (log.isThreat) {
                card.strokeColor = dangerColor
                card.setCardBackgroundColor(Color.parseColor("#140D18"))
                tvVerdictBadge.text = "BLOCKED"
                tvVerdictBadge.setTextColor(dangerColor)
                tvVerdictBadge.setBackgroundResource(R.drawable.card_danger_border)
                layoutAdvice.visibility = View.VISIBLE
                tvAdvice.text = log.verdict.ifBlank { "Dangerous scam lure intercepted." }
            } else {
                card.strokeColor = Color.parseColor("#1E293B")
                card.setCardBackgroundColor(Color.parseColor("#0A1222"))
                tvVerdictBadge.text = "SAFE"
                tvVerdictBadge.setTextColor(safeColor)
                tvVerdictBadge.setBackgroundResource(R.drawable.card_safe_border)
                layoutAdvice.visibility = View.GONE
            }

            card.setOnClickListener {
                AlertDialog.Builder(requireContext())
                    .setTitle(if (log.isThreat) "Security Alert Audit" else "Message Inspection Audit")
                    .setMessage("App: $appDisplayName\nSender: ${log.sender}\nTime: ${log.time}\nStatus: ${if (log.isThreat) "THREAT BLOCKED" else "SAFE"}\nVerdict: ${log.verdict}\n\nIntercepted Message:\n${log.text}")
                    .setPositiveButton("Dismiss", null)
                    .show()
            }

            binding.containerHomeFeed.addView(itemView)
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
