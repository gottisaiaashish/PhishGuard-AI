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
            val tvVerdictDetail = itemView.findViewById<TextView>(R.id.tvFeedVerdictDetail)
            val tvSnippet = itemView.findViewById<TextView>(R.id.tvFeedMessageSnippet)
            val layoutAdvice = itemView.findViewById<View>(R.id.layoutFeedThreatAdvice)
            val tvAdvice = itemView.findViewById<TextView>(R.id.tvFeedThreatAdvice)

            // App badge branding
            val appLower = log.app.lowercase()
            if (appLower.contains("whatsapp")) {
                tvAppBadge.text = "WHATSAPP"
                tvAppBadge.setTextColor(Color.parseColor("#25D366"))
                tvAppBadge.setBackgroundResource(R.drawable.card_safe_border)
            } else if (appLower.contains("sms") || appLower.contains("mms") || appLower.contains("messaging")) {
                tvAppBadge.text = "SMS GUARD"
                tvAppBadge.setTextColor(cyanColor)
                tvAppBadge.setBackgroundResource(R.drawable.card_cyan_border)
            } else {
                tvAppBadge.text = "INBOUND"
                tvAppBadge.setTextColor(mutedColor)
                tvAppBadge.setBackgroundResource(R.drawable.card_cyan_border)
            }

            tvSender.text = log.sender.ifBlank { "Unknown Sender" }
            tvTime.text = log.time
            tvSnippet.text = log.text

            if (log.isThreat) {
                card.strokeColor = dangerColor
                card.setCardBackgroundColor(Color.parseColor("#140D18"))
                tvVerdictBadge.text = "BLOCKED • THREAT"
                tvVerdictBadge.setTextColor(dangerColor)
                tvVerdictBadge.setBackgroundResource(R.drawable.card_danger_border)
                tvVerdictDetail.text = log.verdict.ifBlank { "Phishing Scam Intercepted" }
                tvVerdictDetail.setTextColor(dangerColor)
                layoutAdvice.visibility = View.VISIBLE
                tvAdvice.text = "High-risk lure intercepted. Do not click links or reply."
            } else {
                card.strokeColor = Color.parseColor("#1E293B")
                card.setCardBackgroundColor(Color.parseColor("#0C1322"))
                tvVerdictBadge.text = "VERIFIED SAFE"
                tvVerdictBadge.setTextColor(safeColor)
                tvVerdictBadge.setBackgroundResource(R.drawable.card_safe_border)
                tvVerdictDetail.text = "No malicious links or scam triggers detected"
                tvVerdictDetail.setTextColor(mutedColor)
                layoutAdvice.visibility = View.GONE
            }

            card.setOnClickListener {
                AlertDialog.Builder(requireContext())
                    .setTitle(if (log.isThreat) "Security Alert Audit" else "Message Inspection Audit")
                    .setMessage("Sender: ${log.sender}\nChannel: ${tvAppBadge.text}\nTime: ${log.time}\nStatus: ${if (log.isThreat) "THREAT BLOCKED" else "SAFE"}\nVerdict: ${log.verdict}\n\nIntercepted Message:\n${log.text}")
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
