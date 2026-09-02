package com.phishguard.ai.ui.home

import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
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
        setupQuickActions()
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

    private fun setupQuickActions() {
        binding.btnQuickScanMessage.setOnClickListener {
            (activity as? MainActivity)?.navigateToTab(R.id.nav_scan, 0)
        }
        binding.btnQuickScanLink.setOnClickListener {
            (activity as? MainActivity)?.navigateToTab(R.id.nav_scan, 1)
        }
        binding.btnQuickAssistant.setOnClickListener {
            (activity as? MainActivity)?.navigateToTab(R.id.nav_assistant)
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
            binding.tvHomeFeedEmpty.visibility = View.VISIBLE
            binding.containerHomeFeed.removeAllViews()
            return
        }

        binding.tvHomeFeedEmpty.visibility = View.GONE
        binding.containerHomeFeed.removeAllViews()

        for (log in logs.take(5)) {
            val card = MaterialCardView(requireContext()).apply {
                radius = 10f * resources.displayMetrics.density
                strokeWidth = (1f * resources.displayMetrics.density).toInt()
                setCardBackgroundColor(Color.parseColor("#0F172A"))
                strokeColor = if (log.isThreat) Color.parseColor("#FF3366") else Color.parseColor("#1E293B")
                setContentPadding(16, 12, 16, 12)
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply {
                    setMargins(0, 0, 0, (6 * resources.displayMetrics.density).toInt())
                }
            }

            val layout = LinearLayout(requireContext()).apply {
                orientation = LinearLayout.VERTICAL
            }

            val topRow = LinearLayout(requireContext()).apply {
                orientation = LinearLayout.HORIZONTAL
            }

            val senderView = TextView(requireContext()).apply {
                text = "${log.time} • ${log.sender}"
                setTextColor(Color.parseColor("#F8FAFC"))
                textSize = 12f
                typeface = Typeface.DEFAULT_BOLD
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            }

            val verdictBadge = TextView(requireContext()).apply {
                text = if (log.isThreat) "🚨 THREAT" else "✅ CLEAN"
                setTextColor(if (log.isThreat) Color.parseColor("#FF3366") else Color.parseColor("#00E676"))
                textSize = 11f
                typeface = Typeface.DEFAULT_BOLD
            }

            topRow.addView(senderView)
            topRow.addView(verdictBadge)

            val snippet = TextView(requireContext()).apply {
                text = log.text.take(80) + if (log.text.length > 80) "..." else ""
                setTextColor(Color.parseColor("#94A3B8"))
                textSize = 12f
                setPadding(0, 4, 0, 0)
            }

            layout.addView(topRow)
            layout.addView(snippet)
            card.addView(layout)

            binding.containerHomeFeed.addView(card)
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
