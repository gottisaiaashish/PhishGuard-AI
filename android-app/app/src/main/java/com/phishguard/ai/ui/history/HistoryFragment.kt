package com.phishguard.ai.ui.history

import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.view.Gravity
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import com.google.android.material.card.MaterialCardView
import com.phishguard.ai.R
import com.phishguard.ai.data.db.ScanRecord
import com.phishguard.ai.data.repository.ScanRepository
import com.phishguard.ai.databinding.FragmentHistoryBinding

class HistoryFragment : Fragment() {

    private var _binding: FragmentHistoryBinding? = null
    private val binding get() = _binding!!
    private lateinit var scanRepository: ScanRepository
    private var currentFilter: String? = "ALL"

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        _binding = FragmentHistoryBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        scanRepository = ScanRepository(requireContext())

        setupFilterChips()
        setupClearButton()
        loadHistory()
    }

    override fun onResume() {
        super.onResume()
        loadHistory()
    }

    private fun setupFilterChips() {
        binding.chipGroupHistoryFilter.setOnCheckedStateChangeListener { _, checkedIds ->
            if (checkedIds.isNotEmpty()) {
                currentFilter = when (checkedIds[0]) {
                    R.id.chipFilterThreats -> "THREATS"
                    R.id.chipFilterMessages -> "MESSAGE"
                    R.id.chipFilterLinks -> "URL"
                    else -> "ALL"
                }
                loadHistory()
            }
        }
    }

    private fun setupClearButton() {
        binding.btnClearHistory.setOnClickListener {
            AlertDialog.Builder(requireContext())
                .setTitle("Clear Security History")
                .setMessage("Are you sure you want to permanently delete all scan records?")
                .setPositiveButton("Clear All") { _, _ ->
                    scanRepository.clearHistory()
                    loadHistory()
                }
                .setNegativeButton("Cancel", null)
                .show()
        }
    }

    private fun loadHistory() {
        val allScans = scanRepository.getHistory(null)
        val filtered = when (currentFilter) {
            "THREATS" -> allScans.filter { it.verdict == "HIGH_RISK" || it.verdict == "SUSPICIOUS" }
            "MESSAGE" -> allScans.filter { it.scanType == "MESSAGE" || it.scanType == "NOTIFICATION_INTERCEPT" }
            "URL" -> allScans.filter { it.scanType == "URL" }
            else -> allScans
        }

        if (filtered.isEmpty()) {
            binding.tvHistoryEmpty.visibility = View.VISIBLE
            binding.scrollHistory.visibility = View.GONE
        } else {
            binding.tvHistoryEmpty.visibility = View.GONE
            binding.scrollHistory.visibility = View.VISIBLE
            renderHistoryItems(filtered)
        }
    }

    private fun renderHistoryItems(items: List<ScanRecord>) {
        binding.containerHistoryItems.removeAllViews()
        val density = resources.displayMetrics.density

        for (item in items) {
            val isDanger = item.verdict == "HIGH_RISK"
            val isSuspicious = item.verdict == "SUSPICIOUS"

            val card = MaterialCardView(requireContext()).apply {
                radius = 14f * density
                strokeWidth = (1f * density).toInt()
                setCardBackgroundColor(Color.parseColor("#0F172A"))
                strokeColor = when {
                    isDanger -> Color.parseColor("#33FF3366")
                    isSuspicious -> Color.parseColor("#33FFAA00")
                    else -> Color.parseColor("#1E293B")
                }
                setContentPadding((14 * density).toInt(), (12 * density).toInt(), (14 * density).toInt(), (12 * density).toInt())
                isClickable = true
                isFocusable = true
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply {
                    setMargins(0, 0, 0, (10 * density).toInt())
                }
                setOnClickListener {
                    showScanDetailDialog(item)
                }
            }

            val cardContent = LinearLayout(requireContext()).apply {
                orientation = LinearLayout.VERTICAL
            }

            // Top Row: Type & Timestamp + Status Badge
            val topRow = LinearLayout(requireContext()).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
            }

            val typeIcon = ImageView(requireContext()).apply {
                layoutParams = LinearLayout.LayoutParams((18 * density).toInt(), (18 * density).toInt()).apply {
                    marginEnd = (8 * density).toInt()
                }
                val iconRes = when (item.scanType) {
                    "URL" -> R.drawable.ic_action_link
                    "MESSAGE" -> R.drawable.ic_action_message
                    else -> R.drawable.ic_shield_check
                }
                setImageResource(iconRes)
                setColorFilter(Color.parseColor("#94A3B8"))
            }

            val typeBadge = TextView(requireContext()).apply {
                text = "${item.scanType} • ${item.createdAt}"
                setTextColor(Color.parseColor("#94A3B8"))
                textSize = 11f
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            }

            val verdictBadge = TextView(requireContext()).apply {
                text = when {
                    isDanger -> "BLOCKED (${item.riskScore})"
                    isSuspicious -> "SUSPICIOUS (${item.riskScore})"
                    else -> "SAFE"
                }
                setTextColor(
                    when {
                        isDanger -> ContextCompat.getColor(requireContext(), R.color.threat_danger)
                        isSuspicious -> ContextCompat.getColor(requireContext(), R.color.threat_warning)
                        else -> ContextCompat.getColor(requireContext(), R.color.threat_safe)
                    }
                )
                textSize = 10f
                typeface = Typeface.DEFAULT_BOLD
                setPadding((8 * density).toInt(), (3 * density).toInt(), (8 * density).toInt(), (3 * density).toInt())
                setBackgroundResource(
                    when {
                        isDanger -> R.drawable.card_danger_border
                        isSuspicious -> R.drawable.card_cyan_border
                        else -> R.drawable.card_safe_border
                    }
                )
            }

            topRow.addView(typeIcon)
            topRow.addView(typeBadge)
            topRow.addView(verdictBadge)

            // Content Snippet
            val contentSnippet = TextView(requireContext()).apply {
                text = item.content.take(120) + if (item.content.length > 120) "..." else ""
                setTextColor(Color.parseColor("#E2E8F0"))
                textSize = 13f
                setPadding(0, (8 * density).toInt(), 0, (4 * density).toInt())
            }

            // Reason / Subtitle
            val detailSnippet = TextView(requireContext()).apply {
                text = item.details.ifBlank { "Analysis complete" }
                setTextColor(Color.parseColor("#64748B"))
                textSize = 11f
            }

            cardContent.addView(topRow)
            cardContent.addView(contentSnippet)
            cardContent.addView(detailSnippet)
            card.addView(cardContent)

            binding.containerHistoryItems.addView(card)
        }
    }

    private fun showScanDetailDialog(item: ScanRecord) {
        AlertDialog.Builder(requireContext())
            .setTitle("Audit Details • ${item.scanType}")
            .setMessage("Analyzed Content:\n${item.content}\n\nThreat Score: ${item.riskScore} / 100\nVerdict: ${item.verdict}\nDate: ${item.createdAt}\n\nFindings:\n${item.details}")
            .setPositiveButton("Close", null)
            .show()
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
