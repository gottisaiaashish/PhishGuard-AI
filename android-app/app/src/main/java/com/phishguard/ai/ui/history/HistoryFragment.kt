package com.phishguard.ai.ui.history

import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
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
                .setTitle("Clear History")
                .setMessage("Are you sure you want to delete all saved scan records?")
                .setPositiveButton("Clear") { _, _ ->
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

        for (item in items) {
            val isThreat = item.verdict == "HIGH_RISK" || item.verdict == "SUSPICIOUS"

            val card = MaterialCardView(requireContext()).apply {
                radius = 12f * resources.displayMetrics.density
                strokeWidth = (1f * resources.displayMetrics.density).toInt()
                setCardBackgroundColor(Color.parseColor("#0F172A"))
                strokeColor = if (isThreat) Color.parseColor("#FF3366") else Color.parseColor("#1E293B")
                setContentPadding(16, 14, 16, 14)
                isClickable = true
                isFocusable = true
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply {
                    setMargins(0, 0, 0, (8 * resources.displayMetrics.density).toInt())
                }
                setOnClickListener {
                    showScanDetailDialog(item)
                }
            }

            val layout = LinearLayout(requireContext()).apply {
                orientation = LinearLayout.VERTICAL
            }

            val topRow = LinearLayout(requireContext()).apply {
                orientation = LinearLayout.HORIZONTAL
            }

            val typeBadge = TextView(requireContext()).apply {
                text = "${item.createdAt} • ${item.scanType}"
                setTextColor(Color.parseColor("#94A3B8"))
                textSize = 12f
                typeface = Typeface.DEFAULT_BOLD
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            }

            val verdictText = TextView(requireContext()).apply {
                text = when (item.verdict) {
                    "HIGH_RISK" -> "🚨 SCAM (${item.riskScore})"
                    "SUSPICIOUS" -> "⚠️ RISKY (${item.riskScore})"
                    else -> "✅ SAFE"
                }
                setTextColor(
                    when (item.verdict) {
                        "HIGH_RISK" -> ContextCompat.getColor(requireContext(), R.color.threat_danger)
                        "SUSPICIOUS" -> ContextCompat.getColor(requireContext(), R.color.threat_warning)
                        else -> ContextCompat.getColor(requireContext(), R.color.threat_safe)
                    }
                )
                textSize = 11f
                typeface = Typeface.DEFAULT_BOLD
            }

            topRow.addView(typeBadge)
            topRow.addView(verdictText)

            val contentSnippet = TextView(requireContext()).apply {
                text = item.content.take(100) + if (item.content.length > 100) "..." else ""
                setTextColor(Color.parseColor("#F8FAFC"))
                textSize = 13f
                setPadding(0, 6, 0, 0)
            }

            layout.addView(topRow)
            layout.addView(contentSnippet)
            card.addView(layout)

            binding.containerHistoryItems.addView(card)
        }
    }

    private fun showScanDetailDialog(item: ScanRecord) {
        AlertDialog.Builder(requireContext())
            .setTitle("Scan Details • ${item.scanType}")
            .setMessage("Analyzed Content:\n${item.content}\n\nThreat Score: ${item.riskScore}/100\nVerdict: ${item.verdict}\n\nFindings:\n${item.details}")
            .setPositiveButton("Close", null)
            .show()
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
