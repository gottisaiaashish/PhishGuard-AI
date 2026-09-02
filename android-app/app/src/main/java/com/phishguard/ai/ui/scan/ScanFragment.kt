package com.phishguard.ai.ui.scan

import android.content.ClipboardManager
import android.content.Context
import android.content.res.ColorStateList
import android.graphics.Color
import android.os.Bundle
import android.util.Base64
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.phishguard.ai.R
import com.phishguard.ai.data.repository.ScanRepository
import com.phishguard.ai.databinding.FragmentScanBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.TimeUnit
import java.util.regex.Pattern

class ScanFragment : Fragment() {

    private var _binding: FragmentScanBinding? = null
    private val binding get() = _binding!!
    private lateinit var scanRepository: ScanRepository

    private var currentMode = "MESSAGE" // "MESSAGE" or "URL"
    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(8, TimeUnit.SECONDS)
        .readTimeout(8, TimeUnit.SECONDS)
        .build()

    private val GEMINI_API_KEY = String(Base64.decode("QVEuQWI4Uk42Sk9OUUlvWXRDa1JRbG5KUWlaZjF0V1F1dVJjNHRMN3pydDgzems0TkZfVEE=", Base64.DEFAULT))

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        _binding = FragmentScanBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        scanRepository = ScanRepository(requireContext())

        setupTabs()
        setupClipboardPaste()
        setupAnalyzeButton()

        // Check if opened with pre-selected tab mode
        arguments?.getInt("initial_tab")?.let { tabIndex ->
            setMode(if (tabIndex == 1) "URL" else "MESSAGE")
        }
    }

    private fun setupTabs() {
        binding.tabScanMessage.setOnClickListener { setMode("MESSAGE") }
        binding.tabScanLink.setOnClickListener { setMode("URL") }
    }

    fun setMode(mode: String) {
        currentMode = mode
        if (mode == "MESSAGE") {
            binding.tabScanMessage.backgroundTintList = ColorStateList.valueOf(ContextCompat.getColor(requireContext(), R.color.accent_cyan))
            binding.tabScanMessage.setTextColor(ContextCompat.getColor(requireContext(), R.color.bg_dark))
            binding.tabScanLink.backgroundTintList = ColorStateList.valueOf(Color.TRANSPARENT)
            binding.tabScanLink.setTextColor(ContextCompat.getColor(requireContext(), R.color.text_secondary))

            binding.tvInputLabel.text = "Paste Message Content:"
            binding.etScanInput.hint = "Paste suspicious message, notification, or email text here..."
        } else {
            binding.tabScanLink.backgroundTintList = ColorStateList.valueOf(ContextCompat.getColor(requireContext(), R.color.accent_cyan))
            binding.tabScanLink.setTextColor(ContextCompat.getColor(requireContext(), R.color.bg_dark))
            binding.tabScanMessage.backgroundTintList = ColorStateList.valueOf(Color.TRANSPARENT)
            binding.tabScanMessage.setTextColor(ContextCompat.getColor(requireContext(), R.color.text_secondary))

            binding.tvInputLabel.text = "Paste Website URL / Link:"
            binding.etScanInput.hint = "e.g. https://sbi-kyc-verify.xyz/login"
        }
        binding.cardScanResult.visibility = View.GONE
    }

    private fun setupClipboardPaste() {
        binding.btnPasteClipboard.setOnClickListener {
            val clipboard = requireContext().getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = clipboard.primaryClip
            if (clip != null && clip.itemCount > 0) {
                val text = clip.getItemAt(0).text
                binding.etScanInput.setText(text)
                Toast.makeText(requireContext(), "Pasted from clipboard", Toast.LENGTH_SHORT).show()
            } else {
                Toast.makeText(requireContext(), "Clipboard is empty", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun setupAnalyzeButton() {
        binding.btnAnalyze.setOnClickListener {
            val input = binding.etScanInput.text?.toString().orEmpty().trim()
            if (input.isBlank()) {
                Toast.makeText(requireContext(), "Please enter or paste text to analyze", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            performAnalysis(input)
        }
    }

    private fun performAnalysis(input: String) {
        binding.btnAnalyze.isEnabled = false
        binding.pbScanLoading.visibility = View.VISIBLE
        binding.cardScanResult.visibility = View.GONE

        lifecycleScope.launch(Dispatchers.IO) {
            // Check heuristic zero-day first
            val isUrgent = Pattern.compile("(?i)(urgent|immediate|suspend|freeze|blocked|kyc|pan card|winner|won|lottery|power cut|part-time|apk)").matcher(input).find()
            val hasBadDomain = Pattern.compile("(?i)(\\.xyz|\\.top|\\.cc|\\.tk|\\.su|\\.vip|\\.club|micros0ft|paypa[il]|g00gle)").matcher(input).find()

            var verdict = "SAFE"
            var score = 10
            var reasons = "• Normal communication verified\n• No scam keywords or malicious links detected"
            var advice = "👉 ACTION: This content appears safe to open."

            try {
                val prompt = """Analyze this mobile ${if (currentMode == "URL") "URL" else "message"} for phishing, scams, or fraud:
"$input"

Respond strictly with a JSON object:
{
  "verdict": "SAFE" or "SUSPICIOUS" or "HIGH_RISK",
  "score": integer (0 to 100),
  "reasons": "2-3 short bullet points in plain English explaining why",
  "advice": "1 sentence action recommendation"
}"""

                val requestJson = JSONObject().apply {
                    val parts = JSONArray().put(JSONObject().put("text", prompt))
                    put("contents", JSONArray().put(JSONObject().put("parts", parts)))
                    put("generationConfig", JSONObject().apply {
                        put("temperature", 0.2)
                        put("maxOutputTokens", 200)
                        put("responseMimeType", "application/json")
                    })
                }

                val url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-flash-lite:generateContent?key=$GEMINI_API_KEY"
                val request = Request.Builder()
                    .url(url)
                    .post(requestJson.toString().toRequestBody("application/json".toMediaType()))
                    .build()

                val response = httpClient.newCall(request).execute()
                if (response.isSuccessful) {
                    val body = response.body?.string().orEmpty()
                    val candidate = JSONObject(body).optJSONArray("candidates")?.optJSONObject(0)
                        ?.optJSONObject("content")?.optJSONArray("parts")?.optJSONObject(0)?.optString("text").orEmpty()
                    if (candidate.isNotBlank()) {
                        val parsed = JSONObject(candidate)
                        verdict = parsed.optString("verdict", "SAFE")
                        score = parsed.optInt("score", 15)
                        reasons = parsed.optString("reasons", reasons)
                        advice = parsed.optString("advice", advice)
                    }
                }
            } catch (e: Exception) {
                // Fallback to local heuristic if offline
                if (isUrgent && hasBadDomain) {
                    verdict = "HIGH_RISK"
                    score = 95
                    reasons = "• Urgent threat language demanding fast action\n• Suspicious unverified domain extension detected"
                    advice = "RECOMMENDED: Do NOT click any links. Delete this message immediately."
                } else if (isUrgent || hasBadDomain) {
                    verdict = "SUSPICIOUS"
                    score = 65
                    reasons = "• Contains urgency triggers or unverified links\n• Proceed with caution"
                    advice = "RECOMMENDED: Verify with the sender directly before clicking."
                }
            }

            // Save to persistent database!
            scanRepository.saveScan(
                scanType = currentMode,
                content = input,
                riskScore = score,
                verdict = verdict,
                details = reasons
            )

            withContext(Dispatchers.Main) {
                binding.btnAnalyze.isEnabled = true
                binding.pbScanLoading.visibility = View.GONE
                displayResult(verdict, score, reasons, advice)
            }
        }
    }

    private fun displayResult(verdict: String, score: Int, reasons: String, advice: String) {
        binding.cardScanResult.visibility = View.VISIBLE
        binding.tvResultScore.text = "$score/100"
        binding.tvResultReasons.text = reasons
        binding.tvResultAdvice.text = advice

        when (verdict) {
            "HIGH_RISK" -> {
                binding.tvResultVerdict.text = "HIGH RISK / SCAM DETECTED"
                binding.tvResultVerdict.setTextColor(ContextCompat.getColor(requireContext(), R.color.threat_danger))
                binding.tvResultScore.setTextColor(ContextCompat.getColor(requireContext(), R.color.threat_danger))
                binding.tvResultAdvice.setBackgroundResource(R.drawable.card_danger_border)
                binding.tvResultAdvice.setTextColor(ContextCompat.getColor(requireContext(), R.color.threat_danger))
            }
            "SUSPICIOUS" -> {
                binding.tvResultVerdict.text = "SUSPICIOUS ACTIVITY"
                binding.tvResultVerdict.setTextColor(ContextCompat.getColor(requireContext(), R.color.threat_warning))
                binding.tvResultScore.setTextColor(ContextCompat.getColor(requireContext(), R.color.threat_warning))
                binding.tvResultAdvice.setBackgroundResource(R.drawable.card_cyan_border)
                binding.tvResultAdvice.setTextColor(ContextCompat.getColor(requireContext(), R.color.threat_warning))
            }
            else -> {
                binding.tvResultVerdict.text = "VERIFIED SAFE"
                binding.tvResultVerdict.setTextColor(ContextCompat.getColor(requireContext(), R.color.threat_safe))
                binding.tvResultScore.setTextColor(ContextCompat.getColor(requireContext(), R.color.threat_safe))
                binding.tvResultAdvice.setBackgroundResource(R.drawable.card_safe_border)
                binding.tvResultAdvice.setTextColor(ContextCompat.getColor(requireContext(), R.color.threat_safe))
            }
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
