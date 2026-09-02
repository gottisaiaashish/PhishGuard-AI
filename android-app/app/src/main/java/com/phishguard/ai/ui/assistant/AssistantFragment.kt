package com.phishguard.ai.ui.assistant

import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.util.Base64
import android.view.Gravity
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.google.android.material.card.MaterialCardView
import com.phishguard.ai.R
import com.phishguard.ai.data.SessionManager
import com.phishguard.ai.data.db.AppDatabase
import com.phishguard.ai.databinding.FragmentAssistantBinding
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

class AssistantFragment : Fragment() {

    private var _binding: FragmentAssistantBinding? = null
    private val binding get() = _binding!!
    private lateinit var db: AppDatabase
    private lateinit var sessionManager: SessionManager

    private var currentLanguage = "English"
    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(8, TimeUnit.SECONDS)
        .readTimeout(8, TimeUnit.SECONDS)
        .build()

    private val GEMINI_API_KEY = String(Base64.decode("QVEuQWI4Uk42Sk9OUUlvWXRDa1JRbG5KUWlaZjF0V1F1dVJjNHRMN3pydDgzems0TkZfVEE=", Base64.DEFAULT))

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        _binding = FragmentAssistantBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        db = AppDatabase.getInstance(requireContext())
        sessionManager = SessionManager.getInstance(requireContext())

        currentLanguage = sessionManager.getUserLanguage()
        setupLanguageSelector()
        setupClearChatButton()
        loadSavedMessages()
        setupSendButton()
    }

    private fun setupLanguageSelector() {
        binding.tvAssistantLangIndicator.text = "Online • $currentLanguage"
        binding.btnAssistantSettings.setOnClickListener {
            val languages = arrayOf(
                "English",
                "Telugu (తెలుగు)",
                "Hindi (हिंदी)",
                "Tamil (தமிழ்)",
                "Kannada (ಕನ್ನಡ)",
                "Malayalam (മലയാളം)"
            )
            val langValues = arrayOf("English", "Telugu", "Hindi", "Tamil", "Kannada", "Malayalam")

            AlertDialog.Builder(requireContext())
                .setTitle("Assistant Language")
                .setItems(languages) { _, which ->
                    currentLanguage = langValues[which]
                    sessionManager.setLanguage(currentLanguage)
                    binding.tvAssistantLangIndicator.text = "Online • $currentLanguage"
                    val userId = sessionManager.getUserId()
                    if (userId > 0) {
                        db.updateUserLanguage(userId, currentLanguage)
                    }
                    Toast.makeText(requireContext(), "Language set to $currentLanguage", Toast.LENGTH_SHORT).show()
                }
                .show()
        }
    }

    private fun setupClearChatButton() {
        binding.btnClearChat.setOnClickListener {
            AlertDialog.Builder(requireContext())
                .setTitle("Clear Conversation")
                .setMessage("Delete all chat messages?")
                .setPositiveButton("Clear") { _, _ ->
                    val userId = sessionManager.getUserId().let { if (it > 0) it else 1L }
                    db.clearUserChat(userId)
                    loadSavedMessages()
                }
                .setNegativeButton("Cancel", null)
                .show()
        }
    }

    private fun loadSavedMessages() {
        binding.containerChatMessages.removeAllViews()
        val userId = sessionManager.getUserId().let { if (it > 0) it else 1L }
        val saved = db.getUserChatMessages(userId)

        if (saved.isEmpty()) {
            // Welcome message
            addChatBubble(
                sender = "assistant",
                message = "Hello! I am your PhishGuard Cybersecurity Assistant.\n\nYou can ask me about suspicious messages, fake links, bank fraud, or online scams. I can speak English, Telugu, Hindi, Tamil, Kannada, or Malayalam!"
            )
        } else {
            for (msg in saved) {
                addChatBubble(sender = msg.sender, message = msg.text)
            }
        }
    }

    private fun setupSendButton() {
        binding.btnSendChat.setOnClickListener {
            val text = binding.etChatInput.text?.toString().orEmpty().trim()
            if (text.isBlank()) return@setOnClickListener

            binding.etChatInput.setText("")
            addChatBubble("user", text)

            val userId = sessionManager.getUserId().let { if (it > 0) it else 1L }
            db.insertChatMessage(userId, "user", text, currentLanguage)

            sendMessageToGemini(text)
        }

        binding.btnClearChat.setOnClickListener {
            binding.containerChatMessages.removeAllViews()
            addChatBubble("assistant", "Chat cleared. How can I help protect you today?")
        }
    }

    private fun sendMessageToGemini(userText: String) {
        binding.pbChatLoading.visibility = View.VISIBLE
        binding.btnSendChat.isEnabled = false

        lifecycleScope.launch(Dispatchers.IO) {
            var aiReply = "I am currently offline. Remember: never share your OTP, UPI PIN, or bank passwords with anyone."

            try {
                val systemPrompt = """You are PhishGuard Assistant, a friendly mobile cybersecurity AI.
Selected Language: $currentLanguage.
CRITICAL RULES:
1. Respond STRICTLY in $currentLanguage. (If Telugu/Hindi/Tamil/Kannada/Malayalam, write in natural, friendly everyday language that common people easily understand).
2. NEVER use difficult technical jargon. Explain scams simply in everyday terms (e.g. "fake link trap", "money theft trick").
3. Give short, direct, actionable advice in 2-3 short bullet points.
4. Keep the answer concise (under 80 words) for a mobile screen."""

                val fullPrompt = "$systemPrompt\n\nUser Question: \"$userText\""

                val requestJson = JSONObject().apply {
                    val parts = JSONArray().put(JSONObject().put("text", fullPrompt))
                    put("contents", JSONArray().put(JSONObject().put("parts", parts)))
                    put("generationConfig", JSONObject().apply {
                        put("temperature", 0.3)
                        put("maxOutputTokens", 220)
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
                        aiReply = candidate.trim()
                    }
                }
            } catch (e: Exception) {
                // Keep default offline reply
            }

            val userId = sessionManager.getUserId().let { if (it > 0) it else 1L }
            db.insertChatMessage(userId, "assistant", aiReply, currentLanguage)

            withContext(Dispatchers.Main) {
                binding.pbChatLoading.visibility = View.GONE
                binding.btnSendChat.isEnabled = true
                addChatBubble("assistant", aiReply)
            }
        }
    }

    private fun addChatBubble(sender: String, message: String) {
        val isUser = sender == "user"
        val wrapper = LinearLayout(requireContext()).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply {
                setMargins(0, 0, 0, (8 * resources.displayMetrics.density).toInt())
            }
            gravity = if (isUser) Gravity.END else Gravity.START
        }

        val card = MaterialCardView(requireContext()).apply {
            radius = 12f * resources.displayMetrics.density
            strokeWidth = (1f * resources.displayMetrics.density).toInt()
            setCardBackgroundColor(if (isUser) Color.parseColor("#00D2D3") else Color.parseColor("#131D35"))
            strokeColor = if (isUser) Color.parseColor("#00D2D3") else Color.parseColor("#1E293B")
            setContentPadding(16, 12, 16, 12)
            layoutParams = LinearLayout.LayoutParams(
                (resources.displayMetrics.widthPixels * 0.78).toInt(),
                LinearLayout.LayoutParams.WRAP_CONTENT
            )
        }

        val textView = TextView(requireContext()).apply {
            text = message
            setTextColor(if (isUser) Color.parseColor("#080D1A") else Color.parseColor("#F8FAFC"))
            textSize = 13f
            if (isUser) typeface = Typeface.DEFAULT_BOLD
        }

        card.addView(textView)
        wrapper.addView(card)
        binding.containerChatMessages.addView(wrapper)

        // Scroll to bottom
        binding.scrollChat.post {
            binding.scrollChat.fullScroll(View.FOCUS_DOWN)
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
