package com.phishguard.ai

import android.content.Intent
import android.content.res.ColorStateList
import android.graphics.Color
import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.phishguard.ai.data.repository.AuthRepository
import com.phishguard.ai.databinding.ActivityAuthBinding

class AuthActivity : AppCompatActivity() {

    private lateinit var binding: ActivityAuthBinding
    private lateinit var authRepository: AuthRepository
    private var isSignUpMode = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityAuthBinding.inflate(layoutInflater)
        setContentView(binding.root)

        authRepository = AuthRepository(this)

        setupTabs()
        setupSubmitButton()
    }

    private fun setupTabs() {
        binding.tabSignIn.setOnClickListener {
            if (isSignUpMode) {
                isSignUpMode = false
                updateTabUI()
            }
        }

        binding.tabSignUp.setOnClickListener {
            if (!isSignUpMode) {
                isSignUpMode = true
                updateTabUI()
            }
        }
    }

    private fun updateTabUI() {
        binding.tvAuthError.visibility = View.GONE
        if (isSignUpMode) {
            // Sign Up active
            binding.tabSignUp.backgroundTintList = ColorStateList.valueOf(ContextCompat.getColor(this, R.color.accent_cyan))
            binding.tabSignUp.setTextColor(ContextCompat.getColor(this, R.color.bg_dark))

            binding.tabSignIn.backgroundTintList = ColorStateList.valueOf(Color.TRANSPARENT)
            binding.tabSignIn.setTextColor(ContextCompat.getColor(this, R.color.text_secondary))

            binding.tilName.visibility = View.VISIBLE
            binding.tilConfirmPassword.visibility = View.VISIBLE
            binding.tvAuthSubtitle.text = "Create your secure PhishGuard account"
            binding.btnAuthSubmit.text = "Create Account"
        } else {
            // Sign In active
            binding.tabSignIn.backgroundTintList = ColorStateList.valueOf(ContextCompat.getColor(this, R.color.accent_cyan))
            binding.tabSignIn.setTextColor(ContextCompat.getColor(this, R.color.bg_dark))

            binding.tabSignUp.backgroundTintList = ColorStateList.valueOf(Color.TRANSPARENT)
            binding.tabSignUp.setTextColor(ContextCompat.getColor(this, R.color.text_secondary))

            binding.tilName.visibility = View.GONE
            binding.tilConfirmPassword.visibility = View.GONE
            binding.tvAuthSubtitle.text = "Sign in to your cybersecurity account"
            binding.btnAuthSubmit.text = "Sign In"
        }
    }

    private fun setupSubmitButton() {
        binding.btnAuthSubmit.setOnClickListener {
            binding.tvAuthError.visibility = View.GONE
            val email = binding.etEmail.text?.toString().orEmpty().trim()
            val password = binding.etPassword.text?.toString().orEmpty()

            if (isSignUpMode) {
                val name = binding.etName.text?.toString().orEmpty().trim()
                val confirmPass = binding.etConfirmPassword.text?.toString().orEmpty()

                if (name.isBlank()) {
                    showError("Please enter your full name.")
                    return@setOnClickListener
                }
                if (password != confirmPass) {
                    showError("Passwords do not match.")
                    return@setOnClickListener
                }

                val result = authRepository.register(name, email, password)
                result.fold(
                    onSuccess = {
                        navigateToMain()
                    },
                    onFailure = { error ->
                        showError(error.message ?: "Registration failed.")
                    }
                )
            } else {
                val result = authRepository.login(email, password)
                result.fold(
                    onSuccess = {
                        navigateToMain()
                    },
                    onFailure = { error ->
                        showError(error.message ?: "Invalid email or password.")
                    }
                )
            }
        }
    }

    private fun showError(message: String) {
        binding.tvAuthError.text = message
        binding.tvAuthError.visibility = View.VISIBLE
    }

    private fun navigateToMain() {
        startActivity(Intent(this, MainActivity::class.java))
        finish()
    }
}
