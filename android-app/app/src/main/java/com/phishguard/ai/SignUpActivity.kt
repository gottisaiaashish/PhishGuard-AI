package com.phishguard.ai

import android.content.Intent
import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import com.phishguard.ai.data.repository.AuthRepository
import com.phishguard.ai.databinding.ActivitySignupBinding

class SignUpActivity : AppCompatActivity() {

    private lateinit var binding: ActivitySignupBinding
    private lateinit var authRepository: AuthRepository

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivitySignupBinding.inflate(layoutInflater)
        setContentView(binding.root)

        authRepository = AuthRepository(this)

        setupButtons()
    }

    private fun setupButtons() {
        binding.btnSignUpBack.setOnClickListener {
            finish()
        }

        binding.btnGoToLogin.setOnClickListener {
            finish()
        }

        binding.btnSignUpSubmit.setOnClickListener {
            binding.tvSignUpError.visibility = View.GONE

            val name = binding.etSignUpName.text?.toString().orEmpty().trim()
            val email = binding.etSignUpEmail.text?.toString().orEmpty().trim()
            val password = binding.etSignUpPassword.text?.toString().orEmpty()
            val confirmPass = binding.etSignUpConfirmPassword.text?.toString().orEmpty()

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
                    val intent = Intent(this, MainActivity::class.java).apply {
                        flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
                    }
                    startActivity(intent)
                    finish()
                },
                onFailure = { error ->
                    showError(error.message ?: "Registration failed.")
                }
            )
        }
    }

    private fun showError(message: String) {
        binding.tvSignUpError.text = message
        binding.tvSignUpError.visibility = View.VISIBLE
    }
}
