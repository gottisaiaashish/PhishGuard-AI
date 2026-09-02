package com.phishguard.ai

import android.content.Intent
import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import com.phishguard.ai.data.repository.AuthRepository
import com.phishguard.ai.databinding.ActivityLoginBinding

class LoginActivity : AppCompatActivity() {

    private lateinit var binding: ActivityLoginBinding
    private lateinit var authRepository: AuthRepository

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityLoginBinding.inflate(layoutInflater)
        setContentView(binding.root)

        authRepository = AuthRepository(this)

        setupLoginButton()
        setupNavigationToSignUp()
        setupForgotPassword()
    }

    private fun setupLoginButton() {
        binding.btnLoginSubmit.setOnClickListener {
            binding.tvLoginError.visibility = View.GONE
            val email = binding.etLoginEmail.text?.toString().orEmpty().trim()
            val password = binding.etLoginPassword.text?.toString().orEmpty()

            val result = authRepository.login(email, password)
            result.fold(
                onSuccess = {
                    startActivity(Intent(this, MainActivity::class.java))
                    finish()
                },
                onFailure = { error ->
                    binding.tvLoginError.text = error.message ?: "Invalid email or password."
                    binding.tvLoginError.visibility = View.VISIBLE
                }
            )
        }
    }

    private fun setupNavigationToSignUp() {
        binding.btnGoToSignUp.setOnClickListener {
            startActivity(Intent(this, SignUpActivity::class.java))
        }
    }

    private fun setupForgotPassword() {
        binding.tvForgotPassword.setOnClickListener {
            AlertDialog.Builder(this)
                .setTitle("Password Recovery")
                .setMessage("Enter your registered email address to receive password reset instructions.")
                .setPositiveButton("OK", null)
                .show()
        }
    }
}
