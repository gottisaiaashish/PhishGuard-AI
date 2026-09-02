package com.phishguard.ai

import android.annotation.SuppressLint
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.animation.AlphaAnimation
import androidx.appcompat.app.AppCompatActivity
import com.phishguard.ai.data.SessionManager
import com.phishguard.ai.databinding.ActivitySplashBinding

@SuppressLint("CustomSplashScreen")
class SplashActivity : AppCompatActivity() {

    private lateinit var binding: ActivitySplashBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivitySplashBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Subtle logo fade-in
        val fadeIn = AlphaAnimation(0.2f, 1.0f).apply {
            duration = 900
        }
        binding.ivSplashLogo.startAnimation(fadeIn)

        Handler(Looper.getMainLooper()).postDelayed({
            val sessionManager = SessionManager.getInstance(this)
            if (sessionManager.isLoggedIn()) {
                startActivity(Intent(this, MainActivity::class.java))
            } else {
                startActivity(Intent(this, AuthActivity::class.java))
            }
            finish()
        }, 1200)
    }
}
