package com.phishguard.ai

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import com.phishguard.ai.databinding.ActivityMainBinding
import com.phishguard.ai.ui.assistant.AssistantFragment
import com.phishguard.ai.ui.history.HistoryFragment
import com.phishguard.ai.ui.home.HomeFragment
import com.phishguard.ai.ui.profile.ProfileFragment
import com.phishguard.ai.ui.scan.ScanFragment

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    private val homeFragment = HomeFragment()
    private val scanFragment = ScanFragment()
    private val assistantFragment = AssistantFragment()
    private val historyFragment = HistoryFragment()
    private val profileFragment = ProfileFragment()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Android 13+ Notification Post Permission
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.POST_NOTIFICATIONS), 101)
            }
        }

        setupBottomNavigation()

        // Load HomeFragment initially
        if (savedInstanceState == null) {
            switchFragment(homeFragment)
        }
    }

    private fun setupBottomNavigation() {
        binding.bottomNavigation.setOnItemSelectedListener { item ->
            when (item.itemId) {
                R.id.nav_home -> {
                    switchFragment(homeFragment)
                    true
                }
                R.id.nav_scan -> {
                    switchFragment(scanFragment)
                    true
                }
                R.id.nav_assistant -> {
                    switchFragment(assistantFragment)
                    true
                }
                R.id.nav_history -> {
                    switchFragment(historyFragment)
                    true
                }
                R.id.nav_profile -> {
                    switchFragment(profileFragment)
                    true
                }
                else -> false
            }
        }
    }

    private fun switchFragment(fragment: Fragment) {
        supportFragmentManager.beginTransaction()
            .replace(R.id.fragmentContainer, fragment)
            .commit()
    }

    fun navigateToTab(tabId: Int, initialTab: Int = 0) {
        if (tabId == R.id.nav_scan) {
            scanFragment.arguments = Bundle().apply { putInt("initial_tab", initialTab) }
        }
        binding.bottomNavigation.selectedItemId = tabId
    }
}
