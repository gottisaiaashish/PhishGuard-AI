package com.phishguard.ai

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import android.util.Log

class SmsReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context?, intent: Intent?) {
        if (context == null || intent == null) return

        if (Telephony.Sms.Intents.SMS_RECEIVED_ACTION == intent.action) {
            val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent)
            for (sms in messages) {
                val sender = sms.displayOriginatingAddress ?: "Unknown SMS"
                val body = sms.displayMessageBody ?: ""

                Log.d("PhishGuardSMS", "Direct SMS received from $sender: $body")

                ThreatScanner.scanNotification(
                    context = context,
                    sender = sender,
                    messageText = body,
                    packageName = "com.android.mms"
                )
            }
        }
    }
}
