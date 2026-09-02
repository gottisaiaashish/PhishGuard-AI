# Proguard rules for PhishGuard AI
-keepattributes *Annotation*
-keepclassmembers class * {
    @org.json.* <fields>;
}
