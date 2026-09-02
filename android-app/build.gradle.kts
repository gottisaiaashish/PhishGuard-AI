plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.android) apply false
}

// Redirect build artifacts outside OneDrive to prevent Windows/OneDrive file-locking conflicts
allprojects {
    val buildDirName = if (project == rootProject) "root" else project.name
    layout.buildDirectory.set(file("C:/Users/gotti/.phishguard-build/$buildDirName"))
}
