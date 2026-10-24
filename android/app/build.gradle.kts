plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.kankipro.klink"
    compileSdk = 35
    defaultConfig {
        applicationId = "com.kankipro.klink"
        minSdk = 23
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"
    }
    buildTypes {
        release {
            isMinifyEnabled = false
            isShrinkResources = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    packaging {
        jniLibs { useLegacyPackaging = false }
    }
    lint { abortOnError = true }
}

dependencies {
    implementation(fileTree(mapOf("dir" to "libs", "include" to listOf("*.jar", "*.aar"))))
}

tasks.register<Exec>("buildGoCore") {
    group = "build"
    description = "Builds the real KLINK gomobile AAR when it is missing."
    onlyIf { !file("libs/klink.aar").exists() || project.hasProperty("rebuildGo") }
    workingDir = rootDir
    commandLine("bash", "build-go.sh")
}
tasks.named("preBuild") { dependsOn("buildGoCore") }
