package com.example.securestoragecapabilitiesinspector

import java.util.Date

enum class BiometricEnrollmentStatus {
    ENROLLED,
    ONLY_DEVICE_CREDENTIALS_ENROLLED,
    UNKNOWN,
    UNSUPPORTED,
    HW_UNAVAILABLE,
    NONE_ENROLLED,
    NO_HARDWARE,
    SECURITIY_UPDATE_REQUIRED,
}

enum class StrongBoxKeystoreProperties {
    V300, V200, V100, V41, V40, VERSION_UNKNOWN
}

enum class KeyGenerationSecurityLevel {
    UNKNOWN,
    UNKNOWN_SECURE,
    SOFTWARE,
    TRUSTED_ENVIRONMENT,
    STRONGBOX,
}

data class SecureStorageCapabilities (
    val isDeviceSecure: Boolean,
    val biometricEnrollmentStatus: BiometricEnrollmentStatus,
    val strongBoxKeystoreProperties: StrongBoxKeystoreProperties?,
    val rsa256KeySecureStorageCapabilities: KeySecureStorageCapabilities,
    val rsa512KeySecureStorageCapabilities: KeySecureStorageCapabilities,
    val ec256KeySecureStorageCapabilities: KeySecureStorageCapabilities,
    val ec512KeySecureStorageCapabilities: KeySecureStorageCapabilities,
    val aesKeySecureStorageCapabilities: KeySecureStorageCapabilities,
)

data class KeySecureStorageCapabilities (
    val keyAlgorithm: String,
    val keyGenerationSuccessful: Boolean,
    val isKeyGenerationInsideSecureHardware: Boolean,
    val keyGenerationSecurityLevel: KeyGenerationSecurityLevel?,
    val isUserAuthenticationRequirementEnforcedBySecureHardware: Boolean,
    val certificateChain: List<Certificate>? = null,
)

data class Certificate (
    val subject: String,
    val notBefore: Date,
    val notAfter: Date,
    val stringRepresentation: String,
) {
    override fun toString(): String {
        return stringRepresentation
    }
}
