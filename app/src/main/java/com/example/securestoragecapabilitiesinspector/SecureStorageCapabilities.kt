package com.example.securestoragecapabilitiesinspector

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
    val aesKeySecureStorageCapabilities: KeySecureStorageCapabilities,
    val rsaKeySecureStorageCapabilities: KeySecureStorageCapabilities,
)

data class KeySecureStorageCapabilities (
    val keyGenerationSuccessful: Boolean,
    val isKeyGenerationInsideSecureHardware: Boolean,
    val keyGenerationSecurityLevel: KeyGenerationSecurityLevel?,
    val isUserAuthenticationRequirementEnforcedBySecureHardware: Boolean,
)
