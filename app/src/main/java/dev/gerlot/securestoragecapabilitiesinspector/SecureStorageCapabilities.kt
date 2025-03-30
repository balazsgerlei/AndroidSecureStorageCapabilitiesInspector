package dev.gerlot.securestoragecapabilitiesinspector

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

enum class KeyAlgorithm(val displayName: String) {
    RSA_SHA256("RSA with SHA-256"),
    RSA_SHA512("RSA with SHA-512"),
    EC_SHA256("EC with SHA-256"),
    EC_SHA512("EC with SHA-512"),
    AES("AES"),
}

data class SecureStorageCapabilities (
    val isDeviceSecure: Boolean,
    val biometricEnrollmentStatus: BiometricEnrollmentStatus,
    val strongBoxKeystoreProperties: StrongBoxKeystoreProperties?,
    val keySecureStorageCapabilities: Map<KeyAlgorithm, KeySecureStorageCapabilities>,
)

data class KeySecureStorageCapabilities (
    val keyAlgorithm: KeyAlgorithm,
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
