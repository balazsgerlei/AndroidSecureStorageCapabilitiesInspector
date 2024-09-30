package com.example.securestoragecapabilitiesinspector

import java.security.cert.Certificate

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
    val certificateChain: Array<Certificate>? = null,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as KeySecureStorageCapabilities

        if (keyGenerationSuccessful != other.keyGenerationSuccessful) return false
        if (isKeyGenerationInsideSecureHardware != other.isKeyGenerationInsideSecureHardware) return false
        if (keyGenerationSecurityLevel != other.keyGenerationSecurityLevel) return false
        if (isUserAuthenticationRequirementEnforcedBySecureHardware != other.isUserAuthenticationRequirementEnforcedBySecureHardware) return false
        if (certificateChain != null) {
            if (other.certificateChain == null) return false
            if (!certificateChain.contentEquals(other.certificateChain)) return false
        } else if (other.certificateChain != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = keyGenerationSuccessful.hashCode()
        result = 31 * result + isKeyGenerationInsideSecureHardware.hashCode()
        result = 31 * result + (keyGenerationSecurityLevel?.hashCode() ?: 0)
        result = 31 * result + isUserAuthenticationRequirementEnforcedBySecureHardware.hashCode()
        result = 31 * result + (certificateChain?.contentHashCode() ?: 0)
        return result
    }
}
