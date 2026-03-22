package dev.gerlot.securestoragecapabilitiesinspector

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Log
import androidx.biometric.BiometricManager
import androidx.lifecycle.ViewModel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.security.Key
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.ProviderException
import java.security.cert.X509Certificate
import java.util.Calendar
import java.util.GregorianCalendar
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory

private const val ANDROID_KEYSTORE = "AndroidKeyStore"
private const val SAMPLE_AES_KEY_ALIAS = "sample_aes_key"
private const val SAMPLE_RSA_KEY_ALIAS = "sample_rsa_key"
private const val SAMPLE_EC_KEY_ALIAS = "sample_ec_key"

class MainViewModel : ViewModel() {

    private val _deviceInfo = MutableStateFlow(
        DeviceInfo(
            deviceName = Build.MODEL ?: "Unknown",
            deviceBrand = Build.MANUFACTURER ?: "Unknown",
            deviceModel = Build.DEVICE ?: "Unknown",
            androidVersion = Build.VERSION.RELEASE ?: "Unknown",
            androidApiLevel = Build.VERSION.SDK_INT,
            androidVariantName = AndroidVariantUtils.variantName
        )
    )
    val deviceInfo = _deviceInfo.asStateFlow()

    private val _secureStorageCapabilities = MutableStateFlow<SecureStorageCapabilities?>(null)
    val secureStorageCapabilities = _secureStorageCapabilities.asStateFlow()

    private val _keySecureStorageCapabilities = MutableStateFlow<Map<KeyAlgorithm, KeySecureStorageCapabilities>?>(null)
    val keySecureStorageCapabilities = _keySecureStorageCapabilities.asStateFlow()

    fun checkForGrapheneOs(context: Context) {
        if (GrapheneOsHelper.isGrapheneOs(context)) {
            _deviceInfo.value = _deviceInfo.value.copy(
                androidVariantName = "GrapheneOS"
            )
        }
    }

    fun inspectSecureStorageCapabilities(context: Context) {
        val keyGuardManager: KeyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager

        val isDeviceSecure = keyGuardManager.isDeviceSecure

        val strongBoxKeystoreProperties = getStrongBoxKeystoreProperties(context.packageManager)
        val canUseStrongBoxForKeyGeneration = strongBoxKeystoreProperties != null

        val biometricEnrollmentStatus = getBiometricEnrollmentStatus(BiometricManager.from(context))
        val canRequireUserAuthentication = biometricEnrollmentStatus == BiometricEnrollmentStatus.ENROLLED
                || biometricEnrollmentStatus == BiometricEnrollmentStatus.ONLY_DEVICE_CREDENTIALS_ENROLLED

        _secureStorageCapabilities.value = SecureStorageCapabilities(
            isDeviceSecure,
            biometricEnrollmentStatus,
            strongBoxKeystoreProperties,
        )
        inspectKeySecureStorageCapabilities(canUseStrongBoxForKeyGeneration, canRequireUserAuthentication)
    }

    private fun inspectKeySecureStorageCapabilities(
        canUseStrongBoxForKeyGeneration: Boolean,
        canRequireUserAuthentication: Boolean
    ) {
        CoroutineScope(Dispatchers.Default).launch {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
                load(null) // The KeyStore needs to be initialized via a call to load, to be able to use it
            }

            val sampleAESKey = generateSampleAESKey(
                shouldUseStrongBox = canUseStrongBoxForKeyGeneration,
                requireUserAuthentication = canRequireUserAuthentication
            )
            val sampleRSA256Key = generateSampleRSAKeyPair(
                shouldUseStrongBox = canUseStrongBoxForKeyGeneration,
                requireUserAuthentication = canRequireUserAuthentication,
                digest = KeyProperties.DIGEST_SHA256
            )?.private
            val sampleRSA512Key = generateSampleRSAKeyPair(
                shouldUseStrongBox = canUseStrongBoxForKeyGeneration,
                requireUserAuthentication = canRequireUserAuthentication,
                digest = KeyProperties.DIGEST_SHA512
            )?.private
            val sampleEC256Key = generateSampleECKeyPair(
                shouldUseStrongBox = canUseStrongBoxForKeyGeneration,
                requireUserAuthentication = canRequireUserAuthentication,
                digest = KeyProperties.DIGEST_SHA256
            )?.private
            val sampleEC512Key = generateSampleECKeyPair(
                shouldUseStrongBox = canUseStrongBoxForKeyGeneration,
                requireUserAuthentication = canRequireUserAuthentication,
                digest = KeyProperties.DIGEST_SHA512
            )?.private

            val sampleAESKeyInfo = getKeyInfoForAESKey(sampleAESKey)
            val sampleRSA256KeyInfo = getKeyInfoForRSAKey(sampleRSA256Key)
            val sampleRSA512KeyInfo = getKeyInfoForRSAKey(sampleRSA512Key)
            val sampleEC256KeyInfo = getKeyInfoForECKey(sampleEC256Key)
            val sampleEC512KeyInfo = getKeyInfoForECKey(sampleEC512Key)
            val rsa256KeyCertificateChain: List<Certificate>? = certificateChainForKeyInfo(sampleRSA256KeyInfo, keyStore)
            val rsa512KeyCertificateChain: List<Certificate>? = certificateChainForKeyInfo(sampleRSA512KeyInfo, keyStore)
            val ec256KeyCertificateChain: List<Certificate>? = certificateChainForKeyInfo(sampleEC256KeyInfo, keyStore)
            val ec512KeyCertificateChain: List<Certificate>? = certificateChainForKeyInfo(sampleEC512KeyInfo, keyStore)

            val keySecureStorageCapabilities: Map<KeyAlgorithm, KeySecureStorageCapabilities> = mapOf (
                KeyAlgorithm.RSA_SHA256 to KeySecureStorageCapabilities(
                    keyAlgorithm = KeyAlgorithm.RSA_SHA256,
                    keyGenerationSuccessful = sampleRSA256Key != null && sampleRSA256KeyInfo != null,
                    isKeyGenerationInsideSecureHardware = sampleRSA256KeyInfo?.isInsideSecureHardware ?: false,
                    keyGenerationSecurityLevel = keyGenerationSecurityLevelFromKeyInfo(sampleRSA256KeyInfo),
                    isUserAuthenticationRequirementEnforcedBySecureHardware = sampleRSA256KeyInfo?.isUserAuthenticationRequirementEnforcedBySecureHardware ?: false,
                    certificateChain = rsa256KeyCertificateChain,
                ),
                KeyAlgorithm.RSA_SHA512 to KeySecureStorageCapabilities(
                    keyAlgorithm = KeyAlgorithm.RSA_SHA512,
                    keyGenerationSuccessful = sampleRSA512Key != null && sampleRSA512KeyInfo != null,
                    isKeyGenerationInsideSecureHardware = sampleRSA512KeyInfo?.isInsideSecureHardware ?: false,
                    keyGenerationSecurityLevel = keyGenerationSecurityLevelFromKeyInfo(sampleRSA512KeyInfo),
                    isUserAuthenticationRequirementEnforcedBySecureHardware = sampleRSA512KeyInfo?.isUserAuthenticationRequirementEnforcedBySecureHardware ?: false,
                    certificateChain = rsa512KeyCertificateChain,
                ),
                KeyAlgorithm.EC_SHA256 to KeySecureStorageCapabilities(
                    keyAlgorithm = KeyAlgorithm.EC_SHA256,
                    keyGenerationSuccessful = sampleEC256Key != null && sampleEC256KeyInfo != null,
                    isKeyGenerationInsideSecureHardware = sampleEC256KeyInfo?.isInsideSecureHardware ?: false,
                    keyGenerationSecurityLevel = keyGenerationSecurityLevelFromKeyInfo(sampleEC256KeyInfo),
                    isUserAuthenticationRequirementEnforcedBySecureHardware = sampleEC256KeyInfo?.isUserAuthenticationRequirementEnforcedBySecureHardware ?: false,
                    certificateChain = ec256KeyCertificateChain,
                ),
                KeyAlgorithm.EC_SHA512 to KeySecureStorageCapabilities(
                    keyAlgorithm = KeyAlgorithm.EC_SHA512,
                    keyGenerationSuccessful = sampleEC512Key != null && sampleEC512KeyInfo != null,
                    isKeyGenerationInsideSecureHardware = sampleEC512KeyInfo?.isInsideSecureHardware ?: false,
                    keyGenerationSecurityLevel = keyGenerationSecurityLevelFromKeyInfo(sampleEC512KeyInfo),
                    isUserAuthenticationRequirementEnforcedBySecureHardware = sampleEC512KeyInfo?.isUserAuthenticationRequirementEnforcedBySecureHardware ?: false,
                    certificateChain = ec512KeyCertificateChain,
                ),
                KeyAlgorithm.AES to KeySecureStorageCapabilities(
                    keyAlgorithm = KeyAlgorithm.AES,
                    keyGenerationSuccessful = sampleAESKey != null && sampleAESKeyInfo != null,
                    isKeyGenerationInsideSecureHardware = sampleAESKeyInfo?.isInsideSecureHardware ?: false,
                    keyGenerationSecurityLevel = keyGenerationSecurityLevelFromKeyInfo(sampleAESKeyInfo),
                    isUserAuthenticationRequirementEnforcedBySecureHardware = sampleAESKeyInfo?.isUserAuthenticationRequirementEnforcedBySecureHardware ?: false,
                ),
            )

            CoroutineScope(Dispatchers.Main).launch {
                _keySecureStorageCapabilities.value = keySecureStorageCapabilities
            }
        }
    }

    private fun getBiometricEnrollmentStatus(biometricManager: BiometricManager): BiometricEnrollmentStatus {
        var biometricEnrollmentStatus = when (biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)) {
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> BiometricEnrollmentStatus.HW_UNAVAILABLE
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> BiometricEnrollmentStatus.NO_HARDWARE
            BiometricManager.BIOMETRIC_SUCCESS -> BiometricEnrollmentStatus.ENROLLED
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> BiometricEnrollmentStatus.NONE_ENROLLED
            BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> BiometricEnrollmentStatus.SECURITY_UPDATE_REQUIRED
            BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED -> BiometricEnrollmentStatus.UNSUPPORTED
            else -> BiometricEnrollmentStatus.UNKNOWN
        }
        if (biometricEnrollmentStatus != BiometricEnrollmentStatus.ENROLLED && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val canAuthenticateWithDeviceCredentials =
                biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL)
            if (canAuthenticateWithDeviceCredentials == BiometricManager.BIOMETRIC_SUCCESS) {
                biometricEnrollmentStatus =
                    BiometricEnrollmentStatus.ONLY_DEVICE_CREDENTIALS_ENROLLED
            }
        }
        return biometricEnrollmentStatus
    }

    private fun getStrongBoxKeystoreProperties(packageManager: PackageManager) =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)) {
            when {
                packageManager.hasSystemFeature(
                    PackageManager.FEATURE_STRONGBOX_KEYSTORE,
                    400
                ) -> StrongBoxKeystoreProperties.V400

                packageManager.hasSystemFeature(
                    PackageManager.FEATURE_STRONGBOX_KEYSTORE,
                    300
                ) -> StrongBoxKeystoreProperties.V300

                packageManager.hasSystemFeature(
                    PackageManager.FEATURE_STRONGBOX_KEYSTORE,
                    200
                ) -> StrongBoxKeystoreProperties.V200

                packageManager.hasSystemFeature(
                    PackageManager.FEATURE_STRONGBOX_KEYSTORE,
                    100
                ) -> StrongBoxKeystoreProperties.V100

                packageManager.hasSystemFeature(
                    PackageManager.FEATURE_STRONGBOX_KEYSTORE,
                    41
                ) -> StrongBoxKeystoreProperties.V41

                packageManager.hasSystemFeature(
                    PackageManager.FEATURE_STRONGBOX_KEYSTORE,
                    40
                ) -> StrongBoxKeystoreProperties.V40

                else -> StrongBoxKeystoreProperties.VERSION_UNKNOWN
            }
        } else null

    private fun getKeyInfoForAESKey(key: Key?) = key?.let {
        getKeyInfoForSymmetricSecretKey(it as SecretKey)
    }

    private fun getKeyInfoForRSAKey(key: Key?) = key?.let {
        getKeyInfoForAsymmetricPrivateKey(it as PrivateKey)
    }

    private fun getKeyInfoForECKey(key: Key?) = key?.let {
        getKeyInfoForAsymmetricPrivateKey(it as PrivateKey)
    }

    private fun certificateChainForKeyInfo(
        keyInfo: KeyInfo?,
        keyStore: KeyStore
    ): List<Certificate>? = keyInfo?.let {
        keyStore.getCertificateChain(keyInfo.keystoreAlias).map { certificate ->
            val x509Certificate = certificate as X509Certificate
            Certificate(
                subject = x509Certificate.subjectX500Principal.name,
                notBefore = x509Certificate.notBefore,
                notAfter = x509Certificate.notAfter,
                stringRepresentation = certificate.toString(),
                encoded = certificate.encoded,
            )
        }
    }

    private fun keyGenerationSecurityLevelFromKeyInfo(keyInfo: KeyInfo?) =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            when (keyInfo?.securityLevel) {
                KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE -> KeyGenerationSecurityLevel.UNKNOWN_SECURE
                KeyProperties.SECURITY_LEVEL_SOFTWARE -> KeyGenerationSecurityLevel.SOFTWARE
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> KeyGenerationSecurityLevel.TRUSTED_ENVIRONMENT
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> KeyGenerationSecurityLevel.STRONGBOX
                else -> KeyGenerationSecurityLevel.UNKNOWN
            }
        } else null

    private fun createAESKeyGenSpec(
        shouldUseStrongBox: Boolean,
        requireUserAuthentication: Boolean,
    ): KeyGenParameterSpec = KeyGenParameterSpec.Builder(
        SAMPLE_AES_KEY_ALIAS,
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
    ).run {
        setBlockModes(KeyProperties.BLOCK_MODE_CBC)
        setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
        setRandomizedEncryptionRequired(true)
        setUserAuthenticationRequired(requireUserAuthentication)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            setIsStrongBoxBacked(shouldUseStrongBox)
        }
        build()
    }

    private fun initKeyGeneratorWithAESKeyPair(
        shouldUseStrongBox: Boolean = false,
        requireUserAuthentication: Boolean = true,
    ): KeyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES).also { keyGenerator ->
        val keyGenParameterSpec = createAESKeyGenSpec(shouldUseStrongBox, requireUserAuthentication)
        keyGenerator.init(keyGenParameterSpec)
    }

    private fun generateSampleAESKey(
        shouldUseStrongBox: Boolean = false,
        requireUserAuthentication: Boolean = true,
    ): SecretKey? {
        try {
            val keyGenerator = initKeyGeneratorWithAESKeyPair(shouldUseStrongBox, requireUserAuthentication)
            return keyGenerator.generateKey()
        } catch (ex: Exception) {
            if (ex is ProviderException) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && ex is StrongBoxUnavailableException) {
                    Log.d("SecureStorageCapabilitiesInspector", "StrongBox not available on the device, falling back to TEE")
                    val keyGenerator = initKeyGeneratorWithAESKeyPair(shouldUseStrongBox = false, requireUserAuthentication)
                    return keyGenerator.generateKey()
                } else {
                    try {
                        Log.d("SecureStorageCapabilitiesInspector", "ProviderException when StrongBox tried to be used re-init KeyGenerator without it")
                        val keyGenerator = initKeyGeneratorWithAESKeyPair(shouldUseStrongBox = false, requireUserAuthentication)
                        return keyGenerator.generateKey()
                    } catch (e: Exception) {
                        Log.d("SecureStorageCapabilitiesInspector", "Could not determine if private key is in secure hardware or not")
                        return null
                    }
                }
            } else {
                Log.d("SecureStorageCapabilitiesInspector", "Could not determine if private key is in secure hardware or not")
                return null
            }

        }
    }

    private fun getKeyInfoForSymmetricSecretKey(secretKey: SecretKey): KeyInfo {
        val factory = SecretKeyFactory.getInstance(secretKey.algorithm, ANDROID_KEYSTORE)
        return factory.getKeySpec(secretKey, KeyInfo::class.java) as KeyInfo
    }

    private fun createRSAKeyGenSpec(
        startDate: GregorianCalendar,
        endDate: GregorianCalendar,
        shouldUseStrongBox: Boolean,
        requireUserAuthentication: Boolean,
        attestationChallenge: ByteArray?,
        digest: String,
    ): KeyGenParameterSpec = KeyGenParameterSpec.Builder(
        SAMPLE_RSA_KEY_ALIAS,
        KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
    ).run {
        setDigests(digest)
        setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
        setCertificateNotBefore(startDate.time)
        setCertificateNotAfter(endDate.time)
        setUserAuthenticationRequired(requireUserAuthentication)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            setIsStrongBoxBacked(shouldUseStrongBox)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N && attestationChallenge != null) {
            setAttestationChallenge(attestationChallenge)
        }
        build()
    }

    private fun initKeyPairGeneratorWithRSAKeyPair(
        shouldUseStrongBox: Boolean = false,
        requireUserAuthentication: Boolean = true,
        attestationChallenge: ByteArray? = null,
        digest: String,
    ): KeyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE)
        .also { keyPairGenerator ->
            val startDate = GregorianCalendar()
            val endDate = GregorianCalendar().apply {
                add(Calendar.YEAR, 1)
            }

            val keyGenParameterSpec = createRSAKeyGenSpec(startDate, endDate, shouldUseStrongBox, requireUserAuthentication, attestationChallenge, digest)
            keyPairGenerator.initialize(keyGenParameterSpec)
        }

    private fun generateSampleRSAKeyPair(
        shouldUseStrongBox: Boolean = false,
        requireUserAuthentication: Boolean = true,
        digest: String = KeyProperties.DIGEST_SHA256,
    ): KeyPair? {
        val attestationChallenge = "test challenge phrase".toByteArray()
        try {
            val keyPairGenerator = initKeyPairGeneratorWithRSAKeyPair(
                shouldUseStrongBox,
                requireUserAuthentication,
                attestationChallenge,
                digest
            )
            return keyPairGenerator.genKeyPair()
        } catch (ex: Exception) {
            if (ex is ProviderException) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && ex is StrongBoxUnavailableException) {
                    Log.d("SecureStorageCapabilitiesInspector", "StrongBox not available on the device, falling back to TEE")
                    try {
                        val keyPairGenerator = initKeyPairGeneratorWithRSAKeyPair(
                            shouldUseStrongBox = false,
                            requireUserAuthentication,
                            attestationChallenge,
                            digest
                        )
                        return keyPairGenerator.genKeyPair()
                    } catch (pe: ProviderException) {
                        Log.d("SecureStorageCapabilitiesInspector", "ProviderException when attestation challenge provided re-init KeyPairGenerator without it")
                        val keyPairGenerator = initKeyPairGeneratorWithRSAKeyPair(
                            shouldUseStrongBox = false,
                            requireUserAuthentication,
                            digest = digest
                        )
                        return keyPairGenerator.genKeyPair()
                    }
                } else {
                    if (ex.cause?.message?.contains("Unsupported digest") == true && shouldUseStrongBox) {
                        Log.d("SecureStorageCapabilitiesInspector", "ProviderException caused by unsupported digest when Strongbox should be used re-init KeyPairGenerator without it")
                        val keyPairGenerator = initKeyPairGeneratorWithRSAKeyPair(
                            shouldUseStrongBox = false,
                            requireUserAuthentication,
                            attestationChallenge,
                            digest = digest
                        )
                        return keyPairGenerator.genKeyPair()
                    } else {
                        try {
                            Log.d("SecureStorageCapabilitiesInspector", "ProviderException when attestation challenge provided re-init KeyPairGenerator without it")
                            val keyPairGenerator = initKeyPairGeneratorWithRSAKeyPair(
                                shouldUseStrongBox,
                                requireUserAuthentication,
                                digest = digest
                            )
                            return keyPairGenerator.genKeyPair()
                        } catch (pe: ProviderException) {
                            try {
                                Log.d("SecureStorageCapabilitiesInspector", "ProviderException when StrongBox tried to be used re-init KeyGenerator without it")
                                val keyPairGenerator = initKeyPairGeneratorWithRSAKeyPair(
                                    shouldUseStrongBox = false,
                                    requireUserAuthentication,
                                    attestationChallenge,
                                    digest = digest
                                )
                                return keyPairGenerator.genKeyPair()
                            } catch (e: Exception) {
                                Log.d("SecureStorageCapabilitiesInspector", "Could not determine if private key is in secure hardware or not")
                                return null
                            }
                        }
                    }
                }
            } else {
                Log.d("SecureStorageCapabilitiesInspector", "Could not determine if private key is in secure hardware or not")
                return null
            }
        }
    }

    private fun createECKeyGenSpec(
        startDate: GregorianCalendar,
        endDate: GregorianCalendar,
        shouldUseStrongBox: Boolean,
        requireUserAuthentication: Boolean,
        attestationChallenge: ByteArray?,
        digest: String,
    ): KeyGenParameterSpec = KeyGenParameterSpec.Builder(
        SAMPLE_EC_KEY_ALIAS,
        KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
    ).run {
        setDigests(digest)
        setCertificateNotBefore(startDate.time)
        setCertificateNotAfter(endDate.time)
        setUserAuthenticationRequired(requireUserAuthentication)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            setIsStrongBoxBacked(shouldUseStrongBox)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N && attestationChallenge != null) {
            setAttestationChallenge(attestationChallenge)
        }
        build()
    }

    private fun initKeyPairGeneratorWithECKeyPair(
        shouldUseStrongBox: Boolean = false,
        requireUserAuthentication: Boolean = true,
        attestationChallenge: ByteArray? = null,
        digest: String,
    ): KeyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        .also { keyPairGenerator ->
            val startDate = GregorianCalendar()
            val endDate = GregorianCalendar().apply {
                add(Calendar.YEAR, 1)
            }

            val keyGenParameterSpec = createECKeyGenSpec(startDate, endDate, shouldUseStrongBox, requireUserAuthentication, attestationChallenge, digest)
            keyPairGenerator.initialize(keyGenParameterSpec)
        }

    private fun generateSampleECKeyPair(
        shouldUseStrongBox: Boolean = false,
        requireUserAuthentication: Boolean = true,
        digest: String = KeyProperties.DIGEST_SHA256,
    ): KeyPair? {
        val attestationChallenge = "test challenge phrase".toByteArray()
        try {
            val keyPairGenerator = initKeyPairGeneratorWithECKeyPair(
                shouldUseStrongBox,
                requireUserAuthentication,
                attestationChallenge,
                digest
            )
            return keyPairGenerator.genKeyPair()
        } catch (ex: Exception) {
            if (ex is ProviderException) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && ex is StrongBoxUnavailableException) {
                    Log.d("SecureStorageCapabilitiesInspector", "StrongBox not available on the device, falling back to TEE")
                    try {
                        val keyPairGenerator = initKeyPairGeneratorWithECKeyPair(
                            shouldUseStrongBox = false,
                            requireUserAuthentication,
                            attestationChallenge,
                            digest = digest
                        )
                        return keyPairGenerator.genKeyPair()
                    } catch (pe: ProviderException) {
                        Log.d("SecureStorageCapabilitiesInspector", "ProviderException when attestation challenge provided re-init KeyPairGenerator without it")
                        val keyPairGenerator = initKeyPairGeneratorWithECKeyPair(
                            shouldUseStrongBox = false,
                            requireUserAuthentication,
                            digest = digest
                        )
                        return keyPairGenerator.genKeyPair()
                    }
                } else {
                    if (ex.cause?.message?.contains("Unsupported digest") == true && shouldUseStrongBox) {
                        Log.d("SecureStorageCapabilitiesInspector", "ProviderException caused by unsupported digest when Strongbox should be used re-init KeyPairGenerator without it")
                        val keyPairGenerator = initKeyPairGeneratorWithECKeyPair(
                            shouldUseStrongBox = false,
                            requireUserAuthentication,
                            attestationChallenge,
                            digest = digest
                        )
                        return keyPairGenerator.genKeyPair()
                    } else {
                        try {
                            Log.d("SecureStorageCapabilitiesInspector", "ProviderException when attestation challenge provided re-init KeyPairGenerator without it")
                            val keyPairGenerator = initKeyPairGeneratorWithECKeyPair(
                                shouldUseStrongBox,
                                requireUserAuthentication,
                                digest = digest
                            )
                            return keyPairGenerator.genKeyPair()
                        } catch (pe: ProviderException) {
                            try {
                                Log.d("SecureStorageCapabilitiesInspector", "ProviderException when StrongBox tried to be used re-init KeyGenerator without it")
                                val keyPairGenerator = initKeyPairGeneratorWithECKeyPair(
                                    shouldUseStrongBox = false,
                                    requireUserAuthentication,
                                    attestationChallenge,
                                    digest = digest
                                )
                                return keyPairGenerator.genKeyPair()
                            } catch (e: Exception) {
                                Log.d("SecureStorageCapabilitiesInspector", "Could not determine if private key is in secure hardware or not")
                                return null
                            }
                        }
                    }
                }
            } else {
                Log.d("SecureStorageCapabilitiesInspector", "Could not determine if private key is in secure hardware or not")
                return null
            }
        }
    }

    private fun getKeyInfoForAsymmetricPrivateKey(privateKey: PrivateKey): KeyInfo {
        val factory: KeyFactory = KeyFactory.getInstance(privateKey.algorithm, ANDROID_KEYSTORE)
        return factory.getKeySpec(privateKey, KeyInfo::class.java)
    }

}
