package com.example.securestoragecapabilitiesinspector

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
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
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

class MainViewModel: ViewModel()  {

    private val _secureStorageCapabilities = MutableLiveData<SecureStorageCapabilities>()
    val secureStorageCapabilities: LiveData<SecureStorageCapabilities> = _secureStorageCapabilities

    private val _deviceInfo = MutableLiveData<DeviceInfo>()
    val deviceInfo: LiveData<DeviceInfo> = _deviceInfo

    fun retrieveDeviceInfo() {
        _deviceInfo.value = DeviceInfo(
            deviceName = Build.MODEL,
            deviceBrand = Build.MANUFACTURER,
            deviceModel = Build.DEVICE,
            androidVersion = Build.VERSION.RELEASE,
            androidApiLevel = Build.VERSION.SDK_INT,
        )
    }

    fun inspectSecureStorageCapabilities(context: Context) {
        CoroutineScope(Dispatchers.Default).launch {
            val keyGuardManager: KeyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
                load(null) // The KeyStore needs to be initialized via a call to load, to be able to use it
            }

            val isDeviceSecure = keyGuardManager.isDeviceSecure

            val strongBoxKeystoreProperties = getStrongBoxKeystoreProperties(context.packageManager)
            val canUseStrongBoxForKeyGeneration = strongBoxKeystoreProperties != null

            val biometricEnrollmentStatus = getBiometricEnrollmentStatus(BiometricManager.from(context))
            val canRequireUserAuthentication = biometricEnrollmentStatus == BiometricEnrollmentStatus.ENROLLED
                || biometricEnrollmentStatus == BiometricEnrollmentStatus.ONLY_DEVICE_CREDENTIALS_ENROLLED

            val sampleAESKey = generateSampleAESKey(
                shouldUseStrongBox = canUseStrongBoxForKeyGeneration,
                requireUserAuthentication = canRequireUserAuthentication)
            val sampleRSAKey = generateSampleRSAKeyPair(
                shouldUseStrongBox = canUseStrongBoxForKeyGeneration,
                requireUserAuthentication = canRequireUserAuthentication)?.private
            val sampleECKey = generateSampleECKeyPair(
                shouldUseStrongBox = canUseStrongBoxForKeyGeneration,
                requireUserAuthentication = canRequireUserAuthentication)?.private

            val sampleAESKeyInfo = getKeyInfoForAESKey(sampleAESKey)
            val sampleRSAKeyInfo = getKeyInfoForRSAKey(sampleRSAKey)
            val sampleECKeyInfo = getKeyInfoForECKey(sampleECKey)
            val rsaKeyCertificateChain: List<Certificate>? = certificateChainForKeyInfo(sampleRSAKeyInfo, keyStore)
            val ecKeyCertificateChain: List<Certificate>? = certificateChainForKeyInfo(sampleECKeyInfo, keyStore)

            val secureStorageCapabilitiesResult = SecureStorageCapabilities(
                isDeviceSecure,
                biometricEnrollmentStatus,
                strongBoxKeystoreProperties,
                rsaKeySecureStorageCapabilities = KeySecureStorageCapabilities(
                    keyAlgorithm = "RSA",
                    keyGenerationSuccessful = sampleRSAKey != null && sampleRSAKeyInfo != null,
                    isKeyGenerationInsideSecureHardware = sampleRSAKeyInfo?.isInsideSecureHardware ?: false,
                    keyGenerationSecurityLevel = keyGenerationSecurityLevelFromKeyInfo(sampleRSAKeyInfo),
                    isUserAuthenticationRequirementEnforcedBySecureHardware = sampleRSAKeyInfo?.isUserAuthenticationRequirementEnforcedBySecureHardware ?: false,
                    certificateChain = rsaKeyCertificateChain,
                ),
                ecKeySecureStorageCapabilities = KeySecureStorageCapabilities(
                    keyAlgorithm = "EC",
                    keyGenerationSuccessful = sampleECKey != null && sampleECKeyInfo != null,
                    isKeyGenerationInsideSecureHardware = sampleECKeyInfo?.isInsideSecureHardware ?: false,
                    keyGenerationSecurityLevel = keyGenerationSecurityLevelFromKeyInfo(sampleECKeyInfo),
                    isUserAuthenticationRequirementEnforcedBySecureHardware = sampleECKeyInfo?.isUserAuthenticationRequirementEnforcedBySecureHardware ?: false,
                    certificateChain = ecKeyCertificateChain,
                ),
                aesKeySecureStorageCapabilities = KeySecureStorageCapabilities(
                    keyAlgorithm = "AES",
                    keyGenerationSuccessful = sampleAESKey != null && sampleAESKeyInfo != null,
                    isKeyGenerationInsideSecureHardware = sampleAESKeyInfo?.isInsideSecureHardware ?: false,
                    keyGenerationSecurityLevel = keyGenerationSecurityLevelFromKeyInfo(sampleAESKeyInfo),
                    isUserAuthenticationRequirementEnforcedBySecureHardware = sampleAESKeyInfo?.isUserAuthenticationRequirementEnforcedBySecureHardware ?: false,
                ),
            )
            CoroutineScope(Dispatchers.Main).launch {
                _secureStorageCapabilities.value = secureStorageCapabilitiesResult
            }
        }
    }

    private fun getBiometricEnrollmentStatus(biometricManager: BiometricManager): BiometricEnrollmentStatus {
        var biometricEnrollmentStatus = when (biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)) {
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> BiometricEnrollmentStatus.HW_UNAVAILABLE
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> BiometricEnrollmentStatus.NO_HARDWARE
            BiometricManager.BIOMETRIC_SUCCESS -> BiometricEnrollmentStatus.ENROLLED
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> BiometricEnrollmentStatus.NONE_ENROLLED
            BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> BiometricEnrollmentStatus.SECURITIY_UPDATE_REQUIRED
            BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED -> BiometricEnrollmentStatus.UNSUPPORTED
            else -> BiometricEnrollmentStatus.UNKNOWN
        }
        if (biometricEnrollmentStatus != BiometricEnrollmentStatus.ENROLLED && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val canAuthenticateWithDeviceCredentials =
                biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL)
            if (canAuthenticateWithDeviceCredentials == BiometricManager.BIOMETRIC_SUCCESS) {
                biometricEnrollmentStatus = BiometricEnrollmentStatus.ONLY_DEVICE_CREDENTIALS_ENROLLED
            }
        }
        return biometricEnrollmentStatus
    }

    private fun getStrongBoxKeystoreProperties(packageManager: PackageManager) =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)) {
            when {
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

    private fun certificateChainForKeyInfo(keyInfo: KeyInfo?, keyStore: KeyStore): List<Certificate>? = keyInfo?.let {
        keyStore.getCertificateChain(keyInfo.keystoreAlias).map { certificate ->
            val x509Certificate = certificate as X509Certificate
            Certificate(
                subject = x509Certificate.subjectX500Principal.name,
                notBefore = x509Certificate.notBefore,
                notAfter = x509Certificate.notAfter,
                stringRepresentation = certificate.toString()
            )
        }
    }

    private fun keyGenerationSecurityLevelFromKeyInfo(keyInfo: KeyInfo?) = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        when(keyInfo?.securityLevel) {
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
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && ex is StrongBoxUnavailableException) {
                Log.d("SecureStorageCapabilitiesInspector", "StrongBox not available on the device, falling back to TEE")
                val keyGenerator = initKeyGeneratorWithAESKeyPair(shouldUseStrongBox = false, requireUserAuthentication)
                return keyGenerator.generateKey()
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
    ): KeyGenParameterSpec = KeyGenParameterSpec.Builder(
        SAMPLE_RSA_KEY_ALIAS,
        KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
    ).run {
        setDigests(KeyProperties.DIGEST_SHA256)
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
    ): KeyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE)
        .also { keyPairGenerator ->
            val startDate = GregorianCalendar()
            val endDate = GregorianCalendar().apply {
                add(Calendar.YEAR, 1)
            }

            val keyGenParameterSpec = createRSAKeyGenSpec(startDate, endDate, shouldUseStrongBox, requireUserAuthentication, attestationChallenge)
            keyPairGenerator.initialize(keyGenParameterSpec)
        }

    private fun generateSampleRSAKeyPair(
        shouldUseStrongBox: Boolean = false,
        requireUserAuthentication: Boolean = true,
    ): KeyPair? {
        val attestationChallenge = "test challenge phrase".toByteArray()
        try {
            val keyPairGenerator = initKeyPairGeneratorWithRSAKeyPair(
                shouldUseStrongBox,
                requireUserAuthentication,
                attestationChallenge,
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
                        )
                        return keyPairGenerator.genKeyPair()
                    } catch (pe: ProviderException) {
                        Log.d("SecureStorageCapabilitiesInspector", "ProviderException when attestation challenge provided re-init KeyPairGenerator without it")
                        val keyPairGenerator = initKeyPairGeneratorWithRSAKeyPair(
                            shouldUseStrongBox = false,
                            requireUserAuthentication
                        )
                        return keyPairGenerator.genKeyPair()
                    }
                } else {
                    Log.d("SecureStorageCapabilitiesInspector", "ProviderException when attestation challenge provided re-init KeyPairGenerator without it")
                    val keyPairGenerator = initKeyPairGeneratorWithRSAKeyPair(
                        shouldUseStrongBox,
                        requireUserAuthentication
                    )
                    return keyPairGenerator.genKeyPair()
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
    ) : KeyGenParameterSpec = KeyGenParameterSpec.Builder(
        SAMPLE_EC_KEY_ALIAS,
        KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
    ).run {
        setDigests(KeyProperties.DIGEST_SHA256)
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
    ): KeyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        .also { keyPairGenerator ->
            val startDate = GregorianCalendar()
            val endDate = GregorianCalendar().apply {
                add(Calendar.YEAR, 1)
            }

            val keyGenParameterSpec = createECKeyGenSpec(startDate, endDate, shouldUseStrongBox, requireUserAuthentication, attestationChallenge)
            keyPairGenerator.initialize(keyGenParameterSpec)
        }

    private fun generateSampleECKeyPair(
        shouldUseStrongBox: Boolean = false,
        requireUserAuthentication: Boolean = true,
    ): KeyPair? {
        val attestationChallenge = "test challenge phrase".toByteArray()
        try {
            val keyPairGenerator = initKeyPairGeneratorWithECKeyPair(
                shouldUseStrongBox,
                requireUserAuthentication,
                attestationChallenge,
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
                        )
                        return keyPairGenerator.genKeyPair()
                    } catch (pe: ProviderException) {
                        Log.d("SecureStorageCapabilitiesInspector", "ProviderException when attestation challenge provided re-init KeyPairGenerator without it")
                        val keyPairGenerator = initKeyPairGeneratorWithECKeyPair(
                            shouldUseStrongBox = false,
                            requireUserAuthentication
                        )
                        return keyPairGenerator.genKeyPair()
                    }
                } else {
                    Log.d("SecureStorageCapabilitiesInspector", "ProviderException when attestation challenge provided re-init KeyPairGenerator without it")
                    val keyPairGenerator = initKeyPairGeneratorWithECKeyPair(
                        shouldUseStrongBox,
                        requireUserAuthentication
                    )
                    return keyPairGenerator.genKeyPair()
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
