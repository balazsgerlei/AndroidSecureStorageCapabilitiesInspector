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
import java.math.BigInteger
import java.security.GeneralSecurityException
import java.security.Key
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.ProviderException
import java.security.cert.Certificate
import java.util.Calendar
import java.util.GregorianCalendar
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.security.auth.x500.X500Principal

private const val ANDROID_KEYSTORE = "AndroidKeyStore"
private const val SAMPLE_AES_KEY_ALIAS = "sample_aes_key"
private const val SAMPLE_RSA_KEY_ALIAS = "sample_rsa_key"

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

            val sampleAESKeyInfo = getKeyInfoForAESKey(sampleAESKey)
            val sampleRSAKeyInfo = getKeyInfoForRSAKey(sampleRSAKey)
            val rsaKeyCertificateChain: Array<Certificate>? = keyStore.getCertificateChain(sampleRSAKeyInfo?.keystoreAlias)

            val secureStorageCapabilitiesResult = SecureStorageCapabilities(
                isDeviceSecure,
                biometricEnrollmentStatus,
                strongBoxKeystoreProperties,
                aesKeySecureStorageCapabilities = KeySecureStorageCapabilities(
                    keyGenerationSuccessful = sampleAESKey != null && sampleAESKeyInfo != null,
                    isKeyGenerationInsideSecureHardware = sampleAESKeyInfo?.isInsideSecureHardware ?: false,
                    keyGenerationSecurityLevel = keyGenerationSecurityLevelFromKeyInfo(sampleAESKeyInfo),
                    isUserAuthenticationRequirementEnforcedBySecureHardware = sampleAESKeyInfo?.isUserAuthenticationRequirementEnforcedBySecureHardware ?: false,
                ),
                rsaKeySecureStorageCapabilities = KeySecureStorageCapabilities(
                    keyGenerationSuccessful = sampleRSAKey != null && sampleRSAKeyInfo != null,
                    isKeyGenerationInsideSecureHardware = sampleRSAKeyInfo?.isInsideSecureHardware ?: false,
                    keyGenerationSecurityLevel = keyGenerationSecurityLevelFromKeyInfo(sampleRSAKeyInfo),
                    isUserAuthenticationRequirementEnforcedBySecureHardware = sampleRSAKeyInfo?.isUserAuthenticationRequirementEnforcedBySecureHardware ?: false,
                    certificateChain = rsaKeyCertificateChain,
                )
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
            try {
                setIsStrongBoxBacked(shouldUseStrongBox)
            } catch (ex: StrongBoxUnavailableException) {
                Log.d("SecureStorageCapabilitiesInspector", "StrongBox not available on the device")
            }
        }
        build()
    }

    private fun initKeyGeneratorWithAESKeyPair(
        shouldUseStrongBox: Boolean = false,
        requireUserAuthentication: Boolean = true,
    ): KeyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES).also { keyGenerator ->
        try {
            createAESKeyGenSpec(shouldUseStrongBox, requireUserAuthentication)
        } catch (ex: Exception) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && ex is StrongBoxUnavailableException) {
                Log.d("SecureStorageCapabilitiesInspector", "StrongBox not available on the device, falling back to TEE")
                createAESKeyGenSpec(shouldUseStrongBox = false, requireUserAuthentication)
            } else {
                null
            }
        }?.also {
            keyGenerator.init(it)
        }
    }

    private fun generateSampleAESKey(
        shouldUseStrongBox: Boolean = false,
        requireUserAuthentication: Boolean = true,
    ): SecretKey? {
        try {
            val keyGenerator = initKeyGeneratorWithAESKeyPair(shouldUseStrongBox, requireUserAuthentication)
            return keyGenerator.generateKey()
        } catch (e: GeneralSecurityException) {
            Log.d("SecureStorageCapabilitiesInspector", "Could not determine if private key is in secure hardware or not")
        }
        return null
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
        setCertificateSerialNumber(BigInteger.valueOf(777))                 // Serial number used for the self-signed certificate of the generated key pair, default is 1
        setCertificateSubject(X500Principal("CN=$SAMPLE_RSA_KEY_ALIAS"))  // Subject used for the self-signed certificate of the generated key pair, default is CN=fake
        setDigests(KeyProperties.DIGEST_SHA256)                                 // Set of digests algorithms with which the key can be used
        setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)         // Set of padding schemes with which the key can be used when signing/verifying
        setCertificateNotBefore(startDate.time)                                 // Start of the validity period for the self-signed certificate of the generated, default Jan 1 1970
        setCertificateNotAfter(endDate.time)                                    // End of the validity period for the self-signed certificate of the generated key, default Jan 1 2048
        setUserAuthenticationRequired(requireUserAuthentication)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                setIsStrongBoxBacked(shouldUseStrongBox)
            } catch (ex: StrongBoxUnavailableException) {
                Log.d("SecureStorageCapabilitiesInspector", "StrongBox not available on the device")
            }
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
            val endDate = GregorianCalendar()
            endDate.add(Calendar.YEAR, 1)

            try {
                createRSAKeyGenSpec(startDate, endDate, shouldUseStrongBox, requireUserAuthentication, attestationChallenge)
            } catch (ex: Exception) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && ex is StrongBoxUnavailableException) {
                    Log.d("SecureStorageCapabilitiesInspector", "StrongBox not available on the device, falling back to TEE")
                    createRSAKeyGenSpec(startDate, endDate, shouldUseStrongBox = false, requireUserAuthentication, attestationChallenge)
                } else {
                    null
                }
            }?.also {
                keyPairGenerator.initialize(it)
            }
        }

    private fun generateSampleRSAKeyPair(
        shouldUseStrongBox: Boolean = false,
        requireUserAuthentication: Boolean = true,
    ): KeyPair? {
        try {
            val keyPairGenerator = initKeyPairGeneratorWithRSAKeyPair(
                shouldUseStrongBox,
                requireUserAuthentication,
                attestationChallenge = "test challenge phrase".toByteArray()
            )
            return keyPairGenerator.genKeyPair()
        } catch (pe: ProviderException) {
            val keyPairGenerator = initKeyPairGeneratorWithRSAKeyPair(shouldUseStrongBox, requireUserAuthentication)
            return keyPairGenerator.genKeyPair()
        } catch (e: GeneralSecurityException) {
            Log.d("SecureStorageCapabilitiesInspector", "Could not determine if private key is in secure hardware or not")
        }
        return null
    }

    private fun getKeyInfoForAsymmetricPrivateKey(privateKey: PrivateKey): KeyInfo {
        val factory: KeyFactory = KeyFactory.getInstance(privateKey.algorithm, ANDROID_KEYSTORE)
        return factory.getKeySpec(privateKey, KeyInfo::class.java)
    }

}
