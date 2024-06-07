package com.example.securestoragecapabilitiesinspector

import android.os.Build
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Dangerous
import androidx.compose.material.icons.filled.DeviceUnknown
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.MultiChoiceSegmentedButtonRow
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.livedata.observeAsState
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.example.securestoragecapabilitiesinspector.ui.theme.SecureStorageCapabilitiesInspectorTheme
import java.lang.StringBuilder

class MainActivity : AppCompatActivity() {

    private val viewModel: MainViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            SecureStorageCapabilitiesInspectorTheme {
                val deviceInfoState = viewModel.deviceInfo.observeAsState()
                val secureStorageCapabilitiesState = viewModel.secureStorageCapabilities.observeAsState()

                SecureStorageCapabilitiesDisplayScreen(
                    deviceInfoState = deviceInfoState.value,
                    secureStorageCapabilitiesState = secureStorageCapabilitiesState.value,
                    modifier = Modifier.fillMaxSize(),
                )
            }
        }
    }

    override fun onResume() {
        super.onResume()
        viewModel.retrieveDeviceInfo()
        viewModel.inspectSecureStorageCapabilities(this)
    }

}

@Composable
fun SecureStorageCapabilitiesDisplayScreen(
    deviceInfoState: DeviceInfo?,
    secureStorageCapabilitiesState: SecureStorageCapabilities?,
    modifier: Modifier = Modifier
) {
    Surface(
        color = MaterialTheme.colorScheme.background
    ) {
        Column(
            modifier = modifier
        ) {
            DeviceInfoDisplay(
                state = deviceInfoState,
            )
            SecureStorageCapabilitiesDisplay(
                state = secureStorageCapabilitiesState,
                modifier = Modifier.fillMaxSize(),
            )
        }
    }
}

@Composable
fun DeviceInfoDisplay(
    state: DeviceInfo?,
    modifier: Modifier = Modifier
) {
    if (state != null) {
        Column (
            modifier = modifier
                .padding(start = 8.dp, top = 16.dp, end = 8.dp, bottom = 8.dp)
                .fillMaxWidth(),
        ) {
            Text(
                text = "${state.deviceBrand} ${state.deviceName} (${state.deviceModel})",
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier
                    .padding(vertical = 4.dp, horizontal = 8.dp)
                    .fillMaxWidth(),
            )
            Text(
                text = "Android ${state.androidVersion} (API ${state.androidApiLevel})",
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier
                    .padding(vertical = 4.dp, horizontal = 8.dp)
                    .fillMaxWidth(),
            )
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SecureStorageCapabilitiesDisplay(
    state: SecureStorageCapabilities?,
    modifier: Modifier = Modifier
) {
    // We show the key with the higher security level initially
    // As we are most interested in the highest capability of the device
    // If security equasl, we default to show AES
    val aesKeySecureStorageCapabilities = state?.aesKeySecureStorageCapabilities
    val rsaKeySecureStorageCapabilities = state?.rsaKeySecureStorageCapabilities
    val keySecurityEquals =
        aesKeySecureStorageCapabilities?.isKeyGenerationInsideSecureHardware == rsaKeySecureStorageCapabilities?.isKeyGenerationInsideSecureHardware
            && aesKeySecureStorageCapabilities?.isUserAuthenticationRequirementEnforcedBySecureHardware == rsaKeySecureStorageCapabilities?.isUserAuthenticationRequirementEnforcedBySecureHardware
    val moreSecureKeyVariant =
        if (keySecurityEquals || (aesKeySecureStorageCapabilities?.isKeyGenerationInsideSecureHardware == true
            && aesKeySecureStorageCapabilities.isUserAuthenticationRequirementEnforcedBySecureHardware)) 0
        else 1
    var selectedKeyVariant by remember { mutableIntStateOf(moreSecureKeyVariant) }
    val options = listOf("AES", "RSA")

    if (state != null) {
        Column(
            modifier = modifier.padding(horizontal = 8.dp, vertical = 8.dp)
        ) {
            DeviceSecureDisplay(
                isDeviceSecure = state.isDeviceSecure,
                modifier = Modifier
                    .padding(horizontal = 8.dp)
                    .padding(bottom = 16.dp),
            )
            BiometricsEnrollmentStatusDisplay(
                biometricEnrollmentStatus = state.biometricEnrollmentStatus,
                modifier = Modifier
                    .padding(horizontal = 8.dp)
                    .padding(bottom = 16.dp),
            )
            HasStrongboxKeystoreDisplay(
                strongBoxKeystore = state.strongBoxKeystoreProperties,
                modifier = Modifier
                    .padding(horizontal = 8.dp)
                    .padding(bottom = 16.dp),
            )

            Card (
                modifier = Modifier.fillMaxWidth()
            ) {
                MultiChoiceSegmentedButtonRow(
                    modifier = Modifier
                        .align(Alignment.CenterHorizontally)
                        .padding(top = 8.dp, bottom = 8.dp)
                ) {
                    options.forEachIndexed { index, label ->
                        SegmentedButton(
                            shape = SegmentedButtonDefaults.itemShape(index = index, count = options.size),
                            onCheckedChange = {
                                selectedKeyVariant = index
                            },
                            checked = index == selectedKeyVariant
                        ) {
                            Text(label)
                        }
                    }
                }

                val secureStorageCapabilitiesToDisplay = when(selectedKeyVariant) {
                    0 -> state.aesKeySecureStorageCapabilities
                    else -> state.rsaKeySecureStorageCapabilities
                }
                if (secureStorageCapabilitiesToDisplay.keyGenerationSuccessful) {
                    KeyGenerationSecurityLevelDisplay(
                        isKeyGenerationInsideSecureHardware = secureStorageCapabilitiesToDisplay.isKeyGenerationInsideSecureHardware,
                        keyGenerationSecurityLevel = secureStorageCapabilitiesToDisplay.keyGenerationSecurityLevel,
                        modifier = Modifier
                            .padding(horizontal = 8.dp)
                            .padding(bottom = 8.dp),
                    )
                    UserAuthenticationRequirementEnforcementDisplay(
                        biometricEnrollmentStatus = state.biometricEnrollmentStatus ,
                        isUserAuthenticationRequirementEnforcedBySecureHardware = secureStorageCapabilitiesToDisplay.isUserAuthenticationRequirementEnforcedBySecureHardware,
                        modifier = Modifier
                            .padding(horizontal = 8.dp)
                            .padding(bottom = 16.dp),
                    )
                } else {
                    Text(
                        text = "Could not get Key information",
                        modifier = Modifier
                            .align(Alignment.CenterHorizontally)
                            .padding(bottom = 16.dp),
                    )
                }
            }
        }
    } else {
        Box(
            modifier = Modifier.fillMaxSize(),
            contentAlignment = Alignment.Center,
        ) {
            CircularProgressIndicator(
                modifier = Modifier.width(64.dp),
                color = MaterialTheme.colorScheme.secondary,
                trackColor = MaterialTheme.colorScheme.surfaceVariant,
            )
        }
    }
}

@Composable
fun DeviceSecureDisplay(isDeviceSecure: Boolean, modifier: Modifier = Modifier) {
    val icon = if (isDeviceSecure) {
        Icons.Default.Lock
    } else Icons.Default.Warning
    val iconTint = if (isDeviceSecure) {
        Color(0xFF4CAF50)
    } else Color(0xFFF44336)
    val text =
        if (isDeviceSecure) "Device is protected with a PIN, pattern or password"
        else "Device unprotected (NO secure lock screen set)"
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = modifier,
    ) {
        Icon(
            icon,
            tint = iconTint,
            contentDescription = null,
        )
        Text(
            text = text,
            modifier = Modifier.padding(start = 8.dp),
        )
    }
}

@Composable
fun BiometricsEnrollmentStatusDisplay(biometricEnrollmentStatus: BiometricEnrollmentStatus, modifier: Modifier = Modifier) {
    val icon = when(biometricEnrollmentStatus) {
        BiometricEnrollmentStatus.ENROLLED, BiometricEnrollmentStatus.ONLY_DEVICE_CREDENTIALS_ENROLLED -> Icons.Default.Lock
        else -> Icons.Default.Warning
    }
    val iconTint = when(biometricEnrollmentStatus) {
        BiometricEnrollmentStatus.ENROLLED -> Color(0xFF4CAF50)
        BiometricEnrollmentStatus.ONLY_DEVICE_CREDENTIALS_ENROLLED -> Color(0xFFBFE98D)
        else -> Color(0xFFF44336)
    }
    val text = when(biometricEnrollmentStatus) {
        BiometricEnrollmentStatus.ENROLLED -> "Biometrics enrolled"
        BiometricEnrollmentStatus.ONLY_DEVICE_CREDENTIALS_ENROLLED -> "Secure device credentials set (NO STRONG biometrics enrolled)"
        BiometricEnrollmentStatus.UNKNOWN -> "Biometrics enrollment status UNKNOWN"
        BiometricEnrollmentStatus.UNSUPPORTED -> "Biometrics NOT SUPPORTED"
        BiometricEnrollmentStatus.HW_UNAVAILABLE -> "Biometrics hardware UNAVAILABLE"
        BiometricEnrollmentStatus.NONE_ENROLLED -> "NO Biometrics credential enrolled"
        BiometricEnrollmentStatus.NO_HARDWARE -> "NO Biometrics hardware found"
        BiometricEnrollmentStatus.SECURITIY_UPDATE_REQUIRED -> "Security update required to re-enable Biometrics"
    }
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = modifier,
    ) {
        Icon(
            icon,
            tint = iconTint,
            contentDescription = null,
        )
        Text(
            text = text,
            modifier = Modifier.padding(start = 8.dp),
        )
    }

}

@Composable
fun HasStrongboxKeystoreDisplay(strongBoxKeystore: StrongBoxKeystoreProperties?, modifier: Modifier = Modifier) {
    val text = if (strongBoxKeystore != null) {
        "Device has StrongBox Keystore: $strongBoxKeystore"
    } else "Device has NO StrongBox Keystore"
    val icon = when(strongBoxKeystore) {
        null -> Icons.Default.Warning
        StrongBoxKeystoreProperties.VERSION_UNKNOWN -> Icons.Default.DeviceUnknown
        StrongBoxKeystoreProperties.V300, StrongBoxKeystoreProperties.V200, StrongBoxKeystoreProperties.V100, StrongBoxKeystoreProperties.V41, StrongBoxKeystoreProperties.V40 -> Icons.Default.CheckCircle
    }
    val iconTint = when(strongBoxKeystore) {
        null -> Color(0xFFF44336)
        StrongBoxKeystoreProperties.VERSION_UNKNOWN -> Color(0xFFFFC107)
        StrongBoxKeystoreProperties.V300, StrongBoxKeystoreProperties.V200, StrongBoxKeystoreProperties.V100, StrongBoxKeystoreProperties.V41, StrongBoxKeystoreProperties.V40 -> Color(0xFF4CAF50)
    }
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = modifier,
    ) {
        Icon(
            icon,
            tint = iconTint,
            contentDescription = null,
        )
        Text(
            text = text,
            modifier = Modifier.padding(start = 8.dp),
        )
    }
}

@Composable
fun KeyGenerationSecurityLevelDisplay(
    isKeyGenerationInsideSecureHardware: Boolean,
    keyGenerationSecurityLevel: KeyGenerationSecurityLevel?,
    modifier: Modifier = Modifier) {

    Column(
        modifier = modifier
    ) {
        val secureHardwareIcon = if (isKeyGenerationInsideSecureHardware) {
            Icons.Default.CheckCircle
        } else Icons.Default.Warning
        val secureHardwareIconTint = if (isKeyGenerationInsideSecureHardware) {
            Color(0xFF4CAF50)
        } else Color(0xFFF44336)
        val secureHardwareText =
            if (isKeyGenerationInsideSecureHardware) "Key generated inside secure hardware"
            else "Key NOT generated inside secure hardware"
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.padding(bottom = 8.dp),
        ) {
            Icon(
                secureHardwareIcon,
                tint = secureHardwareIconTint,
                contentDescription = null,
            )
            Text(
                text = secureHardwareText,
                modifier = Modifier.padding(start = 8.dp),
            )
        }

        val keySecurityLevelIcon = when (keyGenerationSecurityLevel) {
            null -> Icons.Default.Dangerous
            KeyGenerationSecurityLevel.SOFTWARE -> Icons.Default.Dangerous
            KeyGenerationSecurityLevel.UNKNOWN -> Icons.Default.DeviceUnknown
            KeyGenerationSecurityLevel.UNKNOWN_SECURE -> Icons.Default.Warning
            KeyGenerationSecurityLevel.TRUSTED_ENVIRONMENT, KeyGenerationSecurityLevel.STRONGBOX -> Icons.Default.Lock
        }
        val keySecurityLevelTint = when (keyGenerationSecurityLevel) {
            null -> Color(0xFFF44336)
            KeyGenerationSecurityLevel.UNKNOWN, KeyGenerationSecurityLevel.SOFTWARE -> Color(
                0xFFF44336
            )
            KeyGenerationSecurityLevel.UNKNOWN_SECURE -> Color(0xFFFFC107)
            KeyGenerationSecurityLevel.TRUSTED_ENVIRONMENT -> Color(0xFFBFE98D)
            KeyGenerationSecurityLevel.STRONGBOX -> Color(0xFF4CAF50)
        }
        val keySecurityLevelText = if (keyGenerationSecurityLevel != null) {
            "Key generation security level: $keyGenerationSecurityLevel"
        } else {
            StringBuilder("Key generation security level cannot be determined").also {
                if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
                    it.append(" (No API to check)")
                }
            }.toString()
        }
        Row(
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(
                keySecurityLevelIcon,
                tint = keySecurityLevelTint,
                contentDescription = null,
            )
            Text(
                text = keySecurityLevelText,
                modifier = Modifier.padding(start = 8.dp),
            )
        }
    }

}

@Composable
fun UserAuthenticationRequirementEnforcementDisplay(
    biometricEnrollmentStatus: BiometricEnrollmentStatus,
    isUserAuthenticationRequirementEnforcedBySecureHardware: Boolean,
    modifier: Modifier = Modifier
) {
    val icon = if (isUserAuthenticationRequirementEnforcedBySecureHardware) {
        Icons.Default.CheckCircle
    } else Icons.Default.Warning
    val iconTint = if (isUserAuthenticationRequirementEnforcedBySecureHardware) {
        Color(0xFF4CAF50)
    } else Color(0xFFF44336)
    val text =
        if (isUserAuthenticationRequirementEnforcedBySecureHardware) {
            "Key user authentication requirement enforced by secure hardware"
        }
        else {
            StringBuilder("Key user authentication requirement NOT enforced by secure hardware").also {
                if (biometricEnrollmentStatus != BiometricEnrollmentStatus.ENROLLED) {
                    it.append(" (NO Biometric credentials enrolled)")
                }
            }.toString()
        }
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = modifier,
    ) {
        Icon(
            icon,
            tint = iconTint,
            contentDescription = null,
        )
        Text(
            text = text,
            modifier = Modifier.padding(start = 8.dp),
        )
    }
}

@Preview(showBackground = true)
@Composable
fun SecureStorageCapabilitiesDisplayScreenPreview() {
    SecureStorageCapabilitiesInspectorTheme {
        SecureStorageCapabilitiesDisplayScreen(
            deviceInfoState = DeviceInfo(
                deviceName = "Pixel 8 Pro",
                deviceBrand = "Google",
                deviceModel = "husky",
                androidVersion = "14",
                androidApiLevel = 34,
            ),
            secureStorageCapabilitiesState = SecureStorageCapabilities(
                isDeviceSecure = true,
                biometricEnrollmentStatus = BiometricEnrollmentStatus.ENROLLED,
                strongBoxKeystoreProperties = StrongBoxKeystoreProperties.V100,
                aesKeySecureStorageCapabilities = KeySecureStorageCapabilities(
                    keyGenerationSuccessful = true,
                    isKeyGenerationInsideSecureHardware = true,
                    keyGenerationSecurityLevel = KeyGenerationSecurityLevel.STRONGBOX,
                    isUserAuthenticationRequirementEnforcedBySecureHardware = true,
                ),

                rsaKeySecureStorageCapabilities = KeySecureStorageCapabilities(
                    keyGenerationSuccessful = true,
                    isKeyGenerationInsideSecureHardware = true,
                    keyGenerationSecurityLevel = KeyGenerationSecurityLevel.STRONGBOX,
                    isUserAuthenticationRequirementEnforcedBySecureHardware = true,
                ),
            ),
            modifier = Modifier.fillMaxSize())
    }
}

@Preview(showBackground = true)
@Composable
fun DeviceInfoDisplayPreview() {
    SecureStorageCapabilitiesInspectorTheme {
        Surface(
            color = MaterialTheme.colorScheme.background
        ) {
            DeviceInfoDisplay(
                state = DeviceInfo(
                    deviceName = "Pixel 8 Pro",
                    deviceBrand = "Google",
                    deviceModel = "husky",
                    androidVersion = "14",
                    androidApiLevel = 34,
                ),
            )
        }
    }
}

@Preview(showBackground = true)
@Composable
fun SecureStorageCapabilitiesDisplayPreview() {
    SecureStorageCapabilitiesInspectorTheme {
        Surface(
            color = MaterialTheme.colorScheme.background
        ) {
            SecureStorageCapabilitiesDisplay(
                state = SecureStorageCapabilities(
                    isDeviceSecure = true,
                    biometricEnrollmentStatus = BiometricEnrollmentStatus.ENROLLED,
                    strongBoxKeystoreProperties = StrongBoxKeystoreProperties.V100,
                    aesKeySecureStorageCapabilities = KeySecureStorageCapabilities(
                        keyGenerationSuccessful = true,
                        isKeyGenerationInsideSecureHardware = true,
                        keyGenerationSecurityLevel = KeyGenerationSecurityLevel.STRONGBOX,
                        isUserAuthenticationRequirementEnforcedBySecureHardware = true,
                    ),

                    rsaKeySecureStorageCapabilities = KeySecureStorageCapabilities(
                        keyGenerationSuccessful = true,
                        isKeyGenerationInsideSecureHardware = true,
                        keyGenerationSecurityLevel = KeyGenerationSecurityLevel.STRONGBOX,
                        isUserAuthenticationRequirementEnforcedBySecureHardware = true,
                    ),
                ),
            )
        }
    }
}
