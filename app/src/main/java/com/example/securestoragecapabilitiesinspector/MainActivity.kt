package com.example.securestoragecapabilitiesinspector

import android.os.Build
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Dangerous
import androidx.compose.material.icons.filled.DeviceUnknown
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.MultiChoiceSegmentedButtonRow
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.OutlinedIconButton
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.livedata.observeAsState
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.DialogProperties
import com.example.securestoragecapabilitiesinspector.ui.theme.SecureStorageCapabilitiesInspectorTheme
import java.lang.StringBuilder
import java.security.cert.Certificate
import java.security.cert.X509Certificate

class MainActivity : AppCompatActivity() {

    private val viewModel: MainViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            SecureStorageCapabilitiesInspectorTheme {
                val deviceInfoState = viewModel.deviceInfo.observeAsState()
                val secureStorageCapabilitiesState = viewModel.secureStorageCapabilities.observeAsState()
                val certificateToDisplayInDialog = remember { mutableStateOf<Certificate?>(null) }

                SecureStorageCapabilitiesDisplayScreen(
                    deviceInfoState = deviceInfoState.value,
                    secureStorageCapabilitiesState = secureStorageCapabilitiesState.value,
                    certificateToDisplayInDialog = certificateToDisplayInDialog,
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
    certificateToDisplayInDialog: MutableState<Certificate?>,
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
                certificateToDisplayInDialog = certificateToDisplayInDialog,
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
                    .padding(start = 8.dp, end = 8.dp, bottom = 2.dp)
                    .fillMaxWidth(),
            )
            Text(
                text = "Android ${state.androidVersion} (API ${state.androidApiLevel})",
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier
                    .padding(horizontal = 8.dp)
                    .fillMaxWidth(),
            )
        }
    }
}

@Composable
fun SecureStorageCapabilitiesDisplay(
    state: SecureStorageCapabilities?,
    certificateToDisplayInDialog: MutableState<Certificate?>,
    modifier: Modifier = Modifier
) {
    // We show the key with the higher security level initially
    // As we are most interested in the highest capability of the device
    // If security equals, we default to show RSA
    val aesKeySecureStorageCapabilities = state?.aesKeySecureStorageCapabilities
    val rsaKeySecureStorageCapabilities = state?.rsaKeySecureStorageCapabilities
    val ecKeySecureStorageCapabilities = state?.ecKeySecureStorageCapabilities
    val keySecurityEquals =
        aesKeySecureStorageCapabilities?.isKeyGenerationInsideSecureHardware == rsaKeySecureStorageCapabilities?.isKeyGenerationInsideSecureHardware
                && rsaKeySecureStorageCapabilities?.isKeyGenerationInsideSecureHardware == ecKeySecureStorageCapabilities?.isKeyGenerationInsideSecureHardware
                && aesKeySecureStorageCapabilities?.isUserAuthenticationRequirementEnforcedBySecureHardware == rsaKeySecureStorageCapabilities?.isUserAuthenticationRequirementEnforcedBySecureHardware
                && rsaKeySecureStorageCapabilities?.isUserAuthenticationRequirementEnforcedBySecureHardware == ecKeySecureStorageCapabilities?.isUserAuthenticationRequirementEnforcedBySecureHardware
    val moreSecureKeyVariant =
        if (keySecurityEquals || (rsaKeySecureStorageCapabilities?.isKeyGenerationInsideSecureHardware == true
            && rsaKeySecureStorageCapabilities.isUserAuthenticationRequirementEnforcedBySecureHardware)) 0
        else if (ecKeySecureStorageCapabilities?.isKeyGenerationInsideSecureHardware == true
            && ecKeySecureStorageCapabilities.isUserAuthenticationRequirementEnforcedBySecureHardware) 1
        else 2
    var selectedKeyVariant by remember { mutableIntStateOf(moreSecureKeyVariant) }
    val options = listOf("RSA", "EC", "AES")

    if (state != null) {
        Column(
            modifier = modifier
                .padding(start = 8.dp, end = 8.dp, bottom = 8.dp)
                .verticalScroll(rememberScrollState())
        ) {
            DeviceSecureDisplay(
                isDeviceSecure = state.isDeviceSecure,
                modifier = Modifier
                    .padding(horizontal = 8.dp)
                    .padding(bottom = 8.dp),
            )
            BiometricsEnrollmentStatusDisplay(
                biometricEnrollmentStatus = state.biometricEnrollmentStatus,
                modifier = Modifier
                    .padding(horizontal = 8.dp)
                    .padding(bottom = 8.dp),
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
                    0 -> state.rsaKeySecureStorageCapabilities
                    1 -> state.ecKeySecureStorageCapabilities
                    else -> state.aesKeySecureStorageCapabilities
                }
                KeySecurityDisplay(
                    state = secureStorageCapabilitiesToDisplay,
                    biometricEnrollmentStatus = state.biometricEnrollmentStatus,
                    certificateToDisplayInDialog = certificateToDisplayInDialog,
                    modifier = Modifier.padding(bottom = 8.dp)
                )
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
fun DeviceSecureDisplay(
    isDeviceSecure: Boolean,
    modifier: Modifier = Modifier
) {
    val icon = if (isDeviceSecure) {
        Icons.Default.Lock
    } else Icons.Default.Warning
    val iconTint = if (isDeviceSecure) {
        Color(0xFF4CAF50)
    } else Color(0xFFF44336)
    val text =
        if (isDeviceSecure) "Protected with PIN, pattern or password"
        else "Unprotected (NO secure lock screen set)"
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
fun BiometricsEnrollmentStatusDisplay(
    biometricEnrollmentStatus: BiometricEnrollmentStatus,
    modifier: Modifier = Modifier
) {
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
fun HasStrongboxKeystoreDisplay(
    strongBoxKeystore: StrongBoxKeystoreProperties?,
    modifier: Modifier = Modifier
) {
    val text = if (strongBoxKeystore != null) {
        "StrongBox Keystore supported: $strongBoxKeystore"
    } else "NO StrongBox Keystore"
    val icon = when(strongBoxKeystore) {
        null -> Icons.Default.Warning
        StrongBoxKeystoreProperties.VERSION_UNKNOWN -> Icons.Default.DeviceUnknown
        StrongBoxKeystoreProperties.V300, StrongBoxKeystoreProperties.V200, StrongBoxKeystoreProperties.V100, StrongBoxKeystoreProperties.V41, StrongBoxKeystoreProperties.V40 -> Icons.Default.CheckCircle
    }
    val iconTint = when(strongBoxKeystore) {
        null -> Color(0xFFFFC107)
        StrongBoxKeystoreProperties.VERSION_UNKNOWN -> Color(0xFFBFE98D)
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
fun KeySecurityDisplay(
    state: KeySecureStorageCapabilities,
    biometricEnrollmentStatus: BiometricEnrollmentStatus,
    certificateToDisplayInDialog: MutableState<Certificate?>,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier
    ) {
        if (state.keyGenerationSuccessful) {
            KeyGenerationSecurityLevelDisplay(
                isKeyGenerationInsideSecureHardware = state.isKeyGenerationInsideSecureHardware,
                keyGenerationSecurityLevel = state.keyGenerationSecurityLevel,
                modifier = Modifier
                    .padding(horizontal = 8.dp)
                    .padding(bottom = 8.dp),
            )
            UserAuthenticationRequirementEnforcementDisplay(
                biometricEnrollmentStatus = biometricEnrollmentStatus ,
                isUserAuthenticationRequirementEnforcedBySecureHardware = state.isUserAuthenticationRequirementEnforcedBySecureHardware,
                modifier = Modifier
                    .padding(horizontal = 8.dp)
                    .padding(bottom = 8.dp),
            )
            CertificateChainDisplay(
                certificateChain = state.certificateChain,
                certificateToDisplayInDialog = certificateToDisplayInDialog,
                modifier = Modifier
                    .padding(horizontal = 8.dp),
            )
        } else {
            Text(
                text = "Could not get Key information",
                modifier = Modifier
                    .align(Alignment.CenterHorizontally)
                    .padding(horizontal = 8.dp),
            )
        }
    }

}

@Composable
fun KeyGenerationSecurityLevelDisplay(
    isKeyGenerationInsideSecureHardware: Boolean,
    keyGenerationSecurityLevel: KeyGenerationSecurityLevel?,
    modifier: Modifier = Modifier
) {
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
            null -> Icons.Default.Warning
            KeyGenerationSecurityLevel.SOFTWARE -> Icons.Default.Dangerous
            KeyGenerationSecurityLevel.UNKNOWN -> Icons.Default.DeviceUnknown
            KeyGenerationSecurityLevel.UNKNOWN_SECURE -> Icons.Default.Warning
            KeyGenerationSecurityLevel.TRUSTED_ENVIRONMENT, KeyGenerationSecurityLevel.STRONGBOX -> Icons.Default.Lock
        }
        val keySecurityLevelTint = when (keyGenerationSecurityLevel) {
            null -> {
                if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
                    Color(0xFFFFC107)
                } else Color(0xFFF44336)
            }
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

@Composable
fun CertificateChainDisplay(
    certificateChain: Array<Certificate>?,
    certificateToDisplayInDialog: MutableState<Certificate?>,
    modifier: Modifier = Modifier,
) {
    if (!certificateChain.isNullOrEmpty()) {
        val showCertificateChain = remember { mutableStateOf(false) }

        Column (
            modifier = modifier,
        ) {
            Row (
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.padding(bottom = 8.dp, end = 8.dp)
            ) {
                Text(
                    "Certificate Chain",
                    modifier = Modifier
                        .padding(horizontal = 8.dp)
                        .weight(1f)
                )
                OutlinedIconButton (
                    onClick = {
                        showCertificateChain.value = !showCertificateChain.value
                    },
                    modifier = Modifier
                        .size(44.dp)
                ) {
                    Icon(
                        imageVector = if (showCertificateChain.value) Icons.Default.KeyboardArrowUp else Icons.Default.KeyboardArrowDown,
                        contentDescription = null
                    )
                }
            }
            if(showCertificateChain.value) {
                certificateChain.forEach { certificate ->
                    (certificate as? X509Certificate)?.let { x509Certificate ->
                        CertificateDisplay(
                            certificate = x509Certificate,
                            onCertificateClick = {
                                certificateToDisplayInDialog.value = it
                            }
                        )
                    }
                }
            }
        }

        certificateToDisplayInDialog.value?.let {
            AlertDialog(
                modifier = Modifier.fillMaxWidth()
                    .padding(16.dp),
                properties = DialogProperties(
                    usePlatformDefaultWidth = false
                ),
                onDismissRequest = {
                    certificateToDisplayInDialog.value = null
                },
                title = { Text(text = "Certificate Details") },
                text = {
                    Text(
                        text = certificateToDisplayInDialog.value.toString(),
                        modifier = Modifier
                            .verticalScroll(rememberScrollState())
                    )
                },
                confirmButton = {
                    Button(
                        onClick = {
                            certificateToDisplayInDialog.value = null
                        }
                    ) {
                        Text("Close")
                    }
                }
            )
        }
    } else {
        Text(
            text = "No Certificate Chain",
            modifier = modifier
                .padding(horizontal = 8.dp),
        )
    }
}

@Composable
fun CertificateDisplay(
    certificate: X509Certificate,
    onCertificateClick: (Certificate) -> Unit,
    modifier: Modifier = Modifier,
) {
    OutlinedCard (
        onClick = {
            onCertificateClick(certificate)
        },
        modifier = modifier.padding(bottom = 8.dp),
    ) {
        Row (
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.padding(start = 8.dp, top = 8.dp, end = 16.dp, bottom = 8.dp)
        ) {
            Column (
                modifier = Modifier
                    .padding(8.dp)
                    .weight(1f)
            ) {
                Text("subject: ${certificate.subjectX500Principal.name}")
                Text("not before: ${certificate.notBefore}")
                Text("not after: ${certificate.notAfter}")
            }
            Icon(
                Icons.Outlined.Info,
                contentDescription = null,
                modifier = Modifier
                    .size(32.dp)
            )
        }
    }
}

@Preview(showBackground = true)
@Composable
fun SecureStorageCapabilitiesDisplayScreenPreview() {
    val certificateToDisplayInDialog = remember { mutableStateOf<Certificate?>(null) }

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
                rsaKeySecureStorageCapabilities = KeySecureStorageCapabilities(
                    keyGenerationSuccessful = true,
                    isKeyGenerationInsideSecureHardware = true,
                    keyGenerationSecurityLevel = KeyGenerationSecurityLevel.STRONGBOX,
                    isUserAuthenticationRequirementEnforcedBySecureHardware = true,
                ),
                ecKeySecureStorageCapabilities = KeySecureStorageCapabilities(
                    keyGenerationSuccessful = true,
                    isKeyGenerationInsideSecureHardware = true,
                    keyGenerationSecurityLevel = KeyGenerationSecurityLevel.STRONGBOX,
                    isUserAuthenticationRequirementEnforcedBySecureHardware = true,
                ),
                aesKeySecureStorageCapabilities = KeySecureStorageCapabilities(
                    keyGenerationSuccessful = true,
                    isKeyGenerationInsideSecureHardware = true,
                    keyGenerationSecurityLevel = KeyGenerationSecurityLevel.STRONGBOX,
                    isUserAuthenticationRequirementEnforcedBySecureHardware = true,
                ),
            ),
            certificateToDisplayInDialog = certificateToDisplayInDialog,
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
fun KeySecurityDisplayPreview() {
    val certificateToDisplayInDialog = remember { mutableStateOf<Certificate?>(null) }

    SecureStorageCapabilitiesInspectorTheme {
        Surface(
            color = MaterialTheme.colorScheme.surfaceContainerHighest
        ) {
            KeySecurityDisplay(
                state = KeySecureStorageCapabilities(
                    keyGenerationSuccessful = true,
                    isKeyGenerationInsideSecureHardware = true,
                    keyGenerationSecurityLevel = KeyGenerationSecurityLevel.STRONGBOX,
                    isUserAuthenticationRequirementEnforcedBySecureHardware = true,
                ),
                biometricEnrollmentStatus = BiometricEnrollmentStatus.ENROLLED,
                certificateToDisplayInDialog = certificateToDisplayInDialog,
            )
        }
    }
}

@Preview(showBackground = true)
@Composable
fun CertificateChainDisplayPreview() {
    val certificateToDisplayInDialog = remember { mutableStateOf<Certificate?>(null) }

    SecureStorageCapabilitiesInspectorTheme {
        Surface(
            color = MaterialTheme.colorScheme.surfaceContainerHighest
        ) {
            CertificateChainDisplay(
                certificateChain = null,
                certificateToDisplayInDialog = certificateToDisplayInDialog,
            )
        }
    }
}

@Preview(showBackground = true)
@Composable
fun SecureStorageCapabilitiesDisplayPreview() {
    val certificateToDisplayInDialog = remember { mutableStateOf<Certificate?>(null) }

    SecureStorageCapabilitiesInspectorTheme {
        SecureStorageCapabilitiesDisplay(
            state = SecureStorageCapabilities(
                isDeviceSecure = true,
                biometricEnrollmentStatus = BiometricEnrollmentStatus.ENROLLED,
                strongBoxKeystoreProperties = StrongBoxKeystoreProperties.V100,
                rsaKeySecureStorageCapabilities = KeySecureStorageCapabilities(
                    keyGenerationSuccessful = true,
                    isKeyGenerationInsideSecureHardware = true,
                    keyGenerationSecurityLevel = KeyGenerationSecurityLevel.STRONGBOX,
                    isUserAuthenticationRequirementEnforcedBySecureHardware = true,
                ),
                ecKeySecureStorageCapabilities = KeySecureStorageCapabilities(
                    keyGenerationSuccessful = true,
                    isKeyGenerationInsideSecureHardware = true,
                    keyGenerationSecurityLevel = KeyGenerationSecurityLevel.STRONGBOX,
                    isUserAuthenticationRequirementEnforcedBySecureHardware = true,
                ),
                aesKeySecureStorageCapabilities = KeySecureStorageCapabilities(
                    keyGenerationSuccessful = true,
                    isKeyGenerationInsideSecureHardware = true,
                    keyGenerationSecurityLevel = KeyGenerationSecurityLevel.STRONGBOX,
                    isUserAuthenticationRequirementEnforcedBySecureHardware = true,
                ),
            ),
            certificateToDisplayInDialog = certificateToDisplayInDialog,
        )
    }
}
