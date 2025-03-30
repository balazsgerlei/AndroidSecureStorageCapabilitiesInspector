package com.example.securestoragecapabilitiesinspector

import android.os.Build
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Dangerous
import androidx.compose.material.icons.filled.DeviceUnknown
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.OutlinedIconButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.livedata.observeAsState
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.DialogProperties
import com.example.securestoragecapabilitiesinspector.ui.theme.SecureStorageCapabilitiesInspectorTheme

class MainActivity : AppCompatActivity() {

    private val viewModel: MainViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        setContent {
            SecureStorageCapabilitiesInspectorTheme {
                val deviceInfoState = viewModel.deviceInfo.observeAsState()
                val secureStorageCapabilitiesState = viewModel.secureStorageCapabilities.observeAsState()
                val certificateToDisplayInDialog = remember { mutableStateOf<Certificate?>(null) }

                SecureStorageCapabilitiesDisplayScreen(
                    deviceInfoState = deviceInfoState.value,
                    secureStorageCapabilitiesState = secureStorageCapabilitiesState.value,
                    certificateToDisplayInDialog = certificateToDisplayInDialog
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

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SecureStorageCapabilitiesDisplayScreen(
    deviceInfoState: DeviceInfo?,
    secureStorageCapabilitiesState: SecureStorageCapabilities?,
    certificateToDisplayInDialog: MutableState<Certificate?>
) {
    Scaffold (
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text("${deviceInfoState?.deviceBrand} ${deviceInfoState?.deviceName} (${deviceInfoState?.deviceModel})")
                        Text("Android ${deviceInfoState?.androidVersion} (API ${deviceInfoState?.androidApiLevel})")
                    }
                },
            )
        }
    ) { innerPadding ->
        SecureStorageCapabilitiesDisplay(
            state = secureStorageCapabilitiesState,
            certificateToDisplayInDialog = certificateToDisplayInDialog,
            modifier = Modifier.padding(innerPadding),
        )
    }
}

@Composable
fun SecureStorageCapabilitiesDisplay(
    state: SecureStorageCapabilities?,
    certificateToDisplayInDialog: MutableState<Certificate?>,
    modifier: Modifier = Modifier
) {
    if (state != null) {
        Column(
            modifier = modifier
                .padding(start = 8.dp, top = 8.dp, end = 8.dp, bottom = 8.dp)
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

            val deviceSupportsStrongbox = state.strongBoxKeystoreProperties != null
            OutlinedCard (
                modifier = Modifier.padding(bottom = 8.dp)
            ) {
                KeySecurityDisplay(
                    state = state.rsa256KeySecureStorageCapabilities,
                    deviceSupportsStrongbox = deviceSupportsStrongbox,
                    biometricEnrollmentStatus = state.biometricEnrollmentStatus,
                    onCertificateClick = { certificate ->
                        certificateToDisplayInDialog.value = certificate
                    },
                    modifier = Modifier.padding(bottom = 8.dp)
                )
            }
            OutlinedCard (
                modifier = Modifier.padding(bottom = 8.dp)
            ) {
                KeySecurityDisplay(
                    state = state.rsa512KeySecureStorageCapabilities,
                    deviceSupportsStrongbox = deviceSupportsStrongbox,
                    biometricEnrollmentStatus = state.biometricEnrollmentStatus,
                    onCertificateClick = { certificate ->
                        certificateToDisplayInDialog.value = certificate
                    },
                    modifier = Modifier.padding(bottom = 8.dp)
                )
            }
            OutlinedCard (
                modifier = Modifier.padding(bottom = 8.dp)
            ) {
                KeySecurityDisplay(
                    state = state.ec256KeySecureStorageCapabilities,
                    deviceSupportsStrongbox = deviceSupportsStrongbox,
                    biometricEnrollmentStatus = state.biometricEnrollmentStatus,
                    onCertificateClick = { certificate ->
                        certificateToDisplayInDialog.value = certificate
                    },
                    modifier = Modifier.padding(bottom = 8.dp)
                )
            }
            OutlinedCard (
                modifier = Modifier.padding(bottom = 8.dp)
            ) {
                KeySecurityDisplay(
                    state = state.ec512KeySecureStorageCapabilities,
                    deviceSupportsStrongbox = deviceSupportsStrongbox,
                    biometricEnrollmentStatus = state.biometricEnrollmentStatus,
                    onCertificateClick = { certificate ->
                        certificateToDisplayInDialog.value = certificate
                    },
                    modifier = Modifier.padding(bottom = 8.dp)
                )
            }
            OutlinedCard (
                modifier = Modifier.padding(bottom = 8.dp)
            ) {
                KeySecurityDisplay(
                    state = state.aesKeySecureStorageCapabilities,
                    deviceSupportsStrongbox = deviceSupportsStrongbox,
                    biometricEnrollmentStatus = state.biometricEnrollmentStatus,
                    onCertificateClick = { certificate ->
                        certificateToDisplayInDialog.value = certificate
                    },
                    modifier = Modifier.padding(bottom = 8.dp)
                )
            }
        }

        certificateToDisplayInDialog.value?.let {
            AlertDialog(
                modifier = Modifier
                    .fillMaxWidth()
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
    deviceSupportsStrongbox: Boolean,
    biometricEnrollmentStatus: BiometricEnrollmentStatus,
    onCertificateClick: (Certificate) -> Unit,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier
            .padding(top = 8.dp)
            .fillMaxWidth()
    ) {
        Text(
            text = state.keyAlgorithm,
            style = MaterialTheme.typography.titleMedium,
            modifier = Modifier.padding(start = 8.dp, top = 8.dp, end = 0.dp, bottom = 8.dp)
        )
        if (state.keyGenerationSuccessful) {
            KeyGenerationSecurityLevelDisplay(
                isKeyGenerationInsideSecureHardware = state.isKeyGenerationInsideSecureHardware,
                keyGenerationSecurityLevel = state.keyGenerationSecurityLevel,
                deviceSupportsStrongbox = deviceSupportsStrongbox,
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
                onCertificateClick = onCertificateClick,
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
    deviceSupportsStrongbox: Boolean,
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
            KeyGenerationSecurityLevel.TRUSTED_ENVIRONMENT -> if (!deviceSupportsStrongbox) {
                Icons.Default.Lock
            } else {
                Icons.Default.Warning
            }
            KeyGenerationSecurityLevel.STRONGBOX -> Icons.Default.Lock
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
            KeyGenerationSecurityLevel.TRUSTED_ENVIRONMENT -> if(!deviceSupportsStrongbox) Color(0xFFBFE98D) else Color(0xFFFFC107)
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
    certificateChain: List<Certificate>?,
    onCertificateClick: (Certificate) -> Unit,
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
                    CertificateDisplay(certificate, onCertificateClick)
                }
            }
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
    certificate: Certificate,
    onCertificateClick: (Certificate) -> Unit,
    modifier: Modifier = Modifier,
) {
    Card (
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
                Text("subject: ${certificate.subject}")
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
                rsa256KeySecureStorageCapabilities = KeySecureStorageCapabilities(
                    keyAlgorithm = "RSA with SHA-256",
                    keyGenerationSuccessful = true,
                    isKeyGenerationInsideSecureHardware = true,
                    keyGenerationSecurityLevel = KeyGenerationSecurityLevel.STRONGBOX,
                    isUserAuthenticationRequirementEnforcedBySecureHardware = true,
                ),
                rsa512KeySecureStorageCapabilities = KeySecureStorageCapabilities(
                    keyAlgorithm = "RSA with SHA-512",
                    keyGenerationSuccessful = true,
                    isKeyGenerationInsideSecureHardware = true,
                    keyGenerationSecurityLevel = KeyGenerationSecurityLevel.STRONGBOX,
                    isUserAuthenticationRequirementEnforcedBySecureHardware = true,
                ),
                ec256KeySecureStorageCapabilities = KeySecureStorageCapabilities(
                    keyAlgorithm = "EC with SHA-256",
                    keyGenerationSuccessful = true,
                    isKeyGenerationInsideSecureHardware = true,
                    keyGenerationSecurityLevel = KeyGenerationSecurityLevel.STRONGBOX,
                    isUserAuthenticationRequirementEnforcedBySecureHardware = true,
                ),
                ec512KeySecureStorageCapabilities = KeySecureStorageCapabilities(
                    keyAlgorithm = "EC with SHA-512",
                    keyGenerationSuccessful = true,
                    isKeyGenerationInsideSecureHardware = true,
                    keyGenerationSecurityLevel = KeyGenerationSecurityLevel.STRONGBOX,
                    isUserAuthenticationRequirementEnforcedBySecureHardware = true,
                ),
                aesKeySecureStorageCapabilities = KeySecureStorageCapabilities(
                    keyAlgorithm = "AES",
                    keyGenerationSuccessful = true,
                    isKeyGenerationInsideSecureHardware = true,
                    keyGenerationSecurityLevel = KeyGenerationSecurityLevel.STRONGBOX,
                    isUserAuthenticationRequirementEnforcedBySecureHardware = true,
                ),
            ),
            certificateToDisplayInDialog = certificateToDisplayInDialog
        )
    }
}

@Preview(showBackground = true)
@Composable
fun KeySecurityDisplayPreview() {
    SecureStorageCapabilitiesInspectorTheme {
        Surface(
            color = MaterialTheme.colorScheme.surfaceContainerHighest
        ) {
            KeySecurityDisplay(
                state = KeySecureStorageCapabilities(
                    keyAlgorithm = "RSA",
                    keyGenerationSuccessful = true,
                    isKeyGenerationInsideSecureHardware = true,
                    keyGenerationSecurityLevel = KeyGenerationSecurityLevel.STRONGBOX,
                    isUserAuthenticationRequirementEnforcedBySecureHardware = true,
                ),
                deviceSupportsStrongbox = true,
                biometricEnrollmentStatus = BiometricEnrollmentStatus.ENROLLED,
                onCertificateClick = { },
            )
        }
    }
}

@Preview(showBackground = true)
@Composable
fun CertificateChainDisplayPreview() {
    SecureStorageCapabilitiesInspectorTheme {
        Surface(
            color = MaterialTheme.colorScheme.surfaceContainerHighest
        ) {
            CertificateChainDisplay(
                certificateChain = null,
                onCertificateClick = { },
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
                rsa256KeySecureStorageCapabilities = KeySecureStorageCapabilities(
                    keyAlgorithm = "RSA with SHA-256",
                    keyGenerationSuccessful = true,
                    isKeyGenerationInsideSecureHardware = true,
                    keyGenerationSecurityLevel = KeyGenerationSecurityLevel.STRONGBOX,
                    isUserAuthenticationRequirementEnforcedBySecureHardware = true,
                ),
                rsa512KeySecureStorageCapabilities = KeySecureStorageCapabilities(
                    keyAlgorithm = "RSA with SHA-512",
                    keyGenerationSuccessful = true,
                    isKeyGenerationInsideSecureHardware = true,
                    keyGenerationSecurityLevel = KeyGenerationSecurityLevel.STRONGBOX,
                    isUserAuthenticationRequirementEnforcedBySecureHardware = true,
                ),
                ec256KeySecureStorageCapabilities = KeySecureStorageCapabilities(
                    keyAlgorithm = "EC with SHA-256",
                    keyGenerationSuccessful = true,
                    isKeyGenerationInsideSecureHardware = true,
                    keyGenerationSecurityLevel = KeyGenerationSecurityLevel.STRONGBOX,
                    isUserAuthenticationRequirementEnforcedBySecureHardware = true,
                ),
                ec512KeySecureStorageCapabilities = KeySecureStorageCapabilities(
                    keyAlgorithm = "EC with SHA-512",
                    keyGenerationSuccessful = true,
                    isKeyGenerationInsideSecureHardware = true,
                    keyGenerationSecurityLevel = KeyGenerationSecurityLevel.STRONGBOX,
                    isUserAuthenticationRequirementEnforcedBySecureHardware = true,
                ),
                aesKeySecureStorageCapabilities = KeySecureStorageCapabilities(
                    keyAlgorithm = "AES",
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
