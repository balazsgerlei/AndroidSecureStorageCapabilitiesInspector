package dev.gerlot.securestoragecapabilitiesinspector

import android.content.Intent
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
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.OutlinedIconButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.DialogProperties
import dev.gerlot.securestoragecapabilitiesinspector.ui.theme.Green200
import dev.gerlot.securestoragecapabilitiesinspector.ui.theme.SecureStorageCapabilitiesInspectorTheme
import java.util.Date

class MainActivity : AppCompatActivity() {

    private val viewModel: MainViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        setContent {
            SecureStorageCapabilitiesInspectorTheme {
                val deviceInfoState by viewModel.deviceInfo.collectAsState()
                val secureStorageCapabilitiesState by viewModel.secureStorageCapabilities.collectAsState()
                val keySecureStorageCapabilities by viewModel.keySecureStorageCapabilities.collectAsState()
                val certificateToDisplayInDialog = remember { mutableStateOf<Certificate?>(null) }

                SecureStorageCapabilitiesDisplayScreen(
                    deviceInfoState = deviceInfoState,
                    secureStorageCapabilitiesState = secureStorageCapabilitiesState,
                    keySecureStorageCapabilitiesState = keySecureStorageCapabilities,
                    certificateToDisplayInDialog = certificateToDisplayInDialog,
                    onExportCertificateChainClick = { certificates ->
                        val certificatesExport = certificates.joinToString(
                            separator = ",\n"
                        ) {
                            encodeBERCertificateToString(it.encoded)
                        }
                        val sendIntent: Intent = Intent().apply {
                            action = Intent.ACTION_SEND
                            putExtra(Intent.EXTRA_TEXT, certificatesExport)
                            type = "text/plain"
                        }

                        val shareIntent = Intent.createChooser(sendIntent, null)
                        startActivity(shareIntent)
                    }
                )
            }
        }
    }

    override fun onResume() {
        super.onResume()
        viewModel.inspectSecureStorageCapabilities(this)
    }

}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SecureStorageCapabilitiesDisplayScreen(
    deviceInfoState: DeviceInfo,
    secureStorageCapabilitiesState: SecureStorageCapabilities?,
    keySecureStorageCapabilitiesState: Map<KeyAlgorithm, KeySecureStorageCapabilities>?,
    certificateToDisplayInDialog: MutableState<Certificate?>,
    onExportCertificateChainClick: (List<Certificate>) -> Unit,
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(
                            text = if (!deviceInfoState.deviceName.lowercase().contains(deviceInfoState.deviceBrand.lowercase())) {
                                "${deviceInfoState.deviceBrand} ${deviceInfoState.deviceName} (${deviceInfoState.deviceModel})"
                            } else {
                                "${deviceInfoState.deviceName} (${deviceInfoState.deviceModel})"
                            },
                            maxLines = 1,
                            style = MaterialTheme.typography.titleLarge,
                            overflow = TextOverflow.Ellipsis,
                        )
                        Text(
                            text = "Android ${deviceInfoState.androidVersion} (API ${deviceInfoState.androidApiLevel})",
                            maxLines = 1,
                            style = MaterialTheme.typography.titleMedium,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                },
            )
        }
    ) { innerPadding ->
        SecureStorageCapabilitiesDisplay(
            secureStorageCapabilitiesState = secureStorageCapabilitiesState,
            keySecureStorageCapabilitiesState = keySecureStorageCapabilitiesState,
            certificateToDisplayInDialog = certificateToDisplayInDialog,
            onExportCertificateChainClick = onExportCertificateChainClick,
            modifier = Modifier.padding(innerPadding),
        )
    }
}

@Composable
fun SecureStorageCapabilitiesDisplay(
    secureStorageCapabilitiesState: SecureStorageCapabilities?,
    keySecureStorageCapabilitiesState: Map<KeyAlgorithm, KeySecureStorageCapabilities>?,
    certificateToDisplayInDialog: MutableState<Certificate?>,
    onExportCertificateChainClick: (List<Certificate>) -> Unit,
    modifier: Modifier = Modifier
) {
    if (secureStorageCapabilitiesState != null) {
        Column(
            modifier = modifier
                .padding(start = 8.dp, top = 8.dp, end = 8.dp, bottom = 8.dp)
        ) {
            Column {
                DeviceSecureDisplay(
                    isDeviceSecure = secureStorageCapabilitiesState.isDeviceSecure,
                    modifier = Modifier
                        .padding(horizontal = 8.dp)
                        .padding(bottom = 8.dp),
                )
                BiometricsEnrollmentStatusDisplay(
                    biometricEnrollmentStatus = secureStorageCapabilitiesState.biometricEnrollmentStatus,
                    modifier = Modifier
                        .padding(horizontal = 8.dp)
                        .padding(bottom = 8.dp),
                )
                HasStrongboxKeystoreDisplay(
                    strongBoxKeystore = secureStorageCapabilitiesState.strongBoxKeystoreProperties,
                    modifier = Modifier
                        .padding(horizontal = 8.dp)
                        .padding(bottom = 16.dp),
                )
            }

            val deviceSupportsStrongbox = secureStorageCapabilitiesState.strongBoxKeystoreProperties != null
            val biometricEnrollmentStatus = secureStorageCapabilitiesState.biometricEnrollmentStatus
            if (keySecureStorageCapabilitiesState != null) {
                Column(
                    modifier = Modifier.verticalScroll(rememberScrollState())
                ) {
                    keySecureStorageCapabilitiesState[KeyAlgorithm.RSA_SHA256]?.let {
                        OutlinedCard(
                            modifier = Modifier.padding(bottom = 8.dp)
                        ) {
                            KeySecurityDisplay(
                                state = it,
                                deviceSupportsStrongbox = deviceSupportsStrongbox,
                                biometricEnrollmentStatus = biometricEnrollmentStatus,
                                onCertificateClick = { certificate ->
                                    certificateToDisplayInDialog.value = certificate
                                },
                                onExportCertificateChainClick = onExportCertificateChainClick,
                                modifier = Modifier.padding(bottom = 8.dp)
                            )
                        }
                    }
                    keySecureStorageCapabilitiesState[KeyAlgorithm.RSA_SHA512]?.let {
                        OutlinedCard(
                            modifier = Modifier.padding(bottom = 8.dp)
                        ) {
                            KeySecurityDisplay(
                                state = it,
                                deviceSupportsStrongbox = deviceSupportsStrongbox,
                                biometricEnrollmentStatus = biometricEnrollmentStatus,
                                onCertificateClick = { certificate ->
                                    certificateToDisplayInDialog.value = certificate
                                },
                                onExportCertificateChainClick = onExportCertificateChainClick,
                                modifier = Modifier.padding(bottom = 8.dp)
                            )
                        }
                    }
                    keySecureStorageCapabilitiesState[KeyAlgorithm.EC_SHA256]?.let {
                        OutlinedCard(
                            modifier = Modifier.padding(bottom = 8.dp)
                        ) {
                            KeySecurityDisplay(
                                state = it,
                                deviceSupportsStrongbox = deviceSupportsStrongbox,
                                biometricEnrollmentStatus = biometricEnrollmentStatus,
                                onCertificateClick = { certificate ->
                                    certificateToDisplayInDialog.value = certificate
                                },
                                onExportCertificateChainClick = onExportCertificateChainClick,
                                modifier = Modifier.padding(bottom = 8.dp)
                            )
                        }
                    }
                    keySecureStorageCapabilitiesState[KeyAlgorithm.EC_SHA512]?.let {
                        OutlinedCard(
                            modifier = Modifier.padding(bottom = 8.dp)
                        ) {
                            KeySecurityDisplay(
                                state = it,
                                deviceSupportsStrongbox = deviceSupportsStrongbox,
                                biometricEnrollmentStatus = biometricEnrollmentStatus,
                                onCertificateClick = { certificate ->
                                    certificateToDisplayInDialog.value = certificate
                                },
                                onExportCertificateChainClick = onExportCertificateChainClick,
                                modifier = Modifier.padding(bottom = 8.dp)
                            )
                        }
                    }
                    keySecureStorageCapabilitiesState[KeyAlgorithm.AES]?.let {
                        OutlinedCard(
                            modifier = Modifier.padding(bottom = 8.dp)
                        ) {
                            KeySecurityDisplay(
                                state = it,
                                deviceSupportsStrongbox = deviceSupportsStrongbox,
                                biometricEnrollmentStatus = biometricEnrollmentStatus,
                                onCertificateClick = { certificate ->
                                    certificateToDisplayInDialog.value = certificate
                                },
                                onExportCertificateChainClick = onExportCertificateChainClick,
                                modifier = Modifier.padding(bottom = 8.dp)
                            )
                        }
                    }
                }
            } else {
                Box(
                    modifier = Modifier
                        .weight(1f)
                        .fillMaxSize(),
                    contentAlignment = Alignment.Center,
                ) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(64.dp),
                        color = MaterialTheme.colorScheme.secondary,
                        trackColor = MaterialTheme.colorScheme.surfaceVariant,
                    )
                }
            }
        }

        certificateToDisplayInDialog.value?.let { certificate ->
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
                    Column(
                        modifier = Modifier
                            .verticalScroll(rememberScrollState())
                    ) {
                        Text(
                            text = certificate.toString(),
                            fontWeight = FontWeight.Bold,
                        )
                        Text(
                            text = encodeBERCertificateToString(certificate.encoded)
                        )
                    }
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
        if (isDeviceSecure) "Secure lock (PIN, pattern or password) set"
        else "NO secure lock (PIN, pattern or password) set"
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
    val icon = when (biometricEnrollmentStatus) {
        BiometricEnrollmentStatus.ENROLLED, BiometricEnrollmentStatus.ONLY_DEVICE_CREDENTIALS_ENROLLED -> Icons.Default.Lock
        else -> Icons.Default.Warning
    }
    val iconTint = when (biometricEnrollmentStatus) {
        BiometricEnrollmentStatus.ENROLLED -> Color(0xFF4CAF50)
        BiometricEnrollmentStatus.ONLY_DEVICE_CREDENTIALS_ENROLLED -> Color(0xFFBFE98D)
        else -> Color(0xFFF44336)
    }
    val text = when (biometricEnrollmentStatus) {
        BiometricEnrollmentStatus.ENROLLED -> "Biometrics enrolled"
        BiometricEnrollmentStatus.ONLY_DEVICE_CREDENTIALS_ENROLLED -> "Secure device credentials set (NO STRONG biometrics enrolled)"
        BiometricEnrollmentStatus.UNKNOWN -> "Biometrics enrollment status UNKNOWN"
        BiometricEnrollmentStatus.UNSUPPORTED -> "Biometrics NOT SUPPORTED"
        BiometricEnrollmentStatus.HW_UNAVAILABLE -> "Biometrics hardware UNAVAILABLE"
        BiometricEnrollmentStatus.NONE_ENROLLED -> "NO Biometrics credential enrolled"
        BiometricEnrollmentStatus.NO_HARDWARE -> "NO Biometrics hardware found"
        BiometricEnrollmentStatus.SECURITY_UPDATE_REQUIRED -> "Security update required to re-enable Biometrics"
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
        "StrongBox available ($strongBoxKeystore)"
    } else "NO StrongBox"
    val icon = when (strongBoxKeystore) {
        null -> Icons.Default.Warning
        StrongBoxKeystoreProperties.VERSION_UNKNOWN -> Icons.Default.DeviceUnknown
        StrongBoxKeystoreProperties.V400, StrongBoxKeystoreProperties.V300, StrongBoxKeystoreProperties.V200, StrongBoxKeystoreProperties.V100, StrongBoxKeystoreProperties.V41, StrongBoxKeystoreProperties.V40 -> Icons.Default.CheckCircle
    }
    val iconTint = when (strongBoxKeystore) {
        null -> Color(0xFFFFC107)
        StrongBoxKeystoreProperties.VERSION_UNKNOWN -> Color(0xFFBFE98D)
        StrongBoxKeystoreProperties.V400, StrongBoxKeystoreProperties.V300, StrongBoxKeystoreProperties.V200, StrongBoxKeystoreProperties.V100, StrongBoxKeystoreProperties.V41, StrongBoxKeystoreProperties.V40 -> Color(0xFF4CAF50)
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
    onExportCertificateChainClick: (List<Certificate>) -> Unit,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier
            .padding(top = 8.dp)
            .fillMaxWidth()
    ) {
        Text(
            text = state.keyAlgorithm.displayName,
            style = MaterialTheme.typography.titleMedium,
            modifier = Modifier.padding(start = 8.dp, top = 8.dp, end = 0.dp, bottom = 8.dp)
        )
        if (state.keyGenerationSuccessful) {
            val showCertificateChain = remember { mutableStateOf(false) }

            KeyGenerationSecurityLevelDisplay(
                isKeyGenerationInsideSecureHardware = state.isKeyGenerationInsideSecureHardware,
                keyGenerationSecurityLevel = state.keyGenerationSecurityLevel,
                deviceSupportsStrongbox = deviceSupportsStrongbox,
                modifier = Modifier
                    .padding(horizontal = 8.dp)
                    .padding(bottom = 8.dp),
            )
            UserAuthenticationRequirementEnforcementDisplay(
                biometricEnrollmentStatus = biometricEnrollmentStatus,
                isUserAuthenticationRequirementEnforcedBySecureHardware = state.isUserAuthenticationRequirementEnforcedBySecureHardware,
                modifier = Modifier
                    .padding(horizontal = 8.dp)
                    .padding(bottom = 8.dp),
            )
            CertificateChainDisplay(
                showCertificateChain = showCertificateChain.value,
                onShowCertificateChainClick = {
                    showCertificateChain.value = !showCertificateChain.value
                },
                certificateChain = state.certificateChain,
                onCertificateClick = onCertificateClick,
                onExportCertificateChainClick = onExportCertificateChainClick,
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
            if (isKeyGenerationInsideSecureHardware) "Generated inside secure hardware"
            else "NOT generated inside secure hardware"
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

            KeyGenerationSecurityLevel.UNKNOWN, KeyGenerationSecurityLevel.SOFTWARE -> Color(0xFFF44336)

            KeyGenerationSecurityLevel.UNKNOWN_SECURE -> Color(0xFFFFC107)
            KeyGenerationSecurityLevel.TRUSTED_ENVIRONMENT -> if (!deviceSupportsStrongbox) {
                Color(0xFFBFE98D)
            } else Color(0xFFFFC107)

            KeyGenerationSecurityLevel.STRONGBOX -> Color(0xFF4CAF50)
        }
        val keySecurityLevelText = if (keyGenerationSecurityLevel != null) {
            "Security level: $keyGenerationSecurityLevel"
        } else {
            StringBuilder("Security level cannot be determined").also {
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
            "User authentication requirement enforced by secure hardware"
        } else {
            StringBuilder("User authentication requirement NOT enforced by secure hardware").also {
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
    showCertificateChain: Boolean,
    onShowCertificateChainClick: () -> Unit,
    certificateChain: List<Certificate>?,
    onCertificateClick: (Certificate) -> Unit,
    onExportCertificateChainClick: (List<Certificate>) -> Unit,
    modifier: Modifier = Modifier,
) {
    if (!certificateChain.isNullOrEmpty()) {
        Column(
            modifier = modifier,
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.padding(bottom = 8.dp, end = 8.dp)
            ) {
                Text(
                    "Certificate Chain",
                    modifier = Modifier
                        .padding(horizontal = 8.dp)
                        .weight(1f)
                )
                OutlinedIconButton(
                    onClick = onShowCertificateChainClick,
                    modifier = Modifier
                        .size(44.dp)
                ) {
                    Icon(
                        imageVector = if (showCertificateChain) Icons.Default.KeyboardArrowUp else Icons.Default.KeyboardArrowDown,
                        contentDescription = null
                    )
                }
            }
            if (showCertificateChain) {
                certificateChain.forEach { certificate ->
                    CertificateDisplay(certificate, onCertificateClick)
                }
                OutlinedButton(
                    onClick = { onExportCertificateChainClick(certificateChain) },
                    modifier = Modifier
                        .align(Alignment.CenterHorizontally)
                        .padding(bottom = 8.dp)
                ) {
                    Text("Export Certificate Chain")
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
    Card(
        onClick = {
            onCertificateClick(certificate)
        },
        colors = if (GOOGLE_ROOT_CERTIFICATES.contains(encodeBERCertificateToString(certificate.encoded))) {
            CardDefaults.cardColors().copy(
                containerColor = Green200,
                contentColor = Color.Black,
            )
        } else CardDefaults.cardColors(),
        modifier = modifier.padding(bottom = 8.dp),
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.padding(start = 8.dp, top = 8.dp, end = 16.dp, bottom = 8.dp)
        ) {
            Column(
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
            ),
            keySecureStorageCapabilitiesState = mapOf(
                KeyAlgorithm.RSA_SHA256 to KeySecureStorageCapabilities(
                    keyAlgorithm = KeyAlgorithm.RSA_SHA256,
                    keyGenerationSuccessful = true,
                    isKeyGenerationInsideSecureHardware = true,
                    keyGenerationSecurityLevel = KeyGenerationSecurityLevel.STRONGBOX,
                    isUserAuthenticationRequirementEnforcedBySecureHardware = true,
                ),
                KeyAlgorithm.RSA_SHA512 to KeySecureStorageCapabilities(
                    keyAlgorithm = KeyAlgorithm.RSA_SHA512,
                    keyGenerationSuccessful = true,
                    isKeyGenerationInsideSecureHardware = true,
                    keyGenerationSecurityLevel = KeyGenerationSecurityLevel.STRONGBOX,
                    isUserAuthenticationRequirementEnforcedBySecureHardware = true,
                ),
                KeyAlgorithm.EC_SHA256 to KeySecureStorageCapabilities(
                    keyAlgorithm = KeyAlgorithm.EC_SHA256,
                    keyGenerationSuccessful = true,
                    isKeyGenerationInsideSecureHardware = true,
                    keyGenerationSecurityLevel = KeyGenerationSecurityLevel.STRONGBOX,
                    isUserAuthenticationRequirementEnforcedBySecureHardware = true,
                ),
                KeyAlgorithm.EC_SHA512 to KeySecureStorageCapabilities(
                    keyAlgorithm = KeyAlgorithm.EC_SHA512,
                    keyGenerationSuccessful = true,
                    isKeyGenerationInsideSecureHardware = true,
                    keyGenerationSecurityLevel = KeyGenerationSecurityLevel.STRONGBOX,
                    isUserAuthenticationRequirementEnforcedBySecureHardware = true,
                ),
                KeyAlgorithm.AES to KeySecureStorageCapabilities(
                    keyAlgorithm = KeyAlgorithm.AES,
                    keyGenerationSuccessful = true,
                    isKeyGenerationInsideSecureHardware = true,
                    keyGenerationSecurityLevel = KeyGenerationSecurityLevel.STRONGBOX,
                    isUserAuthenticationRequirementEnforcedBySecureHardware = true,
                ),
            ),
            certificateToDisplayInDialog = certificateToDisplayInDialog,
            onExportCertificateChainClick = { },
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
                    keyAlgorithm = KeyAlgorithm.RSA_SHA256,
                    keyGenerationSuccessful = true,
                    isKeyGenerationInsideSecureHardware = true,
                    keyGenerationSecurityLevel = KeyGenerationSecurityLevel.STRONGBOX,
                    isUserAuthenticationRequirementEnforcedBySecureHardware = true,
                ),
                deviceSupportsStrongbox = true,
                biometricEnrollmentStatus = BiometricEnrollmentStatus.ENROLLED,
                onCertificateClick = { },
                onExportCertificateChainClick = { },
            )
        }
    }
}

@Preview(showBackground = true)
@Composable
fun NoCertificateChainDisplayPreview() {
    SecureStorageCapabilitiesInspectorTheme {
        Surface(
            color = MaterialTheme.colorScheme.surfaceContainerHighest
        ) {
            CertificateChainDisplay(
                showCertificateChain = false,
                onShowCertificateChainClick = { },
                certificateChain = null,
                onCertificateClick = { },
                onExportCertificateChainClick = { },
            )
        }
    }
}

@Preview(showBackground = true)
@Composable
fun CertificateChainDisplayPreview() {
    val certificateChain = listOf(
        Certificate(
            subject = "",
            notBefore = Date(),
            notAfter = Date(),
            stringRepresentation = "",
            encoded = byteArrayOf(),
        ),
        Certificate(
            subject = "",
            notBefore = Date(),
            notAfter = Date(),
            stringRepresentation = "",
            encoded = byteArrayOf(),
        )
    )
    SecureStorageCapabilitiesInspectorTheme {
        Surface(
            color = MaterialTheme.colorScheme.surfaceContainerHighest
        ) {
            CertificateChainDisplay(
                showCertificateChain = false,
                onShowCertificateChainClick = { },
                certificateChain = certificateChain,
                onCertificateClick = { },
                onExportCertificateChainClick = { },
            )
        }
    }
}

@Preview(showBackground = true)
@Composable
fun ExpandedCertificateChainDisplayPreview() {
    val certificateChain = listOf(
        Certificate(
            subject = "CN=Android Keystore Key",
            notBefore = Date(),
            notAfter = Date(),
            stringRepresentation = "",
            encoded = byteArrayOf(),
        ),
        Certificate(
            subject = "CN=Android Keystore Key",
            notBefore = Date(),
            notAfter = Date(),
            stringRepresentation = "",
            encoded = byteArrayOf(),
        )
    )
    SecureStorageCapabilitiesInspectorTheme {
        Surface(
            color = MaterialTheme.colorScheme.surfaceContainerHighest
        ) {
            CertificateChainDisplay(
                showCertificateChain = true,
                onShowCertificateChainClick = { },
                certificateChain = certificateChain,
                onCertificateClick = { },
                onExportCertificateChainClick = { },
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
            secureStorageCapabilitiesState = SecureStorageCapabilities(
                isDeviceSecure = true,
                biometricEnrollmentStatus = BiometricEnrollmentStatus.ENROLLED,
                strongBoxKeystoreProperties = StrongBoxKeystoreProperties.V100,
            ),
            keySecureStorageCapabilitiesState = mapOf(
                KeyAlgorithm.RSA_SHA256 to KeySecureStorageCapabilities(
                    keyAlgorithm = KeyAlgorithm.RSA_SHA256,
                    keyGenerationSuccessful = true,
                    isKeyGenerationInsideSecureHardware = true,
                    keyGenerationSecurityLevel = KeyGenerationSecurityLevel.STRONGBOX,
                    isUserAuthenticationRequirementEnforcedBySecureHardware = true,
                ),
                KeyAlgorithm.RSA_SHA512 to KeySecureStorageCapabilities(
                    keyAlgorithm = KeyAlgorithm.RSA_SHA512,
                    keyGenerationSuccessful = true,
                    isKeyGenerationInsideSecureHardware = true,
                    keyGenerationSecurityLevel = KeyGenerationSecurityLevel.STRONGBOX,
                    isUserAuthenticationRequirementEnforcedBySecureHardware = true,
                ),
                KeyAlgorithm.EC_SHA256 to KeySecureStorageCapabilities(
                    keyAlgorithm = KeyAlgorithm.EC_SHA256,
                    keyGenerationSuccessful = true,
                    isKeyGenerationInsideSecureHardware = true,
                    keyGenerationSecurityLevel = KeyGenerationSecurityLevel.STRONGBOX,
                    isUserAuthenticationRequirementEnforcedBySecureHardware = true,
                ),
                KeyAlgorithm.EC_SHA512 to KeySecureStorageCapabilities(
                    keyAlgorithm = KeyAlgorithm.EC_SHA512,
                    keyGenerationSuccessful = true,
                    isKeyGenerationInsideSecureHardware = true,
                    keyGenerationSecurityLevel = KeyGenerationSecurityLevel.STRONGBOX,
                    isUserAuthenticationRequirementEnforcedBySecureHardware = true,
                ),
                KeyAlgorithm.AES to KeySecureStorageCapabilities(
                    keyAlgorithm = KeyAlgorithm.AES,
                    keyGenerationSuccessful = true,
                    isKeyGenerationInsideSecureHardware = true,
                    keyGenerationSecurityLevel = KeyGenerationSecurityLevel.STRONGBOX,
                    isUserAuthenticationRequirementEnforcedBySecureHardware = true,
                ),
            ),
            certificateToDisplayInDialog = certificateToDisplayInDialog,
            onExportCertificateChainClick = { },
        )
    }
}
