package dev.gerlot.securestoragecapabilitiesinspector

import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

const val CERTIFICATE_HEADER = "-----BEGIN CERTIFICATE-----"
const val CERTIFICATE_FOOTER = "-----BEGIN CERTIFICATE-----"

@OptIn(ExperimentalEncodingApi::class)
fun encodeBERCertificateToString(encoded: ByteArray) = "$CERTIFICATE_HEADER\n${
    Base64.Default.encode(encoded).chunked(64).joinToString("\n")
}\n$CERTIFICATE_FOOTER"
