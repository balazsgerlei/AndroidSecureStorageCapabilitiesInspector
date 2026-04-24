package dev.gerlot.securestoragecapabilities

data class DeviceInfo(
    val deviceName: String,
    val deviceBrand: String,
    val deviceModel: String,
    val androidVersion: String,
    val androidApiLevel: Int,
    val androidVariantName: String? = null,
)
