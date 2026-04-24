package dev.gerlot.securestoragecapabilities

import android.annotation.SuppressLint
import android.os.Build

class AndroidVariantUtils {

    companion object {

        /**
         * Helper function to read hidden system properties via reflection.
         */
        @SuppressLint("PrivateApi")
        private fun getSystemProperty(key: String): String {
            return try {
                val systemProperties = Class.forName("android.os.SystemProperties")
                val getMethod = systemProperties.getMethod("get", String::class.java, String::class.java)
                getMethod.invoke(null, key, "") as String
            } catch (_: Exception) {
                ""
            }
        }

        @JvmStatic
        val variantName: String?
            get() {
                /**
                 * OEM Skins
                 */
                // Xiaomi HyperOS (Xiaomi's new skin)
                // Need to check this BEFORE MIUI because HyperOS still has some legacy MIUI properties
                if (getSystemProperty("ro.mi.os.version.name").isNotEmpty()) {
                    return "HyperOS"
                }

                // Xiaomi MIUI
                if (getSystemProperty("ro.miui.ui.version.name").isNotEmpty()) {
                    return "MIUI"
                }

                // ColorOS, Realme UI and OxygenOS (OPPO and OnePlus)
                // Oppo, Realme and OnePlus share a unified codebase now, so they all trigger the 'oplusrom' property
                val oplusVersion = getSystemProperty("ro.build.version.oplusrom")
                if (oplusVersion.isNotEmpty()) {
                    // To be able to distinguish them, we fall back to checking the manufacturer or legacy Oxygen props
                    if (getSystemProperty("ro.oxygen.version").isNotEmpty() ||
                        Build.MANUFACTURER.contains("oneplus", ignoreCase = true)
                    ) {
                        return "OxygenOS"
                    } else if (getSystemProperty("ro.realme.ui.version").isNotEmpty()
                        || Build.MANUFACTURER.contains("realme", ignoreCase = true)
                    ) {
                        return "Realme UI"
                    } else {
                        return "ColorOS"
                    }
                }

                // ColorOS (older versions)
                // Before merging the codebase of OxygenOS and ColorOS, another property should be checked
                if (getSystemProperty("ro.build.version.opporom").isNotEmpty()
                    || Build.MANUFACTURER.contains("oppo", ignoreCase = true)
                ) {
                    return "ColorOS"
                }

                // Nothing OS
                if (getSystemProperty("ro.nothing.os.version").isNotEmpty()
                    || Build.MANUFACTURER.contains("nothing", ignoreCase = true)
                ) {
                    return "Nothing OS"
                }

                // ASUS (ZenUI / ROG UI)
                if (getSystemProperty("ro.build.asus.version").isNotEmpty()) {
                    return "ZenUI / ROG UI"
                }

                // Motorola My UX
                if (getSystemProperty("ro.mot.build.customerid").isNotEmpty()) {
                    return "Moto My UX"
                }

                /**
                 * Community ROMs
                 */
                // LineageOS
                if (getSystemProperty("ro.lineage.build.version").isNotEmpty()
                    || getSystemProperty("ro.lineage.version").isNotEmpty()
                ) {
                    return "LineageOS"
                }
                // LineageOS fallback
                if (Build.DISPLAY.contains("lineage", ignoreCase = true)) {
                    return "LineageOS"
                }

                // iodéOS
                // Usually based on Lineage but branded
                if (Build.DISPLAY.contains("iode", ignoreCase = true)) {
                    return "iodéOS"
                }

                // Volla OS
                if (Build.MODEL.contains("Volla", ignoreCase = true) ||
                    Build.DISPLAY.contains("Volla", ignoreCase = true)
                ) {
                    return "Volla OS"
                }

                // Evolution X
                if (Build.DISPLAY.contains("evolution", ignoreCase = true)
                    || Build.PRODUCT.contains("evolution", ignoreCase = true)) {
                    return "Evolution X"
                }

                // Project Elixir
                if (getSystemProperty("ro.elixir.version").isNotEmpty()
                    || Build.DISPLAY.contains("elixir", ignoreCase = true)) {
                    return "Project Elixir"
                }

                /**
                 * Privacy and Security focused ROMs
                 */
                // /e/OS
                // /e/OS is a fork of LineageOS, so it might share the lineage property,
                // but it usually flags itself in the display build
                if (Build.DISPLAY.contains("e/OS", ignoreCase = true)) {
                    return "/e/OS"
                }

                // CalyxOS
                if (Build.DISPLAY.contains("CalyxOS", ignoreCase = true) ||
                    getSystemProperty("ro.com.google.clientidbase").contains(
                        "calyx",
                        ignoreCase = true
                    )
                ) {
                    return "CalyxOS"
                }

                // GrapheneOS
                // GrapheneOS fights fingerprinting so this might not succeed
                if (Build.DISPLAY.contains("grapheneos", ignoreCase = true) ||
                    Build.FINGERPRINT.contains("grapheneos", ignoreCase = true)
                ) {
                    return "GrapheneOS"
                }
                // Fallback for GrapheneOS
                if (Build.USER == "build-user" && Build.HOST == "build-host") {
                    return "GrapheneOS (or similar)"
                }

                return null
            }

    }

}
