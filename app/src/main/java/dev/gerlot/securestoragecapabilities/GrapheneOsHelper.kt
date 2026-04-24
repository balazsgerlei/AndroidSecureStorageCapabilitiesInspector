package dev.gerlot.securestoragecapabilities

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager

class GrapheneOsHelper {

    companion object {

        private val graphenePackages = listOf(
            "app.grapheneos.camera",
            "app.grapheneos.camera.play",
            "app.grapheneos.pdfviewer",
            "app.grapheneos.networklocation",
            "app.grapheneos.apps"
        )

        private fun isSystemPackage(packageManager: PackageManager, packageName: String): Boolean {
            return try {
                return packageManager.getPackageInfo(packageName, 0).applicationInfo?.run {
                    val isSystemApp = (flags and ApplicationInfo.FLAG_SYSTEM) != 0
                    val isUpdatedSystemApp = (flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0

                    isSystemApp || isUpdatedSystemApp
                } ?: false
            } catch (_: PackageManager.NameNotFoundException) {
                false
            }
        }

        private var _isGrapheneOs: Boolean? = null

        fun isGrapheneOs(context: Context): Boolean {
            if (_isGrapheneOs == null) {
                for (packageName in graphenePackages) {
                    if (isSystemPackage(context.packageManager, packageName)) {
                        _isGrapheneOs = true
                        break
                    }
                }
            }
            return _isGrapheneOs == true
        }

    }
}
