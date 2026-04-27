# Android Secure Storage Capabilities Inspector

[![API](https://img.shields.io/badge/API-23%2B-brightgreen.svg)](https://android-arsenal.com/api?level=23)
[![last commit](https://img.shields.io/github/last-commit/balazsgerlei/AndroidSecureStorageCapabilitiesInspector?color=018786)](https://github.com/balazsgerlei/AndroidSecureStorageCapabilitiesInspector/commits/main)

![pic1](https://github.com/balazsgerlei/AndroidSecureStorageCapabilitiesInspector/blob/main/app/src/main/res/mipmap-xxhdpi/ic_launcher.png)

The hardware security implementation varies wildly across Android manufacturers. This little utility app, primarily aimed at developers, displays the secure storage capabilities of the device, namely Trusted Execution Environment (TEE) and StrongBox. It also displays the certificate chain, highlighting the presence of a valid root certificate issued by Google (Root of Trust), which is useful for key attestation.

Without actually generating test keys, it is not possible to fully assess whether a device supports, for example, different algorithms, so the app does that for you!

These capabilities are rarely listed in the spec sheets of devices, so you need this tool to assess devices.
