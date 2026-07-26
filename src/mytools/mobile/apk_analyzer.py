"""APK metadata analysis via androguard."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("mytools.mobile.apk_analyzer")

# Known SDK fingerprints: package prefix → SDK name
_SDK_FINGERPRINTS: dict[str, str] = {
    "com.google.firebase": "Firebase",
    "com.google.android.gms": "Google Play Services",
    "com.facebook": "Facebook SDK",
    "com.twitter": "Twitter/X SDK",
    "com.squareup.okhttp": "OkHttp",
    "com.squareup.retrofit": "Retrofit",
    "io.realm": "Realm",
    "com.amplitude": "Amplitude Analytics",
    "com.mixpanel": "Mixpanel",
    "com.adjust": "Adjust",
    "com.appsflyer": "AppsFlyer",
    "com.braze": "Braze",
    "com.segment": "Segment",
    "com.kochava": "Kochava",
    "com.leanplum": "Leanplum",
    "com.urbanairship": "Urban Airship",
    "com.onesignal": "OneSignal",
    "com.intercom": "Intercom",
    "com.zendesk": "Zendesk",
    "com.crashlytics": "Crashlytics",
    "io.sentry": "Sentry",
    "com.datadog": "Datadog",
    "com.newrelic": "New Relic",
    "com.microsoft.appcenter": "App Center",
    "com.amazon": "Amazon SDK",
    "com.microsoft.azure": "Azure SDK",
    "io.flutter": "Flutter",
    "com.reactnative": "React Native",
    "expo.modules": "Expo",
    "org.apache.cordova": "Cordova",
    "com.unity3d": "Unity",
    "com.gameanalytics": "GameAnalytics",
    "net.hockeyapp": "HockeyApp",
}


def analyze_apk(file_path: str) -> dict[str, Any]:
    """Extrai metadata completa de um APK.

    Returns:
        Dict com keys: package, version_name, version_code, min_sdk,
        target_sdk, permissions, exported_components, activities,
        services, receivers, providers, sdk_fingerprints, file_size.
    """
    try:
        from androguard.misc import AnalyzeAPK
    except ImportError:
        logger.error("androguard not installed: pip install androguard==4.1.4")
        return {"error": "androguard not installed"}

    try:
        a, _d, dx = AnalyzeAPK(file_path)  # type: ignore[no-untyped-def]
    except Exception as e:
        logger.error("Failed to parse APK %s: %s", file_path, e)
        return {"error": str(e)[:200]}

    # Metadata
    package = a.get_package() or ""
    version_name = a.get_androidversion_name() or ""
    version_code = a.get_androidversion_code() or ""
    min_sdk = a.get_min_sdk_version() or ""
    target_sdk = a.get_target_sdk_version() or ""

    # Permissions
    permissions = sorted(a.get_permissions() or [])

    # Components
    activities = sorted(a.get_activities() or [])
    services = sorted(a.get_services() or [])
    receivers = sorted(a.get_receivers() or [])
    providers = sorted(a.get_providers() or [])

    exported_activities = sorted(a.get_activities() or [])
    exported_services = sorted(a.get_services() or [])
    exported_receivers = sorted(a.get_receivers() or [])
    exported_providers = sorted(a.get_providers() or [])

    # SDK fingerprinting via DEX strings
    sdk_fingerprints: list[str] = []
    try:
        all_strings = [s.get_value() for s in dx.get_strings()]
        for sdk_pkg, sdk_name in _SDK_FINGERPRINTS.items():
            if any(sdk_pkg in s for s in all_strings):
                sdk_fingerprints.append(sdk_name)
    except Exception:
        pass

    from pathlib import Path

    return {
        "package": package,
        "version_name": version_name,
        "version_code": version_code,
        "min_sdk": min_sdk,
        "target_sdk": target_sdk,
        "permissions": permissions,
        "permissions_count": len(permissions),
        "activities": activities,
        "services": services,
        "receivers": receivers,
        "providers": providers,
        "exported_activities": exported_activities,
        "exported_services": exported_services,
        "exported_receivers": exported_receivers,
        "exported_providers": exported_providers,
        "sdk_fingerprints": sdk_fingerprints,
        "file_size": Path(file_path).stat().st_size,
    }
