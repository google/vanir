/*
 * Copyright (C) 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.permissioncontroller.permission.model.livedatatypes

import android.content.pm.PackageManager
import android.content.pm.PermissionInfo
import com.android.permissioncontroller.permission.utils.SoftRestrictedPermissionPolicy
import com.android.permissioncontroller.permission.utils.Utils
import com.android.permissioncontroller.permission.utils.Utils.isRuntimePlatformPermission

/**
 * Represents a single permission, and its state
 *
 * @param pkgInfo The package requesting the permission
 * @param permInfo The permissionInfo this represents
 * @param isGrantedIncludingAppOp Whether or not this permission is functionally granted.
 * A non-granted app op but granted permission is counted as not granted
 * @param flags The PermissionController flags for this permission
 * @param foregroundPerms The foreground permission names corresponding to this permission, if this
 * permission is a background permission
 */
data class LightPermission(
    val pkgInfo: LightPackageInfo,
    val permInfo: LightPermInfo,
    val isGrantedIncludingAppOp: Boolean,
    val flags: Int,
    val foregroundPerms: List<String>?
) {

    constructor(
        pkgInfo: LightPackageInfo,
        permInfo: LightPermInfo,
        permState: PermState,
        foregroundPerms: List<String>?
    ) :
        this(pkgInfo, permInfo, permState.granted, permState.permFlags, foregroundPerms)

    /** The name of this permission */
    val name = permInfo.name
    /** The background permission name of this permission, if it exists */
    val backgroundPermission: String? = permInfo.backgroundPermission
    /** If this is a background permission **/
    val isBackgroundPermission = foregroundPerms?.isNotEmpty() ?: false
    /** Whether this permission is fixed by policy */
    val isPolicyFixed = flags and PackageManager.FLAG_PERMISSION_POLICY_FIXED != 0
    /** Whether this permission is fixed by the system */
    val isSystemFixed = flags and PackageManager.FLAG_PERMISSION_SYSTEM_FIXED != 0
    /** Whether this permission is fixed by the system */
    val isUserFixed = flags and PackageManager.FLAG_PERMISSION_USER_FIXED != 0
    /** Whether this permission is user set */
    val isUserSet = flags and PackageManager.FLAG_PERMISSION_USER_SET != 0
    /** Whether this permission is granted, but its app op is revoked */
    val isCompatRevoked = flags and PackageManager.FLAG_PERMISSION_REVOKED_COMPAT != 0
    /** Whether this permission requires review (only relevant for pre-M apps) */
    val isReviewRequired = flags and PackageManager.FLAG_PERMISSION_REVIEW_REQUIRED != 0
    /** Whether this permission is one-time */
    val isOneTime = flags and PackageManager.FLAG_PERMISSION_ONE_TIME != 0
    /** Whether this permission is an instant app permission */
    val isInstantPerm = permInfo.protectionFlags and PermissionInfo.PROTECTION_FLAG_INSTANT != 0
    /** Whether this permission is a runtime only permission */
    val isRuntimeOnly =
        permInfo.protectionFlags and PermissionInfo.PROTECTION_FLAG_RUNTIME_ONLY != 0
    /** Whether this permission is granted by default */
    val isGrantedByDefault = flags and PackageManager.FLAG_PERMISSION_GRANTED_BY_DEFAULT != 0
    /** Whether this permission is granted by role */
    val isGrantedByRole = flags and PackageManager.FLAG_PERMISSION_GRANTED_BY_ROLE != 0
    /** Whether this permission is set to be revoked upon being requested */
    val isRevokeWhenRequested = flags and PackageManager.FLAG_PERMISSION_REVOKE_WHEN_REQUESTED != 0
    /** Whether this permission is user sensitive in its current grant state */
    val isUserSensitive = !isRuntimePlatformPermission(permInfo.name) ||
            (isGrantedIncludingAppOp &&
                    (flags and PackageManager.FLAG_PERMISSION_USER_SENSITIVE_WHEN_GRANTED) != 0) ||
            (!isGrantedIncludingAppOp &&
                    (flags and PackageManager.FLAG_PERMISSION_USER_SENSITIVE_WHEN_DENIED) != 0)
    /** Whether the permission is restricted */
    val isRestricted = when {
        (permInfo.flags and PermissionInfo.FLAG_HARD_RESTRICTED) != 0 -> {
            flags and Utils.FLAGS_PERMISSION_RESTRICTION_ANY_EXEMPT == 0
        }
        (permInfo.flags and PermissionInfo.FLAG_SOFT_RESTRICTED) != 0 -> {
            !SoftRestrictedPermissionPolicy.shouldShow(pkgInfo, permInfo.name, flags)
        }
        else -> {
            false
        }
    }
    /** Whether the permission is auto revoked */
    val isAutoRevoked = flags and PackageManager.FLAG_PERMISSION_AUTO_REVOKED != 0
    /**
     * Whether the location permission is selected as the level of granularity of location accuracy
     */
    val isSelectedLocationAccuracy =
        flags and PackageManager.FLAG_PERMISSION_SELECTED_LOCATION_ACCURACY != 0

    override fun toString() = buildString {
        append(name)
        if (isGrantedIncludingAppOp) append(", Granted") else append(", NotGranted")
        if (isPolicyFixed) append(", PolicyFixed")
        if (isSystemFixed) append(", SystemFixed")
        if (isUserFixed) append(", UserFixed")
        if (isUserSet) append(", UserSet")
        if (isRevokeWhenRequested) append(", RevokeWhenRequested")
        if (isCompatRevoked) append(", CompatRevoked")
        if (isReviewRequired) append(", ReviewRequired")
        if (isOneTime) append(", OneTime")
        if (isGrantedByDefault) append(", GrantedByDefault")
        if (isGrantedByRole) append(", GrantedByRole")
        if (isUserSensitive) append(", UserSensitive")
        if (isRestricted) append(", Restricted")
        if (isAutoRevoked) append(", AutoRevoked")
        if (isSelectedLocationAccuracy) append(", SelectedLocationAccuracy")
    }
}