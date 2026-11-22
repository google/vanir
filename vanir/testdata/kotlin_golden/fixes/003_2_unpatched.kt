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

package com.android.packageinstaller.permission.data

import android.app.Application
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.UserHandle
import android.util.Log
import androidx.lifecycle.LiveData

/**
 * LiveData for PackageInfo.
 *
 * @param app: The application this LiveData will watch
 * @param packageName: The name of the package this LiveData will watch for mode changes for
 * @param user: The user for whom the packageInfo will be defined
 */
class PackageInfoLiveData(
    private val app: Application,
    private val packageName: String,
    private val user: UserHandle
) : LiveData<PackageInfo>(),
    PackageBroadcastReceiver.PackageBroadcastListener,
    PermissionListenerMultiplexer.PermissionChangeCallback,
    DataRepository.InactiveTimekeeper {

    private val LOG_TAG = PackageInfoLiveData::class.java.simpleName

    private var context = PackageInfoRepository.getUserContext(app, user)
    private var uid: Int? = null

    /**
     * The currently registered UID on which this LiveData is listening for permission changes
     */
    private var registeredUid: Int? = null

    override var timeWentInactive: Long? = null

    /**
     * Callback from the PackageBroadcastReceiver. Either deletes or generates package data.
     *
     * @param packageName the name of the package which was updated. Ignored in this method.
     */
    override fun onPackageUpdate(packageName: String) {
        generatePackageData()
    }

    override fun getValue(): PackageInfo? {
        return super.getValue() ?: run {
            generatePackageData()
            return super.getValue()
        }
    }

    /**
     * Generates a PackageInfo for our given package.
     */
    private fun generatePackageData() {
        try {
            val packageInfo = context.packageManager.getPackageInfo(packageName,
                PackageManager.GET_PERMISSIONS)
            if (relevantPackageInfoFieldsEqual(packageInfo, super.getValue())) {
                return
            }
            uid = packageInfo.applicationInfo.uid
            value = packageInfo
            return
        } catch (e: PackageManager.NameNotFoundException) {
            Log.w(LOG_TAG, "Package \"$packageName\" not found")
            if (super.getValue() != null) {
                value = null
            }
        }
        return
    }

    private fun relevantPackageInfoFieldsEqual(
        newPkg: PackageInfo?,
        oldPkg: PackageInfo?
    ): Boolean {
        if (oldPkg == null && newPkg == null) {
            return true
        }
        if (oldPkg == null || newPkg == null) {
            return false
        }

        if (oldPkg.packageName != newPkg.packageName || oldPkg.applicationInfo.uid !=
            newPkg.applicationInfo.uid) {
            return false
        }

        val oldPerms = oldPkg.requestedPermissions
        val newPerms = newPkg.requestedPermissions
        if (oldPerms != null) {
            if (!oldPerms.contentEquals(newPerms)) {
                return false
            }
        } else {
            if (newPerms != null) {
                return false
            }
        }

        val oldFlags = oldPkg.requestedPermissionsFlags
        val newFlags = newPkg.requestedPermissionsFlags
        if (oldFlags != null) {
            if (!oldFlags.contentEquals(newFlags)) {
                return false
            }
        } else {
            if (newFlags == null) {
                return false
            }
        }

        return true
    }

    override fun onPermissionChange() {
        generatePackageData()
    }

    override fun onActive() {
        super.onActive()

        PackageInfoRepository.getPackageBroadcastReceiver(app)
            .addChangeCallback(packageName, this)
        generatePackageData()
        value?.applicationInfo?.uid?.let { newUid ->
            uid = newUid
            registeredUid = newUid
            PackageInfoRepository.permissionListenerMultiplexer?.addCallback(newUid, this)
        }
    }

    override fun onInactive() {
        super.onInactive()

        timeWentInactive = System.nanoTime()
        PackageInfoRepository.getPackageBroadcastReceiver(app)
            .removeChangeCallback(packageName, this)
        registeredUid?.let { regUid ->
            PackageInfoRepository.permissionListenerMultiplexer
                ?.removeCallback(regUid, this)
            registeredUid = null
        }
    }
}