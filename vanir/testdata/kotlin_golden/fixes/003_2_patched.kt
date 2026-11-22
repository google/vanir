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
import android.content.pm.PackageManager
import android.os.UserHandle
import android.util.Log
import com.android.packageinstaller.permission.model.livedatatypes.LightPackageInfo
import com.android.packageinstaller.permission.utils.Utils

/**
 * LiveData for PackageInfo.
 *
 * @param app: The current Application
 * @param packageName: The name of the package this LiveData will watch for mode changes for
 * @param user: The user for whom the packageInfo will be defined
 */
class PackageInfoLiveData(
    private val app: Application,
    private val packageName: String,
    private val user: UserHandle
) : SmartAsyncMediatorLiveData<LightPackageInfo>(),
    PackageBroadcastReceiver.PackageBroadcastListener,
    PermissionListenerMultiplexer.PermissionChangeCallback {

    private val LOG_TAG = PackageInfoLiveData::class.java.simpleName

    private var context = Utils.getUserContext(app, user)
    private var uid: Int? = null
    /**
     * The currently registered UID on which this LiveData is listening for permission changes.
     */
    private var registeredUid: Int? = null

    /**
     * Callback from the PackageBroadcastReceiver. Either deletes or generates package data.
     *
     * @param packageName the name of the package which was updated. Ignored in this method
     */
    override fun onPackageUpdate(packageName: String) {
        updateAsync()
    }

    override fun setValue(newValue: LightPackageInfo?) {
        newValue?.let { packageInfo ->
            if (packageInfo.uid != uid) {
                uid = packageInfo.uid
                PackageInfoRepository.permissionListenerMultiplexer?.addOrReplaceCallback(
                    registeredUid, packageInfo.uid, this)
                registeredUid = uid
            }
        }
        super.setValue(newValue)
    }

    override fun loadData(isCancelled: () -> Boolean): LightPackageInfo? {
        try {
            if (isCancelled()) {
                // return will be ignored
                return value
            }
            return LightPackageInfo(context.packageManager.getPackageInfo(packageName,
                PackageManager.GET_PERMISSIONS))
        } catch (e: PackageManager.NameNotFoundException) {
            Log.w(LOG_TAG, "Package \"$packageName\" not found")
            value = null
        }
        return null
    }

    /**
     * Callback from the PermissionListener. Either deletes or generates package data.
     */
    override fun onPermissionChange() {
        updateAsync()
    }

    override fun onActive() {
        super.onActive()

        PackageInfoRepository.getPackageBroadcastReceiver(app)
            .addChangeCallback(packageName, this)
        uid?.let {
            registeredUid = uid
            PackageInfoRepository.permissionListenerMultiplexer?.addCallback(it, this)
        }
        updateAsync()
    }

    override fun onInactive() {
        super.onInactive()

        PackageInfoRepository.getPackageBroadcastReceiver(app)
            .removeChangeCallback(packageName, this)
        registeredUid?.let {
            PackageInfoRepository.permissionListenerMultiplexer
                ?.removeCallback(it, this)
            registeredUid = null
        }
    }
}

/**
 * Repository for PackageInfoLiveDatas, and a PackageBroadcastReceiver.
 * <p> Key value is a string package name and UserHandle pair, value is its corresponding LiveData.
 */
object PackageInfoRepository : DataRepository<Pair<String, UserHandle>, PackageInfoLiveData>() {

    private var broadcastReceiver: PackageBroadcastReceiver? = null

    /**
     * Gets the PackageBroadcastReceiver, instantiating it if need be.
     *
     * @param app: The current application
     *
     * @return The cached or newly created PackageBroadcastReceiver
     */
    fun getPackageBroadcastReceiver(app: Application): PackageBroadcastReceiver {
        if (broadcastReceiver == null) {
            broadcastReceiver = PackageBroadcastReceiver(app)
        }
        return broadcastReceiver!!
    }

    /**
     * Used by the PackageInfoLiveData objects. Must be instantiated if used before
     * getPackageInfoLiveData is called for the first time.
     */
    var permissionListenerMultiplexer: PermissionListenerMultiplexer? = null

    /**
     * Gets the PackageInfoLiveData associated with the provided package name and user,
     * creating it if need be.
     *
     * @param app: The current application
     * @param packageName: The name of the package desired
     * @param user: The UserHandle for whom we want the package
     *
     * @return The cached or newly created PackageInfoLiveData
     */
    fun getPackageInfoLiveData(app: Application, packageName: String, user: UserHandle):
        PackageInfoLiveData {
        if (permissionListenerMultiplexer == null) {
            permissionListenerMultiplexer =
                PermissionListenerMultiplexer(app)
        }
        return getDataObject(app, packageName to user)
    }

    /**
     * Sets the value of the specified PackageInfoLiveData to the provided PackageInfo, creating it
     * if need be. Used only by the UserPackageInfoLiveData, since that gets fresh PackageInfos.
     *
     * @param app: The current application
     * @param packageInfo: The PackageInfo we wish to set the value to
     */
    fun setPackageInfoLiveData(app: Application, packageInfo: LightPackageInfo) {
        val user = UserHandle.getUserHandleForUid(packageInfo.uid)
        val liveData = getDataObject(app, packageInfo.packageName to user)
        liveData.value = packageInfo
    }

    override fun newValue(app: Application, key: Pair<String, UserHandle>): PackageInfoLiveData {
        return PackageInfoLiveData(app, key.first, key.second)
    }
}
