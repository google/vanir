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
 * limitations under the License
 */

package com.android.packageinstaller.permission.data

import android.app.Application
import android.content.pm.PackageManager
import android.os.UserHandle
import com.android.packageinstaller.permission.model.AppPermissionGroup
import com.android.packageinstaller.permission.utils.Utils

/**
 * Live Data for an AppPermissionGroup.
 *
 * @param app: The current application
 * @param packageName: The name of the package whose permission group will be observed
 * @param permissionGroupName: The name of the permission group whose permissions will be observed
 * @param user: The user whose app permission group will be observed
 */
class AppPermissionGroupLiveData(
    private val app: Application,
    private val packageName: String,
    private val permissionGroupName: String,
    private val user: UserHandle
) : SmartUpdateMediatorLiveData<AppPermissionGroup?>(),
    DataRepository.InactiveTimekeeper {

    private val context = Utils.getUserContext(app, user)
    private val packageInfoLiveData =
        PackageInfoRepository.getPackageInfoLiveData(app, packageName, user)
    private val groupLiveData =
        PermGroupRepository.getPermGroupLiveData(app, permissionGroupName)
    private val permStateLiveData =
        PermStateRepository.getPermStateLiveData(app, packageName, permissionGroupName,
            user)

    /**
     * If package and permission group are valid, then initialize appOpsLiveData, add all liveDatas
     * as source, and generate value.
     */
    init {

        addSource(groupLiveData) {
            update()
        }
        if (!groupLiveData.isInitialized) {
            groupLiveData.update()
        }

        addSource(packageInfoLiveData) {
            update()
        }

        addSource(permStateLiveData) {
            update()
        }

        // TODO ntmyren: Fix the AppPermissionFragment, remove this once done
        if (!isInitialized) {
            update()
        }
    }

    /**
     * Create a new AppPermissionGroup, or update the existing one.
     */
    private fun update() {
        // TODO ntmyren: Fix the AppPermissionFragment, remove this once done
        val userContext = Utils.getUserContext(app, user)
        val packageInfo = packageInfoLiveData.value?.toPackageInfo(app)
            ?: userContext.packageManager.getPackageInfo(packageName,
                PackageManager.GET_PERMISSIONS)
        val groupInfo = groupLiveData.value?.groupInfo ?: return
        val lightPermInfos = groupLiveData.value?.permissionInfos?.values?.toList()
        val permissionInfos = lightPermInfos?.map {
            lightPermInfo -> lightPermInfo.toPermissionInfo(app) }

        value = AppPermissionGroup.create(context, packageInfo,
            groupInfo.toPackageItemInfo(app), permissionInfos, false)
    }
}

/**
 * Repository for AppPermissionGroupLiveDatas.
 * <p> Key value is a (packageName, permissionGroupName, user) triple, value is an app permission
 * group LiveData.
 */
object AppPermissionGroupRepository
    : DataRepository<Triple<String, String, UserHandle>, AppPermissionGroupLiveData>() {

    /**
     * Gets the AppPermissionGroupLiveData associated with the provided group name and user,
     * creating it if need be.
     *
     * @param app: The current application
     * @param packageName: The name of the package desired
     * @param permissionGroup: The name of the permission group desired
     * @param user: The UserHandle of the user desired
     *
     * @return The cached or newly created AppPermissionGroupLiveData
     */
    fun getAppPermissionGroupLiveData(
        app: Application,
        packageName: String,
        permissionGroup: String,
        user: UserHandle
    ): AppPermissionGroupLiveData {
        return getDataObject(app, Triple(packageName, permissionGroup, user))
    }

    override fun newValue(
        app: Application,
        key: Triple<String, String, UserHandle>
    ): AppPermissionGroupLiveData {
        return AppPermissionGroupLiveData(app, key.first, key.second, key.third)
    }
}
