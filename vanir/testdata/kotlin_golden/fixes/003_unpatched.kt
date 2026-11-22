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
import android.os.UserHandle
import androidx.lifecycle.MediatorLiveData
import com.android.packageinstaller.permission.model.AppPermissionGroup

/**
 * Live Data for AppPermissionGroup
 *
 * @param app: The application this LiveData is being instantiated in
 * @param packageName: The name of the package whose permission group will be watched
 * @param permissionGroupName: The name of the permission group whose app ops this LiveData
 * will watch
 * @param user: The user whose permission group will be observed
 */
class AppPermissionGroupLiveData(
    private val app: Application,
    private val packageName: String,
    private val permissionGroupName: String,
    private val user: UserHandle
) : MediatorLiveData<AppPermissionGroup?>(),
    DataRepository.InactiveTimekeeper {

    private val context = PackageInfoRepository.getUserContext(app, user)
    private lateinit var appOpsLiveData: AppOpsLiveData
    private val packageInfoLiveData =
        PackageInfoRepository.getPackageInfoLiveData(app, packageName, user)
    private val groupLiveData =
        PermissionGroupRepository.getPermissionGroupLiveData(app, permissionGroupName, user)

    override var timeWentInactive: Long? = null

    /**
     * If package and permission group are valid, then initialize appOpsLiveData, add all liveDatas
     * as source, and generate value.
     */
    init {
        if (packageInfoLiveData.value != null && groupLiveData.value != null) {
            appOpsLiveData = AppOpsLiveData(app, packageName, permissionGroupName, user)

            addSource(packageInfoLiveData) {
                generateNewPermissionGroup()
            }

            addSource(groupLiveData) {
                generateNewPermissionGroup()
            }

            /**
             * Since the AppPermissionGroup only keeps a reference to the AppOpManager, it is not
             * immediately affected by app op changes. Regenerate the AppPermissionGroup
             */
            addSource(appOpsLiveData) {
                generateNewPermissionGroup()
            }

            generateNewPermissionGroup()
        }
    }

    /**
     * Create a new AppPermissionGroup. If the package or permission group has become invalid,
     * set value to null, and remove all sources
     */
    private fun generateNewPermissionGroup() {
        val packageInfo = packageInfoLiveData.value
        val groupInfo = groupLiveData.value?.groupInfo
        val permissionInfos = groupLiveData.value?.permissionInfos?.values?.toList()

        if (packageInfo == null || groupInfo == null || permissionInfos == null) {
            removeSource(appOpsLiveData)
            removeSource(groupLiveData)
            removeSource(packageInfoLiveData)
            value = null
        } else {
            value = AppPermissionGroup.create(context, packageInfo, groupInfo,
                permissionInfos, false)
        }
    }

    override fun onInactive() {
        super.onInactive()

        timeWentInactive = System.nanoTime()
    }
}