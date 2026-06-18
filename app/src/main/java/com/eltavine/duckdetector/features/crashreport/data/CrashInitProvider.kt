/*
 * Copyright 2026 Duck Apps Contributor
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.eltavine.duckdetector.features.crashreport.data

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri
import android.util.Log

/**
 * Installs the global crash handler at the earliest possible moment.
 *
 * Android calls [ContentProvider.onCreate] **before** [Application.onCreate],
 * making this the earliest safe hook for registering an
 * [UncaughtExceptionHandler][java.lang.Thread.UncaughtExceptionHandler].
 *
 * This provider does not serve any actual content — it exists purely as an
 * initialization vehicle.
 *
 * Registered in AndroidManifest.xml with `initOrder` to guarantee it runs
 * before any other provider or the Application.
 */
class CrashInitProvider : ContentProvider() {

    override fun onCreate(): Boolean {
        context?.let { ctx ->
            CrashHandler.install(ctx)
            Log.d("DuckCrashInit", "Crash handler installed via ContentProvider (earliest hook)")
        }
        return true
    }

    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?,
    ): Cursor? = null

    override fun getType(uri: Uri): String? = null

    override fun insert(uri: Uri, values: ContentValues?): Uri? = null

    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0

    override fun update(
        uri: Uri,
        values: ContentValues?,
        selection: String?,
        selectionArgs: Array<out String>?,
    ): Int = 0
}
