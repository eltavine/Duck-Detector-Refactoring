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

package com.eltavine.duckdetector.features.systemproperties.presentation

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.eltavine.duckdetector.features.systemproperties.data.repository.SystemPropertiesRepository
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertiesReport
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertiesStage
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

class SystemPropertiesViewModel(
    private val repository: SystemPropertiesRepository,
    private val mapper: SystemPropertiesCardModelMapper = SystemPropertiesCardModelMapper(),
) : ViewModel() {

    private val _uiState = MutableStateFlow(
        SystemPropertiesUiState(
            stage = SystemPropertiesUiStage.LOADING,
            report = SystemPropertiesReport.loading(),
            cardModel = mapper.map(SystemPropertiesReport.loading()),
        ),
    )
    val uiState: StateFlow<SystemPropertiesUiState> = _uiState.asStateFlow()

    init {
        rescan()
    }

    fun rescan() {
        viewModelScope.launch {
            val loading = SystemPropertiesReport.loading()
            _uiState.update {
                it.copy(
                    stage = SystemPropertiesUiStage.LOADING,
                    report = loading,
                    cardModel = mapper.map(loading),
                )
            }

            val report = repository.scan()
            _uiState.update {
                it.copy(
                    stage = if (report.stage == SystemPropertiesStage.FAILED) {
                        SystemPropertiesUiStage.FAILED
                    } else {
                        SystemPropertiesUiStage.READY
                    },
                    report = report,
                    cardModel = mapper.map(report),
                )
            }
        }
    }

    companion object {
        fun factory(): ViewModelProvider.Factory {
            return object : ViewModelProvider.Factory {
                @Suppress("UNCHECKED_CAST")
                override fun <T : ViewModel> create(modelClass: Class<T>): T {
                    return SystemPropertiesViewModel(SystemPropertiesRepository()) as T
                }
            }
        }
    }
}
