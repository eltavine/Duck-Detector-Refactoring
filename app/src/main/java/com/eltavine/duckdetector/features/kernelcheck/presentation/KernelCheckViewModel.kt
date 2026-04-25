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

package com.eltavine.duckdetector.features.kernelcheck.presentation

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.eltavine.duckdetector.features.kernelcheck.data.repository.KernelCheckRepository
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckReport
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckStage
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

class KernelCheckViewModel(
    private val repository: KernelCheckRepository,
    private val mapper: KernelCheckCardModelMapper = KernelCheckCardModelMapper(),
) : ViewModel() {

    private val _uiState = MutableStateFlow(
        KernelCheckUiState(
            stage = KernelCheckUiStage.LOADING,
            report = KernelCheckReport.loading(),
            cardModel = mapper.map(KernelCheckReport.loading()),
        ),
    )
    val uiState: StateFlow<KernelCheckUiState> = _uiState.asStateFlow()

    init {
        rescan()
    }

    fun rescan() {
        viewModelScope.launch {
            val loading = KernelCheckReport.loading()
            _uiState.update {
                it.copy(
                    stage = KernelCheckUiStage.LOADING,
                    report = loading,
                    cardModel = mapper.map(loading),
                )
            }

            val report = repository.scan()
            _uiState.update {
                it.copy(
                    stage = if (report.stage == KernelCheckStage.FAILED) {
                        KernelCheckUiStage.FAILED
                    } else {
                        KernelCheckUiStage.READY
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
                    return KernelCheckViewModel(KernelCheckRepository()) as T
                }
            }
        }
    }
}
