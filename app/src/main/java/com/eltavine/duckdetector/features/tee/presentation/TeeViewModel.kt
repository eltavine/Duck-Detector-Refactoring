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

package com.eltavine.duckdetector.features.tee.presentation

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.eltavine.duckdetector.features.tee.data.repository.TeeRepository
import com.eltavine.duckdetector.features.tee.domain.TeeReport
import com.eltavine.duckdetector.features.tee.domain.TeeScanStage
import com.eltavine.duckdetector.features.tee.ui.model.TeeFooterActionId
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

class TeeViewModel(
    private val repository: TeeRepository,
    private val mapper: TeeCardModelMapper = TeeCardModelMapper(),
) : ViewModel() {

    private val _uiState = MutableStateFlow(
        TeeUiState(
            stage = TeeUiStage.LOADING,
            report = TeeReport.loading(),
            cardModel = mapper.map(TeeReport.loading(), isExpanded = false),
        ),
    )
    val uiState: StateFlow<TeeUiState> = _uiState.asStateFlow()

    init {
        rescan()
    }

    fun onExpandedChange(expanded: Boolean) {
        _uiState.update { state ->
            state.copy(cardModel = mapper.map(state.report, expanded))
        }
    }

    fun onFooterAction(actionId: TeeFooterActionId) {
        when (actionId) {
            TeeFooterActionId.RESCAN -> rescan()
            TeeFooterActionId.DETAILS -> _uiState.update { it.copy(showDetailsDialog = true) }
            TeeFooterActionId.CERTIFICATES -> _uiState.update { it.copy(showCertificatesDialog = true) }
        }
    }

    fun dismissDetails() {
        _uiState.update { it.copy(showDetailsDialog = false) }
    }

    fun dismissCertificates() {
        _uiState.update { it.copy(showCertificatesDialog = false) }
    }

    fun rescan() {
        viewModelScope.launch {
            val expanded = _uiState.value.cardModel.isExpanded
            val loading = TeeReport.loading()
            _uiState.update { state ->
                state.copy(
                    stage = TeeUiStage.LOADING,
                    report = loading,
                    cardModel = mapper.map(loading, expanded),
                )
            }
            val report = repository.scan()
            val stage = when {
                report.stage == TeeScanStage.FAILED -> TeeUiStage.FAILED
                else -> TeeUiStage.READY
            }
            _uiState.update { state ->
                state.copy(
                    stage = stage,
                    report = report,
                    cardModel = mapper.map(report, state.cardModel.isExpanded),
                )
            }
        }
    }

    companion object {
        fun factory(context: Context): ViewModelProvider.Factory {
            val appContext = context.applicationContext
            return object : ViewModelProvider.Factory {
                @Suppress("UNCHECKED_CAST")
                override fun <T : ViewModel> create(modelClass: Class<T>): T {
                    return TeeViewModel(TeeRepository(appContext)) as T
                }
            }
        }
    }
}
