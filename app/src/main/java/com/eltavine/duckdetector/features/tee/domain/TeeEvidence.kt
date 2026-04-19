package com.eltavine.duckdetector.features.tee.domain

data class TeeEvidenceItem(
    val title: String,
    val body: String,
    val level: TeeSignalLevel,
    // 这是隐藏交互使用的原始复制文本；默认不展示在 UI 上，只在特定行位通过手势导出给人工审查。
    // Raw copy text for hidden interaction; it stays out of the visible UI and is only exported from specific rows through a gesture.
    val hiddenCopyText: String? = null,
)

data class TeeEvidenceSection(
    val title: String,
    val items: List<TeeEvidenceItem>,
)
