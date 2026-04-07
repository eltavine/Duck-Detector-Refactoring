package com.eltavine.duckdetector.buildlogic

import org.gradle.api.provider.Property
import org.gradle.api.provider.ValueSource
import org.gradle.api.provider.ValueSourceParameters
import org.gradle.process.ExecOperations
import java.io.ByteArrayOutputStream
import java.io.File
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import javax.inject.Inject

private const val UNKNOWN = "unknown"
private val BUILD_TIME_FORMATTER = DateTimeFormatter.ofPattern("yyyyMMddHHmmss")
    .withZone(ZoneOffset.UTC)

interface GitRepositoryParameters : ValueSourceParameters {
    val repositoryRoot: Property<String>
}

abstract class GitShortHashValueSource @Inject constructor(
    private val execOperations: ExecOperations,
) : ValueSource<String, GitRepositoryParameters> {
    override fun obtain(): String = runGitCommand(
        execOperations = execOperations,
        repositoryRoot = parameters.repositoryRoot.get(),
        "rev-parse",
        "--short=12",
        "HEAD",
    )
}

abstract class GitCommitTimestampValueSource @Inject constructor(
    private val execOperations: ExecOperations,
) : ValueSource<String, GitRepositoryParameters> {
    override fun obtain(): String {
        val epochSeconds = runGitCommand(
            execOperations = execOperations,
            repositoryRoot = parameters.repositoryRoot.get(),
            "log",
            "-1",
            "--format=%ct",
            "HEAD",
        )
        val instant = epochSeconds.toLongOrNull()?.let(Instant::ofEpochSecond) ?: return UNKNOWN
        return BUILD_TIME_FORMATTER.format(instant)
    }
}

private fun runGitCommand(
    execOperations: ExecOperations,
    repositoryRoot: String,
    vararg arguments: String,
): String {
    val stdout = ByteArrayOutputStream()
    val stderr = ByteArrayOutputStream()

    val result = runCatching {
        execOperations.exec {
            workingDir = File(repositoryRoot)
            commandLine("git", *arguments)
            standardOutput = stdout
            errorOutput = stderr
            isIgnoreExitValue = true
        }
    }.getOrNull() ?: return UNKNOWN

    return if (result.exitValue == 0) {
        stdout.toString().trim().ifBlank { UNKNOWN }
    } else {
        UNKNOWN
    }
}
