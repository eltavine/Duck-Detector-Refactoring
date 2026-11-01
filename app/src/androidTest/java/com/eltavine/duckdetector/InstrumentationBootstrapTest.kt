package com.eltavine.duckdetector

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import androidx.tracing.Trace
import org.junit.Test
import org.junit.runner.RunWith

/** Does not reference target-app classes that R8 can rename or remove. */
@RunWith(AndroidJUnit4::class)
class InstrumentationBootstrapTest {
    @Test fun testRuntimeLinksRequiredLibraries() {
        assertEquals(
            "com.eltavine.duckdetector",
            InstrumentationRegistry.getInstrumentation().targetContext.packageName,
        )
        assertEquals("bootstrap", listOf("bootstrap").single())
        Trace.beginSection("InstrumentationBootstrap")
        Trace.endSection()
    }
}
