package com.eltavine.duckdetector

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith

/** Does not reference target-app classes that R8 can rename or remove. */
@RunWith(AndroidJUnit4::class)
class InstrumentationBootstrapTest {
    @Test fun testRuntimeIsIndependentOfTargetApk() {
        assertEquals(
            "com.eltavine.duckdetector",
            InstrumentationRegistry.getInstrumentation().targetContext.packageName,
        )
        assertNotNull(Class.forName("kotlin.jvm.internal.Intrinsics"))
        assertNotNull(Class.forName("androidx.tracing.Trace"))
    }
}
