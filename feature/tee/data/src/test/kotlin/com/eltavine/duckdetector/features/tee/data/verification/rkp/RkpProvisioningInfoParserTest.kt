package com.eltavine.duckdetector.features.tee.data.verification.rkp

import org.bouncycastle.asn1.DEROctetString
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RkpProvisioningInfoParserTest {
    private val parser = RkpProvisioningInfoParser()

    @Test
    fun `nested metadata and optional boolean preserve known fields regardless of map order`() {
        val result = parseCbor(
            "a6 05 a3 01 68 415050524f564544 03 6c 4e4f545f415050524f564544 04 42 00ff " +
                "06 f5 07 82 00f6 01 1904d2 03 64 41636d65 04 63 544545",
        )

        assertEquals(1234, result.certsIssued)
        assertEquals("Acme", result.manufacturer)
        assertEquals("TEE", result.validatedEntity)
        val metadata = requireNotNull(result.buildMetadata)
        assertTrue(metadata.contains("\"APPROVED\""))
        assertTrue(metadata.contains("\"NOT_APPROVED\""))
        assertTrue(metadata.contains("h'00FF'", ignoreCase = true))
        assertNull(result.issue)
    }

    @Test
    fun `older map without build metadata remains supported`() {
        val result = parseCbor("a2 01 01 04 63 544545")
        assertEquals(1, result.certsIssued)
        assertEquals("TEE", result.validatedEntity)
        assertNull(result.buildMetadata)
        assertNull(result.issue)
    }

    @Test
    fun `indefinite map and future typed fields do not discard manufacturer`() {
        val result = parseCbor("bf 08 c1 00 01 00 04 63 544545 03 64 41636d65 05 bf 01 81 f4 ff ff")
        assertEquals("Acme", result.manufacturer)
        assertTrue(result.buildMetadata!!.contains("false"))
        assertNull(result.issue)
    }

    @Test
    fun `wrong known field types preserve unrelated fields and report partial decoding`() {
        val result = parseCbor("a3 01 f5 03 00 04 63 544545")
        assertNull(result.certsIssued)
        assertNull(result.manufacturer)
        assertEquals("TEE", result.validatedEntity)
        assertNotNull(result.issue)
    }

    @Test
    fun `large counts are not clamped or wrapped into a different value`() {
        for (count in listOf("1b0000000100000000", "1bffffffffffffffff", "20")) {
            val result = parseCbor("a2 01 $count 04 63 544545")
            assertNull(result.certsIssued)
            assertEquals("TEE", result.validatedEntity)
            assertNotNull(result.issue)
        }
        assertEquals(Int.MAX_VALUE, parseCbor("a1 01 1a7fffffff").certsIssued)
    }

    @Test
    fun `tagged known fields are not silently interpreted as untagged strings`() {
        val result = parseCbor("a2 03 c1 64 41636d65 04 63 544545")
        assertNull(result.manufacturer)
        assertEquals("TEE", result.validatedEntity)
        assertNotNull(result.issue)
    }

    @Test
    fun `malformed ambiguous or trailing CBOR is unavailable`() {
        for (cbor in listOf(
            "a2 01 01 01 02", // Duplicate keys.
            "a1 01 01 00", // Trailing object.
            "a1 03 63 41", // Truncated string.
            "a1 03 61 ff", // Invalid UTF-8.
            "c1 a0", // Tagged top-level map.
            "81 00", // Top-level array.
            "a1 01 1a ff", // Truncated integer.
            "a1 08 9a ffffffff", // Impossible collection length.
        )) {
            val result = parseCbor(cbor)
            assertNotNull(cbor, result.issue)
            assertNull(cbor, result.buildMetadata)
        }
    }

    @Test
    fun `invalid DER wrapping is reported without escaping into the scan`() {
        for (der in listOf("", "a0", "04", "0480a00000", "0402a0", "0401a000", "3000")) {
            assertNotNull(der, parser.parse(hex(der)).issue)
        }
    }

    @Test
    fun `BER octet strings are not accepted as DER extension wrappers`() {
        assertNull(parser.parse(hex("0408 a201010463544545")).issue)
        for (ber in listOf(
            "048108 a201010463544545", // Non-minimal length encoding.
            "240a 0408 a201010463544545", // Constructed OCTET STRING.
            "2480 0408 a201010463544545 0000", // Indefinite-length OCTET STRING.
        )) {
            val result = parser.parse(hex(ber))
            assertNotNull(ber, result.issue)
            assertNull(ber, result.validatedEntity)
        }
    }

    @Test
    fun `deeply constructed ASN1 cannot escape as a stack overflow`() {
        val constructed = hex("2480".repeat(2000) + "0408 a201010463544545" + "0000".repeat(2000))
        val result = parser.parse(constructed)
        assertNotNull(result.issue)
        assertNull(result.validatedEntity)
    }

    @Test
    fun `excessive nesting and extension size have explicit unavailable states`() {
        assertNotNull(parseCbor("a105" + "81".repeat(600) + "00").issue)
        assertNotNull(parser.parse(ByteArray(65537)).issue)
    }

    @Test
    fun `missing required fields remain partial rather than a fully decoded empty map`() {
        val result = parseCbor("a0")
        assertNotNull(result.issue)
        assertNull(result.certsIssued)
        assertNull(result.validatedEntity)
    }

    @Test
    fun `long metadata is explicitly truncated while known fields remain usable`() {
        val result = parseCbor("a3 01 00 04 63 544545 05 79 2328 " + "61".repeat(9000))
        assertEquals(0, result.certsIssued)
        assertEquals("TEE", result.validatedEntity)
        val metadata = requireNotNull(result.buildMetadata)
        assertEquals(8193, metadata.length)
        assertTrue(metadata.endsWith("…"))
        assertTrue(result.issue!!.contains("truncated"))
    }

    @Test
    fun `valid deeply nested metadata is explicitly unavailable instead of silently elided`() {
        val result = parseCbor("a3 01 00 04 63 544545 05 " + "81".repeat(40) + "00")
        assertEquals(0, result.certsIssued)
        assertEquals("TEE", result.validatedEntity)
        assertNull(result.buildMetadata)
        assertTrue(result.issue!!.contains("display nesting limit"))
    }

    private fun parseCbor(value: String): RkpProvisioningInfo = parser.parse(derCbor(value))
}

internal fun derCbor(value: String): ByteArray = DEROctetString(hex(value)).encoded

private fun hex(value: String): ByteArray = value.filterNot(Char::isWhitespace)
    .chunked(2).map { it.toInt(16).toByte() }.toByteArray()
