package com.androidharness.app.tools

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SecretRedactorTest {

    @Test
    fun `common secret shapes are stripped`() {
        val raw = """
            token=sk-abcDEF1234567890xyz
            AWS AKIAIOSFODNN7EXAMPLE
            Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig
            GEMINI AIzaSyA-not-a-real-key-0123456789abcd
            password=hunter2
            -----BEGIN PRIVATE KEY-----
            MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC
            -----END PRIVATE KEY-----
        """.trimIndent()
        val out = SecretRedactor.redact(raw)
        assertFalse(out.contains("sk-abcDEF"))
        assertFalse(out.contains("AKIAIOSFODNN7EXAMPLE"))
        assertFalse(out.contains("eyJhbGciOiJIUzI1NiJ9"))
        assertFalse(out.contains("AIzaSyA-not-a-real-key"))
        assertFalse(out.contains("hunter2"))
        assertFalse(out.contains("MIIEvQIBADANBgkqhkiG9w0BAQE"))
        assertTrue(out.contains("[redacted]"))
    }

    @Test
    fun `anthropic openai groq and tavily keys are stripped`() {
        val raw = """
            ANTHROPIC=sk-ant-api03-1234567890abcdef1234567890abcdef12345678
            OPENAI_PROJ=sk-proj-1234567890abcdef1234567890abcdef
            GROQ=gsk_1234567890abcdef1234567890abcdef
            TAVILY=tvly-1234567890abcdef1234567890abcdef
        """.trimIndent()
        val out = SecretRedactor.redact(raw)
        assertFalse(out.contains("sk-ant-api03"))
        assertFalse(out.contains("sk-proj-12345"))
        assertFalse(out.contains("gsk_1234567890"))
        assertFalse(out.contains("tvly-1234567890"))
        assertTrue(out.contains("[redacted]"))
    }

    @Test
    fun `github tokens are stripped everywhere they appear`() {
        val raw = """
            export GH_TOKEN=gho_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8
            clone https://x-access-token:ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456@github.com/o/r.git
            remote: github_pat_AAAA0000bbbb1111CCCC2222dddd3333EEEE4444
        """.trimIndent()
        val out = SecretRedactor.redact(raw)
        assertFalse(out.contains("gho_A1b2C3d4"))
        assertFalse(out.contains("ghp_ABCDEFGHIJKLMNOP"))
        assertFalse(out.contains("github_pat_AAAA0000"))
        // the host and path survive the userinfo redaction
        assertTrue(out.contains("https://[redacted]@github.com/o/r.git"))
    }

    @Test
    fun `ordinary code is left alone`() {
        val src = "fun main() { println(\"hello\") }\nval api = 1"
        assertTrue(SecretRedactor.redact(src) == src)
    }

    @Test
    fun `plain urls without userinfo are untouched`() {
        val src = "https://github.com/Sanuu7/AndroidHarness.git https://example.com/a?b=1"
        assertTrue(SecretRedactor.redact(src) == src)
    }
}
