package com.paramunwrapper.codec;

import com.paramunwrapper.model.CodecStepType;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for codec chain roundtrip behaviour.
 */
class CodecChainTest {

    @Test
    void base64RoundtripSingleStep() throws CodecException {
        CodecChain chain = new CodecChain(List.of(CodecStepType.BASE64_DECODE));
        String original = "{\"key\":\"one\",\"key2\":\"two\"}";
        String encoded = chain.encode(original);
        assertNotEquals(original, encoded, "Encoded value should differ from original");
        String decoded = chain.decode(encoded);
        assertEquals(original, decoded, "Roundtrip should recover the original string");
    }

    @Test
    void urlRoundtripSingleStep() throws CodecException {
        CodecChain chain = new CodecChain(List.of(CodecStepType.URL_DECODE));
        String original = "hello world & foo=bar";
        String encoded = chain.encode(original);
        assertNotEquals(original, encoded, "Encoded value should differ from original");
        String decoded = chain.decode(encoded);
        assertEquals(original, decoded, "Roundtrip should recover the original string");
    }

    @Test
    void base64ThenUrlRoundtrip() throws CodecException {
        // Chain: first BASE64_DECODE, then URL_DECODE
        // Decode direction: base64 → url-decode
        // Encode direction (inverse, reversed): url-encode → base64
        CodecChain chain = new CodecChain(
                List.of(CodecStepType.BASE64_DECODE, CodecStepType.URL_DECODE));

        String original = "hello world";
        String encoded = chain.encode(original);
        String decoded = chain.decode(encoded);
        assertEquals(original, decoded, "Chained roundtrip should recover the original string");
    }

    @Test
    void emptyChainIsPassthrough() throws CodecException {
        CodecChain chain = new CodecChain(List.of());
        String value = "anything";
        assertEquals(value, chain.decode(value));
        assertEquals(value, chain.encode(value));
    }

    @Test
    void base64DecodesKnownValue() throws CodecException {
        // eyJrZXkiOiJvbmUiLCJrZXkyIjoidHdvIn0= is base64({"key":"one","key2":"two"})
        CodecChain chain = new CodecChain(List.of(CodecStepType.BASE64_DECODE));
        String decoded = chain.decode("eyJrZXkiOiJvbmUiLCJrZXkyIjoidHdvIn0=");
        assertEquals("{\"key\":\"one\",\"key2\":\"two\"}", decoded);
    }

    @Test
    void base64InvalidInputThrows() {
        CodecChain chain = new CodecChain(List.of(CodecStepType.BASE64_DECODE));
        assertThrows(CodecException.class, () -> chain.decode("!!!not-valid-base64!!!"));
    }

    // ------------------------------------------------------------------ HTML entity

    @Test
    void htmlEntityRoundtripSingleStep() throws CodecException {
        CodecChain chain = new CodecChain(List.of(CodecStepType.HTML_ENTITY_DECODE));
        String original = "<script>alert('xss & \"test\"')</script>";
        String encoded = chain.encode(original);
        assertNotEquals(original, encoded, "Encoded value should differ from original");
        String decoded = chain.decode(encoded);
        assertEquals(original, decoded, "HTML entity roundtrip should recover the original string");
    }

    @Test
    void htmlEntityDecodesNamedEntities() throws CodecException {
        CodecChain chain = new CodecChain(List.of(CodecStepType.HTML_ENTITY_DECODE));
        assertEquals("<>&\"'", chain.decode("&lt;&gt;&amp;&quot;&apos;"));
    }

    @Test
    void htmlEntityDecodesDecimalNumericEntity() throws CodecException {
        CodecChain chain = new CodecChain(List.of(CodecStepType.HTML_ENTITY_DECODE));
        assertEquals("<", chain.decode("&#60;"));
    }

    @Test
    void htmlEntityDecodesHexNumericEntity() throws CodecException {
        CodecChain chain = new CodecChain(List.of(CodecStepType.HTML_ENTITY_DECODE));
        assertEquals("<", chain.decode("&#x3c;"));
        assertEquals("<", chain.decode("&#X3C;"));
    }

    // ------------------------------------------------------------------ Unicode escape

    @Test
    void unicodeEscapeRoundtripSingleStep() throws CodecException {
        CodecChain chain = new CodecChain(List.of(CodecStepType.UNICODE_ESCAPE_DECODE));
        String original = "hello\u00e9 world";
        String encoded = chain.encode(original);
        assertNotEquals(original, encoded, "Encoded value should differ from original");
        String decoded = chain.decode(encoded);
        assertEquals(original, decoded, "Unicode escape roundtrip should recover the original string");
    }

    @Test
    void unicodeEscapeDecodesBackslashU() throws CodecException {
        CodecChain chain = new CodecChain(List.of(CodecStepType.UNICODE_ESCAPE_DECODE));
        assertEquals("A", chain.decode("\\u0041"));
        assertEquals("<", chain.decode("\\u003C"));
    }

    @Test
    void unicodeEscapeDecodesBackslashX() throws CodecException {
        CodecChain chain = new CodecChain(List.of(CodecStepType.UNICODE_ESCAPE_DECODE));
        assertEquals("A", chain.decode("\\x41"));
        assertEquals("<", chain.decode("\\x3C"));
    }
}
