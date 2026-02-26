package com.paramunwrapper.scanner;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.paramunwrapper.model.CandidateType;
import com.paramunwrapper.model.ParserType;
import com.paramunwrapper.model.UnwrapRule;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link UnwrapInsertionPoint} – specifically the improved
 * {@link UnwrapInsertionPoint#baseValue()} and
 * {@link UnwrapInsertionPoint#findPayloadOffset(ByteArray)} behaviour.
 */
class UnwrapInsertionPointTest {

    // -----------------------------------------------------------------------
    // baseValue() – live re-derivation for WHOLE_BODY
    // -----------------------------------------------------------------------

    @Test
    void baseValueWholebody_decodesContainerFromBaseRequest() {
        // Base64-encoded body: "hello"
        String base64Body = java.util.Base64.getEncoder().encodeToString("hello".getBytes());
        HttpRequest req = stubRequestWithBody(base64Body);

        UnwrapRule rule = wholeBodyBase64Rule();
        ContainerExtractor extractor = new ContainerExtractor(false, null);
        UnwrapInsertionPoint ip = new UnwrapInsertionPoint(
                rule, CandidateType.WHOLE_BODY, "whole_body", req, "stale", extractor);

        assertEquals("hello", ip.baseValue());
    }

    @Test
    void baseValueWholebody_fallsBackToCachedWhenBodyNull() {
        HttpRequest req = stubRequestWithBody(null);

        UnwrapRule rule = wholeBodyBase64Rule();
        ContainerExtractor extractor = new ContainerExtractor(false, null);
        UnwrapInsertionPoint ip = new UnwrapInsertionPoint(
                rule, CandidateType.WHOLE_BODY, "whole_body", req, "cached", extractor);

        assertEquals("cached", ip.baseValue());
    }

    @Test
    void baseValueWholebody_fallsBackToEmptyStringWhenCachedIsNull() {
        // bodyToString() returns invalid base64 → decode throws → cachedValue()
        HttpRequest req = stubRequestWithBody("!!!not-base64!!!");

        UnwrapRule rule = wholeBodyBase64Rule();
        ContainerExtractor extractor = new ContainerExtractor(false, null);
        UnwrapInsertionPoint ip = new UnwrapInsertionPoint(
                rule, CandidateType.WHOLE_BODY, "whole_body", req, null, extractor);

        assertEquals("", ip.baseValue());
    }

    // -----------------------------------------------------------------------
    // baseValue() – live re-derivation for JSON VALUE
    // -----------------------------------------------------------------------

    @Test
    void baseValueJson_returnsLiveValueFromBaseRequest() {
        // body: base64( {"field":"live_value"} )
        String json = "{\"field\":\"live_value\"}";
        String encoded = java.util.Base64.getEncoder().encodeToString(json.getBytes());
        HttpRequest req = stubRequestWithBody(encoded);

        UnwrapRule rule = jsonBase64Rule();
        ContainerExtractor extractor = new ContainerExtractor(false, null);
        // JSON identifiers use JSON-Pointer syntax (e.g. "/field")
        UnwrapInsertionPoint ip = new UnwrapInsertionPoint(
                rule, CandidateType.VALUE, "/field", req, "stale_value", extractor);

        assertEquals("live_value", ip.baseValue());
    }

    @Test
    void baseValueJson_fallsBackToCachedWhenFieldAbsent() {
        // body: base64( {"other":"x"} ) – "/field" is absent
        String json = "{\"other\":\"x\"}";
        String encoded = java.util.Base64.getEncoder().encodeToString(json.getBytes());
        HttpRequest req = stubRequestWithBody(encoded);

        UnwrapRule rule = jsonBase64Rule();
        ContainerExtractor extractor = new ContainerExtractor(false, null);
        UnwrapInsertionPoint ip = new UnwrapInsertionPoint(
                rule, CandidateType.VALUE, "/field", req, "cached", extractor);

        assertEquals("cached", ip.baseValue());
    }

    // -----------------------------------------------------------------------
    // baseValue() – CUSTOM regex
    // -----------------------------------------------------------------------

    @Test
    void baseValueCustom_returnsMatchedGroup() {
        // body: base64( token=secret )
        String content = "token=secret";
        String encoded = java.util.Base64.getEncoder().encodeToString(content.getBytes());
        HttpRequest req = stubRequestWithBody(encoded);

        UnwrapRule rule = customBase64Rule();
        ContainerExtractor extractor = new ContainerExtractor(false, null);
        UnwrapInsertionPoint ip = new UnwrapInsertionPoint(
                rule, CandidateType.VALUE, "regex:token=(?<value>[^&]+)", req, "stale", extractor);

        assertEquals("secret", ip.baseValue());
    }

    @Test
    void baseValueCustom_fallsBackWhenRegexDoesNotMatch() {
        String content = "other=value";
        String encoded = java.util.Base64.getEncoder().encodeToString(content.getBytes());
        HttpRequest req = stubRequestWithBody(encoded);

        UnwrapRule rule = customBase64Rule();
        ContainerExtractor extractor = new ContainerExtractor(false, null);
        UnwrapInsertionPoint ip = new UnwrapInsertionPoint(
                rule, CandidateType.VALUE, "regex:token=(?<value>[^&]+)", req, "cached", extractor);

        assertEquals("cached", ip.baseValue());
    }

    @Test
    void baseValueCustom_fallsBackWhenPatternIsInvalid() {
        // Identifier doesn't start with "regex:" so customPattern == null
        HttpRequest req = stubRequestWithBody("anything");

        UnwrapRule rule = customBase64Rule();
        ContainerExtractor extractor = new ContainerExtractor(false, null);
        // Identifier without "regex:" prefix → customPattern is null
        UnwrapInsertionPoint ip = new UnwrapInsertionPoint(
                rule, CandidateType.VALUE, "not_a_regex_identifier", req, "cached", extractor);

        assertEquals("cached", ip.baseValue());
    }

    // -----------------------------------------------------------------------
    // findPayloadOffset() – payload location in raw bytes
    // -----------------------------------------------------------------------

    @Test
    void findPayloadOffset_returnsNegativeOneWhenBuildReturnsNull() {
        // withBody() returns null → buildHttpRequestWithPayload returns baseRequest, which
        // has toByteArray() that doesn't contain the payload
        HttpRequest req = stubRequestWithBodyAndNullWithBody("base_body");

        UnwrapRule rule = wholeBodyBase64Rule();
        ContainerExtractor extractor = new ContainerExtractor(false, null);
        UnwrapInsertionPoint ip = new UnwrapInsertionPoint(
                rule, CandidateType.WHOLE_BODY, "whole_body", req, "", extractor);

        ByteArray payload = stubByteArray("PAYLOAD");
        // The built request falls back to baseRequest which doesn't contain "PAYLOAD"
        // (findPayloadOffset calls toByteArray on the built request, which is the stub
        //  returning null from withBody – so built falls back to req which has no toByteArray)
        int offset = ip.findPayloadOffset(payload);
        // offset must be -1 (payload not found in the base request's raw bytes)
        assertEquals(-1, offset);
    }

    @Test
    void findPayloadOffset_findsPayloadInRawBytes() {
        // Arrange: a request whose withBody() returns a request with known raw bytes
        String rawContent = "POST / HTTP/1.1\r\nContent-Length: 7\r\n\r\nPAYLOAD";
        HttpRequest builtRequest = stubRequestWithRawBytes(rawContent);
        HttpRequest baseReq = stubRequestReturningBuiltOnWithBody("ignored_body", builtRequest);

        UnwrapRule rule = wholeBodyBase64Rule();
        ContainerExtractor extractor = new ContainerExtractor(false, null);
        UnwrapInsertionPoint ip = new UnwrapInsertionPoint(
                rule, CandidateType.WHOLE_BODY, "whole_body", baseReq, "", extractor);

        ByteArray payload = stubByteArrayWithIndexOf("PAYLOAD");
        int offset = ip.findPayloadOffset(payload);

        assertEquals(rawContent.indexOf("PAYLOAD"), offset);
    }

    @Test
    void findPayloadOffset_returnsNegativeOneWhenPayloadAbsent() {
        String rawContent = "POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nbody";
        HttpRequest builtRequest = stubRequestWithRawBytes(rawContent);
        HttpRequest baseReq = stubRequestReturningBuiltOnWithBody("ignored", builtRequest);

        UnwrapRule rule = wholeBodyBase64Rule();
        ContainerExtractor extractor = new ContainerExtractor(false, null);
        UnwrapInsertionPoint ip = new UnwrapInsertionPoint(
                rule, CandidateType.WHOLE_BODY, "whole_body", baseReq, "", extractor);

        ByteArray payload = stubByteArrayWithIndexOf("NOTHERE");
        int offset = ip.findPayloadOffset(payload);

        assertEquals(-1, offset);
    }

    @Test
    void findPayloadOffset_returnsNegativeOneWhenToByteArrayThrows() {
        // toByteArray() on the built request throws – must not propagate
        HttpRequest throwing = stubRequestThrowingOnToByteArray();
        HttpRequest baseReq = stubRequestReturningBuiltOnWithBody("body", throwing);

        UnwrapRule rule = wholeBodyBase64Rule();
        ContainerExtractor extractor = new ContainerExtractor(false, null);
        UnwrapInsertionPoint ip = new UnwrapInsertionPoint(
                rule, CandidateType.WHOLE_BODY, "whole_body", baseReq, "", extractor);

        ByteArray payload = stubByteArray("anything");
        assertEquals(-1, ip.findPayloadOffset(payload));
    }

    @Test
    void findPayloadOffset_returnsNegativeOneForEmptyPayload() {
        HttpRequest baseReq = stubRequestWithBody("body");

        UnwrapRule rule = wholeBodyBase64Rule();
        ContainerExtractor extractor = new ContainerExtractor(false, null);
        UnwrapInsertionPoint ip = new UnwrapInsertionPoint(
                rule, CandidateType.WHOLE_BODY, "whole_body", baseReq, "", extractor);

        ByteArray payload = stubByteArray(""); // empty payload
        assertEquals(-1, ip.findPayloadOffset(payload));
    }

    // -----------------------------------------------------------------------
    // Rule factories
    // -----------------------------------------------------------------------

    private static UnwrapRule wholeBodyBase64Rule() {
        UnwrapRule rule = new UnwrapRule();
        rule.setName("test-rule");
        rule.setEnabled(true);
        rule.setParserType(ParserType.JSON);
        rule.setUseNamedParameter(false);
        // Single BASE64 codec step
        rule.setCodecChain(List.of(com.paramunwrapper.model.CodecStepType.BASE64_DECODE));
        return rule;
    }

    private static UnwrapRule jsonBase64Rule() {
        UnwrapRule rule = new UnwrapRule();
        rule.setName("test-rule-json");
        rule.setEnabled(true);
        rule.setParserType(ParserType.JSON);
        rule.setUseNamedParameter(false);
        rule.setCodecChain(List.of(com.paramunwrapper.model.CodecStepType.BASE64_DECODE));
        return rule;
    }

    private static UnwrapRule customBase64Rule() {
        UnwrapRule rule = new UnwrapRule();
        rule.setName("test-rule-custom");
        rule.setEnabled(true);
        rule.setParserType(ParserType.CUSTOM);
        rule.setUseNamedParameter(false);
        rule.setCodecChain(List.of(com.paramunwrapper.model.CodecStepType.BASE64_DECODE));
        return rule;
    }

    // -----------------------------------------------------------------------
    // Stub helpers
    // -----------------------------------------------------------------------

    /** Stub that returns a fixed body string from {@code bodyToString()}. */
    private static HttpRequest stubRequestWithBody(String body) {
        return (HttpRequest) Proxy.newProxyInstance(
                HttpRequest.class.getClassLoader(),
                new Class[]{HttpRequest.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "bodyToString" -> body;
                    case "parameters"   -> List.of();
                    case "headerValue"  -> null;
                    default             -> null;
                });
    }

    /** Stub where {@code withBody()} returns {@code null} (simulates a failing build). */
    private static HttpRequest stubRequestWithBodyAndNullWithBody(String body) {
        return (HttpRequest) Proxy.newProxyInstance(
                HttpRequest.class.getClassLoader(),
                new Class[]{HttpRequest.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "bodyToString" -> body;
                    case "parameters"   -> List.of();
                    case "headerValue"  -> null;
                    case "withBody"     -> null;
                    default             -> null;
                });
    }

    /**
     * Stub whose {@code withBody()} always returns {@code builtRequest},
     * allowing the highlights path to proceed to {@code toByteArray()}.
     */
    private static HttpRequest stubRequestReturningBuiltOnWithBody(String body,
                                                                    HttpRequest builtRequest) {
        return (HttpRequest) Proxy.newProxyInstance(
                HttpRequest.class.getClassLoader(),
                new Class[]{HttpRequest.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "bodyToString" -> body;
                    case "parameters"   -> List.of();
                    case "headerValue"  -> null;
                    case "withBody"     -> builtRequest;
                    default             -> null;
                });
    }

    /**
     * Stub whose {@code toByteArray()} returns a {@link ByteArray} proxy backed by
     * {@code rawContent}, supporting {@code indexOf(String)} and {@code length()}.
     */
    private static HttpRequest stubRequestWithRawBytes(String rawContent) {
        ByteArray byteArray = stubByteArrayWithIndexOf(rawContent);
        return (HttpRequest) Proxy.newProxyInstance(
                HttpRequest.class.getClassLoader(),
                new Class[]{HttpRequest.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "toByteArray"  -> byteArray;
                    case "bodyToString" -> rawContent;
                    case "parameters"   -> List.of();
                    case "headerValue"  -> null;
                    default             -> null;
                });
    }

    /** Stub whose {@code toByteArray()} throws an exception. */
    private static HttpRequest stubRequestThrowingOnToByteArray() {
        return (HttpRequest) Proxy.newProxyInstance(
                HttpRequest.class.getClassLoader(),
                new Class[]{HttpRequest.class},
                (proxy, method, args) -> {
                    if ("toByteArray".equals(method.getName())) {
                        throw new UnsupportedOperationException("toByteArray not available");
                    }
                    return null;
                });
    }

    /**
     * Minimal {@link ByteArray} stub that implements {@code toString()},
     * {@code length()}, and no-op {@code indexOf()} (always returns -1 / null).
     */
    private static ByteArray stubByteArray(String content) {
        return (ByteArray) Proxy.newProxyInstance(
                ByteArray.class.getClassLoader(),
                new Class[]{ByteArray.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "toString" -> content;
                    case "length"   -> (content != null ? content.length() : 0);
                    default         -> null;
                });
    }

    /**
     * {@link ByteArray} stub backed by {@code content} that properly implements
     * {@code indexOf(String)} so range computation can be verified.
     */
    private static ByteArray stubByteArrayWithIndexOf(String content) {
        return (ByteArray) Proxy.newProxyInstance(
                ByteArray.class.getClassLoader(),
                new Class[]{ByteArray.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "indexOf" -> {
                        if (args != null && args.length >= 1 && args[0] instanceof String s) {
                            yield content.indexOf(s);
                        }
                        yield -1;
                    }
                    case "toString" -> content;
                    case "length"   -> content.length();
                    default         -> null;
                });
    }
}
