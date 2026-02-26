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
 * {@link UnwrapInsertionPoint#issueHighlights(ByteArray)} behaviour.
 */
class UnwrapInsertionPointTest {

    // -----------------------------------------------------------------------
    // baseValue() tests
    // -----------------------------------------------------------------------

    @Test
    void baseValueReturnsLiveBodyForWholeBodyCandidate() {
        // WHOLE_BODY with an empty codec chain: baseValue() must return bodyToString()
        // even when a stale currentValue was provided at construction time.
        UnwrapRule rule = new UnwrapRule("test");
        rule.setParserType(ParserType.JSON);
        ContainerExtractor extractor = new ContainerExtractor(false, null);
        HttpRequest request = stubRequestWithBody("live_body_value");

        UnwrapInsertionPoint ip = new UnwrapInsertionPoint(
                rule, CandidateType.WHOLE_BODY, "whole", request, "stale_value", extractor);

        assertEquals("live_body_value", ip.baseValue(),
                "baseValue() should return the live value from the request, not the stale cached value");
    }

    @Test
    void baseValueFallsBackToCachedValueWhenContainerIsNull() {
        // When extractRawContainer() returns null, fall back to the cached currentValue.
        UnwrapRule rule = new UnwrapRule("test");
        ContainerExtractor extractor = new ContainerExtractor(false, null);
        HttpRequest request = stubRequestWithBody(null); // bodyToString() returns null

        UnwrapInsertionPoint ip = new UnwrapInsertionPoint(
                rule, CandidateType.WHOLE_BODY, "whole", request, "fallback_value", extractor);

        assertEquals("fallback_value", ip.baseValue());
    }

    @Test
    void baseValueReturnsEmptyStringWhenContainerNullAndCachedValueNull() {
        UnwrapRule rule = new UnwrapRule("test");
        ContainerExtractor extractor = new ContainerExtractor(false, null);
        HttpRequest request = stubRequestWithBody(null);

        UnwrapInsertionPoint ip = new UnwrapInsertionPoint(
                rule, CandidateType.WHOLE_BODY, "whole", request, null, extractor);

        assertEquals("", ip.baseValue());
    }

    @Test
    void baseValueReturnsJsonFieldValueForValueCandidate() {
        // VALUE candidate: baseValue() must re-parse the JSON and return the current field value.
        UnwrapRule rule = new UnwrapRule("test");
        rule.setParserType(ParserType.JSON);
        ContainerExtractor extractor = new ContainerExtractor(false, null);
        HttpRequest request = stubRequestWithBody("{\"key\":\"live_value\"}");

        UnwrapInsertionPoint ip = new UnwrapInsertionPoint(
                rule, CandidateType.VALUE, "/key", request, "stale_value", extractor);

        assertEquals("live_value", ip.baseValue(),
                "baseValue() should return the current JSON field value from the request body");
    }

    @Test
    void baseValueFallsBackWhenJsonParseFailsForValueCandidate() {
        UnwrapRule rule = new UnwrapRule("test");
        rule.setParserType(ParserType.JSON);
        ContainerExtractor extractor = new ContainerExtractor(false, null);
        HttpRequest request = stubRequestWithBody("not-valid-json");

        UnwrapInsertionPoint ip = new UnwrapInsertionPoint(
                rule, CandidateType.VALUE, "/key", request, "cached_fallback", extractor);

        assertEquals("cached_fallback", ip.baseValue(),
                "baseValue() should fall back to cached value when JSON parsing fails");
    }

    @Test
    void baseValueReturnsCustomRegexCaptureGroup() {
        UnwrapRule rule = new UnwrapRule("custom");
        rule.setParserType(ParserType.CUSTOM);
        ContainerExtractor extractor = new ContainerExtractor(false, null);
        // body contains token=abc123
        HttpRequest request = stubRequestWithBody("token=abc123&other=x");

        UnwrapInsertionPoint ip = new UnwrapInsertionPoint(
                rule, CandidateType.VALUE, "regex:token=(?<value>[^&]+)",
                request, "stale", extractor);

        assertEquals("abc123", ip.baseValue(),
                "baseValue() should return the captured group 'value' from the custom regex");
    }

    // -----------------------------------------------------------------------
    // issueHighlights() tests
    // -----------------------------------------------------------------------

    @Test
    void issueHighlightsReturnsEmptyListWhenBuildRequestReturnsNull() {
        // withBody() returns null → buildHttpRequestWithPayload returns null → empty list
        UnwrapRule rule = new UnwrapRule("test");
        ContainerExtractor extractor = new ContainerExtractor(false, null);
        HttpRequest request = stubRequestWithBodyAndNullWithBody("original_body");

        UnwrapInsertionPoint ip = new UnwrapInsertionPoint(
                rule, CandidateType.WHOLE_BODY, "whole", request, "original_body", extractor);

        List<Range> highlights = ip.issueHighlights(stubByteArray("<payload>"));
        assertNotNull(highlights);
        assertTrue(highlights.isEmpty(),
                "issueHighlights() must return empty list when the built request is null");
    }

    @Test
    void issueHighlightsReturnsEmptyListWhenPayloadNotFoundInRequest() {
        // The built request's raw bytes do not contain the payload → return empty
        final String payloadStr = "<NOT_IN_REQUEST>";
        final String rawRequest = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\nbody_without_payload";

        UnwrapRule rule = new UnwrapRule("test");
        ContainerExtractor extractor = new ContainerExtractor(false, null);
        HttpRequest builtRequest = stubRequestWithRawBytes(rawRequest);
        HttpRequest baseRequest = stubRequestReturningBuiltOnWithBody("original", builtRequest);

        UnwrapInsertionPoint ip = new UnwrapInsertionPoint(
                rule, CandidateType.WHOLE_BODY, "whole", baseRequest, "original", extractor);

        List<Range> highlights = ip.issueHighlights(stubByteArray(payloadStr));
        assertNotNull(highlights);
        assertTrue(highlights.isEmpty());
    }

    @Test
    void findPayloadOffsetReturnsCorrectIndexForWholeBodyPayload() {
        // Verify that findPayloadOffset locates the payload within the built request bytes.
        // Tested via the package-visible helper to avoid the Montoya Range factory dependency.
        final String payloadStr = "<XSS_FUZZ>";
        final String rawRequest = "POST / HTTP/1.1\r\nHost: example.com\r\n\r\n" + payloadStr;
        final int expectedStart = rawRequest.indexOf(payloadStr);

        UnwrapRule rule = new UnwrapRule("test");
        ContainerExtractor extractor = new ContainerExtractor(false, null);
        HttpRequest builtRequest = stubRequestWithRawBytes(rawRequest);
        HttpRequest baseRequest = stubRequestReturningBuiltOnWithBody("original", builtRequest);

        UnwrapInsertionPoint ip = new UnwrapInsertionPoint(
                rule, CandidateType.WHOLE_BODY, "whole", baseRequest, "original", extractor);

        int offset = ip.findPayloadOffset(stubByteArray(payloadStr));
        assertEquals(expectedStart, offset,
                "findPayloadOffset should return the byte offset of the payload in the raw request");
    }

    @Test
    void findPayloadOffsetReturnsMinusOneWhenPayloadAbsent() {
        final String rawRequest = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\nbody";
        UnwrapRule rule = new UnwrapRule("test");
        ContainerExtractor extractor = new ContainerExtractor(false, null);
        HttpRequest builtRequest = stubRequestWithRawBytes(rawRequest);
        HttpRequest baseRequest = stubRequestReturningBuiltOnWithBody("body", builtRequest);

        UnwrapInsertionPoint ip = new UnwrapInsertionPoint(
                rule, CandidateType.WHOLE_BODY, "whole", baseRequest, "body", extractor);

        int offset = ip.findPayloadOffset(stubByteArray("<NOT_HERE>"));
        assertEquals(-1, offset);
    }

    @Test
    void findPayloadOffsetReturnsMinusOneWhenBuiltRequestIsNull() {
        UnwrapRule rule = new UnwrapRule("test");
        ContainerExtractor extractor = new ContainerExtractor(false, null);
        HttpRequest baseRequest = stubRequestWithBodyAndNullWithBody("body");

        UnwrapInsertionPoint ip = new UnwrapInsertionPoint(
                rule, CandidateType.WHOLE_BODY, "whole", baseRequest, "body", extractor);

        int offset = ip.findPayloadOffset(stubByteArray("<payload>"));
        assertEquals(-1, offset);
    }

    @Test
    void findPayloadOffsetReturnsMinusOneWhenToByteArrayThrows() {
        // toByteArray() throws → findPayloadOffset catches the exception and returns -1
        UnwrapRule rule = new UnwrapRule("test");
        ContainerExtractor extractor = new ContainerExtractor(false, null);
        HttpRequest builtRequest = stubRequestThrowingOnToByteArray();
        HttpRequest baseRequest = stubRequestReturningBuiltOnWithBody("original", builtRequest);

        UnwrapInsertionPoint ip = new UnwrapInsertionPoint(
                rule, CandidateType.WHOLE_BODY, "whole", baseRequest, "original", extractor);

        int offset = ip.findPayloadOffset(stubByteArray("<payload>"));
        assertEquals(-1, offset);
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
                    case "length"   -> content.length();
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
