package com.paramunwrapper.scanner;

import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link ContainerExtractor} – focusing on the raw-byte patching path
 * introduced for 2-stage scan compatibility, and its fallback behaviour.
 */
class ContainerExtractorTest {

    // -----------------------------------------------------------------------
    // encodeForRawBytes – pure function, no Burp runtime needed
    // -----------------------------------------------------------------------

    @Test
    void encodeForRawBytes_urlParam_encodesSpecialChars() {
        String encoded = ContainerExtractor.encodeForRawBytes("a+b=c", HttpParameterType.URL);
        // URLEncoder encodes '+' as %2B and '=' as %3D
        assertEquals("a%2Bb%3Dc", encoded);
    }

    @Test
    void encodeForRawBytes_bodyParam_encodesSpecialChars() {
        String encoded = ContainerExtractor.encodeForRawBytes("a+b=c", HttpParameterType.BODY);
        assertEquals("a%2Bb%3Dc", encoded);
    }

    @Test
    void encodeForRawBytes_cookieParam_returnsAsIs() {
        String encoded = ContainerExtractor.encodeForRawBytes("a+b=c", HttpParameterType.COOKIE);
        assertEquals("a+b=c", encoded);
    }

    @Test
    void encodeForRawBytes_plainBase64_noChange() {
        // Standard base64 without special characters that require URL encoding
        // (no '+', '/', or '=') should pass through unchanged for URL params
        String plain = "eyJhIjoiYiJ9";
        assertEquals(plain, ContainerExtractor.encodeForRawBytes(plain, HttpParameterType.URL));
    }

    @Test
    void encodeForRawBytes_base64WithPadding_encodesPaddingForUrlParam() {
        // The '=' padding character must be percent-encoded in URL params
        String withPadding = "eyJhIjoiYiJ9==";
        String encoded = ContainerExtractor.encodeForRawBytes(withPadding, HttpParameterType.URL);
        assertTrue(encoded.contains("%3D"), "= should be encoded as %3D for URL params");
        assertFalse(encoded.contains("=="), "raw = must not appear in URL-encoded output");
    }

    // -----------------------------------------------------------------------
    // tryRawBytePatch – falls back gracefully when Burp runtime is absent
    // -----------------------------------------------------------------------

    @Test
    void tryRawBytePatch_returnsNullWhenValueOffsetsThrows() {
        // valueOffsets() throws (no Burp runtime) → should return null, not propagate
        ParsedHttpParameter param = stubParam("data", "oldValue", HttpParameterType.URL,
                /* throwOnValueOffsets= */ true);
        HttpRequest request = stubRequestWithParams(List.of(param), "oldValue");

        ContainerExtractor extractor = new ContainerExtractor(true, "data");
        HttpRequest result = extractor.tryRawBytePatch(request, param, "newValue");

        assertNull(result, "tryRawBytePatch must return null when valueOffsets() is unavailable");
    }

    @Test
    void tryRawBytePatch_returnsNullWhenToByteArrayThrows() {
        // toByteArray() throws → should return null
        ParsedHttpParameter param = stubParam("data", "oldValue", HttpParameterType.URL,
                /* throwOnValueOffsets= */ false);
        HttpRequest request = stubRequestThrowingOnToByteArray(param);

        ContainerExtractor extractor = new ContainerExtractor(true, "data");
        HttpRequest result = extractor.tryRawBytePatch(request, param, "newValue");

        assertNull(result, "tryRawBytePatch must return null when toByteArray() is unavailable");
    }

    // -----------------------------------------------------------------------
    // buildRequestWithContainer – fallback via withUpdatedParameters
    // -----------------------------------------------------------------------

    @Test
    void buildRequestWithContainer_wholeBody_usesWithBody() {
        // Whole-body mode: withBody() should be called with newValue
        HttpRequest sentinel = stubRequestWithBody("new_body_content");
        HttpRequest request = stubRequestReturningOnWithBody(sentinel);

        ContainerExtractor extractor = new ContainerExtractor(false, null);
        HttpRequest result = extractor.buildRequestWithContainer(request, "new_body_content");

        assertSame(sentinel, result,
                "Whole-body mode should call withBody() and return its result");
    }

    @Test
    void buildRequestWithContainer_namedParamNotFound_returnsOriginal() {
        // No matching parameter, no JSON body → should return original request unchanged
        HttpRequest request = stubRequestWithParams(List.of(), null);

        ContainerExtractor extractor = new ContainerExtractor(true, "missing");
        HttpRequest result = extractor.buildRequestWithContainer(request, "anything");

        assertSame(request, result,
                "When parameter is not found and body is not JSON, original request must be returned");
    }

    // -----------------------------------------------------------------------
    // extractRawContainer – basic extraction
    // -----------------------------------------------------------------------

    @Test
    void extractRawContainer_namedParam_returnsParamValue() {
        ParsedHttpParameter param = stubParam("data", "containerValue", HttpParameterType.URL,
                false);
        HttpRequest request = stubRequestWithParams(List.of(param), "containerValue");

        ContainerExtractor extractor = new ContainerExtractor(true, "data");
        assertEquals("containerValue", extractor.extractRawContainer(request));
    }

    @Test
    void extractRawContainer_wholeBody_returnsBody() {
        HttpRequest request = stubRequestWithBody("bodyContent");

        ContainerExtractor extractor = new ContainerExtractor(false, null);
        assertEquals("bodyContent", extractor.extractRawContainer(request));
    }

    @Test
    void extractRawContainer_namedParamNotFound_returnsNull() {
        HttpRequest request = stubRequestWithParams(List.of(), null);

        ContainerExtractor extractor = new ContainerExtractor(true, "missing");
        assertNull(extractor.extractRawContainer(request));
    }

    // -----------------------------------------------------------------------
    // Stub helpers
    // -----------------------------------------------------------------------

    private static ParsedHttpParameter stubParam(String name, String value,
                                                  HttpParameterType type,
                                                  boolean throwOnValueOffsets) {
        return (ParsedHttpParameter) Proxy.newProxyInstance(
                ParsedHttpParameter.class.getClassLoader(),
                new Class[]{ParsedHttpParameter.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "name"  -> name;
                    case "value" -> value;
                    case "type"  -> type;
                    case "valueOffsets" -> {
                        if (throwOnValueOffsets) {
                            throw new UnsupportedOperationException("valueOffsets not available");
                        }
                        // Return a Range proxy with start=0, end=value.length()
                        yield stubRange(0, value != null ? value.length() : 0);
                    }
                    default -> null;
                });
    }

    private static Object stubRange(int start, int end) {
        return Proxy.newProxyInstance(
                burp.api.montoya.core.Range.class.getClassLoader(),
                new Class[]{burp.api.montoya.core.Range.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "startIndexInclusive" -> start;
                    case "endIndexExclusive"   -> end;
                    default                    -> null;
                });
    }

    private static HttpRequest stubRequestWithParams(List<ParsedHttpParameter> params,
                                                     String body) {
        return (HttpRequest) Proxy.newProxyInstance(
                HttpRequest.class.getClassLoader(),
                new Class[]{HttpRequest.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "parameters"   -> params;
                    case "bodyToString" -> (body != null ? body : "");
                    case "headerValue"  -> null;
                    default             -> null;
                });
    }

    private static HttpRequest stubRequestThrowingOnToByteArray(ParsedHttpParameter param) {
        return (HttpRequest) Proxy.newProxyInstance(
                HttpRequest.class.getClassLoader(),
                new Class[]{HttpRequest.class},
                (proxy, method, args) -> {
                    if ("toByteArray".equals(method.getName())) {
                        throw new UnsupportedOperationException("toByteArray not available");
                    }
                    if ("parameters".equals(method.getName())) return List.of(param);
                    if ("bodyToString".equals(method.getName())) return "";
                    if ("headerValue".equals(method.getName())) return null;
                    return null;
                });
    }

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

    private static HttpRequest stubRequestReturningOnWithBody(HttpRequest withBodyResult) {
        return (HttpRequest) Proxy.newProxyInstance(
                HttpRequest.class.getClassLoader(),
                new Class[]{HttpRequest.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "bodyToString" -> "original_body";
                    case "parameters"   -> List.of();
                    case "headerValue"  -> null;
                    case "withBody"     -> withBodyResult;
                    default             -> null;
                });
    }
}
