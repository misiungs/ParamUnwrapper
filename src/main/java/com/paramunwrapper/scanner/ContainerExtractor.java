package com.paramunwrapper.scanner;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Extracts and replaces the container value from/in an {@link HttpRequest}.
 *
 * <p>Supports two modes:
 * <ul>
 *   <li>Named parameter (query/body/cookie): find the parameter by name and replace its value.
 *       If no standard parameter is found, falls back to a deep JSON body search.</li>
 *   <li>Whole-body: use the entire request body as the container value</li>
 * </ul>
 *
 * <p>When multiple standard parameters share the same name the one with the highest-priority
 * type is used: BODY &gt; URL &gt; COOKIE.
 *
 * <p>For named parameters, {@link #buildRequestWithContainer} first attempts a raw-byte
 * splice using {@link ParsedHttpParameter#valueOffsets()} and
 * {@link HttpRequest#httpRequest(HttpService, ByteArray)}, which performs a truly surgical
 * replacement and preserves all other request bytes (headers, other params, etc.) intact.
 * If the raw-byte approach fails for any reason, it falls back to
 * {@link HttpRequest#withUpdatedParameters}.
 */
public class ContainerExtractor {

    private static final Logger LOG = Logger.getLogger(ContainerExtractor.class.getName());

    private final boolean useNamedParameter;
    private final String parameterName;
    private final JsonBodySearcher jsonSearcher = new JsonBodySearcher();

    public ContainerExtractor(boolean useNamedParameter, String parameterName) {
        this.useNamedParameter = useNamedParameter;
        this.parameterName = parameterName;
    }

    /**
     * Extract the raw container string from the request.
     *
     * <p>When {@code useNamedParameter} is {@code true}: first searches standard Burp parameters
     * (BODY &gt; URL &gt; COOKIE precedence); if not found and the body looks like JSON, performs
     * a deep recursive search for a string-valued property with the configured name.
     *
     * @return raw container string, or {@code null} if not found
     */
    public String extractRawContainer(HttpRequest request) {
        if (useNamedParameter) {
            ParsedHttpParameter param = findParameter(request);
            if (param != null) return param.value();
            // JSON body fallback
            JsonBodySearcher.JsonSearchResult result = findInJson(request);
            return result != null ? result.getValue() : null;
        } else {
            return request.bodyToString();
        }
    }

    /**
     * Return a new request with the container replaced by {@code newValue}.
     *
     * <p>For named parameters, first attempts a raw-byte splice using
     * {@link ParsedHttpParameter#valueOffsets()} so that only the exact parameter value
     * bytes are changed, preserving all other request content. Falls back to
     * {@link HttpRequest#withUpdatedParameters} on any error.
     */
    public HttpRequest buildRequestWithContainer(HttpRequest request, String newValue) {
        if (useNamedParameter) {
            ParsedHttpParameter param = findParameter(request);
            if (param != null) {
                // Preferred: surgical raw-byte replacement preserves all other request content
                HttpRequest patched = tryRawBytePatch(request, param, newValue);
                if (patched != null) return patched;
                // Fallback: structured Montoya API update
                HttpParameter replacement = HttpParameter.parameter(
                        param.name(), newValue, param.type());
                return request.withUpdatedParameters(replacement);
            }
            // JSON body fallback – rewrite the JSON at the discovered pointer
            JsonBodySearcher.JsonSearchResult result = findInJson(request);
            if (result != null) {
                String updatedBody = jsonSearcher.updateAtPointer(
                        request.bodyToString(), result.getPointer(), newValue);
                if (updatedBody != null) {
                    return request.withBody(updatedBody);
                }
            }
            return request;
        } else {
            return request.withBody(newValue);
        }
    }

    /**
     * Attempts to replace the parameter value in the raw request bytes using the exact
     * byte offsets reported by {@link ParsedHttpParameter#valueOffsets()}.
     *
     * <p>For URL and BODY parameters the new value is URL-encoded before splicing so that
     * the raw bytes remain syntactically valid. COOKIE and other parameter types use the
     * value as-is, matching typical cookie header formatting.
     *
     * <p>The reconstructed request is built from the modified byte array via
     * {@link HttpRequest#httpRequest(HttpService, ByteArray)}, which preserves all headers
     * and other request content exactly.
     *
     * @return the patched request, or {@code null} if raw-byte patching is not possible
     *         (e.g., Burp runtime not available, offset out of range, or any other error)
     */
    HttpRequest tryRawBytePatch(HttpRequest request, ParsedHttpParameter param, String newValue) {
        try {
            Range valueRange = param.valueOffsets();
            ByteArray rawBytes = request.toByteArray();
            int start = valueRange.startIndexInclusive();
            int end   = valueRange.endIndexExclusive();
            if (start < 0 || end < start || end > rawBytes.length()) {
                return null;
            }

            String encodedValue = encodeForRawBytes(newValue, param.type());
            ByteArray prefix    = rawBytes.subArray(0, start);
            ByteArray suffix    = rawBytes.subArray(end, rawBytes.length());
            ByteArray newBytes  = ByteArray.byteArray(encodedValue);
            ByteArray modified  = prefix.withAppended(newBytes).withAppended(suffix);

            HttpService service = request.httpService();
            return service != null
                    ? HttpRequest.httpRequest(service, modified)
                    : HttpRequest.httpRequest(modified);
        } catch (Exception e) {
            LOG.log(Level.FINE,
                    "Raw-byte patch failed for parameter ''{0}'', falling back to "
                    + "withUpdatedParameters: {1}",
                    new Object[]{param.name(), e.getMessage()});
            return null;
        }
    }

    /**
     * Encodes {@code value} in the format expected by the raw HTTP request bytes for the
     * given parameter type.
     *
     * <ul>
     *   <li>{@link HttpParameterType#URL} and {@link HttpParameterType#BODY}: percent-encodes
     *       special characters using application/x-www-form-urlencoded rules (spaces as
     *       {@code +}, other specials as {@code %xx}).</li>
     *   <li>All other types (e.g., {@link HttpParameterType#COOKIE}): returned as-is,
     *       since cookie values are not URL-encoded in HTTP/1.1 headers.</li>
     * </ul>
     */
    static String encodeForRawBytes(String value, HttpParameterType type) {
        if (type == HttpParameterType.URL || type == HttpParameterType.BODY) {
            return URLEncoder.encode(value, StandardCharsets.UTF_8);
        }
        return value;
    }

    // --- private helpers ---

    /**
     * Find a standard Burp parameter by name with deterministic precedence:
     * BODY &gt; URL &gt; COOKIE.
     */
    private ParsedHttpParameter findParameter(HttpRequest request) {
        List<ParsedHttpParameter> params = request.parameters();
        ParsedHttpParameter body = null, url = null, cookie = null;
        for (ParsedHttpParameter p : params) {
            if (!p.name().equals(parameterName)) continue;
            switch (p.type()) {
                case BODY:   if (body   == null) body   = p; break;
                case URL:    if (url    == null) url    = p; break;
                case COOKIE: if (cookie == null) cookie = p; break;
                default:     break;
            }
        }
        if (body   != null) return body;
        if (url    != null) return url;
        return cookie;
    }

    /**
     * Attempt to locate {@link #parameterName} as a string-valued field inside the JSON body.
     * Returns {@code null} if the body is not JSON or no string match is found.
     * Logs a warning when multiple matches exist (detected in a single traversal).
     */
    private JsonBodySearcher.JsonSearchResult findInJson(HttpRequest request) {
        String body = request.bodyToString();
        if (!looksLikeJson(body, request)) return null;
        // Collect up to 2 matches in a single traversal to detect ambiguity efficiently
        List<JsonBodySearcher.JsonSearchResult> matches =
                jsonSearcher.findUpTo(body, parameterName, 2);
        if (matches.isEmpty()) return null;
        if (matches.size() > 1) {
            LOG.log(Level.WARNING,
                    "Multiple JSON string matches for field ''{0}''; "
                    + "using first match at pointer ''{1}''",
                    new Object[]{parameterName, matches.get(0).getPointer()});
        }
        return matches.get(0);
    }

    private static boolean looksLikeJson(String body, HttpRequest request) {
        if (body == null || body.isBlank()) return false;
        try {
            String ct = request.headerValue("Content-Type");
            if (ct != null && ct.toLowerCase().contains("application/json")) return true;
        } catch (Exception ignored) {}
        String trimmed = body.trim();
        return trimmed.startsWith("{") || trimmed.startsWith("[");
    }
}
