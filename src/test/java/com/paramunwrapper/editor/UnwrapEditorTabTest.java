package com.paramunwrapper.editor;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.paramunwrapper.model.ParserType;
import com.paramunwrapper.model.UnwrapRule;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link UnwrapEditorTab} CUSTOM rule matching and display logic.
 */
class UnwrapEditorTabTest {

    @BeforeAll
    static void enableHeadless() {
        System.setProperty("java.awt.headless", "true");
    }

    // --- findMatchingRule tests (via isEnabledFor) ---

    @Test
    void customRuleMatchesWhenDecodedBodyIsNonBlank() {
        UnwrapRule rule = new UnwrapRule("custom-rule");
        rule.setEnabled(true);
        rule.setParserType(ParserType.CUSTOM);
        rule.setUseNamedParameter(false); // use whole body

        UnwrapEditorTab tab = new UnwrapEditorTab(List.of(rule));

        HttpRequest request = stubRequest("some decoded content");
        HttpRequestResponse rrr = stubRequestResponse(request);

        assertTrue(tab.isEnabledFor(rrr),
                "CUSTOM rule should match when body is non-blank");
    }

    @Test
    void customRuleDoesNotMatchWhenBodyIsBlank() {
        UnwrapRule rule = new UnwrapRule("custom-rule");
        rule.setEnabled(true);
        rule.setParserType(ParserType.CUSTOM);
        rule.setUseNamedParameter(false);

        UnwrapEditorTab tab = new UnwrapEditorTab(List.of(rule));

        HttpRequest request = stubRequest("");
        HttpRequestResponse rrr = stubRequestResponse(request);

        assertFalse(tab.isEnabledFor(rrr),
                "CUSTOM rule should not match when body is blank");
    }

    @Test
    void disabledCustomRuleDoesNotMatch() {
        UnwrapRule rule = new UnwrapRule("custom-rule");
        rule.setEnabled(false);
        rule.setParserType(ParserType.CUSTOM);
        rule.setUseNamedParameter(false);

        UnwrapEditorTab tab = new UnwrapEditorTab(List.of(rule));

        HttpRequest request = stubRequest("some content");
        HttpRequestResponse rrr = stubRequestResponse(request);

        assertFalse(tab.isEnabledFor(rrr),
                "Disabled rule should never match");
    }

    @Test
    void jsonRuleMatchesWhenBodyIsValidJson() {
        UnwrapRule rule = new UnwrapRule("json-rule");
        rule.setEnabled(true);
        rule.setParserType(ParserType.JSON);
        rule.setUseNamedParameter(false);

        UnwrapEditorTab tab = new UnwrapEditorTab(List.of(rule));

        HttpRequest request = stubRequest("{\"key\":\"value\"}");
        HttpRequestResponse rrr = stubRequestResponse(request);

        assertTrue(tab.isEnabledFor(rrr),
                "JSON rule should match when body is valid JSON");
    }

    @Test
    void jsonRuleDoesNotMatchWhenBodyIsInvalidJson() {
        UnwrapRule rule = new UnwrapRule("json-rule");
        rule.setEnabled(true);
        rule.setParserType(ParserType.JSON);
        rule.setUseNamedParameter(false);

        UnwrapEditorTab tab = new UnwrapEditorTab(List.of(rule));

        HttpRequest request = stubRequest("not json");
        HttpRequestResponse rrr = stubRequestResponse(request);

        assertFalse(tab.isEnabledFor(rrr),
                "JSON rule should not match when body is not valid JSON");
    }

    // --- resolveCustomParameters tests (via reflection) ---

    @Test
    void resolveCustomParametersWithMatchingRegex() throws Exception {
        UnwrapRule rule = new UnwrapRule("custom-rule");
        rule.setIncludeList(List.of("token=(?<value>[^&]+)"));

        UnwrapEditorTab tab = new UnwrapEditorTab(List.of(rule));
        String result = invokeResolveCustomParameters(tab, rule, "token=abc123&other=x");

        assertTrue(result.contains("regex:token=(?<value>[^&]+)"),
                "Should include pattern as key");
        assertTrue(result.contains("abc123"),
                "Should include captured value");
    }

    @Test
    void resolveCustomParametersWithNoMatch() throws Exception {
        UnwrapRule rule = new UnwrapRule("custom-rule");
        rule.setIncludeList(List.of("token=(?<value>[^&]+)"));

        UnwrapEditorTab tab = new UnwrapEditorTab(List.of(rule));
        String result = invokeResolveCustomParameters(tab, rule, "no-token-here");

        assertEquals("No include-list regex matches", result);
    }

    @Test
    void resolveCustomParametersWithEmptyIncludeList() throws Exception {
        UnwrapRule rule = new UnwrapRule("custom-rule");
        rule.setIncludeList(List.of());

        UnwrapEditorTab tab = new UnwrapEditorTab(List.of(rule));
        String result = invokeResolveCustomParameters(tab, rule, "some content");

        assertEquals("No include-list regex matches", result);
    }

    @Test
    void resolveCustomParametersSkipsPatternWithoutValueGroup() throws Exception {
        UnwrapRule rule = new UnwrapRule("custom-rule");
        // Pattern without (?<value>...) group
        rule.setIncludeList(List.of("token=([^&]+)"));

        UnwrapEditorTab tab = new UnwrapEditorTab(List.of(rule));
        String result = invokeResolveCustomParameters(tab, rule, "token=abc123");

        assertEquals("No include-list regex matches", result,
                "Pattern without named 'value' group should produce no matches");
    }

    @Test
    void resolveCustomParametersSkipsInvalidRegex() throws Exception {
        UnwrapRule rule = new UnwrapRule("custom-rule");
        // Invalid regex (unclosed group)
        rule.setIncludeList(List.of("[invalid(regex"));

        UnwrapEditorTab tab = new UnwrapEditorTab(List.of(rule));
        // Should not throw; invalid pattern is silently skipped
        assertDoesNotThrow(() -> invokeResolveCustomParameters(tab, rule, "some content"));
        String result = invokeResolveCustomParameters(tab, rule, "some content");
        assertEquals("No include-list regex matches", result);
    }

    @Test
    void resolveCustomParametersMultiplePatterns() throws Exception {
        UnwrapRule rule = new UnwrapRule("custom-rule");
        rule.setIncludeList(List.of(
                "token=(?<value>[^&]+)",
                "user=(?<value>[^&]+)"
        ));

        UnwrapEditorTab tab = new UnwrapEditorTab(List.of(rule));
        String result = invokeResolveCustomParameters(tab, rule, "token=tok1&user=bob");

        assertTrue(result.contains("tok1"), "First pattern should match");
        assertTrue(result.contains("bob"),  "Second pattern should match");
    }

    // --- helpers ---

    /**
     * Use reflection to call the private {@code resolveCustomParameters} method.
     */
    private static String invokeResolveCustomParameters(
            UnwrapEditorTab tab, UnwrapRule rule, String decoded) throws Exception {
        Method m = UnwrapEditorTab.class.getDeclaredMethod(
                "resolveCustomParameters", UnwrapRule.class, String.class);
        m.setAccessible(true);
        return (String) m.invoke(tab, rule, decoded);
    }

    /** Minimal {@link HttpRequest} stub that returns a fixed body. */
    private static HttpRequest stubRequest(String body) {
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

    /** Minimal {@link HttpRequestResponse} stub that wraps the given request. */
    private static HttpRequestResponse stubRequestResponse(HttpRequest request) {
        return (HttpRequestResponse) Proxy.newProxyInstance(
                HttpRequestResponse.class.getClassLoader(),
                new Class[]{HttpRequestResponse.class},
                (proxy, method, args) -> {
                    if ("request".equals(method.getName())) return request;
                    return null;
                });
    }
}
