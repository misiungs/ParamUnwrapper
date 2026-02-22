package com.paramunwrapper.parser;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for JSON leaf extraction and value update by JSON Pointer.
 */
class JsonContentParserTest {

    @Test
    void extractsTopLevelScalarLeaves() throws ParseException {
        JsonContentParser parser = new JsonContentParser();
        parser.parse("{\"key\":\"one\",\"key2\":\"two\"}");

        List<String> ids = parser.getFieldIdentifiers();
        assertTrue(ids.contains("/key"), "Should contain /key");
        assertTrue(ids.contains("/key2"), "Should contain /key2");
        assertEquals(2, ids.size());
    }

    @Test
    void extractsNestedLeaves() throws ParseException {
        JsonContentParser parser = new JsonContentParser();
        parser.parse("{\"a\":{\"b\":\"deep\"},\"c\":\"flat\"}");

        List<String> ids = parser.getFieldIdentifiers();
        assertTrue(ids.contains("/a/b"), "Should contain /a/b");
        assertTrue(ids.contains("/c"), "Should contain /c");
        assertEquals(2, ids.size());
    }

    @Test
    void extractsArrayLeaves() throws ParseException {
        JsonContentParser parser = new JsonContentParser();
        parser.parse("{\"arr\":[\"x\",\"y\"]}");

        List<String> ids = parser.getFieldIdentifiers();
        assertTrue(ids.contains("/arr/0"), "Should contain /arr/0");
        assertTrue(ids.contains("/arr/1"), "Should contain /arr/1");
    }

    @Test
    void getValueReturnsCorrectValue() throws ParseException {
        JsonContentParser parser = new JsonContentParser();
        parser.parse("{\"key\":\"one\",\"key2\":\"two\"}");

        assertEquals("one", parser.getValue("/key"));
        assertEquals("two", parser.getValue("/key2"));
    }

    @Test
    void withValueUpdatesTopLevelField() throws ParseException {
        JsonContentParser parser = new JsonContentParser();
        parser.parse("{\"key\":\"one\",\"key2\":\"two\"}");

        String updated = parser.withValue("/key", "PAYLOAD");
        // Parse the updated JSON and verify
        JsonContentParser verify = new JsonContentParser();
        verify.parse(updated);
        assertEquals("PAYLOAD", verify.getValue("/key"));
        assertEquals("two", verify.getValue("/key2"), "Other field should be unchanged");
    }

    @Test
    void withValueUpdatesNestedField() throws ParseException {
        JsonContentParser parser = new JsonContentParser();
        parser.parse("{\"a\":{\"b\":\"deep\"}}");

        String updated = parser.withValue("/a/b", "INJECTED");
        JsonContentParser verify = new JsonContentParser();
        verify.parse(updated);
        assertEquals("INJECTED", verify.getValue("/a/b"));
    }

    @Test
    void getAllValuesReturnsAllFields() throws ParseException {
        JsonContentParser parser = new JsonContentParser();
        parser.parse("{\"key\":\"one\",\"key2\":\"two\"}");

        Map<String, String> values = parser.getAllValues();
        assertEquals("one", values.get("/key"));
        assertEquals("two", values.get("/key2"));
    }

    @Test
    void parseInvalidJsonThrows() {
        JsonContentParser parser = new JsonContentParser();
        assertThrows(ParseException.class, () -> parser.parse("not json"));
    }

    @Test
    void getValueMissingPointerReturnsNull() throws ParseException {
        JsonContentParser parser = new JsonContentParser();
        parser.parse("{\"key\":\"one\"}");
        assertNull(parser.getValue("/nonexistent"));
    }

    @Test
    void prettyPrintProducesReadableOutput() throws ParseException {
        JsonContentParser parser = new JsonContentParser();
        parser.parse("{\"key\":\"one\"}");
        String pretty = parser.prettyPrint();
        assertTrue(pretty.contains("key"), "Pretty print should contain field name");
        assertTrue(pretty.contains("one"), "Pretty print should contain field value");
    }

    @Test
    void exampleFromReadme() throws ParseException {
        // data=eyJrZXkiOiJvbmUiLCJrZXkyIjoidHdvIn0= -> {"key":"one","key2":"two"}
        // Verify the parser creates insertion points for "key" and "key2"
        JsonContentParser parser = new JsonContentParser();
        parser.parse("{\"key\":\"one\",\"key2\":\"two\"}");

        List<String> ids = parser.getFieldIdentifiers();
        assertTrue(ids.contains("/key"), "Should have insertion point for /key");
        assertTrue(ids.contains("/key2"), "Should have insertion point for /key2");
    }
}
