package com.paramunwrapper.scanner;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for deep JSON search and JSON Pointer-based rewriting in {@link JsonBodySearcher}.
 */
class JsonBodySearcherTest {

    private final JsonBodySearcher searcher = new JsonBodySearcher();

    // --- findFirst: basic location tests ---

    @Test
    void findsTopLevelStringField() {
        JsonBodySearcher.JsonSearchResult result =
                searcher.findFirst("{\"data\":\"<base64>\"}", "data");

        assertNotNull(result);
        assertEquals("/data", result.getPointer());
        assertEquals("<base64>", result.getValue());
    }

    @Test
    void findsNestedStringField() {
        JsonBodySearcher.JsonSearchResult result =
                searcher.findFirst("{\"wrapper\":{\"data\":\"<base64>\"}}", "data");

        assertNotNull(result);
        assertEquals("/wrapper/data", result.getPointer());
        assertEquals("<base64>", result.getValue());
    }

    @Test
    void findsFieldInsideArrayOfObjects() {
        JsonBodySearcher.JsonSearchResult result =
                searcher.findFirst("{\"items\":[{\"data\":\"<base64>\"}]}", "data");

        assertNotNull(result);
        assertEquals("/items/0/data", result.getPointer());
        assertEquals("<base64>", result.getValue());
    }

    @Test
    void findsFieldInSecondArrayElement() {
        JsonBodySearcher.JsonSearchResult result =
                searcher.findFirst("{\"items\":[{\"x\":\"a\"},{\"data\":\"found\"}]}", "data");

        assertNotNull(result);
        assertEquals("/items/1/data", result.getPointer());
        assertEquals("found", result.getValue());
    }

    // --- findFirst: non-string values must be ignored ---

    @Test
    void ignoresIntegerValuedMatch() {
        JsonBodySearcher.JsonSearchResult result =
                searcher.findFirst("{\"data\":42}", "data");

        assertNull(result, "Integer-valued field must not be accepted as container");
    }

    @Test
    void ignoresBooleanValuedMatch() {
        JsonBodySearcher.JsonSearchResult result =
                searcher.findFirst("{\"data\":true}", "data");

        assertNull(result, "Boolean-valued field must not be accepted as container");
    }

    @Test
    void ignoresObjectValuedMatch() {
        JsonBodySearcher.JsonSearchResult result =
                searcher.findFirst("{\"data\":{\"nested\":42}}", "data");

        assertNull(result, "Object-valued field must not be accepted as container");
    }

    @Test
    void ignoresArrayValuedMatch() {
        JsonBodySearcher.JsonSearchResult result =
                searcher.findFirst("{\"data\":[\"a\",\"b\"]}", "data");

        assertNull(result, "Array-valued field must not be accepted as container");
    }

    @Test
    void nonStringMatchFallsThroughToNestedStringMatch() {
        // "data" at root is an integer; inner "data" in a sibling object is a string
        JsonBodySearcher.JsonSearchResult result =
                searcher.findFirst("{\"data\":42,\"wrapper\":{\"data\":\"found\"}}", "data");

        assertNotNull(result);
        assertEquals("/wrapper/data", result.getPointer());
        assertEquals("found", result.getValue());
    }

    // --- findFirst: depth-first ordering ---

    @Test
    void depthFirstOrderPrefersNestedOverSiblingTopLevel() {
        // Depth-first: "outer" is processed first; its nested "data" is found before the
        // sibling top-level "data" that appears later in declaration order.
        JsonBodySearcher.JsonSearchResult result =
                searcher.findFirst("{\"outer\":{\"data\":\"nested\"},\"data\":\"toplevel\"}", "data");

        assertNotNull(result);
        assertEquals("/outer/data", result.getPointer());
        assertEquals("nested", result.getValue());
    }

    @Test
    void depthFirstOrderSelectsFirstMatchInDeclarationOrder() {
        JsonBodySearcher.JsonSearchResult result =
                searcher.findFirst("{\"data\":\"first\",\"other\":{\"data\":\"second\"}}", "data");

        assertNotNull(result);
        assertEquals("/data", result.getPointer());
        assertEquals("first", result.getValue());
    }

    // --- findFirst: edge / error cases ---

    @Test
    void returnsNullWhenFieldAbsent() {
        JsonBodySearcher.JsonSearchResult result =
                searcher.findFirst("{\"other\":\"value\"}", "data");

        assertNull(result);
    }

    @Test
    void returnsNullForInvalidJson() {
        assertNull(searcher.findFirst("not-json", "data"));
    }

    @Test
    void returnsNullForNullBody() {
        assertNull(searcher.findFirst(null, "data"));
    }

    @Test
    void returnsNullForBlankBody() {
        assertNull(searcher.findFirst("   ", "data"));
    }

    // --- countMatches ---

    @Test
    void countMatchesReturnsZeroWhenAbsent() {
        assertEquals(0, searcher.countMatches("{\"other\":\"v\"}", "data"));
    }

    @Test
    void countMatchesReturnsTwoForAmbiguousBody() {
        String json = "{\"data\":\"a\",\"nested\":{\"data\":\"b\"}}";
        assertEquals(2, searcher.countMatches(json, "data"));
    }

    // --- updateAtPointer ---

    @Test
    void updateAtPointerTopLevel() {
        String updated = searcher.updateAtPointer("{\"data\":\"old\"}", "/data", "newValue");

        assertNotNull(updated);
        assertTrue(updated.contains("\"newValue\""));
        assertFalse(updated.contains("\"old\""));
    }

    @Test
    void updateAtPointerNested() {
        String original = "{\"wrapper\":{\"data\":\"old\"}}";
        String updated = searcher.updateAtPointer(original, "/wrapper/data", "newValue");

        assertNotNull(updated);
        assertTrue(updated.contains("\"newValue\""));
        assertFalse(updated.contains("\"old\""));
    }

    @Test
    void updateAtPointerDoesNotAffectSiblingFields() {
        String original = "{\"wrapper\":{\"data\":\"old\",\"other\":\"keep\"}}";
        String updated = searcher.updateAtPointer(original, "/wrapper/data", "newValue");

        assertNotNull(updated);
        assertTrue(updated.contains("\"other\":\"keep\""), "Sibling field must not be modified");
        assertTrue(updated.contains("\"newValue\""));
    }

    @Test
    void updateAtPointerInsideArray() {
        String original = "{\"items\":[{\"data\":\"old\"}]}";
        String updated = searcher.updateAtPointer(original, "/items/0/data", "newValue");

        assertNotNull(updated);
        assertTrue(updated.contains("\"newValue\""));
        assertFalse(updated.contains("\"old\""));
    }

    @Test
    void updateAtPointerReturnsNullWhenParentMissing() {
        // /missing/field – parent "/missing" does not exist in the document
        String result = searcher.updateAtPointer("{\"data\":\"v\"}", "/missing/field", "x");
        assertNull(result);
    }
}
