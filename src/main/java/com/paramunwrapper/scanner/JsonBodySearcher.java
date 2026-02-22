package com.paramunwrapper.scanner;

import com.fasterxml.jackson.core.JsonPointer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * Utility for performing a deep recursive search in a JSON body for a named field,
 * and for rewriting a JSON value at a given JSON Pointer path.
 *
 * <p>Only properties whose value is a JSON string are considered valid container matches.
 * Traversal is depth-first (objects in field-declaration order, arrays in index order).
 */
public class JsonBodySearcher {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * Result of a JSON deep search: a JSON Pointer (RFC 6901) path and the string value found.
     */
    public static final class JsonSearchResult {
        private final String pointer;
        private final String value;

        JsonSearchResult(String pointer, String value) {
            this.pointer = pointer;
            this.value = value;
        }

        public String getPointer() { return pointer; }
        public String getValue()   { return value; }
    }

    /**
     * Search the given JSON body string for the first property named {@code fieldName}
     * whose value is a JSON string.  Returns {@code null} if not found or the body is not
     * valid JSON.
     *
     * <p>Traversal is depth-first; when a key matches but its value is not a string the
     * search continues deeper into that value (and into subsequent sibling fields).
     */
    public JsonSearchResult findFirst(String jsonBody, String fieldName) {
        if (jsonBody == null || jsonBody.isBlank()) return null;
        try {
            JsonNode root = MAPPER.readTree(jsonBody);
            return deepSearch(root, fieldName, "");
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Collect up to {@code limit} string-valued matches for {@code fieldName} in a single
     * depth-first traversal of the JSON body.  Callers may pass {@code limit=2} to
     * efficiently detect ambiguity without traversing the entire document.
     *
     * @return list of up to {@code limit} results (never {@code null})
     */
    public List<JsonSearchResult> findUpTo(String jsonBody, String fieldName, int limit) {
        List<JsonSearchResult> out = new ArrayList<>();
        if (jsonBody == null || jsonBody.isBlank() || limit <= 0) return out;
        try {
            JsonNode root = MAPPER.readTree(jsonBody);
            collectAll(root, fieldName, "", out, limit);
        } catch (Exception ignored) {}
        return out;
    }

    /**
     * Count all string-valued matches for {@code fieldName} in the JSON body.
     * Used by callers to decide whether to emit an ambiguity warning.
     */
    public int countMatches(String jsonBody, String fieldName) {
        if (jsonBody == null || jsonBody.isBlank()) return 0;
        try {
            JsonNode root = MAPPER.readTree(jsonBody);
            List<JsonSearchResult> all = new ArrayList<>();
            collectAll(root, fieldName, "", all, Integer.MAX_VALUE);
            return all.size();
        } catch (Exception e) {
            return 0;
        }
    }

    /**
     * Update the JSON document at the given JSON Pointer path to a new string value.
     *
     * @param jsonBody  original JSON body string
     * @param pointer   JSON Pointer (RFC 6901) identifying the field to update
     * @param newValue  new string value to set
     * @return updated JSON body string, or {@code null} if the pointer cannot be resolved
     */
    public String updateAtPointer(String jsonBody, String pointer, String newValue) {
        if (jsonBody == null) return null;
        try {
            JsonNode root = MAPPER.readTree(jsonBody);
            JsonPointer ptr = JsonPointer.compile(pointer);
            JsonPointer parentPtr = ptr.head();
            String lastToken = ptr.last().getMatchingProperty();

            JsonNode parent = root.at(parentPtr);
            if (parent == null || parent.isMissingNode() || !(parent instanceof ObjectNode objectNode)) {
                return null;
            }
            objectNode.set(lastToken, new TextNode(newValue));
            return MAPPER.writeValueAsString(root);
        } catch (Exception e) {
            return null;
        }
    }

    // --- private helpers ---

    private JsonSearchResult deepSearch(JsonNode node, String name, String currentPointer) {
        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                String childPointer = currentPointer + "/" + escapePointerToken(field.getKey());
                if (field.getKey().equals(name) && field.getValue().isTextual()) {
                    return new JsonSearchResult(childPointer, field.getValue().asText());
                }
                // Recurse into the value regardless (enables finding matches nested deeper)
                JsonSearchResult nested = deepSearch(field.getValue(), name, childPointer);
                if (nested != null) return nested;
            }
        } else if (node.isArray()) {
            for (int i = 0; i < node.size(); i++) {
                JsonSearchResult nested = deepSearch(node.get(i), name, currentPointer + "/" + i);
                if (nested != null) return nested;
            }
        }
        return null;
    }

    private void collectAll(JsonNode node, String name, String currentPointer,
                             List<JsonSearchResult> out, int limit) {
        if (out.size() >= limit) return;
        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext() && out.size() < limit) {
                Map.Entry<String, JsonNode> field = fields.next();
                String childPointer = currentPointer + "/" + escapePointerToken(field.getKey());
                if (field.getKey().equals(name) && field.getValue().isTextual()) {
                    out.add(new JsonSearchResult(childPointer, field.getValue().asText()));
                }
                collectAll(field.getValue(), name, childPointer, out, limit);
            }
        } else if (node.isArray()) {
            for (int i = 0; i < node.size() && out.size() < limit; i++) {
                collectAll(node.get(i), name, currentPointer + "/" + i, out, limit);
            }
        }
    }

    private static String escapePointerToken(String token) {
        return token.replace("~", "~0").replace("/", "~1");
    }
}
