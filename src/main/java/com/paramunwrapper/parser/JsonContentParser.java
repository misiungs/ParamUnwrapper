package com.paramunwrapper.parser;

import com.fasterxml.jackson.core.JsonPointer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;

import java.util.*;

/**
 * Parses JSON content, exposes scalar leaf fields as JSON Pointer identifiers,
 * and supports value replacement by JSON Pointer.
 */
public class JsonContentParser implements ContentParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private JsonNode root;
    private String originalContent;

    @Override
    public void parse(String content) throws ParseException {
        if (content == null || content.isBlank()) {
            throw new ParseException("JSON content is empty");
        }
        try {
            this.root = MAPPER.readTree(content);
            this.originalContent = content;
        } catch (Exception e) {
            throw new ParseException("Failed to parse JSON: " + e.getMessage(), e);
        }
    }

    @Override
    public List<String> getFieldIdentifiers() {
        List<String> identifiers = new ArrayList<>();
        collectLeafPointers(root, "", identifiers);
        return identifiers;
    }

    @Override
    public String getValue(String identifier) {
        if (root == null) return null;
        try {
            JsonPointer ptr = JsonPointer.compile(identifier);
            JsonNode node = root.at(ptr);
            if (node.isMissingNode() || !node.isValueNode()) {
                return null;
            }
            return node.asText();
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public String withValue(String identifier, String newValue) throws ParseException {
        if (root == null) {
            throw new ParseException("JSON content has not been parsed");
        }
        try {
            JsonNode copy = root.deepCopy();
            JsonPointer ptr = JsonPointer.compile(identifier);
            JsonPointer parentPtr = ptr.head();
            String lastToken = ptr.last().getMatchingProperty();

            // JsonNode.at(emptyPointer) returns the node itself, so this handles both
            // top-level fields (/key → parent is root) and nested fields (/a/b → parent is /a).
            JsonNode parent = copy.at(parentPtr);

            if (parent == null || parent.isMissingNode()) {
                throw new ParseException("Parent node not found for pointer: " + identifier);
            }
            if (!(parent instanceof ObjectNode objectNode)) {
                throw new ParseException("Parent node is not an object for pointer: " + identifier);
            }
            objectNode.set(lastToken, new TextNode(newValue));
            return MAPPER.writeValueAsString(copy);
        } catch (ParseException e) {
            throw e;
        } catch (Exception e) {
            throw new ParseException("Failed to update JSON value at " + identifier + ": " + e.getMessage(), e);
        }
    }

    @Override
    public String prettyPrint() {
        if (root == null) return "";
        try {
            return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(root);
        } catch (Exception e) {
            return originalContent != null ? originalContent : "";
        }
    }

    @Override
    public Map<String, String> getAllValues() {
        Map<String, String> result = new LinkedHashMap<>();
        for (String id : getFieldIdentifiers()) {
            result.put(id, getValue(id));
        }
        return result;
    }

    @Override
    public List<String> getKeyIdentifiers() {
        if (root == null) return Collections.emptyList();
        List<String> keys = new ArrayList<>();
        collectObjectKeyPointers(root, "", keys);
        return keys;
    }

    @Override
    public String withKeyRenamed(String identifier, String newKey) throws ParseException {
        if (root == null) {
            throw new ParseException("JSON content has not been parsed");
        }
        try {
            JsonNode copy = root.deepCopy();
            JsonPointer ptr = JsonPointer.compile(identifier);
            JsonPointer parentPtr = ptr.head();
            String oldKey = ptr.last().getMatchingProperty();

            // JsonNode.at(emptyPointer) returns the node itself, so no special-case needed.
            JsonNode parent = copy.at(parentPtr);

            if (parent == null || parent.isMissingNode()) {
                throw new ParseException("Parent node not found for pointer: " + identifier);
            }
            if (!(parent instanceof ObjectNode objectNode)) {
                throw new ParseException("Parent node is not an object for pointer: " + identifier);
            }
            JsonNode value = objectNode.get(oldKey);
            if (value == null) {
                throw new ParseException("Key not found: " + oldKey + " at " + identifier);
            }
            objectNode.remove(oldKey);
            objectNode.set(newKey, value);
            return MAPPER.writeValueAsString(copy);
        } catch (ParseException e) {
            throw e;
        } catch (Exception e) {
            throw new ParseException("Failed to rename JSON key at " + identifier + ": "
                    + e.getMessage(), e);
        }
    }

    // --- private helpers ---

    private void collectLeafPointers(JsonNode node, String currentPath, List<String> out) {
        if (node == null) return;

        if (node.isValueNode()) {
            out.add(currentPath.isEmpty() ? "/" : currentPath);
        } else if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> entry = fields.next();
                String childPath = currentPath + "/" + escapePointerToken(entry.getKey());
                collectLeafPointers(entry.getValue(), childPath, out);
            }
        } else if (node.isArray()) {
            for (int i = 0; i < node.size(); i++) {
                collectLeafPointers(node.get(i), currentPath + "/" + i, out);
            }
        }
    }

    /**
     * Escape a JSON Pointer token per RFC 6901 (~ -> ~0, / -> ~1).
     */
    private static String escapePointerToken(String token) {
        return token.replace("~", "~0").replace("/", "~1");
    }

    /**
     * Collect JSON Pointer paths for every object key (recursively).
     * Array indices are traversed but not themselves emitted as key identifiers.
     */
    private void collectObjectKeyPointers(JsonNode node, String currentPath, List<String> out) {
        if (node == null) return;
        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> entry = fields.next();
                String childPath = currentPath + "/" + escapePointerToken(entry.getKey());
                out.add(childPath);
                collectObjectKeyPointers(entry.getValue(), childPath, out);
            }
        } else if (node.isArray()) {
            for (int i = 0; i < node.size(); i++) {
                collectObjectKeyPointers(node.get(i), currentPath + "/" + i, out);
            }
        }
    }
}
