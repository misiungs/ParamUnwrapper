package com.paramunwrapper.parser;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Parses application/x-www-form-urlencoded content, exposing each key as a field identifier.
 * Preserves the original key order on serialisation.
 */
public class FormContentParser implements ContentParser {

    /** Ordered entries (key -> value); a LinkedHashMap preserves insertion order */
    private LinkedHashMap<String, String> fields;

    @Override
    public void parse(String content) throws ParseException {
        if (content == null) {
            throw new ParseException("Form content is null");
        }
        fields = new LinkedHashMap<>();
        if (content.isBlank()) {
            return;
        }
        String[] pairs = content.split("&", -1);
        for (String pair : pairs) {
            int idx = pair.indexOf('=');
            String key;
            String value;
            if (idx >= 0) {
                key = urlDecode(pair.substring(0, idx));
                value = urlDecode(pair.substring(idx + 1));
            } else {
                key = urlDecode(pair);
                value = "";
            }
            fields.put(key, value);
        }
    }

    @Override
    public List<String> getFieldIdentifiers() {
        return fields == null ? Collections.emptyList() : new ArrayList<>(fields.keySet());
    }

    @Override
    public String getValue(String identifier) {
        return fields == null ? null : fields.get(identifier);
    }

    @Override
    public String withValue(String identifier, String newValue) throws ParseException {
        if (fields == null) {
            throw new ParseException("Form content has not been parsed");
        }
        if (!fields.containsKey(identifier)) {
            throw new ParseException("Field not found: " + identifier);
        }
        LinkedHashMap<String, String> copy = new LinkedHashMap<>(fields);
        copy.put(identifier, newValue);
        return serialise(copy);
    }

    @Override
    public String prettyPrint() {
        if (fields == null) return "";
        StringBuilder sb = new StringBuilder();
        fields.forEach((k, v) -> sb.append(k).append(" = ").append(v).append("\n"));
        return sb.toString();
    }

    @Override
    public Map<String, String> getAllValues() {
        return fields == null ? Collections.emptyMap() : new LinkedHashMap<>(fields);
    }

    @Override
    public List<String> getKeyIdentifiers() {
        return getFieldIdentifiers();
    }

    @Override
    public String withKeyRenamed(String identifier, String newKey) throws ParseException {
        if (fields == null) {
            throw new ParseException("Form content has not been parsed");
        }
        if (!fields.containsKey(identifier)) {
            throw new ParseException("Key not found: " + identifier);
        }
        // Rebuild map preserving insertion order, swapping the old key for newKey
        LinkedHashMap<String, String> copy = new LinkedHashMap<>();
        for (Map.Entry<String, String> entry : fields.entrySet()) {
            if (entry.getKey().equals(identifier)) {
                copy.put(newKey, entry.getValue());
            } else {
                copy.put(entry.getKey(), entry.getValue());
            }
        }
        return serialise(copy);
    }

    // --- private helpers ---

    private static String urlDecode(String s) {
        try {
            return URLDecoder.decode(s, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return s;
        }
    }

    private static String urlEncode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private static String serialise(LinkedHashMap<String, String> map) {
        StringJoiner joiner = new StringJoiner("&");
        map.forEach((k, v) -> joiner.add(urlEncode(k) + "=" + urlEncode(v)));
        return joiner.toString();
    }
}
