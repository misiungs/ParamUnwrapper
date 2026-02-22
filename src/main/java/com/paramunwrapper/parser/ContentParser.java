package com.paramunwrapper.parser;

import java.util.List;
import java.util.Map;

/**
 * Parses decoded container content and provides read/write access to inner fields.
 */
public interface ContentParser {

    /**
     * Parse the decoded content string.
     *
     * @param content decoded container content
     * @throws ParseException if the content cannot be parsed
     */
    void parse(String content) throws ParseException;

    /**
     * Return all discovered scalar leaf field identifiers.
     * The format of each identifier depends on the parser type:
     * <ul>
     *   <li>JSON: JSON Pointer string (e.g. {@code /key} or {@code /nested/child})</li>
     *   <li>XML: dot-separated path (e.g. {@code root.element} or {@code root.element@attr})</li>
     *   <li>Form: key name</li>
     * </ul>
     */
    List<String> getFieldIdentifiers();

    /**
     * Get the current value of the field at the given identifier.
     *
     * @param identifier field identifier
     * @return string value, or {@code null} if not found
     */
    String getValue(String identifier);

    /**
     * Return a serialised string with the field at {@code identifier} replaced by {@code newValue}.
     *
     * @param identifier field identifier
     * @param newValue   replacement value
     * @return serialised content with the replacement applied
     * @throws ParseException if the identifier is invalid or serialisation fails
     */
    String withValue(String identifier, String newValue) throws ParseException;

    /**
     * Return a human-readable, pretty-printed representation of the parsed content.
     */
    String prettyPrint();

    /**
     * Return a map of all field identifiers to their current values (for display purposes).
     */
    Map<String, String> getAllValues();
}
