package com.paramunwrapper.model;

/**
 * Describes the kind of insertion point a candidate represents.
 *
 * <ul>
 *   <li>{@link #VALUE} – replace a scalar field value at a specific identifier.</li>
 *   <li>{@link #KEY}   – rename a key/field name while preserving its value.</li>
 *   <li>{@link #WHOLE_BODY} – replace the entire decoded container text.</li>
 * </ul>
 */
public enum CandidateType {
    VALUE("Value"),
    KEY("Key rename"),
    WHOLE_BODY("Whole body");

    private final String displayName;

    CandidateType(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    @Override
    public String toString() {
        return displayName;
    }
}
