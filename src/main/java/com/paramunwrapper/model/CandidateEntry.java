package com.paramunwrapper.model;

/**
 * A single candidate insertion point discovered during a "Parse" run.
 *
 * <p>Candidates are stored in a rule's profile so that the scanner can re-create
 * the same set of insertion points without re-running discovery on every request.
 */
public class CandidateEntry {

    /** Identifier constant used for whole-body candidates. */
    public static final String WHOLE_BODY_ID = "__body__";

    private CandidateType type;

    /**
     * Field identifier whose meaning depends on {@link #type}:
     * <ul>
     *   <li>VALUE – the JSON Pointer / form key / XML path of the targeted value.</li>
     *   <li>KEY   – the JSON Pointer / form key of the key to rename.</li>
     *   <li>WHOLE_BODY – {@value #WHOLE_BODY_ID} (the identifier is ignored during scanning).</li>
     * </ul>
     */
    private String identifier;

    /** The value observed at profile-save time (display only; not used at scan time). */
    private String currentValue;

    /** Whether this candidate is included in the active profile. */
    private boolean selected;

    /** Required by Jackson for deserialisation. */
    public CandidateEntry() {}

    public CandidateEntry(CandidateType type, String identifier,
                          String currentValue, boolean selected) {
        this.type = type;
        this.identifier = identifier;
        this.currentValue = currentValue;
        this.selected = selected;
    }

    // --- Getters / setters ---

    public CandidateType getType() {
        return type;
    }

    public void setType(CandidateType type) {
        this.type = type;
    }

    public String getIdentifier() {
        return identifier;
    }

    public void setIdentifier(String identifier) {
        this.identifier = identifier;
    }

    public String getCurrentValue() {
        return currentValue;
    }

    public void setCurrentValue(String currentValue) {
        this.currentValue = currentValue;
    }

    public boolean isSelected() {
        return selected;
    }

    public void setSelected(boolean selected) {
        this.selected = selected;
    }
}
