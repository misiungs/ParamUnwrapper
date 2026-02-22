package com.paramunwrapper.model;

public enum ParserType {
    JSON("JSON"),
    XML("XML"),
    FORM("x-www-form-urlencoded");

    private final String displayName;

    ParserType(String displayName) {
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
