package com.paramunwrapper.model;

public enum CodecStepType {
    URL_DECODE("URL Decode"),
    URL_ENCODE("URL Encode"),
    BASE64_DECODE("Base64 Decode"),
    BASE64_ENCODE("Base64 Encode"),
    HTML_ENTITY_DECODE("HTML Entity Decode"),
    HTML_ENTITY_ENCODE("HTML Entity Encode"),
    UNICODE_ESCAPE_DECODE("Unicode Escape Decode"),
    UNICODE_ESCAPE_ENCODE("Unicode Escape Encode");

    private final String displayName;

    CodecStepType(String displayName) {
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
