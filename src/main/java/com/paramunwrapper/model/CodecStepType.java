package com.paramunwrapper.model;

public enum CodecStepType {
    URL_DECODE("URL Decode"),
    URL_ENCODE("URL Encode"),
    BASE64_DECODE("Base64 Decode"),
    BASE64_ENCODE("Base64 Encode");

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
