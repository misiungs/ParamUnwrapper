package com.paramunwrapper.model;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Represents a single unwrap rule that defines how to decode a container parameter,
 * parse its contents, and expose inner fields as scanner insertion points.
 */
public class UnwrapRule {

    private String id;
    private String name;
    private boolean enabled;

    /** True = use a named Burp parameter; false = use the whole request body */
    private boolean useNamedParameter;

    /** Name of the Burp parameter (query/body/cookie) – only when useNamedParameter=true */
    private String parameterName;

    /** Ordered codec steps applied to decode the container value */
    private List<CodecStepType> codecChain;

    /** How to parse the decoded content */
    private ParserType parserType;

    /**
     * Optional include list of inner parameter identifiers to expose as insertion points.
     * <ul>
     *   <li>JSON: JSON Pointer expressions (e.g. {@code /key} or {@code /nested/field})</li>
     *   <li>XML: simple dot-separated element path or {@code @attr} for attributes</li>
     *   <li>Form: parameter key names</li>
     * </ul>
     * When empty, all discovered scalar leaf fields are exposed.
     */
    private List<String> includeList;

    public UnwrapRule() {
        this.id = UUID.randomUUID().toString();
        this.name = "New Rule";
        this.enabled = true;
        this.useNamedParameter = true;
        this.parameterName = "";
        this.codecChain = new ArrayList<>();
        this.parserType = ParserType.JSON;
        this.includeList = new ArrayList<>();
    }

    public UnwrapRule(String name) {
        this();
        this.name = name;
    }

    // --- Getters and setters ---

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isUseNamedParameter() {
        return useNamedParameter;
    }

    public void setUseNamedParameter(boolean useNamedParameter) {
        this.useNamedParameter = useNamedParameter;
    }

    public String getParameterName() {
        return parameterName;
    }

    public void setParameterName(String parameterName) {
        this.parameterName = parameterName;
    }

    public List<CodecStepType> getCodecChain() {
        return codecChain;
    }

    public void setCodecChain(List<CodecStepType> codecChain) {
        this.codecChain = codecChain;
    }

    public ParserType getParserType() {
        return parserType;
    }

    public void setParserType(ParserType parserType) {
        this.parserType = parserType;
    }

    public List<String> getIncludeList() {
        return includeList;
    }

    public void setIncludeList(List<String> includeList) {
        this.includeList = includeList;
    }

    @Override
    public String toString() {
        return name;
    }
}
