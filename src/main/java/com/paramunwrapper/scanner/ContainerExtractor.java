package com.paramunwrapper.scanner;

import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.List;

/**
 * Extracts and replaces the container value from/in an {@link HttpRequest}.
 *
 * <p>Supports two modes:
 * <ul>
 *   <li>Named parameter (query/body/cookie): find the parameter by name and replace its value</li>
 *   <li>Whole-body: use the entire request body as the container value</li>
 * </ul>
 */
public class ContainerExtractor {

    private final boolean useNamedParameter;
    private final String parameterName;

    public ContainerExtractor(boolean useNamedParameter, String parameterName) {
        this.useNamedParameter = useNamedParameter;
        this.parameterName = parameterName;
    }

    /**
     * Extract the raw container string from the request.
     *
     * @return raw container string, or {@code null} if the named parameter is not found
     */
    public String extractRawContainer(HttpRequest request) {
        if (useNamedParameter) {
            ParsedHttpParameter param = findParameter(request);
            return param != null ? param.value() : null;
        } else {
            return request.bodyToString();
        }
    }

    /**
     * Return a new request with the container replaced by {@code newValue}.
     */
    public HttpRequest buildRequestWithContainer(HttpRequest request, String newValue) {
        if (useNamedParameter) {
            ParsedHttpParameter param = findParameter(request);
            if (param == null) return request;
            HttpParameter replacement = HttpParameter.parameter(
                    param.name(), newValue, param.type());
            return request.withUpdatedParameters(replacement);
        } else {
            return request.withBody(newValue);
        }
    }

    private ParsedHttpParameter findParameter(HttpRequest request) {
        List<ParsedHttpParameter> params = request.parameters();
        for (ParsedHttpParameter p : params) {
            if (p.name().equals(parameterName)
                    && (p.type() == HttpParameterType.URL
                    || p.type() == HttpParameterType.BODY
                    || p.type() == HttpParameterType.COOKIE)) {
                return p;
            }
        }
        return null;
    }
}
