package com.paramunwrapper.scanner;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointProvider;
import com.paramunwrapper.codec.CodecChain;
import com.paramunwrapper.codec.CodecException;
import com.paramunwrapper.model.UnwrapRule;
import com.paramunwrapper.parser.ContentParser;
import com.paramunwrapper.parser.ContentParserFactory;
import com.paramunwrapper.parser.ParseException;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Provides scanner insertion points for requests that match enabled {@link UnwrapRule}s.
 */
public class UnwrapInsertionPointProvider implements AuditInsertionPointProvider {

    private static final Logger LOG = Logger.getLogger(UnwrapInsertionPointProvider.class.getName());

    private final List<UnwrapRule> rules;

    public UnwrapInsertionPointProvider(List<UnwrapRule> rules) {
        this.rules = rules;
    }

    @Override
    public List<AuditInsertionPoint> provideInsertionPoints(HttpRequestResponse requestResponse) {
        HttpRequest request = requestResponse.request();
        List<AuditInsertionPoint> insertionPoints = new ArrayList<>();

        for (UnwrapRule rule : rules) {
            if (!rule.isEnabled()) continue;

            try {
                insertionPoints.addAll(buildInsertionPointsForRule(rule, request));
            } catch (Exception e) {
                LOG.log(Level.WARNING, "Error building insertion points for rule '"
                        + rule.getName() + "': " + e.getMessage(), e);
            }
        }

        return insertionPoints;
    }

    private List<AuditInsertionPoint> buildInsertionPointsForRule(UnwrapRule rule,
                                                                   HttpRequest request) {
        List<AuditInsertionPoint> points = new ArrayList<>();

        ContainerExtractor extractor = new ContainerExtractor(
                rule.isUseNamedParameter(), rule.getParameterName());

        String rawContainer = extractor.extractRawContainer(request);
        if (rawContainer == null || rawContainer.isBlank()) {
            return points;
        }

        CodecChain chain = new CodecChain(rule.getCodecChain());
        String decoded;
        try {
            decoded = chain.decode(rawContainer);
        } catch (CodecException e) {
            LOG.log(Level.FINE, "Codec decode failed for rule '" + rule.getName() + "': "
                    + e.getMessage());
            return points;
        }

        ContentParser parser = ContentParserFactory.create(rule.getParserType());
        try {
            parser.parse(decoded);
        } catch (ParseException e) {
            LOG.log(Level.FINE, "Parse failed for rule '" + rule.getName() + "': "
                    + e.getMessage());
            return points;
        }

        List<String> identifiers = resolveIdentifiers(rule, parser);

        for (String id : identifiers) {
            String value = parser.getValue(id);
            if (value == null) continue;
            points.add(new UnwrapInsertionPoint(rule, id, request, value, extractor));
        }

        return points;
    }

    /**
     * Determine which field identifiers to expose as insertion points.
     * If the rule's includeList is non-empty, use only those identifiers;
     * otherwise expose all discovered scalar leaf fields.
     */
    private List<String> resolveIdentifiers(UnwrapRule rule, ContentParser parser) {
        if (rule.getIncludeList() != null && !rule.getIncludeList().isEmpty()) {
            return rule.getIncludeList();
        }
        return parser.getFieldIdentifiers();
    }
}
