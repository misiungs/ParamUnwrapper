package com.paramunwrapper.scanner;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointProvider;
import com.paramunwrapper.codec.CodecChain;
import com.paramunwrapper.codec.CodecException;
import com.paramunwrapper.model.CandidateEntry;
import com.paramunwrapper.model.CandidateType;
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
 *
 * <p>When a rule has a saved profile (populated via the "Parse" UI), the provider uses
 * those profile entries directly.  Otherwise it falls back to auto-discovering all scalar
 * leaf value fields (legacy behaviour, also covers rules with a non-empty
 * {@link UnwrapRule#getIncludeList() includeList}).
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

        // --- Profile-driven path ---
        List<CandidateEntry> profile = rule.getProfile();
        if (profile != null && !profile.isEmpty()) {
            return buildFromProfile(rule, request, extractor, chain, rawContainer, profile);
        }

        // --- Auto-discovery / legacy include-list path ---
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
            points.add(new UnwrapInsertionPoint(
                    rule, CandidateType.VALUE, id, request, value, extractor));
        }

        return points;
    }

    /**
     * Build insertion points from the rule's saved profile template.
     * For WHOLE_BODY candidates the container is decoded to obtain the current base value.
     */
    private List<AuditInsertionPoint> buildFromProfile(UnwrapRule rule,
                                                        HttpRequest request,
                                                        ContainerExtractor extractor,
                                                        CodecChain chain,
                                                        String rawContainer,
                                                        List<CandidateEntry> profile) {
        List<AuditInsertionPoint> points = new ArrayList<>();

        // Decode once; re-use for all entries (fail gracefully if decode fails)
        String decoded = null;
        ContentParser parser = null;
        try {
            decoded = chain.decode(rawContainer);
            parser = ContentParserFactory.create(rule.getParserType());
            parser.parse(decoded);
        } catch (CodecException | ParseException e) {
            LOG.log(Level.FINE,
                    "Profile path: decode/parse failed for rule ''{0}''; "
                    + "WHOLE_BODY candidates can still proceed: {1}",
                    new Object[]{rule.getName(), e.getMessage()});
            // WHOLE_BODY candidates can still proceed without a parsed tree
        }

        for (CandidateEntry entry : profile) {
            if (!entry.isSelected()) continue;

            try {
                CandidateType type = entry.getType();
                String id = entry.getIdentifier();
                String currentValue;

                if (type == CandidateType.WHOLE_BODY) {
                    currentValue = decoded != null ? decoded : "";
                    points.add(new UnwrapInsertionPoint(
                            rule, type, id, request, currentValue, extractor));
                } else if (parser != null) {
                    if (type == CandidateType.VALUE) {
                        currentValue = parser.getValue(id);
                    } else {
                        // KEY – current value is what the key maps to
                        currentValue = parser.getValue(id);
                    }
                    if (currentValue == null) continue;
                    points.add(new UnwrapInsertionPoint(
                            rule, type, id, request, currentValue, extractor));
                }
            } catch (Exception e) {
                LOG.log(Level.FINE, "Skipping profile entry '" + entry.getIdentifier()
                        + "': " + e.getMessage());
            }
        }

        return points;
    }

    /**
     * Determine which field identifiers to expose as insertion points (legacy path).
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
