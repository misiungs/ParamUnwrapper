package com.paramunwrapper.scanner;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointType;

import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import com.paramunwrapper.codec.CodecChain;
import com.paramunwrapper.codec.CodecException;
import com.paramunwrapper.model.CandidateType;
import com.paramunwrapper.model.ParserType;
import com.paramunwrapper.model.UnwrapRule;
import com.paramunwrapper.parser.ContentParser;
import com.paramunwrapper.parser.ContentParserFactory;
import com.paramunwrapper.parser.ParseException;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * An {@link AuditInsertionPoint} that targets a single inner field inside an encoded container.
 *
 * <p>Three modes are supported, determined by {@link CandidateType}:
 * <ul>
 *   <li>{@link CandidateType#VALUE} – replaces the value at {@code fieldIdentifier}.</li>
 *   <li>{@link CandidateType#KEY}   – renames the key at {@code fieldIdentifier} to the payload.</li>
 *   <li>{@link CandidateType#WHOLE_BODY} – replaces the entire decoded container with the payload.</li>
 * </ul>
 *
 * <p>On each call to {@link #buildHttpRequestWithPayload}:
 * <ol>
 *   <li>Extracts the current container value from the request.</li>
 *   <li>Decodes it through the codec chain.</li>
 *   <li>Applies the mutation.</li>
 *   <li>Serialises and re-encodes the (modified) content.</li>
 *   <li>Rebuilds the HTTP request with the modified container value.</li>
 * </ol>
 */
public class UnwrapInsertionPoint implements AuditInsertionPoint {

    private static final Logger LOG = Logger.getLogger(UnwrapInsertionPoint.class.getName());

    private final UnwrapRule rule;
    private final CandidateType candidateType;
    private final String fieldIdentifier;
    private final HttpRequest baseRequest;
    private final String currentValue;
    private final ContainerExtractor extractor;
    /** Pre-compiled regex pattern for Custom-type insertion points; {@code null} for all other types. */
    private final Pattern customPattern;

    UnwrapInsertionPoint(UnwrapRule rule,
                         CandidateType candidateType,
                         String fieldIdentifier,
                         HttpRequest baseRequest,
                         String currentValue,
                         ContainerExtractor extractor) {
        this.rule = rule;
        this.candidateType = candidateType;
        this.fieldIdentifier = fieldIdentifier;
        this.baseRequest = baseRequest;
        this.currentValue = currentValue;
        this.extractor = extractor;
        if (rule.getParserType() == ParserType.CUSTOM && fieldIdentifier.startsWith("regex:")) {
            Pattern p;
            try {
                p = Pattern.compile(fieldIdentifier.substring("regex:".length()));
            } catch (Exception e) {
                p = null;
            }
            this.customPattern = p;
        } else {
            this.customPattern = null;
        }
    }

    @Override
    public String name() {
        return rule.getName() + " → " + fieldIdentifier
                + (candidateType == CandidateType.KEY ? " [key]" : "");
    }

    @Override
    public String baseValue() {
        return currentValue != null ? currentValue : "";
    }

    @Override
    public List<Range> issueHighlights(ByteArray payload) {
        return Collections.emptyList();
    }

    @Override
    public HttpRequest buildHttpRequestWithPayload(ByteArray payload) {
        try {
            CodecChain chain = new CodecChain(rule.getCodecChain());
            String rawContainer = extractor.extractRawContainer(baseRequest);
            if (rawContainer == null) {
                return baseRequest;
            }

            if (candidateType == CandidateType.WHOLE_BODY) {
                // Payload replaces the entire decoded text; just re-encode and update.
                String reencoded = chain.encode(payload.toString());
                return extractor.buildRequestWithContainer(baseRequest, reencoded);
            }

            String decoded = chain.decode(rawContainer);

            if (rule.getParserType() == ParserType.CUSTOM) {
                String modified = applyCustomReplacement(decoded, fieldIdentifier, payload.toString());
                if (modified == null) return baseRequest;
                String reencoded = chain.encode(modified);
                return extractor.buildRequestWithContainer(baseRequest, reencoded);
            }

            ContentParser parser = ContentParserFactory.create(rule.getParserType());
            parser.parse(decoded);

            String modified;
            if (candidateType == CandidateType.KEY) {
                modified = parser.withKeyRenamed(fieldIdentifier, payload.toString());
            } else {
                modified = parser.withValue(fieldIdentifier, payload.toString());
            }

            String reencoded = chain.encode(modified);
            return extractor.buildRequestWithContainer(baseRequest, reencoded);
        } catch (CodecException | ParseException e) {
            LOG.log(Level.WARNING, "Failed to build request with payload for insertion point '"
                    + name() + "': " + e.getMessage(), e);
            return baseRequest;
        }
    }

    @Override
    public AuditInsertionPointType type() {
        return AuditInsertionPointType.EXTENSION_PROVIDED;
    }

    /**
     * Applies a regex-based span replacement for Custom content type insertion points.
     *
     * <p>The {@code identifier} must be in the form {@code regex:<pattern>} where
     * {@code <pattern>} is a Java regex containing the named capture group {@code (?<value>...)}.
     * Only the first match is used; the span of the captured group {@code value} is replaced
     * with {@code payloadStr}.
     *
     * @return the modified string, or {@code null} if the identifier is not a Custom regex
     *         identifier, the regex does not match, or any error occurs
     */
    private String applyCustomReplacement(String decoded, String identifier, String payloadStr) {
        if (customPattern == null) return null;
        try {
            Matcher m = customPattern.matcher(decoded);
            if (!m.find()) return null;
            int start = m.start("value");
            int end = m.end("value");
            return decoded.substring(0, start) + payloadStr + decoded.substring(end);
        } catch (Exception e) {
            LOG.log(Level.WARNING,
                    "Custom regex replacement failed for pattern '" + identifier + "': "
                    + e.getMessage(), e);
            return null;
        }
    }
}
