package com.paramunwrapper.scanner;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointType;

import java.util.Collections;
import java.util.List;
import com.paramunwrapper.codec.CodecChain;
import com.paramunwrapper.codec.CodecException;
import com.paramunwrapper.model.UnwrapRule;
import com.paramunwrapper.parser.ContentParser;
import com.paramunwrapper.parser.ContentParserFactory;
import com.paramunwrapper.parser.ParseException;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * An {@link AuditInsertionPoint} that targets a single inner field inside an encoded container.
 *
 * <p>When a payload is set the insertion point:
 * <ol>
 *   <li>Extracts the current container value from the request</li>
 *   <li>Decodes it through the codec chain</li>
 *   <li>Parses the decoded content</li>
 *   <li>Replaces the targeted inner field value with the payload</li>
 *   <li>Serialises and re-encodes the content</li>
 *   <li>Rebuilds the HTTP request with the modified container value</li>
 * </ol>
 */
public class UnwrapInsertionPoint implements AuditInsertionPoint {

    private static final Logger LOG = Logger.getLogger(UnwrapInsertionPoint.class.getName());

    private final UnwrapRule rule;
    private final String fieldIdentifier;
    private final HttpRequest baseRequest;
    private final String currentValue;
    private final ContainerExtractor extractor;

    UnwrapInsertionPoint(UnwrapRule rule,
                         String fieldIdentifier,
                         HttpRequest baseRequest,
                         String currentValue,
                         ContainerExtractor extractor) {
        this.rule = rule;
        this.fieldIdentifier = fieldIdentifier;
        this.baseRequest = baseRequest;
        this.currentValue = currentValue;
        this.extractor = extractor;
    }

    @Override
    public String name() {
        return rule.getName() + " → " + fieldIdentifier;
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

            String decoded = chain.decode(rawContainer);

            ContentParser parser = ContentParserFactory.create(rule.getParserType());
            parser.parse(decoded);

            String modified = parser.withValue(fieldIdentifier, payload.toString());

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
}
