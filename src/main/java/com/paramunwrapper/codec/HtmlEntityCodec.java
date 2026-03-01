package com.paramunwrapper.codec;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Codec that HTML-entity-encodes and -decodes strings.
 *
 * Encode converts the five XML/HTML special characters to named entities:
 * {@code &} to {@code &amp;}, {@code <} to {@code &lt;}, {@code >} to {@code &gt;},
 * {@code "} to {@code &quot;}, {@code '} to {@code &#39;}.
 *
 * <p>Decode handles:
 * <ul>
 *   <li>Named entities: {@code &amp;}, {@code &lt;}, {@code &gt;},
 *       {@code &quot;}, {@code &apos;}, {@code &#39;}</li>
 *   <li>Decimal numeric entities: {@code &#60;}</li>
 *   <li>Hex numeric entities (upper- or lower-case x): {@code &#x3c;} / {@code &#X3C;}</li>
 * </ul>
 */
public class HtmlEntityCodec implements Codec {

    /** Named entities recognised during decoding. */
    private static final Map<String, String> NAMED_ENTITIES = new LinkedHashMap<>();

    static {
        NAMED_ENTITIES.put("&amp;",  "&");
        NAMED_ENTITIES.put("&lt;",   "<");
        NAMED_ENTITIES.put("&gt;",   ">");
        NAMED_ENTITIES.put("&quot;", "\"");
        NAMED_ENTITIES.put("&apos;", "'");
        NAMED_ENTITIES.put("&#39;",  "'");
    }

    /** Matches decimal ({@code &#60;}) and hex ({@code &#x3c;} / {@code &#X3C;}) numeric entities. */
    private static final Pattern NUMERIC_ENTITY =
            Pattern.compile("&#([xX][0-9A-Fa-f]+|[0-9]+);");

    @Override
    public String decode(String input) throws CodecException {
        if (input == null) {
            throw new CodecException("HTML-entity decode input must not be null");
        }
        // Replace named entities first
        String result = input;
        for (Map.Entry<String, String> entry : NAMED_ENTITIES.entrySet()) {
            result = result.replace(entry.getKey(), entry.getValue());
        }
        // Replace numeric entities
        Matcher m = NUMERIC_ENTITY.matcher(result);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            String ref = m.group(1);
            int codePoint;
            if (ref.startsWith("x") || ref.startsWith("X")) {
                codePoint = Integer.parseInt(ref.substring(1), 16);
            } else {
                codePoint = Integer.parseInt(ref, 10);
            }
            m.appendReplacement(sb, Matcher.quoteReplacement(new String(Character.toChars(codePoint))));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    @Override
    public String encode(String input) throws CodecException {
        if (input == null) {
            throw new CodecException("HTML-entity encode input must not be null");
        }
        // Encode in a single pass; & must be replaced first to avoid double-encoding
        StringBuilder sb = new StringBuilder(input.length());
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            switch (c) {
                case '&'  -> sb.append("&amp;");
                case '<'  -> sb.append("&lt;");
                case '>'  -> sb.append("&gt;");
                case '"'  -> sb.append("&quot;");
                case '\'' -> sb.append("&#39;");  // &apos; is XML-only; &#39; is safe in HTML4/5
                default   -> sb.append(c);
            }
        }
        return sb.toString();
    }
}
