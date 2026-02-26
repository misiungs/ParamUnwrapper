package com.paramunwrapper.codec;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Codec that encodes/decodes Unicode and hex escape sequences found in
 * JavaScript/JSON payloads.
 *
 * <p>Decode handles:
 * <ul>
 *   <li>{@code \\uXXXX} - four-digit Unicode escape (JSON/JavaScript)</li>
 *   <li>{@code \\xNN}   - two-digit hex byte escape (JavaScript)</li>
 * </ul>
 *
 * <p>Encode converts every character outside the ASCII printable range
 * (U+0020 to U+007E) to a {@code \\uXXXX} escape, and leaves printable ASCII as-is.
 */
public class UnicodeEscapeCodec implements Codec {

    /** Matches backslash-uXXXX (exactly 4 hex digits). */
    private static final Pattern UNICODE_ESCAPE = Pattern.compile("\\\\u([0-9A-Fa-f]{4})");

    /** Matches backslash-xNN (exactly 2 hex digits). */
    private static final Pattern HEX_ESCAPE = Pattern.compile("\\\\x([0-9A-Fa-f]{2})");

    @Override
    public String decode(String input) throws CodecException {
        if (input == null) {
            throw new CodecException("Unicode-escape decode input must not be null");
        }
        // Decode backslash-uXXXX sequences
        String result = replaceEscapes(UNICODE_ESCAPE, input, 16);
        // Decode backslash-xNN sequences
        result = replaceEscapes(HEX_ESCAPE, result, 16);
        return result;
    }

    @Override
    public String encode(String input) throws CodecException {
        if (input == null) {
            throw new CodecException("Unicode-escape encode input must not be null");
        }
        StringBuilder sb = new StringBuilder(input.length());
        for (int i = 0; i < input.length(); ) {
            int cp = input.codePointAt(i);
            if (cp >= 0x20 && cp <= 0x7E) {
                sb.append((char) cp);
            } else if (cp <= 0xFFFF) {
                sb.append(String.format("\\u%04X", cp));
            } else {
                // Supplementary plane: encode both surrogate code units
                char[] chars = Character.toChars(cp);
                sb.append(String.format("\\u%04X", (int) chars[0]));
                sb.append(String.format("\\u%04X", (int) chars[1]));
            }
            i += Character.charCount(cp);
        }
        return sb.toString();
    }

    /** Replace all matches of {@code pattern} (group 1 = hex digits) with the decoded character. */
    private static String replaceEscapes(Pattern pattern, String input, int radix) {
        Matcher m = pattern.matcher(input);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            int codePoint = Integer.parseInt(m.group(1), radix);
            m.appendReplacement(sb, Matcher.quoteReplacement(
                    new String(Character.toChars(codePoint))));
        }
        m.appendTail(sb);
        return sb.toString();
    }
}
