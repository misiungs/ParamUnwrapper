package com.paramunwrapper.codec;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Codec that decodes Base64-encoded strings and encodes strings to Base64.
 * Uses standard Base64 with padding; falls back to URL-safe alphabet on decode.
 */
public class Base64Codec implements Codec {

    @Override
    public String decode(String input) throws CodecException {
        if (input == null) {
            throw new CodecException("Base64 input must not be null");
        }
        String trimmed = input.trim();
        try {
            byte[] decoded = Base64.getDecoder().decode(trimmed);
            return new String(decoded, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            // Try URL-safe decoder as fallback
            try {
                byte[] decoded = Base64.getUrlDecoder().decode(trimmed);
                return new String(decoded, StandardCharsets.UTF_8);
            } catch (IllegalArgumentException e2) {
                throw new CodecException(
                        "Failed to Base64-decode input with both standard and URL-safe decoders: "
                        + e2.getMessage(), e2);
            }
        }
    }

    @Override
    public String encode(String input) throws CodecException {
        if (input == null) {
            throw new CodecException("Base64 input must not be null");
        }
        return Base64.getEncoder().encodeToString(input.getBytes(StandardCharsets.UTF_8));
    }
}
