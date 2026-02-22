package com.paramunwrapper.codec;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * Codec that URL-decodes and URL-encodes strings using UTF-8.
 */
public class UrlCodec implements Codec {

    @Override
    public String decode(String input) throws CodecException {
        if (input == null) {
            throw new CodecException("URL-decode input must not be null");
        }
        try {
            return URLDecoder.decode(input, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw new CodecException("Failed to URL-decode input: " + e.getMessage(), e);
        }
    }

    @Override
    public String encode(String input) throws CodecException {
        if (input == null) {
            throw new CodecException("URL-encode input must not be null");
        }
        return URLEncoder.encode(input, StandardCharsets.UTF_8);
    }
}
