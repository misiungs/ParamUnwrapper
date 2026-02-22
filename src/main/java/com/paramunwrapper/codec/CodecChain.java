package com.paramunwrapper.codec;

import com.paramunwrapper.model.CodecStepType;

import java.util.ArrayList;
import java.util.List;

/**
 * An ordered chain of codec steps.
 *
 * <p>Decoding applies the steps in order (index 0 first).
 * Encoding applies the inverse operations in reverse order (last step first).
 *
 * <p>Example: a chain of [BASE64_DECODE, URL_DECODE] will:
 * <ul>
 *   <li>decode: first Base64-decode, then URL-decode the result</li>
 *   <li>encode: first URL-encode, then Base64-encode the result</li>
 * </ul>
 */
public class CodecChain {

    private final List<Codec> steps;

    public CodecChain(List<CodecStepType> stepTypes) {
        this.steps = new ArrayList<>();
        for (CodecStepType type : stepTypes) {
            this.steps.add(createCodec(type));
        }
    }

    /**
     * Apply all decode operations in order.
     */
    public String decode(String input) throws CodecException {
        String value = input;
        for (Codec codec : steps) {
            value = codec.decode(value);
        }
        return value;
    }

    /**
     * Apply all encode operations in reverse order (inverse of decode).
     */
    public String encode(String input) throws CodecException {
        String value = input;
        for (int i = steps.size() - 1; i >= 0; i--) {
            value = steps.get(i).encode(value);
        }
        return value;
    }

    public boolean isEmpty() {
        return steps.isEmpty();
    }

    private static Codec createCodec(CodecStepType type) {
        return switch (type) {
            case URL_DECODE, URL_ENCODE -> new UrlCodec();
            case BASE64_DECODE, BASE64_ENCODE -> new Base64Codec();
        };
    }
}
