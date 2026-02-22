package com.paramunwrapper.codec;

/**
 * A single codec operation that can encode or decode a string.
 */
public interface Codec {

    /**
     * Apply this codec step (the "forward" direction – towards decoded content).
     *
     * @param input raw input string
     * @return decoded/processed string
     * @throws CodecException if decoding fails
     */
    String decode(String input) throws CodecException;

    /**
     * Apply the inverse of this codec step (the "backward" direction – back to encoded form).
     *
     * @param input decoded string
     * @return encoded string
     * @throws CodecException if encoding fails
     */
    String encode(String input) throws CodecException;
}
