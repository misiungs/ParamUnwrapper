package com.paramunwrapper.codec;

/**
 * Thrown when a codec step fails to encode or decode its input.
 */
public class CodecException extends Exception {

    public CodecException(String message) {
        super(message);
    }

    public CodecException(String message, Throwable cause) {
        super(message, cause);
    }
}
