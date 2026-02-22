package com.paramunwrapper.parser;

/**
 * Thrown when content cannot be parsed or when a field operation fails.
 */
public class ParseException extends Exception {

    public ParseException(String message) {
        super(message);
    }

    public ParseException(String message, Throwable cause) {
        super(message, cause);
    }
}
