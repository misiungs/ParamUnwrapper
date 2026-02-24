package com.paramunwrapper.parser;

import com.paramunwrapper.model.ParserType;

/**
 * Factory that creates {@link ContentParser} instances for a given {@link ParserType}.
 */
public final class ContentParserFactory {

    private ContentParserFactory() {}

    public static ContentParser create(ParserType type) {
        return switch (type) {
            case JSON -> new JsonContentParser();
            case XML -> new XmlContentParser();
            case FORM -> new FormContentParser();
            case CUSTOM -> throw new IllegalArgumentException(
                    "CUSTOM parser type does not use a ContentParser; "
                    + "use regex patterns in the include list");
        };
    }
}
