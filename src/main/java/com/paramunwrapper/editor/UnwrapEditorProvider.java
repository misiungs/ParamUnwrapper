package com.paramunwrapper.editor;

import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import com.paramunwrapper.model.UnwrapRule;

import java.util.List;

/**
 * Factory for {@link UnwrapEditorTab} instances.
 */
public class UnwrapEditorProvider implements HttpRequestEditorProvider {

    private final List<UnwrapRule> rules;

    public UnwrapEditorProvider(List<UnwrapRule> rules) {
        this.rules = rules;
    }

    @Override
    public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(
            EditorCreationContext context) {
        return new UnwrapEditorTab(rules);
    }
}
