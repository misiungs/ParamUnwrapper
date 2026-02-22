package com.paramunwrapper;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.paramunwrapper.editor.UnwrapEditorProvider;
import com.paramunwrapper.model.UnwrapRule;
import com.paramunwrapper.persistence.PersistenceManager;
import com.paramunwrapper.scanner.UnwrapInsertionPointProvider;
import com.paramunwrapper.ui.ParamUnwrapperContextMenuProvider;
import com.paramunwrapper.ui.RulesTab;

import java.util.List;

/**
 * Entry point for the Param Unwrapper Burp Suite extension.
 *
 * <p>Registers:
 * <ul>
 *   <li>A suite tab for managing unwrap rules</li>
 *   <li>A scanner insertion point provider</li>
 *   <li>A message editor tab (request editor)</li>
 * </ul>
 */
public class ParamUnwrapperExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Param Unwrapper");

        PersistenceManager persistence = new PersistenceManager(api);
        List<UnwrapRule> rules = persistence.loadRules();

        // The scanner provider holds a live reference to the rules list.
        // When rules are updated via the UI, the same list instance is mutated in place,
        // so the provider always sees the latest configuration.
        UnwrapInsertionPointProvider insertionPointProvider =
                new UnwrapInsertionPointProvider(rules);

        // Suite tab
        RulesTab rulesTab = new RulesTab(
                rules,
                persistence,
                () -> {}, // could trigger additional actions on change
                api.userInterface());

        api.userInterface().registerSuiteTab("Param Unwrapper", rulesTab);

        // Scanner insertion points
        api.scanner().registerInsertionPointProvider(insertionPointProvider);

        // Context menu: "Send to Param Unwrapper"
        api.userInterface().registerContextMenuItemsProvider(
                new ParamUnwrapperContextMenuProvider(rulesTab));

        // Message editor tab
        api.userInterface().registerHttpRequestEditorProvider(
                new UnwrapEditorProvider(rules));

        api.logging().logToOutput("Param Unwrapper loaded successfully.");
    }
}
