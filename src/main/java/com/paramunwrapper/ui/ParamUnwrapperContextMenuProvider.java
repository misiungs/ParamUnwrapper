package com.paramunwrapper.ui;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Adds a "Send to Param Unwrapper" item to the context menu wherever an HTTP request
 * is available (Proxy history, Repeater, Logger, etc.).
 *
 * <p>When invoked the request is loaded into the Param Unwrapper suite tab's
 * request editor so that the user can then run "Parse" against it.
 */
public class ParamUnwrapperContextMenuProvider implements ContextMenuItemsProvider {

    private final RulesTab rulesTab;

    public ParamUnwrapperContextMenuProvider(RulesTab rulesTab) {
        this.rulesTab = rulesTab;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        HttpRequest request = resolveRequest(event);
        if (request == null) {
            return List.of();
        }

        List<Component> items = new ArrayList<>();
        JMenuItem sendItem = new JMenuItem("Send to Param Unwrapper");
        sendItem.addActionListener(e -> rulesTab.sendRequest(request));
        items.add(sendItem);
        return items;
    }

    // --- private helpers ---

    private static HttpRequest resolveRequest(ContextMenuEvent event) {
        // Prefer the message editor's current request (e.g. Repeater, Proxy intercept)
        if (event.messageEditorRequestResponse().isPresent()) {
            MessageEditorHttpRequestResponse editor =
                    event.messageEditorRequestResponse().get();
            return editor.requestResponse().request();
        }
        // Fall back to the first selected request in a list (e.g. Proxy history)
        if (!event.selectedRequestResponses().isEmpty()) {
            return event.selectedRequestResponses().get(0).request();
        }
        return null;
    }
}
