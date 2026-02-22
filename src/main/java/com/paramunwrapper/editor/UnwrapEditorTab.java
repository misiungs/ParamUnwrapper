package com.paramunwrapper.editor;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import com.paramunwrapper.codec.CodecChain;
import com.paramunwrapper.model.UnwrapRule;
import com.paramunwrapper.parser.ContentParser;
import com.paramunwrapper.parser.ContentParserFactory;
import com.paramunwrapper.scanner.ContainerExtractor;

import javax.swing.*;
import java.awt.*;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * A message editor tab that shows which rule matched a request, displays the decoded
 * container content, and lists all detected inner parameters with their current values.
 */
public class UnwrapEditorTab implements ExtensionProvidedHttpRequestEditor {

    private final List<UnwrapRule> rules;
    private final JPanel panel;
    private final JLabel matchedRuleLabel;
    private final JTextArea decodedContentArea;
    private final JTextArea parametersArea;

    private HttpRequestResponse currentRequestResponse;

    public UnwrapEditorTab(List<UnwrapRule> rules) {
        this.rules = rules;

        panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        topPanel.add(new JLabel("Matched rule: "));
        matchedRuleLabel = new JLabel("(none)");
        matchedRuleLabel.setFont(matchedRuleLabel.getFont().deriveFont(Font.BOLD));
        topPanel.add(matchedRuleLabel);
        panel.add(topPanel, BorderLayout.NORTH);

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setResizeWeight(0.6);

        decodedContentArea = new JTextArea();
        decodedContentArea.setEditable(false);
        decodedContentArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane decodedScroll = new JScrollPane(decodedContentArea);
        decodedScroll.setBorder(BorderFactory.createTitledBorder("Decoded content"));
        splitPane.setTopComponent(decodedScroll);

        parametersArea = new JTextArea();
        parametersArea.setEditable(false);
        parametersArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane paramsScroll = new JScrollPane(parametersArea);
        paramsScroll.setBorder(BorderFactory.createTitledBorder("Detected inner parameters"));
        splitPane.setBottomComponent(paramsScroll);

        panel.add(splitPane, BorderLayout.CENTER);
    }

    @Override
    public HttpRequest getRequest() {
        return currentRequestResponse != null ? currentRequestResponse.request() : null;
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        this.currentRequestResponse = requestResponse;
        updateDisplay(requestResponse.request());
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        // Only show tab when at least one rule can decode the request
        return findMatchingRule(requestResponse.request()).isPresent();
    }

    @Override
    public String caption() {
        return "Param Unwrapper";
    }

    @Override
    public Component uiComponent() {
        return panel;
    }

    @Override
    public Selection selectedData() {
        return null;
    }

    @Override
    public boolean isModified() {
        return false;
    }

    // --- private helpers ---

    private Optional<UnwrapRule> findMatchingRule(HttpRequest request) {
        for (UnwrapRule rule : rules) {
            if (!rule.isEnabled()) continue;
            try {
                ContainerExtractor extractor = new ContainerExtractor(
                        rule.isUseNamedParameter(), rule.getParameterName());
                String raw = extractor.extractRawContainer(request);
                if (raw == null || raw.isBlank()) continue;

                CodecChain chain = new CodecChain(rule.getCodecChain());
                String decoded = chain.decode(raw);

                ContentParser parser = ContentParserFactory.create(rule.getParserType());
                parser.parse(decoded);
                return Optional.of(rule);
            } catch (Exception ignored) {
            }
        }
        return Optional.empty();
    }

    private void updateDisplay(HttpRequest request) {
        SwingUtilities.invokeLater(() -> {
            Optional<UnwrapRule> matchOpt = findMatchingRule(request);
            if (matchOpt.isEmpty()) {
                matchedRuleLabel.setText("(none)");
                decodedContentArea.setText("");
                parametersArea.setText("");
                return;
            }

            UnwrapRule rule = matchOpt.get();
            matchedRuleLabel.setText(rule.getName());

            try {
                ContainerExtractor extractor = new ContainerExtractor(
                        rule.isUseNamedParameter(), rule.getParameterName());
                String raw = extractor.extractRawContainer(request);
                CodecChain chain = new CodecChain(rule.getCodecChain());
                String decoded = chain.decode(raw);

                ContentParser parser = ContentParserFactory.create(rule.getParserType());
                parser.parse(decoded);

                decodedContentArea.setText(parser.prettyPrint());
                decodedContentArea.setCaretPosition(0);

                StringBuilder sb = new StringBuilder();
                Map<String, String> values = parser.getAllValues();
                for (Map.Entry<String, String> entry : values.entrySet()) {
                    sb.append(entry.getKey()).append(" = ").append(entry.getValue()).append("\n");
                }
                parametersArea.setText(sb.toString());
                parametersArea.setCaretPosition(0);
            } catch (Exception e) {
                decodedContentArea.setText("Error: " + e.getMessage());
                parametersArea.setText("");
            }
        });
    }
}
