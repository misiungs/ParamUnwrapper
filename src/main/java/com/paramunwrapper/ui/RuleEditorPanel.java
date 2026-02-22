package com.paramunwrapper.ui;

import com.paramunwrapper.model.CodecStepType;
import com.paramunwrapper.model.ParserType;
import com.paramunwrapper.model.UnwrapRule;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * A panel for editing a single {@link UnwrapRule}.
 */
public class RuleEditorPanel extends JPanel {

    private final JTextField nameField;
    private final JCheckBox enabledCheck;
    private final JRadioButton useParamRadio;
    private final JRadioButton useBodyRadio;
    private final JTextField paramNameField;
    private final DefaultListModel<CodecStepType> codecListModel;
    private final JList<CodecStepType> codecList;
    private final JComboBox<ParserType> parserTypeCombo;
    private final JTextArea includeListArea;

    private UnwrapRule currentRule;
    private final Runnable onChangeCallback;

    public RuleEditorPanel(Runnable onChangeCallback) {
        this.onChangeCallback = onChangeCallback;
        setLayout(new BorderLayout(5, 5));
        setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        // --- Rule name and enabled ---
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        topPanel.add(new JLabel("Rule name:"));
        nameField = new JTextField(20);
        topPanel.add(nameField);
        enabledCheck = new JCheckBox("Enabled", true);
        topPanel.add(enabledCheck);
        add(topPanel, BorderLayout.NORTH);

        // --- Centre: container source, codec chain, parser type, include list ---
        JPanel centrePanel = new JPanel();
        centrePanel.setLayout(new BoxLayout(centrePanel, BoxLayout.Y_AXIS));

        // Container source
        JPanel sourcePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        sourcePanel.setBorder(new TitledBorder("Container source"));
        ButtonGroup sourceGroup = new ButtonGroup();
        useParamRadio = new JRadioButton("Burp parameter by name:", true);
        useBodyRadio = new JRadioButton("Whole request body");
        sourceGroup.add(useParamRadio);
        sourceGroup.add(useBodyRadio);
        paramNameField = new JTextField(15);
        sourcePanel.add(useParamRadio);
        sourcePanel.add(paramNameField);
        sourcePanel.add(useBodyRadio);
        useBodyRadio.addActionListener(e -> paramNameField.setEnabled(false));
        useParamRadio.addActionListener(e -> paramNameField.setEnabled(true));
        centrePanel.add(sourcePanel);

        // Codec chain
        JPanel codecPanel = new JPanel(new BorderLayout(3, 3));
        codecPanel.setBorder(new TitledBorder("Codec chain (decode order, top to bottom)"));
        codecListModel = new DefaultListModel<>();
        codecList = new JList<>(codecListModel);
        codecList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        codecList.setVisibleRowCount(4);
        codecPanel.add(new JScrollPane(codecList), BorderLayout.CENTER);

        JPanel codecButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 3, 0));
        JComboBox<CodecStepType> addCodecCombo = new JComboBox<>(CodecStepType.values());
        JButton addCodecBtn = new JButton("Add");
        JButton removeCodecBtn = new JButton("Remove");
        JButton moveUpBtn = new JButton("↑");
        JButton moveDownBtn = new JButton("↓");
        codecButtons.add(addCodecCombo);
        codecButtons.add(addCodecBtn);
        codecButtons.add(removeCodecBtn);
        codecButtons.add(moveUpBtn);
        codecButtons.add(moveDownBtn);
        codecPanel.add(codecButtons, BorderLayout.SOUTH);

        addCodecBtn.addActionListener(e -> {
            CodecStepType selected = (CodecStepType) addCodecCombo.getSelectedItem();
            if (selected != null) {
                codecListModel.addElement(selected);
                notifyChange();
            }
        });
        removeCodecBtn.addActionListener(e -> {
            int idx = codecList.getSelectedIndex();
            if (idx >= 0) {
                codecListModel.remove(idx);
                notifyChange();
            }
        });
        moveUpBtn.addActionListener(e -> {
            int idx = codecList.getSelectedIndex();
            if (idx > 0) {
                CodecStepType item = codecListModel.remove(idx);
                codecListModel.add(idx - 1, item);
                codecList.setSelectedIndex(idx - 1);
                notifyChange();
            }
        });
        moveDownBtn.addActionListener(e -> {
            int idx = codecList.getSelectedIndex();
            if (idx >= 0 && idx < codecListModel.size() - 1) {
                CodecStepType item = codecListModel.remove(idx);
                codecListModel.add(idx + 1, item);
                codecList.setSelectedIndex(idx + 1);
                notifyChange();
            }
        });
        centrePanel.add(codecPanel);

        // Parser type
        JPanel parserPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        parserPanel.setBorder(new TitledBorder("Content type"));
        parserTypeCombo = new JComboBox<>(ParserType.values());
        parserPanel.add(parserTypeCombo);
        centrePanel.add(parserPanel);

        // Include list
        JPanel includePanel = new JPanel(new BorderLayout(3, 3));
        includePanel.setBorder(new TitledBorder(
                "Include list (one identifier per line; leave empty to expose all scalar fields)"
                + " — JSON: /key or /nested/field  |  XML: path or path@attr  |  Form: key name"));
        includeListArea = new JTextArea(4, 30);
        includeListArea.setLineWrap(false);
        includePanel.add(new JScrollPane(includeListArea), BorderLayout.CENTER);
        centrePanel.add(includePanel);

        add(new JScrollPane(centrePanel), BorderLayout.CENTER);

        // Wire save-on-change
        nameField.addActionListener(e -> notifyChange());
        enabledCheck.addActionListener(e -> notifyChange());
        parserTypeCombo.addActionListener(e -> notifyChange());
        includeListArea.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { notifyChange(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { notifyChange(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { notifyChange(); }
        });
    }

    /** Populate editor fields from the given rule. */
    public void loadRule(UnwrapRule rule) {
        this.currentRule = rule;

        nameField.setText(rule.getName());
        enabledCheck.setSelected(rule.isEnabled());

        if (rule.isUseNamedParameter()) {
            useParamRadio.setSelected(true);
            paramNameField.setEnabled(true);
        } else {
            useBodyRadio.setSelected(true);
            paramNameField.setEnabled(false);
        }
        paramNameField.setText(rule.getParameterName() != null ? rule.getParameterName() : "");

        codecListModel.clear();
        if (rule.getCodecChain() != null) {
            for (CodecStepType step : rule.getCodecChain()) {
                codecListModel.addElement(step);
            }
        }

        parserTypeCombo.setSelectedItem(rule.getParserType());

        StringBuilder sb = new StringBuilder();
        if (rule.getIncludeList() != null) {
            for (String item : rule.getIncludeList()) {
                if (!item.isBlank()) sb.append(item).append("\n");
            }
        }
        includeListArea.setText(sb.toString());
    }

    /** Read back values from the editor into the current rule and invoke callback. */
    public void applyToCurrentRule() {
        if (currentRule == null) return;

        currentRule.setName(nameField.getText().trim());
        currentRule.setEnabled(enabledCheck.isSelected());
        currentRule.setUseNamedParameter(useParamRadio.isSelected());
        currentRule.setParameterName(paramNameField.getText().trim());

        List<CodecStepType> chain = new ArrayList<>();
        for (int i = 0; i < codecListModel.size(); i++) {
            chain.add(codecListModel.getElementAt(i));
        }
        currentRule.setCodecChain(chain);

        currentRule.setParserType((ParserType) parserTypeCombo.getSelectedItem());

        List<String> include = new ArrayList<>();
        for (String line : includeListArea.getText().split("\n")) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty()) include.add(trimmed);
        }
        currentRule.setIncludeList(include);
    }

    public UnwrapRule getCurrentRule() {
        return currentRule;
    }

    private void notifyChange() {
        applyToCurrentRule();
        if (onChangeCallback != null) onChangeCallback.run();
    }
}
