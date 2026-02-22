package com.paramunwrapper.ui;

import burp.api.montoya.ui.UserInterface;
import com.paramunwrapper.model.UnwrapRule;
import com.paramunwrapper.persistence.PersistenceManager;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * The main Burp suite tab that lists all {@link UnwrapRule}s and allows the user
 * to create, delete, and configure them.
 */
public class RulesTab extends JPanel {

    private final List<UnwrapRule> rules;
    private final PersistenceManager persistence;
    private final Runnable onRulesChanged;

    private final DefaultListModel<UnwrapRule> listModel;
    private final JList<UnwrapRule> ruleList;
    private final RuleEditorPanel editorPanel;

    public RulesTab(List<UnwrapRule> rules,
                    PersistenceManager persistence,
                    Runnable onRulesChanged,
                    UserInterface userInterface) {
        this.rules = rules;
        this.persistence = persistence;
        this.onRulesChanged = onRulesChanged;

        setLayout(new BorderLayout(5, 5));
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        // Left: rule list + buttons
        JPanel leftPanel = new JPanel(new BorderLayout(3, 3));
        leftPanel.setPreferredSize(new Dimension(180, 0));

        listModel = new DefaultListModel<>();
        for (UnwrapRule rule : rules) {
            listModel.addElement(rule);
        }
        ruleList = new JList<>(listModel);
        ruleList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        ruleList.setCellRenderer(new RuleListCellRenderer());
        leftPanel.add(new JScrollPane(ruleList), BorderLayout.CENTER);

        JPanel listButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 3, 0));
        JButton addBtn = new JButton("Add");
        JButton deleteBtn = new JButton("Delete");
        listButtons.add(addBtn);
        listButtons.add(deleteBtn);
        leftPanel.add(listButtons, BorderLayout.SOUTH);

        add(leftPanel, BorderLayout.WEST);

        // Right: rule editor
        editorPanel = new RuleEditorPanel(this::onEditorChange);
        add(editorPanel, BorderLayout.CENTER);

        // Wire list selection
        ruleList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                UnwrapRule selected = ruleList.getSelectedValue();
                if (selected != null) {
                    editorPanel.loadRule(selected);
                }
            }
        });

        // Add button
        addBtn.addActionListener(e -> {
            UnwrapRule newRule = new UnwrapRule("Rule " + (rules.size() + 1));
            rules.add(newRule);
            listModel.addElement(newRule);
            ruleList.setSelectedValue(newRule, true);
            editorPanel.loadRule(newRule);
            persistAndNotify();
        });

        // Delete button
        deleteBtn.addActionListener(e -> {
            int idx = ruleList.getSelectedIndex();
            if (idx >= 0) {
                rules.remove(idx);
                listModel.remove(idx);
                if (!listModel.isEmpty()) {
                    int newIdx = Math.min(idx, listModel.size() - 1);
                    ruleList.setSelectedIndex(newIdx);
                    editorPanel.loadRule(ruleList.getSelectedValue());
                }
                persistAndNotify();
            }
        });

        // Select first rule if present
        if (!listModel.isEmpty()) {
            ruleList.setSelectedIndex(0);
            editorPanel.loadRule(rules.get(0));
        }
    }

    private void onEditorChange() {
        // Refresh the list display (rule name may have changed)
        int idx = ruleList.getSelectedIndex();
        if (idx >= 0) {
            listModel.set(idx, rules.get(idx));
        }
        persistAndNotify();
    }

    private void persistAndNotify() {
        persistence.saveRules(rules);
        if (onRulesChanged != null) onRulesChanged.run();
    }

    /** Returns a copy of the current rule list (for use by the insertion point provider). */
    public List<UnwrapRule> getRules() {
        return new ArrayList<>(rules);
    }

    // --- Cell renderer ---

    private static class RuleListCellRenderer extends DefaultListCellRenderer {
        @Override
        public Component getListCellRendererComponent(JList<?> list, Object value,
                                                      int index, boolean isSelected,
                                                      boolean cellHasFocus) {
            super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
            if (value instanceof UnwrapRule rule) {
                setText((rule.isEnabled() ? "✓ " : "✗ ") + rule.getName());
                setForeground(rule.isEnabled() ? list.getForeground() : Color.GRAY);
            }
            return this;
        }
    }
}
