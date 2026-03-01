package com.paramunwrapper.ui;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import com.paramunwrapper.codec.CodecChain;
import com.paramunwrapper.codec.CodecException;
import com.paramunwrapper.model.CandidateEntry;
import com.paramunwrapper.model.CandidateMergeUtils;
import com.paramunwrapper.model.CandidateType;
import com.paramunwrapper.model.ParserType;
import com.paramunwrapper.model.UnwrapRule;
import com.paramunwrapper.parser.ContentParser;
import com.paramunwrapper.parser.ContentParserFactory;
import com.paramunwrapper.parser.ParseException;
import com.paramunwrapper.persistence.PersistenceManager;
import com.paramunwrapper.scanner.ContainerExtractor;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableCellEditor;
import javax.swing.table.TableCellRenderer;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * The main "Param Unwrapper" Burp suite tab.
 *
 * <p>Layout (horizontal split):
 * <ul>
 *   <li>Left panel  – rules list, rule editor, Parse button, candidate table.</li>
 *   <li>Right panel – large HTTP request editor (editable).</li>
 * </ul>
 *
 * <p>Workflow:
 * <ol>
 *   <li>Load a request via "Send to Param Unwrapper" context menu.</li>
 *   <li>Select a rule on the left, configure it as needed.</li>
 *   <li>Click "Parse" to discover candidate insertion points.</li>
 *   <li>Review / adjust the candidates table (check/uncheck, add/delete entries).</li>
 *   <li>Changes to the insertion points table are auto-persisted immediately.</li>
 * </ol>
 */
public class RulesTab extends JPanel {

    private static final Logger LOG = Logger.getLogger(RulesTab.class.getName());

    /**
     * Maximum number of candidates emitted by a single "Parse" run.
     * Caps UI table size and memory usage; discovery stops silently once the limit is reached.
     */
    private static final int MAX_CANDIDATES = 1024;

    private final List<UnwrapRule> rules;
    private final PersistenceManager persistence;
    private final Runnable onRulesChanged;

    // --- Left panel ---
    private final DefaultListModel<UnwrapRule> listModel;
    private final JList<UnwrapRule> ruleList;
    private final RuleEditorPanel editorPanel;
    private final CandidateTableModel candidateTableModel;

    // --- Right panel ---
    private final HttpRequestEditor requestEditor;

    public RulesTab(List<UnwrapRule> rules,
                    PersistenceManager persistence,
                    Runnable onRulesChanged,
                    UserInterface userInterface) {
        this.rules = rules;
        this.persistence = persistence;
        this.onRulesChanged = onRulesChanged;

        setLayout(new BorderLayout());

        // ------------------------------------------------------------------ right panel
        requestEditor = userInterface.createHttpRequestEditor();

        JPanel rightPanel = new JPanel(new BorderLayout(0, 4));
        rightPanel.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));
        rightPanel.add(requestEditor.uiComponent(), BorderLayout.CENTER);

        // ------------------------------------------------------------------ left panel
        listModel = new DefaultListModel<>();
        for (UnwrapRule rule : rules) {
            listModel.addElement(rule);
        }
        ruleList = new JList<>(listModel);
        ruleList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        ruleList.setCellRenderer(new RuleListCellRenderer());

        JPanel listButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 3, 0));
        JButton addBtn    = new JButton("Add");
        JButton deleteBtn = new JButton("Delete");
        listButtonPanel.add(addBtn);
        listButtonPanel.add(deleteBtn);

        JPanel rulesListPanel = new JPanel(new BorderLayout(2, 2));
        rulesListPanel.setBorder(new TitledBorder("Rules"));
        rulesListPanel.add(new JScrollPane(ruleList), BorderLayout.CENTER);
        rulesListPanel.add(listButtonPanel, BorderLayout.SOUTH);
        rulesListPanel.setPreferredSize(new Dimension(0, 140));

        editorPanel = new RuleEditorPanel(this::onEditorChange);

        // Load list, Parse, Clear buttons
        JButton loadListBtn     = new JButton("Load list");
        JButton parseBtn        = new JButton("Parse");
        JButton clearBtn        = new JButton("Clear");
        loadListBtn.setToolTipText(
                "Resolve the rule's include-list identifiers against the decoded request and merge them into candidates");
        parseBtn.setToolTipText(
                "Decode the request using the selected rule and merge discovered candidate fields");
        clearBtn.setToolTipText(
                "Remove all entries from the candidates table");

        JPanel parseButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        parseButtonPanel.add(loadListBtn);
        parseButtonPanel.add(parseBtn);
        parseButtonPanel.add(clearBtn);

        // Candidate table
        candidateTableModel = new CandidateTableModel();
        JTable candidateTable = new JTable(candidateTableModel);
        candidateTable.setRowHeight(18);
        candidateTable.getColumnModel().getColumn(0).setPreferredWidth(30);
        candidateTable.getColumnModel().getColumn(0).setMaxWidth(40);
        candidateTable.getColumnModel().getColumn(1).setPreferredWidth(80);
        candidateTable.getColumnModel().getColumn(2).setPreferredWidth(180);
        candidateTable.getColumnModel().getColumn(3).setPreferredWidth(150);
        candidateTable.getColumnModel().getColumn(4).setPreferredWidth(60);
        candidateTable.getColumnModel().getColumn(4).setMaxWidth(70);
        candidateTable.getColumnModel().getColumn(1).setCellEditor(
                new DefaultCellEditor(new JComboBox<>(CandidateType.values())));
        candidateTable.getColumnModel().getColumn(4).setCellRenderer(new DeleteButtonRenderer());
        candidateTable.getColumnModel().getColumn(4).setCellEditor(new DeleteButtonEditor());

        JPanel addEntryPanel = buildAddEntryPanel();

        JPanel candidatesPanel = new JPanel(new BorderLayout(2, 2));
        candidatesPanel.setBorder(new TitledBorder("Insertion points"));
        candidatesPanel.add(new JScrollPane(candidateTable), BorderLayout.CENTER);
        candidatesPanel.add(addEntryPanel, BorderLayout.SOUTH);

        // Assemble left panel (vertical scrollable stack)
        JPanel leftStack = new JPanel();
        leftStack.setLayout(new BoxLayout(leftStack, BoxLayout.Y_AXIS));
        leftStack.add(rulesListPanel);
        leftStack.add(editorPanel);
        leftStack.add(parseButtonPanel);
        leftStack.add(candidatesPanel);

        JScrollPane leftScroll = new JScrollPane(leftStack,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);

        // ------------------------------------------------------------------ split
        JSplitPane splitPane = new JSplitPane(
                JSplitPane.HORIZONTAL_SPLIT, leftScroll, rightPanel);
        splitPane.setResizeWeight(0.5);
        // Set the divider to the centre after the component is laid out so the
        // position is calculated relative to the actual window width.
        SwingUtilities.invokeLater(() -> splitPane.setDividerLocation(0.5));
        add(splitPane, BorderLayout.CENTER);

        // ------------------------------------------------------------------ listeners
        ruleList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                UnwrapRule selected = ruleList.getSelectedValue();
                if (selected != null) {
                    editorPanel.loadRule(selected);
                    candidateTableModel.setEntries(
                            selected.getProfile() != null ? selected.getProfile() : List.of());
                }
            }
        });

        addBtn.addActionListener(e -> {
            String typedName = editorPanel.getNameFieldText().trim();
            String name = typedName.isEmpty() ? "Rule " + (rules.size() + 1) : typedName;
            UnwrapRule newRule = new UnwrapRule(name);
            rules.add(newRule);
            listModel.addElement(newRule);
            ruleList.setSelectedValue(newRule, true);
            editorPanel.loadRule(newRule);
            candidateTableModel.setEntries(List.of());
            persistAndNotify();
        });

        deleteBtn.addActionListener(e -> {
            int idx = ruleList.getSelectedIndex();
            if (idx >= 0) {
                rules.remove(idx);
                listModel.remove(idx);
                if (!listModel.isEmpty()) {
                    int newIdx = Math.min(idx, listModel.size() - 1);
                    ruleList.setSelectedIndex(newIdx);
                    editorPanel.loadRule(ruleList.getSelectedValue());
                } else {
                    candidateTableModel.setEntries(List.of());
                }
                persistAndNotify();
            }
        });

        parseBtn.addActionListener(e -> runParse());
        loadListBtn.addActionListener(e -> runLoadList());
        clearBtn.addActionListener(e -> candidateTableModel.clearEntries());

        // Select first rule if present
        if (!listModel.isEmpty()) {
            ruleList.setSelectedIndex(0);
            editorPanel.loadRule(rules.get(0));
            UnwrapRule first = rules.get(0);
            candidateTableModel.setEntries(
                    first.getProfile() != null ? first.getProfile() : List.of());
        }

        // Enable auto-save after initial population
        candidateTableModel.setOnChangeCallback(this::autoSaveProfile);
    }

    // ------------------------------------------------------------------ public API

    /**
     * Load a request into the right-side editor (called from the context menu provider).
     */
    public void sendRequest(HttpRequest request) {
        SwingUtilities.invokeLater(() -> requestEditor.setRequest(request));
    }

    /** Returns a copy of the current rule list. */
    public List<UnwrapRule> getRules() {
        return new ArrayList<>(rules);
    }

    // ------------------------------------------------------------------ private helpers

    private JPanel buildAddEntryPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));

        JComboBox<CandidateType> typeCombo =
                new JComboBox<>(new CandidateType[]{CandidateType.VALUE, CandidateType.KEY});
        JTextField idField = new JTextField(15);
        idField.setToolTipText(
                "JSON: /pointer  |  Form: key name");
        JButton addBtn = new JButton("Add entry");

        addBtn.addActionListener(e -> {
            String id = idField.getText().trim();
            if (id.isEmpty()) return;
            CandidateType type = (CandidateType) typeCombo.getSelectedItem();
            candidateTableModel.addEntry(new CandidateEntry(type, id, "", true));
            idField.setText("");
        });

        panel.add(new JLabel("Type:"));
        panel.add(typeCombo);
        panel.add(new JLabel("ID:"));
        panel.add(idField);
        panel.add(addBtn);
        return panel;
    }

    private void runParse() {
        UnwrapRule rule = ruleList.getSelectedValue();
        if (rule == null) {
            JOptionPane.showMessageDialog(this, "Please select a rule first.",
                    "No rule selected", JOptionPane.WARNING_MESSAGE);
            return;
        }

        if (rule.getParserType() == ParserType.CUSTOM) {
            JOptionPane.showMessageDialog(this,
                    "The Custom content type does not support auto-discovery.\n"
                    + "Add regex patterns to the Include list and use 'Load list' instead.",
                    "Not supported for Custom", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        DecodeResult result = decodeAndParse(rule);
        if (result == null) return; // error already shown

        List<CandidateEntry> discovered = discoverCandidates(result.decoded(), result.parser());
        candidateTableModel.mergeEntries(discovered);
    }

    private void runLoadList() {
        UnwrapRule rule = ruleList.getSelectedValue();
        if (rule == null) {
            JOptionPane.showMessageDialog(this, "Please select a rule first.",
                    "No rule selected", JOptionPane.WARNING_MESSAGE);
            return;
        }

        List<String> includeList = rule.getIncludeList();
        if (includeList == null || includeList.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    "The selected rule has an empty include list.\n"
                    + "Add identifiers in the rule editor to use this feature.",
                    "Include list empty", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        DecodeResult result = decodeAndParse(rule);
        if (result == null) return; // error already shown

        if (rule.getParserType() == ParserType.CUSTOM) {
            List<CandidateEntry> resolved = new ArrayList<>();
            for (String pattern : includeList) {
                try {
                    Pattern compiled = Pattern.compile(pattern);
                    Matcher m = compiled.matcher(result.decoded());
                    if (!m.find()) continue;
                    String captured;
                    try {
                        captured = m.group("value");
                    } catch (IllegalArgumentException ex) {
                        JOptionPane.showMessageDialog(this,
                                "Regex does not contain named capture group (?<value>...): " + pattern,
                                "Invalid regex", JOptionPane.WARNING_MESSAGE);
                        continue;
                    }
                    if (captured == null) continue;
                    String id = "regex:" + pattern;
                    addIfUnderLimit(resolved, new CandidateEntry(CandidateType.VALUE, id, captured, true));
                } catch (PatternSyntaxException ex) {
                    JOptionPane.showMessageDialog(this,
                            "Invalid regex pattern: " + pattern + "\n" + ex.getMessage(),
                            "Invalid regex", JOptionPane.WARNING_MESSAGE);
                }
            }
            candidateTableModel.mergeEntries(resolved);
            return;
        }

        List<CandidateEntry> resolved = new ArrayList<>();
        for (String id : includeList) {
            String val = result.parser().getValue(id);
            if (val == null) continue; // identifier not found in decoded content - skip
            addIfUnderLimit(resolved, new CandidateEntry(CandidateType.VALUE, id, val, true));
            if (result.parser().getKeyIdentifiers().contains(id)) {
                addIfUnderLimit(resolved, new CandidateEntry(CandidateType.KEY, id, val, true));
            }
        }
        candidateTableModel.mergeEntries(resolved);
    }

    /**
     * Shared helper: validate that a request is loaded, decode its container using
     * {@code rule}'s codec chain, and return a {@link DecodeResult} with the decoded
     * string and an already-parsed {@link ContentParser}.
     * Shows an error dialog and returns {@code null} on any failure.
     */
    private DecodeResult decodeAndParse(UnwrapRule rule) {
        HttpRequest request = requestEditor.getRequest();
        if (request == null) {
            JOptionPane.showMessageDialog(this, "No request loaded in the editor.\n"
                    + "Use \"Send to Param Unwrapper\" from the context menu first.",
                    "No request", JOptionPane.WARNING_MESSAGE);
            return null;
        }

        try {
            ContainerExtractor extractor = new ContainerExtractor(
                    rule.isUseNamedParameter(), rule.getParameterName());
            String rawContainer = extractor.extractRawContainer(request);
            if (rawContainer == null || rawContainer.isBlank()) {
                JOptionPane.showMessageDialog(this,
                        "Container not found in the request.\n"
                        + "Check the rule's container source setting.",
                        "Container not found", JOptionPane.WARNING_MESSAGE);
                return null;
            }

            CodecChain chain = new CodecChain(rule.getCodecChain());
            String decoded = chain.decode(rawContainer);

            if (rule.getParserType() == ParserType.CUSTOM) {
                return new DecodeResult(decoded, null);
            }

            ContentParser parser = ContentParserFactory.create(rule.getParserType());
            parser.parse(decoded);
            return new DecodeResult(decoded, parser);

        } catch (CodecException ex) {
            JOptionPane.showMessageDialog(this, "Codec error: " + ex.getMessage(),
                    "Decode failed", JOptionPane.ERROR_MESSAGE);
        } catch (ParseException ex) {
            JOptionPane.showMessageDialog(this, "Parse error: " + ex.getMessage(),
                    "Parse failed", JOptionPane.ERROR_MESSAGE);
        } catch (Exception ex) {
            LOG.log(Level.WARNING, "Unexpected error during decode/parse", ex);
            JOptionPane.showMessageDialog(this, "Unexpected error: " + ex.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
        return null;
    }

    private List<CandidateEntry> discoverCandidates(String decoded, ContentParser parser) {
        List<CandidateEntry> candidates = new ArrayList<>();

        // 1. Whole-body candidate
        addIfUnderLimit(candidates, new CandidateEntry(
                CandidateType.WHOLE_BODY, CandidateEntry.WHOLE_BODY_ID, decoded, true));

        // 2. Value candidates (scalar leaf fields)
        for (String id : parser.getFieldIdentifiers()) {
            String val = parser.getValue(id);
            if (!addIfUnderLimit(candidates, new CandidateEntry(
                    CandidateType.VALUE, id, val != null ? val : "", true))) break;
        }

        // 3. Key candidates (renameable field names)
        for (String id : parser.getKeyIdentifiers()) {
            String val = parser.getValue(id);
            if (!addIfUnderLimit(candidates, new CandidateEntry(
                    CandidateType.KEY, id, val != null ? val : "", true))) break;
        }

        return candidates;
    }

    /**
     * Adds {@code entry} to {@code list} if the {@link #MAX_CANDIDATES} limit has not been reached.
     *
     * @return {@code true} if the entry was added, {@code false} if the limit was already reached
     */
    private static boolean addIfUnderLimit(List<CandidateEntry> list, CandidateEntry entry) {
        if (list.size() >= MAX_CANDIDATES) return false;
        list.add(entry);
        return true;
    }

    private void autoSaveProfile() {
        UnwrapRule rule = ruleList.getSelectedValue();
        if (rule == null) return;
        rule.setProfile(new ArrayList<>(candidateTableModel.getEntries()));
        persistAndNotify();
    }

    private void onEditorChange() {
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

    // ------------------------------------------------------------------ inner classes

    /** Holds the result of decoding and parsing a container for a rule. */
    private record DecodeResult(String decoded, ContentParser parser) {}

    /** Table model for the candidates / profile table. */
    private static class CandidateTableModel extends AbstractTableModel {

        private static final String[] COLUMNS =
                {"✓", "Type", "Identifier", "Current value", "Delete"};
        private static final int COL_SELECTED    = 0;
        private static final int COL_TYPE        = 1;
        private static final int COL_IDENTIFIER  = 2;
        private static final int COL_VALUE       = 3;
        private static final int COL_DELETE      = 4;
        private final List<CandidateEntry> entries = new ArrayList<>();
        private Runnable onChangeCallback;

        void setOnChangeCallback(Runnable callback) {
            this.onChangeCallback = callback;
        }

        void setEntries(List<CandidateEntry> newEntries) {
            entries.clear();
            entries.addAll(newEntries);
            fireTableDataChanged();
        }

        void mergeEntries(List<CandidateEntry> incoming) {
            int sizeBefore = entries.size();
            CandidateMergeUtils.mergeInto(entries, incoming);
            if (entries.size() > sizeBefore) {
                fireTableRowsInserted(sizeBefore, entries.size() - 1);
            }
            notifyCallback();
        }

        void clearEntries() {
            if (entries.isEmpty()) return;
            entries.clear();
            fireTableDataChanged();
            notifyCallback();
        }

        void addEntry(CandidateEntry entry) {
            entries.add(entry);
            fireTableRowsInserted(entries.size() - 1, entries.size() - 1);
            notifyCallback();
        }

        void deleteEntry(int row) {
            if (row >= 0 && row < entries.size()) {
                entries.remove(row);
                fireTableRowsDeleted(row, row);
                notifyCallback();
            }
        }

        List<CandidateEntry> getEntries() {
            return List.copyOf(entries);
        }

        @Override public int getRowCount()    { return entries.size(); }
        @Override public int getColumnCount() { return COLUMNS.length; }
        @Override public String getColumnName(int col) { return COLUMNS[col]; }

        @Override
        public Class<?> getColumnClass(int col) {
            if (col == COL_SELECTED) return Boolean.class;
            if (col == COL_TYPE) return CandidateType.class;
            return String.class;
        }

        @Override
        public boolean isCellEditable(int row, int col) {
            return col == COL_SELECTED || col == COL_TYPE
                    || col == COL_IDENTIFIER || col == COL_DELETE;
        }

        @Override
        public Object getValueAt(int row, int col) {
            CandidateEntry e = entries.get(row);
            return switch (col) {
                case COL_SELECTED   -> e.isSelected();
                case COL_TYPE       -> e.getType() != null ? e.getType() : CandidateType.VALUE;
                case COL_IDENTIFIER -> e.getIdentifier() != null ? e.getIdentifier() : "";
                case COL_VALUE      -> e.getCurrentValue() != null ? e.getCurrentValue() : "";
                case COL_DELETE     -> "Delete";
                default -> "";
            };
        }

        @Override
        public void setValueAt(Object value, int row, int col) {
            CandidateEntry e = entries.get(row);
            if (col == COL_SELECTED) {
                e.setSelected(Boolean.TRUE.equals(value));
                notifyCallback();
            } else if (col == COL_IDENTIFIER) {
                e.setIdentifier(value != null ? value.toString() : "");
                notifyCallback();
            } else if (col == COL_TYPE && value instanceof CandidateType ct) {
                e.setType(ct);
                notifyCallback();
            }
            fireTableCellUpdated(row, col);
        }

        private void notifyCallback() {
            if (onChangeCallback != null) onChangeCallback.run();
        }
    }

    /** Cell renderer for the rule list – shows enabled/disabled state. */
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

    /** Cell renderer that displays a "Delete" button in each row of the candidates table. */
    private static class DeleteButtonRenderer extends JButton implements TableCellRenderer {
        DeleteButtonRenderer() {
            setText("Delete");
            setMargin(new Insets(0, 2, 0, 2));
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean isSelected, boolean hasFocus, int row, int column) {
            return this;
        }
    }

    /** Cell editor that removes the corresponding row when the "Delete" button is clicked. */
    private class DeleteButtonEditor extends AbstractCellEditor implements TableCellEditor {
        private final JButton button;
        private int currentRow = -1;

        DeleteButtonEditor() {
            button = new JButton("Delete");
            button.setMargin(new Insets(0, 2, 0, 2));
            button.addActionListener(e -> {
                fireEditingStopped();
                int rowToDelete = currentRow;
                SwingUtilities.invokeLater(() -> candidateTableModel.deleteEntry(rowToDelete));
            });
        }

        @Override
        public Component getTableCellEditorComponent(JTable table, Object value,
                boolean isSelected, int row, int column) {
            currentRow = row;
            return button;
        }

        @Override
        public Object getCellEditorValue() {
            return "Delete";
        }
    }
}
