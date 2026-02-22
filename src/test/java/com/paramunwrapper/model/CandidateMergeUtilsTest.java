package com.paramunwrapper.model;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CandidateMergeUtilsTest {

    private static CandidateEntry value(String id) {
        return new CandidateEntry(CandidateType.VALUE, id, "v", true);
    }

    private static CandidateEntry key(String id) {
        return new CandidateEntry(CandidateType.KEY, id, "k", true);
    }

    // -----------------------------------------------------------------------

    @Test
    void mergeInto_addsNewEntries() {
        List<CandidateEntry> existing = new ArrayList<>();
        List<CandidateEntry> incoming = List.of(value("/a"), key("/a"));

        CandidateMergeUtils.mergeInto(existing, incoming);

        assertEquals(2, existing.size());
    }

    @Test
    void mergeInto_skipsDuplicateTypeAndIdentifier() {
        List<CandidateEntry> existing = new ArrayList<>(List.of(value("/a")));
        List<CandidateEntry> incoming = List.of(value("/a"), value("/b"));

        CandidateMergeUtils.mergeInto(existing, incoming);

        assertEquals(2, existing.size(), "duplicate /a VALUE must not be added");
        assertEquals("/b", existing.get(1).getIdentifier());
    }

    @Test
    void mergeInto_sameIdentifierDifferentTypeIsNotDuplicate() {
        List<CandidateEntry> existing = new ArrayList<>(List.of(value("/a")));
        List<CandidateEntry> incoming = List.of(key("/a"));

        CandidateMergeUtils.mergeInto(existing, incoming);

        assertEquals(2, existing.size(), "KEY /a is distinct from VALUE /a");
    }

    @Test
    void mergeInto_preservesExistingEntryWhenDuplicate() {
        CandidateEntry original = new CandidateEntry(CandidateType.VALUE, "/a", "original", false);
        List<CandidateEntry> existing = new ArrayList<>(List.of(original));
        List<CandidateEntry> incoming = List.of(
                new CandidateEntry(CandidateType.VALUE, "/a", "updated", true));

        CandidateMergeUtils.mergeInto(existing, incoming);

        // The original entry must not be replaced
        assertSame(original, existing.get(0));
        assertEquals("original", existing.get(0).getCurrentValue());
        assertFalse(existing.get(0).isSelected());
    }

    @Test
    void mergeInto_emptyIncomingLeavesExistingUnchanged() {
        CandidateEntry e = value("/x");
        List<CandidateEntry> existing = new ArrayList<>(List.of(e));

        CandidateMergeUtils.mergeInto(existing, List.of());

        assertEquals(1, existing.size());
        assertSame(e, existing.get(0));
    }

    @Test
    void contains_returnsTrueForMatchingTypeAndIdentifier() {
        List<CandidateEntry> list = List.of(value("/foo"));
        assertTrue(CandidateMergeUtils.contains(list, CandidateType.VALUE, "/foo"));
    }

    @Test
    void contains_returnsFalseForDifferentIdentifier() {
        List<CandidateEntry> list = List.of(value("/foo"));
        assertFalse(CandidateMergeUtils.contains(list, CandidateType.VALUE, "/bar"));
    }

    @Test
    void contains_returnsFalseForDifferentType() {
        List<CandidateEntry> list = List.of(value("/foo"));
        assertFalse(CandidateMergeUtils.contains(list, CandidateType.KEY, "/foo"));
    }

    @Test
    void contains_returnsFalseForEmptyList() {
        assertFalse(CandidateMergeUtils.contains(List.of(), CandidateType.VALUE, "/foo"));
    }

    @Test
    void mergeInto_wholeBodyDeduplicated() {
        CandidateEntry wb = new CandidateEntry(
                CandidateType.WHOLE_BODY, CandidateEntry.WHOLE_BODY_ID, "body", true);
        List<CandidateEntry> existing = new ArrayList<>(List.of(wb));
        List<CandidateEntry> incoming = List.of(
                new CandidateEntry(CandidateType.WHOLE_BODY, CandidateEntry.WHOLE_BODY_ID, "new", true));

        CandidateMergeUtils.mergeInto(existing, incoming);

        assertEquals(1, existing.size());
    }
}
