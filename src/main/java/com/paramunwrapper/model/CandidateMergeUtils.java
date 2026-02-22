package com.paramunwrapper.model;

import java.util.List;
import java.util.Objects;

/**
 * Utility methods for merging candidate entries into an existing list.
 *
 * <p>A candidate is considered a duplicate when another entry with the same
 * {@link CandidateType type} <em>and</em> the same identifier string already exists.
 * Duplicate detection is case-sensitive.
 */
public final class CandidateMergeUtils {

    private CandidateMergeUtils() {}

    /**
     * Merge {@code incoming} entries into {@code existing}, skipping any entry
     * whose (type, identifier) pair is already present in {@code existing}.
     *
     * <p>The {@code existing} list is modified in place; entries whose key already
     * exists are left completely unchanged (selected flag, edited identifier, etc.).
     *
     * @param existing mutable list that acts as the merge target
     * @param incoming entries to add when not already present
     */
    public static void mergeInto(List<CandidateEntry> existing, List<CandidateEntry> incoming) {
        for (CandidateEntry candidate : incoming) {
            if (!contains(existing, candidate.getType(), candidate.getIdentifier())) {
                existing.add(candidate);
            }
        }
    }

    /**
     * Returns {@code true} if {@code list} already contains an entry with the given
     * {@code type} and {@code identifier}.
     */
    public static boolean contains(List<CandidateEntry> list,
                                   CandidateType type,
                                   String identifier) {
        for (CandidateEntry e : list) {
            if (e.getType() == type && Objects.equals(identifier, e.getIdentifier())) {
                return true;
            }
        }
        return false;
    }
}
