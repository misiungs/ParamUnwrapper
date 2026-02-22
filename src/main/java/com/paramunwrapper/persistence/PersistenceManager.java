package com.paramunwrapper.persistence;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.paramunwrapper.model.UnwrapRule;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Handles saving and loading {@link UnwrapRule} objects using the Montoya persistence API.
 *
 * <p>Rules are serialised as a JSON array and stored under a single extension-data key.
 */
public class PersistenceManager {

    private static final Logger LOG = Logger.getLogger(PersistenceManager.class.getName());
    private static final String RULES_KEY = "unwrapRules";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final MontoyaApi api;

    public PersistenceManager(MontoyaApi api) {
        this.api = api;
    }

    /**
     * Save the given list of rules to Burp's persistent storage.
     */
    public void saveRules(List<UnwrapRule> rules) {
        try {
            String json = MAPPER.writeValueAsString(rules);
            PersistedObject extensionData = api.persistence().extensionData();
            extensionData.setString(RULES_KEY, json);
        } catch (Exception e) {
            LOG.log(Level.WARNING, "Failed to save unwrap rules", e);
        }
    }

    /**
     * Load rules from Burp's persistent storage.
     * Returns an empty list if no rules have been saved or if deserialisation fails.
     */
    public List<UnwrapRule> loadRules() {
        try {
            PersistedObject extensionData = api.persistence().extensionData();
            String json = extensionData.getString(RULES_KEY);
            if (json == null || json.isBlank()) {
                return new ArrayList<>();
            }
            return MAPPER.readValue(json, new TypeReference<List<UnwrapRule>>() {});
        } catch (Exception e) {
            LOG.log(Level.WARNING, "Failed to load unwrap rules; starting with empty list", e);
            return new ArrayList<>();
        }
    }
}
