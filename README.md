# Param Unwrapper

A Burp Suite extension (Montoya API) that enables active scanning of nested or
encoded parameters by providing an interactive **unwrap → discover → scan** workflow.

## Java version

The extension targets **Java 17** (LTS). Burp Suite 2023.x ships an embedded Java 21
runtime, but the Montoya API 2023.12.1 is fully compatible with Java 17. Java 17 is
chosen because it is the minimum LTS version supported by all current Burp Suite
releases and maximises compatibility with end-user environments.

---

## Build

**Prerequisites:** Java 17+, Apache Maven 3.8+

```bash
mvn package -DskipTests
```

The fat JAR is written to:

```
target/param-unwrapper-1.0.0.jar
```

To also run the unit tests:

```bash
mvn verify
```

---

## Install into Burp Suite

1. Open Burp Suite (Pro or Community ≥ 2023.x).
2. Go to **Extensions → Installed → Add**.
3. Extension type: **Java**.
4. Select `target/param-unwrapper-1.0.0.jar`.
5. Click **Next**. The extension loads and adds a **"Param Unwrapper"** tab to the
   Burp Suite window.

---

## Usage workflow

### 1 – Open the tab

Click **Param Unwrapper** in the Burp Suite tab bar.

The tab is split horizontally:

| Left panel | Right panel |
|---|---|
| Rules list, rule editor, Parse button, Candidates table | Large HTTP request editor |

### 2 – Load a request

Two ways to populate the right-side request editor:

* **Context menu** – right-click any request in Proxy history, Repeater, Logger, etc.
  and choose **"Send to Param Unwrapper"**.
* **Paste** – expand the "Paste raw request" area at the bottom of the right panel,
  paste a complete raw HTTP request, and click **Load**.

### 3 – Configure a rule

1. Click **Add** on the left panel to create a new rule.
2. Set a descriptive **name** and leave **Enabled** checked.

#### Container source

| Option | Description |
|--------|-------------|
| Burp parameter by name | A specific query/body/cookie parameter (e.g. `data`) |
| Whole request body | The entire raw request body |

#### Codec chain

Add decoding steps (applied top-to-bottom on decode, reversed on re-encode):

| Step | Decode | Re-encode (automatic, reversed) |
|------|--------|----------------------------------|
| `Base64 Decode` | Base64-decode | Base64-encode |
| `URL Decode` | URL-decode | URL-encode |

#### Content type

| Type | Field identifiers |
|------|-------------------|
| **JSON** | JSON Pointer (e.g. `/key`, `/nested/field`) |
| **XML** | Dot-separated path (e.g. `root.child`), or `root.child@attr` for attributes |
| **x-www-form-urlencoded** | Key name (e.g. `username`) |

### 4 – Parse and build a profile

With a request loaded and a rule selected, click **Parse**.

The extension:
1. Extracts the container (parameter value or body).
2. Decodes it via the codec chain.
3. Parses the decoded content.
4. Populates the **Candidates (profile)** table with up to 1,024 entries:

| Candidate type | Description |
|---|---|
| **Value** | A scalar leaf field; payload replaces its value |
| **Key rename** | An object/form key; payload becomes the new key name |
| **Whole body** | The entire decoded container; payload replaces it entirely |

Review the table:
* Use the **✓ checkbox** to include/exclude individual candidates.
* Edit an **Identifier** cell directly to adjust a JSON Pointer or form key.
* Use **Add entry** to add a candidate manually.

Click **Save Profile** to persist the selection. The scanner will use this profile
for every subsequent active-scan request that matches the rule.

### 5 – Active scanning

After saving a profile, right-click a matching request and run an active scan.
The scanner creates one insertion point per selected profile entry, applies the
mutation, re-encodes, and sends the modified request.

---

## Example

Request parameter:

```
data=eyJrZXkiOiJvbmUiLCJrZXkyIjoidHdvIn0=
```

Decoded Base64 value:

```json
{"key":"one","key2":"two"}
```

**Rule configuration:**

| Setting | Value |
|---------|-------|
| Container source | Burp parameter by name: `data` |
| Codec chain | `Base64 Decode` |
| Content type | JSON |

After clicking **Parse**, the Candidates table shows:

| ✓ | Type | Identifier | Current value |
|---|------|------------|---------------|
| ✓ | Whole body | `__body__` | `{"key":"one","key2":"two"}` |
| ✓ | Value | `/key` | `one` |
| ✓ | Value | `/key2` | `two` |
| ✓ | Key rename | `/key` | `one` |
| ✓ | Key rename | `/key2` | `two` |

After **Save Profile**, Burp Scanner creates five insertion points, each re-encoding
the modified JSON back to Base64 and updating the `data` parameter.

---

## Message editor tab

When a request is displayed in an HTTP editor (Repeater, Proxy history, etc.) a
**"Param Unwrapper"** tab will appear automatically if a rule matches. The tab shows:

- Which rule matched
- Pretty-printed decoded content
- All detected inner parameters and their current values

---

## Architecture

```
com.paramunwrapper
├── ParamUnwrapperExtension     # BurpExtension entry point
├── model
│   ├── UnwrapRule              # Rule configuration model (includes saved profile)
│   ├── CandidateEntry          # A single profile entry (type + identifier + selected)
│   ├── CandidateType           # Enum: VALUE, KEY, WHOLE_BODY
│   ├── CodecStepType           # Enum: URL_DECODE, URL_ENCODE, BASE64_DECODE, BASE64_ENCODE
│   └── ParserType              # Enum: JSON, XML, FORM
├── codec
│   ├── Codec                   # Interface
│   ├── CodecChain              # Ordered chain (decode / encode)
│   ├── Base64Codec
│   └── UrlCodec
├── parser
│   ├── ContentParser           # Interface (includes getKeyIdentifiers / withKeyRenamed)
│   ├── ContentParserFactory
│   ├── JsonContentParser       # JSON Pointer-based; supports key rename
│   ├── XmlContentParser        # Simple dot-path + @attr (value only)
│   └── FormContentParser       # URL-encoded form fields; supports key rename
├── scanner
│   ├── UnwrapInsertionPointProvider   # Profile-driven; falls back to auto-discovery
│   ├── UnwrapInsertionPoint           # VALUE / KEY / WHOLE_BODY insertion point
│   └── ContainerExtractor
├── editor
│   ├── UnwrapEditorProvider
│   └── UnwrapEditorTab
├── persistence
│   └── PersistenceManager      # Montoya persistence API
└── ui
    ├── RulesTab                        # Suite tab: split layout with request editor
    ├── RuleEditorPanel                 # Rule editor form
    └── ParamUnwrapperContextMenuProvider  # "Send to Param Unwrapper" context menu
```

---

## License

GPL-3.0 — see [LICENSE](LICENSE).
