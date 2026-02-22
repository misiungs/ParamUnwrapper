# Param Unwrapper

A Burp Suite extension (Montoya API) that enables active scanning of nested or
encoded parameters by decoding a user-configured container, exposing its inner
fields as scanner insertion points, and re-encoding payloads back into the container.

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

## Configuration

Open the **Param Unwrapper** suite tab.

### Creating a rule

1. Click **Add** to create a new rule.
2. Give it a descriptive **name**.
3. Tick **Enabled** to activate it.

### Container source

Choose whether the container to decode is:

- **Burp parameter by name** — enter the query/body/cookie parameter name (e.g. `data`).
- **Whole request body** — use the entire raw request body.

### Codec chain

Add codec steps in the order they should be applied during *decoding*:

| Step | Decode | Encode (inverse) |
|------|--------|-----------------|
| `Base64 Decode` | Base64-decode | Base64-encode |
| `URL Decode` | URL-decode | URL-encode |

Encoding reverses the chain automatically (last step first).

### Content type

Select how the decoded content should be parsed:

| Type | Field identifiers |
|------|-------------------|
| **JSON** | JSON Pointer (e.g. `/key`, `/nested/field`) |
| **XML** | Dot-separated path (e.g. `root.child`), or `root.child@attr` for attributes |
| **x-www-form-urlencoded** | Key name (e.g. `username`) |

### Include list

By default all discovered scalar leaf fields are exposed as insertion points.
To restrict to specific fields, enter one identifier per line in the **Include list**.

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
| Include list | *(empty — expose all)* |

Burp Scanner will now create two insertion points:

| Insertion point | Current value |
|-----------------|---------------|
| `My Rule → /key` | `one` |
| `My Rule → /key2` | `two` |

When the scanner injects a payload (e.g. `"><script>`) into `/key`, the extension:

1. Base64-decodes `data` → `{"key":"one","key2":"two"}`
2. Replaces `/key` → `{"key":"\"><script>","key2":"two"}`
3. Base64-encodes the result
4. Sends the request with the modified `data` parameter.

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
│   ├── UnwrapRule              # Rule configuration model
│   ├── CodecStepType           # Enum: URL_DECODE, URL_ENCODE, BASE64_DECODE, BASE64_ENCODE
│   └── ParserType              # Enum: JSON, XML, FORM
├── codec
│   ├── Codec                   # Interface
│   ├── CodecChain              # Ordered chain (decode / encode)
│   ├── Base64Codec
│   └── UrlCodec
├── parser
│   ├── ContentParser           # Interface
│   ├── ContentParserFactory
│   ├── JsonContentParser       # JSON Pointer-based
│   ├── XmlContentParser        # Simple dot-path + @attr
│   └── FormContentParser       # URL-encoded form fields
├── scanner
│   ├── UnwrapInsertionPointProvider
│   ├── UnwrapInsertionPoint
│   └── ContainerExtractor
├── editor
│   ├── UnwrapEditorProvider
│   └── UnwrapEditorTab
├── persistence
│   └── PersistenceManager      # Montoya persistence API
└── ui
    ├── RulesTab                # Burp suite tab
    └── RuleEditorPanel         # Rule editor form
```

---

## License

GPL-3.0 — see [LICENSE](LICENSE).
