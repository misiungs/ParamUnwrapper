package com.paramunwrapper.parser;

import org.w3c.dom.*;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.*;

/**
 * Parses XML content, exposing text-node values and attributes as field identifiers.
 *
 * <p>Field identifier format:
 * <ul>
 *   <li>Text nodes: dot-separated element path, e.g. {@code root.child}</li>
 *   <li>Attributes: path followed by {@code @attrName}, e.g. {@code root.child@id}</li>
 * </ul>
 */
public class XmlContentParser implements ContentParser {

    private Document document;
    private String originalContent;

    @Override
    public void parse(String content) throws ParseException {
        if (content == null || content.isBlank()) {
            throw new ParseException("XML content is empty");
        }
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            // Disable external entity processing (security hardening)
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setExpandEntityReferences(false);
            factory.setXIncludeAware(false);
            DocumentBuilder builder = factory.newDocumentBuilder();
            this.document = builder.parse(new InputSource(new StringReader(content)));
            this.originalContent = content;
        } catch (Exception e) {
            throw new ParseException("Failed to parse XML: " + e.getMessage(), e);
        }
    }

    @Override
    public List<String> getFieldIdentifiers() {
        List<String> identifiers = new ArrayList<>();
        if (document == null) return identifiers;
        collectIdentifiers(document.getDocumentElement(), "", identifiers);
        return identifiers;
    }

    @Override
    public String getValue(String identifier) {
        if (document == null) return null;
        if (identifier.contains("@")) {
            int atIdx = identifier.lastIndexOf('@');
            String elemPath = identifier.substring(0, atIdx);
            String attrName = identifier.substring(atIdx + 1);
            Element elem = findElement(document.getDocumentElement(), elemPath, 0);
            if (elem == null) return null;
            return elem.hasAttribute(attrName) ? elem.getAttribute(attrName) : null;
        } else {
            Element elem = findElement(document.getDocumentElement(), identifier, 0);
            if (elem == null) return null;
            return getDirectTextContent(elem);
        }
    }

    @Override
    public String withValue(String identifier, String newValue) throws ParseException {
        if (document == null) {
            throw new ParseException("XML content has not been parsed");
        }
        try {
            Document copy = (Document) document.cloneNode(true);
            if (identifier.contains("@")) {
                int atIdx = identifier.lastIndexOf('@');
                String elemPath = identifier.substring(0, atIdx);
                String attrName = identifier.substring(atIdx + 1);
                Element elem = findElement(copy.getDocumentElement(), elemPath, 0);
                if (elem == null) {
                    throw new ParseException("Element not found for: " + identifier);
                }
                elem.setAttribute(attrName, newValue);
            } else {
                Element elem = findElement(copy.getDocumentElement(), identifier, 0);
                if (elem == null) {
                    throw new ParseException("Element not found for: " + identifier);
                }
                setDirectTextContent(elem, newValue);
            }
            return serialise(copy);
        } catch (ParseException e) {
            throw e;
        } catch (Exception e) {
            throw new ParseException("Failed to update XML value: " + e.getMessage(), e);
        }
    }

    @Override
    public String prettyPrint() {
        if (document == null) return "";
        try {
            return serialise(document);
        } catch (Exception e) {
            return originalContent != null ? originalContent : "";
        }
    }

    @Override
    public Map<String, String> getAllValues() {
        Map<String, String> result = new LinkedHashMap<>();
        for (String id : getFieldIdentifiers()) {
            result.put(id, getValue(id));
        }
        return result;
    }

    @Override
    public List<String> getKeyIdentifiers() {
        // XML element/attribute rename is not supported in this implementation.
        return Collections.emptyList();
    }

    @Override
    public String withKeyRenamed(String identifier, String newKey) throws ParseException {
        throw new ParseException("Key rename is not supported for XML content");
    }

    // --- private helpers ---

    private void collectIdentifiers(Element element, String parentPath, List<String> out) {
        String currentPath = parentPath.isEmpty()
                ? element.getTagName()
                : parentPath + "." + element.getTagName();

        // Attributes
        NamedNodeMap attrs = element.getAttributes();
        for (int i = 0; i < attrs.getLength(); i++) {
            Attr attr = (Attr) attrs.item(i);
            out.add(currentPath + "@" + attr.getName());
        }

        // Child elements
        NodeList children = element.getChildNodes();
        boolean hasElementChildren = false;
        for (int i = 0; i < children.getLength(); i++) {
            Node child = children.item(i);
            if (child.getNodeType() == Node.ELEMENT_NODE) {
                hasElementChildren = true;
                collectIdentifiers((Element) child, currentPath, out);
            }
        }

        // Direct text content (only leaf elements)
        if (!hasElementChildren) {
            String text = getDirectTextContent(element);
            if (text != null && !text.isBlank()) {
                out.add(currentPath);
            }
        }
    }

    private Element findElement(Element root, String path, int tokenIndex) {
        if (path == null || path.isEmpty()) return null;
        String[] tokens = path.split("\\.");
        if (tokenIndex >= tokens.length) return null;

        if (!root.getTagName().equals(tokens[tokenIndex])) return null;
        if (tokenIndex == tokens.length - 1) return root;

        NodeList children = root.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node child = children.item(i);
            if (child.getNodeType() == Node.ELEMENT_NODE) {
                Element result = findElement((Element) child, path, tokenIndex + 1);
                if (result != null) return result;
            }
        }
        return null;
    }

    private String getDirectTextContent(Element element) {
        StringBuilder sb = new StringBuilder();
        NodeList children = element.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node child = children.item(i);
            if (child.getNodeType() == Node.TEXT_NODE) {
                sb.append(child.getNodeValue());
            }
        }
        return sb.toString();
    }

    private void setDirectTextContent(Element element, String value) {
        NodeList children = element.getChildNodes();
        for (int i = children.getLength() - 1; i >= 0; i--) {
            Node child = children.item(i);
            if (child.getNodeType() == Node.TEXT_NODE) {
                element.removeChild(child);
            }
        }
        element.appendChild(element.getOwnerDocument().createTextNode(value));
    }

    private String serialise(Document doc) throws Exception {
        TransformerFactory factory = TransformerFactory.newInstance();
        factory.setAttribute(javax.xml.XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(javax.xml.XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
        Transformer transformer = factory.newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
        StringWriter writer = new StringWriter();
        transformer.transform(new DOMSource(doc), new StreamResult(writer));
        return writer.toString();
    }
}
