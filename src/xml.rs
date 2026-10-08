//! Enough XML for task files, read into a tree: elements with their
//! attributes, text and children; the five predefined entities and
//! character references decoded, CDATA sections as text; the declaration,
//! processing instructions, comments and the document type skipped.
//! Namespace prefixes are dropped from names. Malformed markup is reported
//! and read as well as it can be: an unclosed element closes at its
//! parent's end, a stray end tag is skipped, elements nested deeper than
//! [`MAX_DEPTH`] are read as empty.

/// The deepest nesting read: task files nest five levels.
const MAX_DEPTH: usize = 64;

/// An element: its name (without prefix), attributes, text (its own
/// character data, joined and trimmed) and child elements.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Element {
    /// The name, namespace prefix dropped.
    pub name: String,
    /// The attributes, names without prefix, values decoded.
    pub attributes: Vec<(String, String)>,
    /// Its own character data, trimmed.
    pub text: String,
    /// Its child elements, in order.
    pub children: Vec<Element>,
}

impl Element {
    /// The first child named `name`.
    #[must_use]
    pub fn child(&self, name: &str) -> Option<&Element> {
        self.children.iter().find(|c| c.name == name)
    }

    /// The text of the first child named `name`, if not empty.
    #[must_use]
    pub fn child_text(&self, name: &str) -> Option<&str> {
        self.child(name)
            .map(|c| c.text.as_str())
            .filter(|t| !t.is_empty())
    }

    /// An attribute's value.
    #[must_use]
    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// The document's root element (`None` when there is none) and the damage
/// met, each with its byte offset into the text.
#[must_use]
pub fn parse(text: &str) -> (Option<Element>, Vec<String>) {
    let mut parser = Parser {
        text,
        open: vec![Element::default()],
        deep: 0,
        problems: Vec::new(),
    };
    let mut at = 0;
    while at < text.len() {
        let rest = &text[at..];
        if rest.starts_with('<') {
            at = parser.markup(at);
        } else {
            let end = rest.find('<').map_or(text.len(), |found| at + found);
            let decoded = decode(&text[at..end], at, &mut parser.problems);
            parser.push_text(&decoded);
            at = end;
        }
    }
    let Parser {
        mut open,
        mut problems,
        ..
    } = parser;
    while open.len() > 1 {
        let element = open.pop().unwrap_or_default();
        problems.push(format!("<{}> never closed", element.name));
        close_into(&mut open, element);
    }
    let mut roots = open.pop().unwrap_or_default().children;
    if roots.len() > 1 {
        problems.push(format!("{} root elements, the first read", roots.len()));
    }
    let root = (!roots.is_empty()).then(|| roots.swap_remove(0));
    (root, problems)
}

/// The document being read.
struct Parser<'a> {
    text: &'a str,
    /// The elements open, innermost last; the first holds the roots.
    open: Vec<Element>,
    /// How many elements deeper than [`MAX_DEPTH`] are open, skipped.
    deep: usize,
    problems: Vec<String>,
}

impl Parser<'_> {
    /// The markup at `at` (a `<`), applied; where the next token starts.
    fn markup(&mut self, at: usize) -> usize {
        let text = self.text;
        let rest = &text[at..];
        if rest.starts_with("<?") {
            self.skip_past(at, "?>", "processing instruction")
        } else if rest.starts_with("<!--") {
            self.skip_past(at, "-->", "comment")
        } else if let Some(body) = rest.strip_prefix("<![CDATA[") {
            let end = body.find("]]>").unwrap_or(body.len());
            self.push_text(&body[..end]);
            self.skip_past(at, "]]>", "CDATA section")
        } else if rest.starts_with("<!") {
            tag_end(rest, true)
                .map_or_else(|| self.cut_short(at, "declaration"), |end| at + end + 1)
        } else if let Some(name) = rest.strip_prefix("</") {
            let Some(end) = name.find('>') else {
                return self.cut_short(at, "end tag");
            };
            self.end_tag(local(name[..end].trim()), at);
            at + 2 + end + 1
        } else if rest[1..].starts_with(|c: char| c.is_alphabetic() || c == '_' || c == ':') {
            let Some(end) = tag_end(&rest[1..], false) else {
                return self.cut_short(at, "tag");
            };
            let (element, empty) = start_tag(&rest[1..=end], at, &mut self.problems);
            self.start(element, empty, at);
            at + 1 + end + 1
        } else {
            self.problems.push(format!(
                "offset {at}: a '<' that starts no tag, read as text"
            ));
            self.push_text("<");
            at + 1
        }
    }

    /// An element starts: open it, add it when empty, or skip it when
    /// nested too deep.
    fn start(&mut self, element: Element, empty: bool, at: usize) {
        if self.deep > 0 || self.open.len() > MAX_DEPTH {
            if self.deep == 0 {
                self.problems.push(format!(
                    "offset {at}: nested deeper than {MAX_DEPTH}, skipped"
                ));
            }
            self.deep += usize::from(!empty);
        } else if empty {
            close_into(&mut self.open, element);
        } else {
            self.open.push(element);
        }
    }

    /// `</name>`: closes the innermost open element of that name, and any
    /// left open inside it (reported); a stray end tag is skipped.
    fn end_tag(&mut self, name: &str, at: usize) {
        if self.deep > 0 {
            self.deep -= 1;
            return;
        }
        let Some(index) = self.open.iter().skip(1).rposition(|e| e.name == name) else {
            self.problems
                .push(format!("offset {at}: </{name}> closes nothing"));
            return;
        };
        while self.open.len() > index + 2 {
            let element = self.open.pop().unwrap_or_default();
            self.problems
                .push(format!("offset {at}: <{}> never closed", element.name));
            close_into(&mut self.open, element);
        }
        let element = self.open.pop().unwrap_or_default();
        close_into(&mut self.open, element);
    }

    /// Moves past the next `end` from `at`, or to the end (reported).
    fn skip_past(&mut self, at: usize, end: &str, what: &str) -> usize {
        match self.text[at..].find(end) {
            Some(found) => at + found + end.len(),
            None => self.cut_short(at, what),
        }
    }

    /// Reports markup the document ends inside; the document's end.
    fn cut_short(&mut self, at: usize, what: &str) -> usize {
        self.problems
            .push(format!("offset {at}: unterminated {what}"));
        self.text.len()
    }

    fn push_text(&mut self, text: &str) {
        if self.deep > 0 {
            return;
        }
        if let Some(element) = self.open.last_mut() {
            element.text.push_str(text);
        }
    }
}

/// The inside of a start tag (`name attr="v" …` or with a trailing `/`):
/// the element and whether it is empty.
fn start_tag(tag: &str, at: usize, problems: &mut Vec<String>) -> (Element, bool) {
    let empty = tag.trim_end().ends_with('/');
    let tag = tag.trim_end().trim_end_matches('/');
    let name_len = tag.find(char::is_whitespace).unwrap_or(tag.len());
    let mut element = Element {
        name: local(&tag[..name_len]).to_owned(),
        ..Element::default()
    };
    let mut rest = tag[name_len..].trim_start();
    while !rest.is_empty() {
        let Some(equals) = rest.find('=') else {
            problems.push(format!("offset {at}: an attribute without a value"));
            break;
        };
        let name = rest[..equals].trim();
        let value = rest[equals + 1..].trim_start();
        let Some(quote) = value.chars().next().filter(|c| *c == '"' || *c == '\'') else {
            problems.push(format!("offset {at}: an unquoted attribute value"));
            break;
        };
        let Some(close) = value[1..].find(quote) else {
            problems.push(format!("offset {at}: an unterminated attribute value"));
            break;
        };
        let decoded = decode(&value[1..=close], at, problems);
        element.attributes.push((local(name).to_owned(), decoded));
        rest = value[close + 2..].trim_start();
    }
    (element, empty)
}

/// Moves a finished element into its parent, its text trimmed.
fn close_into(open: &mut [Element], mut element: Element) {
    let text = &mut element.text;
    let leading = text.len() - text.trim_start().len();
    text.truncate(text.trim_end().len());
    text.drain(..leading.min(text.len()));
    if let Some(parent) = open.last_mut() {
        parent.children.push(element);
    }
}

/// A name without its namespace prefix.
fn local(name: &str) -> &str {
    name.rsplit_once(':').map_or(name, |(_, local)| local)
}

/// Where the `>` ending a tag or declaration is: the first outside quotes
/// and, with `brackets`, outside square brackets.
fn tag_end(text: &str, brackets: bool) -> Option<usize> {
    let mut depth = 0usize;
    let mut quote = None;
    for (offset, byte) in text.bytes().enumerate() {
        if let Some(open) = quote {
            if byte == open {
                quote = None;
            }
            continue;
        }
        match byte {
            b'"' | b'\'' => quote = Some(byte),
            b'[' if brackets => depth += 1,
            b']' if brackets => depth = depth.saturating_sub(1),
            b'>' if depth == 0 => return Some(offset),
            _ => {}
        }
    }
    None
}

/// The longest entity worth looking for a `;` in: `&#x10FFFF;` and a bit.
const MAX_ENTITY_LEN: usize = 12;

/// `raw` with `&lt;` `&gt;` `&amp;` `&quot;` `&apos;` and `&#…;` decoded;
/// unknown entities stay as written (reported).
fn decode(raw: &str, at: usize, problems: &mut Vec<String>) -> String {
    let mut text = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(amp) = rest.find('&') {
        text.push_str(&rest[..amp]);
        rest = &rest[amp..];
        let decoded = rest
            .bytes()
            .take(MAX_ENTITY_LEN)
            .position(|byte| byte == b';')
            .and_then(|semicolon| Some((semicolon, entity(&rest[1..semicolon])?)));
        let Some((semicolon, c)) = decoded else {
            problems.push(format!("offset {at}: an unknown entity, kept as written"));
            text.push('&');
            rest = &rest[1..];
            continue;
        };
        text.push(c);
        rest = &rest[semicolon + 1..];
    }
    text.push_str(rest);
    text
}

/// The character an entity name (between `&` and `;`) stands for.
fn entity(name: &str) -> Option<char> {
    match name {
        "lt" => Some('<'),
        "gt" => Some('>'),
        "amp" => Some('&'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        _ => {
            let number = name.strip_prefix('#')?;
            let (digits, radix) = match number.strip_prefix(['x', 'X']) {
                Some(hex) => (hex, 16),
                None => (number, 10),
            };
            let code = u32::from_str_radix(digits, radix).ok()?;
            Some(char::from_u32(code).unwrap_or(char::REPLACEMENT_CHARACTER))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elements_attributes_and_text() {
        let (root, problems) = parse(
            r#"<?xml version="1.0" encoding="UTF-16"?><!-- c --><t:Task version="1.2" xmlns:t="x"><A Context='Author'> a &amp; b <![CDATA[<c>]]></A><B/></t:Task>"#,
        );
        assert_eq!(problems, Vec::<String>::new());
        let root = root.unwrap();
        assert_eq!(root.name, "Task");
        assert_eq!(root.attribute("version"), Some("1.2"));
        assert_eq!(root.child_text("A"), Some("a & b <c>"));
        assert_eq!(
            root.child("A").unwrap().attribute("Context"),
            Some("Author")
        );
        assert_eq!(root.children.len(), 2);
        assert_eq!(root.child_text("B"), None);
    }

    #[test]
    fn damage_is_reported() {
        let (root, problems) = parse("<a><b>x</a></c><d");
        let root = root.unwrap();
        assert_eq!(root.child_text("b"), Some("x"));
        assert_eq!(problems.len(), 3, "{problems:?}");
        assert_eq!(parse("").0, None);
        assert_eq!(parse("<a x=1>").1.len(), 2);
        let deep = format!("<a>{}x{}</a>", "<b>".repeat(100), "</b>".repeat(100));
        let (root, problems) = parse(&deep);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(root.unwrap().children.len() == 1);
    }
}
