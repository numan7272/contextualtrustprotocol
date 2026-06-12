//! GBNF grammar asset + a self-contained acceptor used to *prove* the
//! grammar excludes prose.
//!
//! The same `verdict.gbnf` shipped to llama.cpp is embedded here. The
//! acceptor parses that file and decides language membership for the GBNF
//! constructs the grammar uses (string literals, character classes,
//! alternation, sequencing, `*`/`+`/`?` repetition, grouping, rule refs).
//!
//! This is not llama.cpp's grammar engine, but membership for these
//! constructs is standard and unambiguous, so "string S is not in the
//! language" is a real, testable property of the deployed asset — exactly
//! what constrains the decoder at inference time. The acceptor is matched
//! as an NFA over input positions, so backtracking and repetition are
//! handled without exponential blowup.

use std::collections::{BTreeSet, HashMap};

/// The GBNF grammar enforced on the guard model's output.
// SECURITY: the deployed grammar IS the output-channel boundary. It is the
// same file fed to the decoder (see inference.rs) and to the acceptor below
// that proves prose is not in the language. Editing it widens what the guard
// can physically say — treat changes as security-relevant.
pub const VERDICT_GBNF: &str = include_str!("../grammar/verdict.gbnf");

#[derive(Debug, Clone)]
enum Node {
    Lit(Vec<char>),
    Class {
        ranges: Vec<(char, char)>,
        negated: bool,
    },
    Ref(String),
    Seq(Vec<Node>),
    Alt(Vec<Node>),
    Rep {
        node: Box<Node>,
        min: usize,
        max: Option<usize>,
    },
}

#[derive(Debug, Clone)]
pub struct Grammar {
    rules: HashMap<String, Node>,
    root: String,
}

impl Grammar {
    /// Parse a GBNF source into an acceptor. Returns a description of the
    /// first syntax problem found.
    pub fn parse(src: &str) -> Result<Grammar, String> {
        let mut rules = HashMap::new();
        for (lineno, raw) in src.lines().enumerate() {
            let line = strip_comment(raw).trim();
            if line.is_empty() {
                continue;
            }
            let (name, body) = line
                .split_once("::=")
                .ok_or_else(|| format!("line {}: missing '::='", lineno + 1))?;
            let name = name.trim().to_string();
            let mut p = ExprParser::new(body.trim());
            let node = p
                .parse_alt()
                .map_err(|e| format!("line {}: {e}", lineno + 1))?;
            p.expect_end()
                .map_err(|e| format!("line {}: {e}", lineno + 1))?;
            rules.insert(name, node);
        }
        if !rules.contains_key("root") {
            return Err("grammar has no 'root' rule".to_string());
        }
        Ok(Grammar {
            rules,
            root: "root".to_string(),
        })
    }

    /// True iff `input` is a complete sentence in the language: the root
    /// matches and consumes every character.
    pub fn accepts(&self, input: &str) -> bool {
        let chars: Vec<char> = input.chars().collect();
        let root = &self.rules[&self.root];
        self.matches(root, &chars, 0).contains(&chars.len())
    }

    /// Set of end positions reachable by matching `node` starting at `pos`.
    fn matches(&self, node: &Node, chars: &[char], pos: usize) -> BTreeSet<usize> {
        let mut out = BTreeSet::new();
        match node {
            Node::Lit(lit) => {
                if pos + lit.len() <= chars.len() && chars[pos..pos + lit.len()] == lit[..] {
                    out.insert(pos + lit.len());
                }
            }
            Node::Class { ranges, negated } => {
                if let Some(&c) = chars.get(pos) {
                    let hit = ranges.iter().any(|&(a, b)| a <= c && c <= b);
                    if hit != *negated {
                        out.insert(pos + 1);
                    }
                }
            }
            Node::Ref(name) => {
                if let Some(rule) = self.rules.get(name) {
                    out.extend(self.matches(rule, chars, pos));
                }
            }
            Node::Seq(items) => {
                let mut frontier = BTreeSet::from([pos]);
                for item in items {
                    let mut next = BTreeSet::new();
                    for &p in &frontier {
                        next.extend(self.matches(item, chars, p));
                    }
                    if next.is_empty() {
                        return BTreeSet::new();
                    }
                    frontier = next;
                }
                out = frontier;
            }
            Node::Alt(branches) => {
                for b in branches {
                    out.extend(self.matches(b, chars, pos));
                }
            }
            Node::Rep { node, min, max } => {
                let cap = max.unwrap_or(chars.len() + 1);
                let mut current = BTreeSet::from([pos]);
                let mut count = 0;
                if *min == 0 {
                    out.insert(pos);
                }
                while count < cap && !current.is_empty() {
                    let mut next = BTreeSet::new();
                    for &p in &current {
                        next.extend(self.matches(node, chars, p));
                    }
                    count += 1;
                    if count >= *min {
                        out.extend(&next);
                    }
                    current = next;
                }
            }
        }
        out
    }
}

fn strip_comment(line: &str) -> &str {
    match line.find('#') {
        Some(i) => &line[..i],
        None => line,
    }
}

struct ExprParser {
    chars: Vec<char>,
    pos: usize,
}

impl ExprParser {
    fn new(s: &str) -> Self {
        ExprParser {
            chars: s.chars().collect(),
            pos: 0,
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(' ') | Some('\t')) {
            self.pos += 1;
        }
    }

    fn expect_end(&mut self) -> Result<(), String> {
        self.skip_ws();
        match self.peek() {
            None => Ok(()),
            Some(c) => Err(format!("unexpected trailing '{c}'")),
        }
    }

    fn parse_alt(&mut self) -> Result<Node, String> {
        let mut branches = vec![self.parse_seq()?];
        loop {
            self.skip_ws();
            if self.peek() == Some('|') {
                self.pos += 1;
                branches.push(self.parse_seq()?);
            } else {
                break;
            }
        }
        Ok(if branches.len() == 1 {
            branches.remove(0)
        } else {
            Node::Alt(branches)
        })
    }

    fn parse_seq(&mut self) -> Result<Node, String> {
        let mut items = Vec::new();
        loop {
            self.skip_ws();
            match self.peek() {
                None | Some('|') | Some(')') => break,
                _ => items.push(self.parse_term()?),
            }
        }
        if items.is_empty() {
            return Err("empty sequence".to_string());
        }
        Ok(if items.len() == 1 {
            items.remove(0)
        } else {
            Node::Seq(items)
        })
    }

    fn parse_term(&mut self) -> Result<Node, String> {
        let factor = self.parse_factor()?;
        match self.peek() {
            Some('*') => {
                self.pos += 1;
                Ok(Node::Rep {
                    node: Box::new(factor),
                    min: 0,
                    max: None,
                })
            }
            Some('+') => {
                self.pos += 1;
                Ok(Node::Rep {
                    node: Box::new(factor),
                    min: 1,
                    max: None,
                })
            }
            Some('?') => {
                self.pos += 1;
                Ok(Node::Rep {
                    node: Box::new(factor),
                    min: 0,
                    max: Some(1),
                })
            }
            _ => Ok(factor),
        }
    }

    fn parse_factor(&mut self) -> Result<Node, String> {
        self.skip_ws();
        match self.peek() {
            Some('"') => self.parse_literal(),
            Some('[') => self.parse_class(),
            Some('(') => {
                self.pos += 1;
                let inner = self.parse_alt()?;
                self.skip_ws();
                if self.peek() != Some(')') {
                    return Err("missing ')'".to_string());
                }
                self.pos += 1;
                Ok(inner)
            }
            Some(c) if c.is_alphabetic() || c == '_' => self.parse_ref(),
            Some(c) => Err(format!("unexpected '{c}'")),
            None => Err("unexpected end of expression".to_string()),
        }
    }

    fn read_escaped(&mut self) -> Result<char, String> {
        // Caller has consumed the backslash.
        match self.peek() {
            Some('n') => {
                self.pos += 1;
                Ok('\n')
            }
            Some('t') => {
                self.pos += 1;
                Ok('\t')
            }
            Some('r') => {
                self.pos += 1;
                Ok('\r')
            }
            Some(c) => {
                self.pos += 1;
                Ok(c)
            } // \" \\ \] \[ \  etc → literal
            None => Err("dangling escape".to_string()),
        }
    }

    fn parse_literal(&mut self) -> Result<Node, String> {
        self.pos += 1; // opening quote
        let mut out = Vec::new();
        loop {
            match self.peek() {
                Some('"') => {
                    self.pos += 1;
                    break;
                }
                Some('\\') => {
                    self.pos += 1;
                    out.push(self.read_escaped()?);
                }
                Some(c) => {
                    self.pos += 1;
                    out.push(c);
                }
                None => return Err("unterminated string literal".to_string()),
            }
        }
        Ok(Node::Lit(out))
    }

    fn parse_class(&mut self) -> Result<Node, String> {
        self.pos += 1; // '['
        let negated = if self.peek() == Some('^') {
            self.pos += 1;
            true
        } else {
            false
        };
        let mut ranges = Vec::new();
        loop {
            match self.peek() {
                Some(']') => {
                    self.pos += 1;
                    break;
                }
                None => return Err("unterminated character class".to_string()),
                Some('\\') => {
                    self.pos += 1;
                    let c = self.read_escaped()?;
                    ranges.push((c, c));
                }
                Some(c) => {
                    self.pos += 1;
                    // range a-z (but '-' just before ']' is literal)
                    if self.peek() == Some('-') && self.chars.get(self.pos + 1) != Some(&']') {
                        self.pos += 1; // '-'
                        let end = match self.peek() {
                            Some('\\') => {
                                self.pos += 1;
                                self.read_escaped()?
                            }
                            Some(e) => {
                                self.pos += 1;
                                e
                            }
                            None => return Err("unterminated range".to_string()),
                        };
                        ranges.push((c, end));
                    } else {
                        ranges.push((c, c));
                    }
                }
            }
        }
        Ok(Node::Class { ranges, negated })
    }

    fn parse_ref(&mut self) -> Result<Node, String> {
        let mut name = String::new();
        while let Some(c) = self.peek() {
            if c.is_alphanumeric() || c == '_' || c == '-' {
                name.push(c);
                self.pos += 1;
            } else {
                break;
            }
        }
        Ok(Node::Ref(name))
    }
}

/// The deployed verdict grammar, parsed. Panics only if the embedded asset
/// is malformed — which a unit test guarantees it is not.
pub fn verdict_grammar() -> Grammar {
    #[allow(clippy::expect_used)] // embedded constant asset, validated by tests
    Grammar::parse(VERDICT_GBNF).expect("embedded verdict.gbnf must parse")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // --- acceptor correctness on tiny hand-built grammars ---

    #[test]
    fn literal_alternation_class_and_repetition() {
        let g = Grammar::parse(
            r#"
            root ::= "ab" digit+ tail?
            digit ::= [0-9]
            tail ::= "x" | "y"
            "#,
        )
        .unwrap();
        assert!(g.accepts("ab1"));
        assert!(g.accepts("ab1234"));
        assert!(g.accepts("ab9x"));
        assert!(g.accepts("ab9y"));
        assert!(!g.accepts("ab")); // digit+ needs at least one
        assert!(!g.accepts("ab1z")); // z not in tail
        assert!(!g.accepts("ab1xx")); // tail? at most one
        assert!(!g.accepts("xab1")); // must start with ab
    }

    #[test]
    fn negated_class() {
        let g = Grammar::parse(r#"root ::= [^0-9]+"#).unwrap();
        assert!(g.accepts("hello"));
        assert!(!g.accepts("hel0o"));
    }

    // --- Auflage 2: the deployed grammar physically excludes prose ---

    #[test]
    fn deployed_grammar_parses() {
        let g = verdict_grammar();
        // sanity: the language is non-empty and contains real verdicts,
        // otherwise a constrained decoder could never emit anything valid.
        assert!(g.accepts(r#"{"verdict":"PASS","confidence":0.00,"flags":[]}"#));
        assert!(g.accepts(r#"{"verdict":"BLOCK","confidence":0.9,"flags":["intent_shift"]}"#));
        assert!(g.accepts(r#"{"verdict":"BLOCK","confidence":1.00,"flags":["a","b_c","d0"]}"#));
    }

    #[test]
    fn prose_and_markdown_are_not_in_the_language() {
        let g = verdict_grammar();
        let rejected = [
            "I think this payload is safe to allow.",
            "PASS",
            "The verdict is BLOCK because of an injection attempt.",
            "```json\n{\"verdict\":\"PASS\",\"confidence\":0.0,\"flags\":[]}\n```",
            "Sure! Here is the JSON: {\"verdict\":\"PASS\",\"confidence\":0.0,\"flags\":[]}",
            "{\"verdict\":\"PASS\",\"confidence\":0.0,\"flags\":[]} (allowed)",
            // off-contract JSON the grammar still excludes:
            "{\"verdict\":\"MAYBE\",\"confidence\":0.5,\"flags\":[]}",
            "{\"verdict\":\"PASS\",\"confidence\":0.5,\"flags\":[],\"note\":\"hi\"}",
            "{\"verdict\":\"pass\",\"confidence\":0.5,\"flags\":[]}",
            "{\"verdict\": \"PASS\", \"confidence\": 0.5, \"flags\": []}", // whitespace not allowed
            "{\"verdict\":\"PASS\",\"confidence\":0.5,\"flags\":[\"Bad Flag\"]}",
            "",
        ];
        for s in rejected {
            assert!(!g.accepts(s), "grammar must reject: {s:?}");
        }
    }
}
