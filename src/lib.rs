//! Rust parser for the HTML [`passwordrules` attribute][whatwg_proposal], a proposal for an
//! HTML attribute that allows services to specify their password requirements in a machine-readable format.
//!
//! This spec is primarily being backed by Apple, and their tools and docs can be found
//! [here][apple_docs].
//!
//! # Password Rules
//!
//! A password rule consists of the following:
//!
//! * `max-consecutive` - The maximum number of consecutive identical characters allowed in the
//!   password
//! * `minlength` - The minimum length of the password
//! * `maxlength` - The maximum length of the password
//! * `allowed` - A set of character classes whose characters the password is allowed to be
//!   generated with
//!     * Note that `allowed: digit, upper;` is equivalent to `allowed: digit; allowed: upper;`
//! * `required` - A set of character classes where at least one character from each `required` set
//!   must appear in the password
//!     * Note that `required: digit, upper;` is **not** equivalent to
//!       `required: digit; required: upper;`. The first (`required: digit, upper;`) means that the
//!       password must contain a `digit` or an `upper`(case) character, while the second
//!       (`required: digit; required: upper;`) means the password must contain a `digit` **AND**
//!       an `upper`(case) character.
//!
//! Rules are separated by a semicolon (`;`), while character classes are separated by a comma (`,`).
//!
//! An example of a password rule:
//!
//! `max-consecutive: 2; minlength: 10; maxlength: 15; allowed: upper; required: digit, special;`
//!
//! # Character Classes
//!
//! There are several different types of character classes:
//!
//! * `Upper` - All ASCII uppercase characters (`ABCDEFGHIJKLMNOPQRSTUVWXZY`)
//! * `Lower` - All ASCII lowercase characters (`abcdefghijklmnopqrstuvwxzy`)
//! * `Digit` - All ASCII digits (`0123456789`)
//! * `Special` - ASCII special characters (`-~!@#$%^&*_+=``|(){}[:;"'<>,.?]`)
//! * `AsciiPrintable` - All ASCII printable characters
//! * `Unicode` - All unicode characters
//!     * **Note:** In this implementation this class is equivalent to `AsciiPrintable`
//! * `Custom` - Contains a set of custom ASCII printable characters in the format `[-abc]]`
//!   where -, a, b, c, and ] are the characters.
//!     * **Note:** `-` and `]` are special characters in a character class where `-` must be the
//!       first character in the set and `]` must be the last character.
//!
//! # Example
//!
//! This example can be run via `cargo run --example parse`.
//!
//! ```
//! use password_rules_parser::{parse_password_rules, CharacterClass};
//!
//! let password_rules = "minlength: 8; maxlength: 32; required: lower, upper; required: digit; allowed: [-_./\\@$*&!#];";
//! let parsed_rules =
//!     parse_password_rules(password_rules, true).expect("failed to parse password rules");
//!
//! assert_eq!(parsed_rules.min_length.unwrap(), 8);
//! assert_eq!(parsed_rules.max_length.unwrap(), 32);
//! // This password rule does not place a restriction on consecutive characters
//! assert!(parsed_rules.max_consecutive.is_none());
//! assert_eq!(
//!     parsed_rules.allowed,
//!     vec![CharacterClass::Custom(vec![
//!         '!', '#', '$', '&', '*', '-', '.', '/', '@', '\\', '_',
//!     ])]
//! );
//! assert_eq!(
//!     parsed_rules.required,
//!     vec![
//!         vec![CharacterClass::Upper, CharacterClass::Lower],
//!         vec![CharacterClass::Digit]
//!     ]
//! );
//!
//! // The above information can be used to make informed decisions about what password
//! // to generate for use with a specific service
//! ```
//!
//! You can try parsing arbitrary rules with this tool via `cargo run --example cli`.
//!
//! [apple_docs]: https://developer.apple.com/password-rules/
//! [whatwg_proposal]: https://github.com/whatwg/html/issues/3518

#![forbid(unsafe_code)]

pub mod error;

use crate::error::{PasswordRulesError, PasswordRulesErrorContext};
use nom::error::FromExternalError;
use nom::{
    self,
    branch::alt,
    bytes::complete::{is_not, tag_no_case as nom_tag},
    character::complete::{char, digit1, multispace0},
    combinator::{complete, cut, map, map_res, opt, peek, recognize, value},
    error::ParseError,
    sequence::{delimited, tuple},
    IResult,
};
use once_cell::sync::Lazy;
use std::collections::{BTreeMap, BTreeSet};
use std::{cmp::max, cmp::min, ops::RangeInclusive};

// FIXME: There's a significant amount of similarity among these different
// variants; find a way to deduplicate.
const ASCII_RANGE: RangeInclusive<char> = ' '..='~';
const UPPER_RANGE: RangeInclusive<char> = 'A'..='Z';
const LOWER_RANGE: RangeInclusive<char> = 'a'..='z';
const DIGIT_RANGE: RangeInclusive<char> = '0'..='9';
const SPECIAL_CHARS: &str = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

/// Character classes that the password can be allowed or required to use
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CharacterClass {
    /// A-Z
    Upper,
    /// a-z
    Lower,
    /// 0-9
    Digit,
    /// -~!@#$%^&*_+=`|(){}[:;"'<>,.? ] and space
    Special,
    /// All ASCII printable characters
    AsciiPrintable,
    /// All unicode characters
    Unicode,
    /// A custom list between \[\] of ascii characters that can be used in the password
    /// For example: \[abc\] consists of the characters a, b, and c
    Custom(Vec<char>),
}

impl CharacterClass {
    /// The characters a character class consists of
    pub fn chars(&self) -> Vec<char> {
        use CharacterClass::*;

        match self {
            Upper => UPPER_RANGE.collect(),
            Lower => LOWER_RANGE.collect(),
            Digit => DIGIT_RANGE.collect(),
            Special => SPECIAL_CHARS.chars().collect(),
            // TODO(brandon): What range should we use for unicode? It's not a great idea to generate
            // a password containing unicode characters if the website doesn't normalize
            // as mentioned by Goldberg in https://github.com/whatwg/html/issues/3518#issuecomment-644581962
            AsciiPrintable | Unicode => ASCII_RANGE.collect(),
            Custom(custom) => custom.clone(),
        }
    }
}

/// The various parsed password rules
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PasswordRules {
    /// The maximum length of consecutive characters in your password
    pub max_consecutive: Option<u32>,
    /// The minimum length of the password
    pub min_length: Option<u32>,
    /// The maximum length of the password
    pub max_length: Option<u32>,
    /// A subset of allowed characters based on a set of `CharacterClass`
    pub allowed: Vec<CharacterClass>,
    /// Restrictions that all passwords must follow based on a set of `CharacterClass`
    pub required: Vec<Vec<CharacterClass>>,
}

/// A PasswordRule is a single row that can appear in a passwordrules document.
/// a list of these is flattened and canonicalized into a final PasswordRules.
#[derive(Debug, Clone)]
enum PasswordRule {
    Allow(Vec<CharacterClass>),
    Require(Vec<CharacterClass>),
    MinLength(Option<u32>),
    MaxLength(Option<u32>),
    MaxConsecutive(Option<u32>),
}

impl PasswordRules {
    pub fn is_subset(&self, other: &PasswordRules) -> bool {
        if let Some(max_consecutive) = other.max_consecutive {
            if self.max_consecutive.map(|x| x <= max_consecutive) != Some(true) {
                return false;
            }
        }

        if let Some(min_length) = other.min_length {
            if self.min_length.map(|x| x >= min_length) != Some(true) {
                return false;
            }
        }

        if let Some(max_length) = other.max_length {
            if self.max_length.map(|x| x <= max_length) != Some(true) {
                return false;
            }
        }

        if !satisfies_allowed(self, other) {
            return false;
        }

        satisfies_required(self.required.clone(), other.required.clone())
    }
}

fn satisfies_allowed(a: &PasswordRules, b: &PasswordRules) -> bool {
    let b_allowed = b
        .required
        .iter()
        .flatten()
        .chain(b.allowed.iter())
        .flat_map(|class| class.chars().into_iter())
        .collect::<BTreeSet<char>>();

    a.required
        .iter()
        .flatten()
        .chain(a.allowed.iter())
        .map(CharacterSet::from)
        .all(|set| set.is_subset(&b_allowed))
}

fn satisfies_required(mut a: Vec<Vec<CharacterClass>>, mut b: Vec<Vec<CharacterClass>>) -> bool {
    /// Sort by number of classes in each required instance, and by number of characters in each class, low to high
    fn presort_by_length(sets: &mut [Vec<CharacterClass>]) {
        for set in sets.iter_mut() {
            set.sort_by_key(|class| CharacterSet::from(class).len());
        }

        sets.sort_by_key(|set| {
            (
                set.len(),
                set.last().map(|class| CharacterSet::from(class).len()),
            )
        });
    }

    presort_by_length(&mut a);
    presort_by_length(&mut b);

    // Is each `x` in `ra` in `a`, a subset of any `y` in `rb` in `b`?
    // If so, delete `rb` from `b`.
    a.iter().for_each(|ra| {
        if let Some(i) = b.iter().enumerate().find_map(|(i, rb)| {
            ra.iter()
                .all(|x_class| {
                    rb.iter().any(|y_class| {
                        let x_set = CharacterSet::from(x_class);
                        let y_set = CharacterSet::from(y_class);
                        x_set.is_subset(&y_set)
                    })
                })
                .then_some(i)
        }) {
            b.remove(i);
        }
    });

    b.is_empty()
}

enum CharacterSet<'a> {
    Static(&'a BTreeSet<char>),
    Dynamic(BTreeSet<char>),
}

impl std::ops::Deref for CharacterSet<'_> {
    type Target = BTreeSet<char>;

    fn deref(&self) -> &Self::Target {
        match self {
            CharacterSet::Static(a) => a,
            CharacterSet::Dynamic(a) => a,
        }
    }
}

impl<'a> From<&'a CharacterClass> for CharacterSet<'a> {
    fn from(class: &'a CharacterClass) -> Self {
        static STATIC_CHARACTER_SETS: Lazy<BTreeMap<CharacterClass, BTreeSet<char>>> =
            Lazy::new(|| {
                [
                    CharacterClass::Upper,
                    CharacterClass::Lower,
                    CharacterClass::Digit,
                    CharacterClass::Special,
                    CharacterClass::AsciiPrintable,
                    CharacterClass::Unicode,
                ]
                .iter()
                .map(|c| (c.clone(), c.chars().into_iter().collect::<BTreeSet<_>>()))
                .collect()
            });

        match class {
            CharacterClass::Custom(_) => CharacterSet::Dynamic(class.chars().into_iter().collect()),
            _ => CharacterSet::Static(STATIC_CHARACTER_SETS.get(class).unwrap()),
        }
    }
}

// HELPER PARSER COMBINATORS
// These are generic combinators used in a few places in the password rules implementations.

/// Wrap a parser such that it accepts any amount (including 0) whitespace
/// before and after itself.
fn space_surround<'a, P, O, E>(parser: P) -> impl FnMut(&'a str) -> IResult<&'a str, O, E>
where
    P: FnMut(&'a str) -> IResult<&'a str, O, E>,
    E: ParseError<&'a str>,
{
    delimited(multispace0, parser, multispace0)
}

/// Parse a sequence with a folding function. This creates a parser that runs the inner `parser` in
/// a loop, using the fold function to create a value. Between each inner parser, it parses and
/// discards a separator, `sep`. If `allow_trailing_separator` is given, a trailing separator may
/// be parsed; otherwise, separators *must* be followed by another value.
///
/// The sequence *must* end with the `terminator`, which will be scanned but not consumed (as a
/// lookahead). If it does not, the parser will return an error. The terminator will not be checked
/// until the loop finishes.
///
/// This combinator exists to provide useful errors. Normally, looping parsers like this return
/// success unconditionally, because an error from the subparser just means that the loop is
/// finished and parsing can continue. By adding a lookahead for the terminator, we can return that
/// error if the loop finished without the presence of the expected terminator.
fn fold_separated_terminated<P, S, R, F, T, I, O, O2, O3, E>(
    mut parser: P,
    mut sep: S,
    terminator: R,
    allow_trailing_separator: bool,
    init: T,
    mut fold: F,
) -> impl FnMut(I) -> IResult<I, T, E>
where
    P: FnMut(I) -> IResult<I, O, E>,
    S: FnMut(I) -> IResult<I, O2, E>,
    R: FnMut(I) -> IResult<I, O3, E>,
    I: Clone,
    T: Clone,
    F: FnMut(T, O) -> T,
    E: ParseError<I>,
{
    let mut terminator_lookahead = peek(terminator);

    move |mut input| {
        let mut accum = init.clone();

        // Parse the first item
        let (fold_err, tail) = match parser(input.clone()) {
            Err(nom::Err::Error(err)) => (err, input),
            Err(err) => return Err(err),
            Ok((tail, output)) => {
                accum = fold(accum, output);
                input = tail;

                // Parse everything after the first item
                loop {
                    // Parse and discard a separator.
                    match sep(input.clone()) {
                        Err(nom::Err::Error(err)) => break (err, input),
                        Err(err) => return Err(err),
                        Ok((tail, _)) => input = tail,
                    }

                    // Parse a subsequent item. If allow_trailing_separator,
                    // this must succeed.
                    match parser(input.clone()) {
                        Err(err) if !allow_trailing_separator => return Err(err),
                        Err(nom::Err::Error(err)) => break (err, input),
                        Err(err) => return Err(err),
                        Ok((tail, output)) => {
                            accum = fold(accum, output);
                            input = tail;
                        }
                    }
                }
            }
        };

        // Check that the terminator is present
        match terminator_lookahead(tail.clone()) {
            Ok(..) => Ok((tail, accum)),
            Err(err) => Err(err.map(move |err| fold_err.or(err))),
        }
    }
}

/// Optionally parse something. The thing, if absent, must end with terminator, which will be
/// scanned but not consumed (as a lookahead). If it does not, the parser will return an error.
///
/// This combinator exists to provide useful errors. Normally, parsers like this return success
/// unconditionally, because an error from the subparser just means that the optional is None, so
/// parsing can continue. By adding a lookahead for the terminator, we can return that error if the
/// optional was absent without the presence of the expected terminator.
fn opt_terminated<P, R, I, O, O2, E>(
    mut parser: P,
    terminator: R,
) -> impl FnMut(I) -> IResult<I, Option<O>, E>
where
    P: FnMut(I) -> IResult<I, O, E>,
    R: FnMut(I) -> IResult<I, O2, E>,
    E: ParseError<I>,
    I: Clone,
{
    let mut terminator_lookahead = peek(terminator);

    move |input| match parser(input.clone()) {
        Ok((tail, value)) => Ok((tail, Some(value))),
        Err(nom::Err::Error(opt_err)) => match terminator_lookahead(input.clone()) {
            Ok(..) => Ok((input, None)),
            Err(err) => Err(err.map(move |err| opt_err.or(err))),
        },
        Err(err) => Err(err),
    }
}

/// Parse only an EOF
fn eof<'a, E>(input: &'a str) -> IResult<&'a str, (), E>
where
    E: ParseError<&'a str>,
{
    if input.is_empty() {
        Ok((input, ()))
    } else {
        Err(nom::Err::Error(E::from_error_kind(
            input,
            nom::error::ErrorKind::Eof,
        )))
    }
}

/// Wrapper for nom::tag_no_case that supports collecting the specific tag into
/// the error, in the event of a mismatch
fn tag_no_case<'a, E>(tag: &'static str) -> impl FnMut(&'a str) -> IResult<&'a str, &'a str, E>
where
    E: error::WithTagError<&'a str>,
{
    let nom_tag = nom_tag(tag);
    move |input| match nom_tag(input) {
        Ok(result) => Ok(result),
        Err(err) => Err(err.map(|()| E::from_tag(input, tag))),
    }
}

// PASSWORD RULES PARSERS

/// Parse a custom character class, which is a series of ascii-printable
/// characters, enclosed by []. if - is present, it must be at the beginning,
/// and if ] is present, it must be at the end.
fn parse_custom_character_class<'a>(
    input: &'a str,
) -> IResult<&'a str, Vec<char>, PasswordRulesErrorContext<'a>> {
    // Parse an optional -
    let opt_dash = opt(char('-'));

    // Parse any number of characters that aren't -]. is_not requires a match
    // of at least 1 character, so we make it optional as well.
    let inner = opt(is_not("-]"));

    // Custom lookahead parser that parses an optional ] only if it's followed by another
    // ]
    let opt_bracket = |input: &'a str| {
        if input.starts_with("]]") {
            Ok((&input[1..], Some(']')))
        } else {
            Ok((input, None))
        }
    };

    // Parse the body (the stuff between the [])
    let body = recognize(tuple((opt_dash, inner, opt_bracket)));

    // Convert the parsed body into a Vec<char>. Per the spec, ignore characters
    // that aren't ' ' or ascii-printables
    let body = map(body, |s| {
        s.chars()
            .filter(|&c| c.is_ascii_graphic() || c == ' ')
            .collect()
    });

    delimited(char('['), body, cut(char(']')))(input)
}

// Parse a string that indicates a character class
fn parse_character_class(input: &str) -> IResult<&str, CharacterClass, PasswordRulesErrorContext> {
    alt((
        value(CharacterClass::Upper, tag_no_case("upper")),
        value(CharacterClass::Lower, tag_no_case("lower")),
        value(CharacterClass::Digit, tag_no_case("digit")),
        value(CharacterClass::Special, tag_no_case("special")),
        value(
            CharacterClass::AsciiPrintable,
            tag_no_case("ascii-printable"),
        ),
        value(CharacterClass::Unicode, tag_no_case("unicode")),
        map(parse_custom_character_class, CharacterClass::Custom),
    ))(input)
}

/// Parse a list of character classes (which are comma-whitespace delimited)
fn parse_character_classes(
    input: &str,
) -> IResult<&str, Vec<CharacterClass>, PasswordRulesErrorContext> {
    let comma = space_surround(char(','));

    // A list of character classes must be terminated either by a semicolon or
    // EOF. We need to use value((), char) to unify the return type with EOF.
    let terminator = space_surround(alt((value((), char(';')), eof)));
    fold_separated_terminated(
        parse_character_class,
        comma,
        terminator,
        false,
        Vec::new(),
        |mut classes, class| {
            classes.push(class);
            classes
        },
    )(input)
}

/// Parse a number, which is 1 or more consecutive digits
fn parse_number<'a, E>(input: &'a str) -> IResult<&'a str, u32, E>
where
    E: ParseError<&'a str> + FromExternalError<&'a str, std::num::ParseIntError>,
{
    map_res(digit1, str::parse)(input)
}

/// A rule looks like "require: upper, lower". It's a string tag, colon, data. This function
/// creates a parser that matches a specific rule, which has a tag name (like "required") and a
/// subparser for the rule content. Because trailing semicolons may be omitted, the semicolon is
/// handled separately when parsing a sequence, not as part of a rule.
fn parse_generic_rule<'a, P, O>(
    name: &'static str,
    parser: P,
) -> impl FnMut(&'a str) -> IResult<&'a str, O, PasswordRulesErrorContext<'a>>
where
    P: Fn(&'a str) -> IResult<&'a str, O, PasswordRulesErrorContext<'a>>,
{
    let colon = space_surround(char(':'));
    let pattern = tuple((tag_no_case(name), cut(colon), cut(parser)));
    map(pattern, |(_, _, out)| out)
}

/// Parse an optional number. If the number is absent, lookahead that the next thing in the input
/// is a semicolon or EoF. This construct is used to ensure "expected number" errors can be
/// correctly delivered to the caller.
fn parse_optional_rule_number<'a, E>(input: &'a str) -> IResult<&'a str, Option<u32>, E>
where
    E: ParseError<&'a str> + FromExternalError<&'a str, std::num::ParseIntError>,
{
    opt_terminated(
        parse_number,
        space_surround(alt((value((), char(';')), eof))),
    )(input)
}

/// Parse a single PasswordRule, which is one of the semicolon delimited lines in a passwordrules
/// document. Because the semicolon is optional, it's handled separately when parsing a sequence
/// of rules, rather than here as part of a single rule.
fn parse_rule(input: &str) -> IResult<&str, PasswordRule, PasswordRulesErrorContext> {
    alt((
        map(
            parse_generic_rule("required", parse_character_classes),
            PasswordRule::Require,
        ),
        map(
            parse_generic_rule("allowed", parse_character_classes),
            PasswordRule::Allow,
        ),
        map(
            parse_generic_rule("max-consecutive", parse_optional_rule_number),
            PasswordRule::MaxConsecutive,
        ),
        map(
            parse_generic_rule("minlength", parse_optional_rule_number),
            PasswordRule::MinLength,
        ),
        map(
            parse_generic_rule("maxlength", parse_optional_rule_number),
            PasswordRule::MaxLength,
        ),
    ))(input)
}

/// If the source option is None, set it to Some(new). Otherwise, call cmp with
/// the old and new T, and set the option to the return value of cmp. Used to
/// implement "min of" and "max of" logic with options.
fn apply<T>(source: &mut Option<T>, new: T, mut cmp: impl FnMut(T, T) -> T) {
    *source = match source.take() {
        None => Some(new),
        Some(old) => Some(cmp(old, new)),
    }
}

/// Naïvely parse a complete rules document. This parser only folds all the rules as seen into
/// a `PasswordRules` struct. It accepts an empty string as an empty `PasswordRules`, and it does
/// not perform the two post processing steps, which are to add AsciiPrintable to "allowed" if both
/// allowed and required are empty, and to canonicalize the allowed set.
fn parse_rule_list(input: &str) -> IResult<&str, PasswordRules, PasswordRulesErrorContext> {
    fold_separated_terminated(
        parse_rule,
        space_surround(char(';')),
        space_surround(eof),
        true,
        PasswordRules::default(),
        |mut rules, rule| {
            match rule {
                PasswordRule::Allow(classes) => rules.allowed.extend(classes),
                PasswordRule::Require(classes) => {
                    let classes = canonicalize(classes);
                    if !classes.is_empty() {
                        rules.required.push(canonicalize(classes));
                    }
                }
                PasswordRule::MinLength(Some(length)) => apply(&mut rules.min_length, length, max),
                PasswordRule::MaxLength(Some(length)) => apply(&mut rules.max_length, length, min),
                PasswordRule::MaxConsecutive(Some(length)) => {
                    apply(&mut rules.max_consecutive, length, min)
                }
                _ => {}
            };
            rules
        },
    )(input)
}

/// Parse a password rules string and return its parts
///
/// All character requirements will be "canonicalized", which means redundant requirements will be
/// collapsed. For instance, "allow: ascii-printable, upper" will be parsed the same as
/// "allow: ascii-printable".
///
/// If `supply_default` is given, `AsciiPrintable` is added to the set of allowed characters if
/// both the allowed and required sets are empty; this behavior is consistent with the
/// specification requirements.
pub fn parse_password_rules(
    s: &str,
    supply_default: bool,
) -> Result<PasswordRules, PasswordRulesError> {
    let s = s.trim();

    if s.is_empty() {
        return Err(PasswordRulesError::empty());
    }

    let mut parse_rules = complete(parse_rule_list);

    let mut rules = match parse_rules(s) {
        Ok((_, rules)) => rules,
        Err(nom::Err::Incomplete(..)) => unreachable!(),
        Err(nom::Err::Error(err)) | Err(nom::Err::Failure(err)) => {
            return Err(err.extract_context(s))
        }
    };

    rules.allowed = canonicalize(rules.allowed);

    // If there are no character classes default to AsciiPrintable
    if supply_default && rules.allowed.is_empty() && rules.required.is_empty() {
        rules.allowed.push(CharacterClass::AsciiPrintable);
    }

    Ok(rules)
}

// TODO: replace with bitvec when const generics are stable
struct AsciiTable {
    table: [bool; 128],
}

#[derive(Debug, Clone)]
enum CheckResult<I> {
    Match,
    Mismatch(I),
}

impl AsciiTable {
    fn new() -> Self {
        Self {
            table: [false; 128],
        }
    }

    /// Add a character to the table. Panics if the character isn't a 7-bit ascii character.
    fn set(&mut self, b: char) {
        self.table[b as usize] = true;
    }

    /// Add a list of characters to the table. Panics if any of them aren't a 7-bit ascii character.
    fn set_range(&mut self, range: impl IntoIterator<Item = char>) {
        range.into_iter().for_each(|c| self.set(c))
    }

    /// Check if a character is present in the table.
    fn check(&self, b: char) -> bool {
        self.table.get(b as usize).copied().unwrap_or(false)
    }

    /// Check if *all* of the given characters are present in the table
    fn check_range(&self, range: impl IntoIterator<Item = char>) -> bool {
        range.into_iter().all(move |b| self.check(b))
    }

    // Check if a range is completely represented in the table. If it isn't,
    // return an iterator over the parts of the range that *are* in the table.
    fn check_or_extract<'s>(
        &'s self,
        range: impl IntoIterator<Item = char> + Clone + 's,
    ) -> CheckResult<impl Iterator<Item = char> + 's> {
        if self.check_range(range.clone()) {
            CheckResult::Match
        } else {
            CheckResult::Mismatch(range.into_iter().filter(move |&b| self.check(b)))
        }
    }
}

/// Converts a list of character classes into a canonicalized list of character classes
fn canonicalize(mut classes: Vec<CharacterClass>) -> Vec<CharacterClass> {
    // Table that stores all of the ASCII characters that we see
    let mut table = AsciiTable::new();

    // Unicode includes AsciiPrintable, and AsciiPrintable includes all other character classes
    // so we will check for these special cases and bail out early with the largest set found
    if classes.contains(&CharacterClass::Unicode) {
        return vec![CharacterClass::Unicode];
    }

    if classes.contains(&CharacterClass::AsciiPrintable) {
        return vec![CharacterClass::AsciiPrintable];
    }

    // Mark off all of the characters from each character class
    for class in classes.drain(..) {
        match class {
            CharacterClass::Upper => table.set_range(UPPER_RANGE),
            CharacterClass::Lower => table.set_range(LOWER_RANGE),
            CharacterClass::Digit => table.set_range(DIGIT_RANGE),
            CharacterClass::Special => table.set_range(SPECIAL_CHARS.chars()),
            CharacterClass::Custom(chars) => table.set_range(chars.into_iter()),
            _ => unreachable!(), // Unicode and AsciiPrintable are handled before the loop.
        }
    }

    // Check the character table to determine what character classes should be returned
    let mut custom_characters = vec![];

    if let CheckResult::Match = table.check_or_extract(ASCII_RANGE) {
        return vec![CharacterClass::AsciiPrintable];
    }

    match table.check_or_extract(UPPER_RANGE) {
        CheckResult::Match => classes.push(CharacterClass::Upper),
        CheckResult::Mismatch(chars) => custom_characters.extend(chars),
    }

    match table.check_or_extract(LOWER_RANGE) {
        CheckResult::Match => classes.push(CharacterClass::Lower),
        CheckResult::Mismatch(chars) => custom_characters.extend(chars),
    }

    match table.check_or_extract(DIGIT_RANGE) {
        CheckResult::Match => classes.push(CharacterClass::Digit),
        CheckResult::Mismatch(chars) => custom_characters.extend(chars),
    }

    match table.check_or_extract(SPECIAL_CHARS.chars()) {
        CheckResult::Match => classes.push(CharacterClass::Special),
        CheckResult::Mismatch(chars) => custom_characters.extend(chars),
    }

    if !custom_characters.is_empty() {
        classes.push(CharacterClass::Custom(custom_characters));
    }

    classes
}

#[cfg(test)]
mod test {
    use super::*;

    mod satisfies_required {
        use super::*;

        #[test]
        fn test_satisfies_required() {
            assert!(satisfies_required(
                vec![vec![CharacterClass::Digit]],
                vec![vec![
                    CharacterClass::Digit,
                    CharacterClass::Upper,
                    CharacterClass::Lower,
                ]],
            ),);

            assert!(!satisfies_required(
                vec![vec![
                    CharacterClass::Digit,
                    CharacterClass::Upper,
                    CharacterClass::Lower,
                ]],
                vec![vec![CharacterClass::Digit]],
            ),);

            assert!(satisfies_required(
                vec![vec![CharacterClass::Digit], vec![CharacterClass::Digit],],
                vec![
                    vec![CharacterClass::Digit],
                    vec![CharacterClass::Digit, CharacterClass::Upper],
                ],
            ),);

            assert!(!satisfies_required(
                vec![
                    vec![CharacterClass::Custom(vec!['[', '#', '!', '*'])],
                    vec![CharacterClass::Digit],
                ],
                vec![
                    vec![CharacterClass::Custom(vec!['#', '!'])],
                    vec![CharacterClass::Digit, CharacterClass::Upper],
                ],
            ),);

            assert!(satisfies_required(
                vec![
                    vec![CharacterClass::Digit, CharacterClass::Upper],
                    vec![CharacterClass::Digit],
                ],
                vec![vec![CharacterClass::Digit],],
            ),);

            assert!(!satisfies_required(
                vec![vec![CharacterClass::Digit],],
                vec![
                    vec![CharacterClass::Digit, CharacterClass::Upper],
                    vec![CharacterClass::Digit],
                ],
            ),);

            assert!(satisfies_required(
                vec![
                    vec![CharacterClass::Custom(vec!['[', '#', '!', '*', '^', '%'])],
                    vec![CharacterClass::Custom(vec!['[', '#', '!', '*'])],
                ],
                vec![vec![CharacterClass::Custom(vec!['[', '#', '!', '*'])],],
            ),);

            assert!(satisfies_required(
                vec![vec![CharacterClass::Upper], vec![CharacterClass::Digit],],
                vec![
                    vec![
                        CharacterClass::Digit,
                        CharacterClass::Lower,
                        CharacterClass::Upper
                    ],
                    vec![CharacterClass::Digit, CharacterClass::Lower],
                ],
            ),);
        }
    }

    mod canonicalize {
        use super::*;

        fn test_canonicalizer(input: &str, expected: Vec<CharacterClass>) {
            let input = input.chars().collect();
            let classes = vec![CharacterClass::Custom(input)];
            let res = canonicalize(classes);

            assert_eq!(res, expected)
        }

        #[test]
        fn few_characters() {
            test_canonicalizer("abc", vec![CharacterClass::Custom(vec!['a', 'b', 'c'])])
        }

        #[test]
        fn all_lower() {
            test_canonicalizer("abcdefghijklmnopqrstuvwxyz", vec![CharacterClass::Lower])
        }

        #[test]
        fn all_alpha() {
            test_canonicalizer(
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
                vec![CharacterClass::Upper, CharacterClass::Lower],
            )
        }

        #[test]
        fn all_special() {
            test_canonicalizer(
                r##"- !"#$%&'()*+,./:;<=>?@[\^_`{|}~]"##,
                vec![CharacterClass::Special],
            )
        }

        #[test]
        fn digits_and_some_lowers() {
            test_canonicalizer(
                "67abc1def0ghijk2ln8op9qr4stuv5wxy3z",
                vec![
                    CharacterClass::Digit,
                    CharacterClass::Custom("abcdefghijklnopqrstuvwxyz".chars().collect()),
                ],
            )
        }

        #[test]
        fn alphanumeric_and_some_specials() {
            test_canonicalizer(
                "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ()*+.",
                vec![
                    CharacterClass::Upper,
                    CharacterClass::Lower,
                    CharacterClass::Digit,
                    CharacterClass::Custom(vec!['(', ')', '*', '+', '.']),
                ],
            )
        }

        #[test]
        fn everything() {
            test_canonicalizer(
                r##"-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!"#$%&'()*+,./:;<=>?@[\^_`{|}~ ]"##,
                vec![CharacterClass::AsciiPrintable],
            )
        }
    }

    mod parser {
        use super::*;

        /// This macro removes the boilerplate involved in creating password
        /// rules parsing tests. It provides a maximally concise syntax for
        /// creating test cases, each of which expands to a #[test] function
        /// that calls test_rules_parser. Example:
        ///
        /// tests! {
        ///     empty_string: "" => None;
        ///
        ///     basic_minlength: "minlength: 10" => password_rules!(
        ///         minlength: 10;
        ///         allowed: ascii;
        ///     );
        ///
        ///     complex_test
        ///     "This tests something complex described in this comment":
        ///     "" => None;
        /// }
        ///
        /// The last case demonstrates an optional string comment; if this is
        /// present and the test fails, the comment will be included in the
        /// assertion failure message.
        macro_rules! tests {
            ($($test:ident $($doc:literal)? : $input:literal => $expected:expr;)*) => {$(
                $(#[doc = $doc])?
                #[test]
                fn $test() {
                    assert_eq!(
                        parse_password_rules($input, true).ok(),
                        $expected,

                        "{doc}\ninput: {input:?}",
                        doc = None $(.or(Some($doc)))? .unwrap_or(""),
                        input = $input
                    );
                }
            )*};
        }

        /// Helper macro to construct a password rules with minimal boilerplate.
        /// Example:
        ///
        /// password_rules! (
        ///     max-consecutive: 10;
        ///     maxlength: 30;
        ///     minlength: 10;
        ///     allowed: digit, special, ['a' 'b' 'c'];
        ///     required: upper;
        ///     required: lower;
        /// )
        ///
        /// This macro returns a PasswordRules struct, wrapped in Some (for
        /// easy use in tests). All of the shown fields are optional, but they
        /// must be given in that precise order.
        macro_rules! password_rules {
            (
                $(max-consecutive: $consecutive:expr;)?
                $(maxlength: $maxlength:expr;)?
                $(minlength: $minlength:expr;)?
                $(allowed: $($allowed_class:tt),* $(,)? ;)?
                $(required: $($required_class:tt),* $(,)? ;)*
            ) => {
                Some(PasswordRules{
                    max_consecutive: None $(.or(Some($consecutive)))?,
                    max_length: None $(.or(Some($maxlength)))?,
                    min_length: None $(.or(Some($minlength)))?,
                    allowed: vec![$($(
                        character_class!($allowed_class),
                    )*)?],
                    required: vec![$(
                        vec![$(
                            character_class!($required_class),
                        )*],
                    )*],
                })
            }
        }

        /// Helper macro to construct a CharacterClass enum. Used in `password_rules!`.
        macro_rules! character_class {
            (upper) => {CharacterClass::Upper};
            (lower) => {CharacterClass::Lower};
            (digit) => {CharacterClass::Digit};
            (special) => {CharacterClass::Special};
            (ascii) => {CharacterClass::AsciiPrintable};
            (unicode) => {CharacterClass::Unicode};
            ([$($c:expr)*]) => {CharacterClass::Custom(vec![$($c,)*])};
        }

        tests! {
            empty_string: "" => None;

            missing_property: "allowed:;" => password_rules!(allowed: ascii;);

            multiple_classes: "allowed: digit, special;" => password_rules!(
                allowed: digit, special;
            );

            missing_integers: "max-consecutive:;minlength:;maxlength:;" => password_rules!(
                allowed: ascii;
            );

            empty_custom_class: "allowed:[];" => password_rules!(allowed: ascii;);

            multiple_length_constraints:
                "maxlength:50;\
                max-consecutive:40;\
                minlength:10;\
                max-consecutive:30;\
                minlength:12;\
                maxlength:20;"
                =>
                password_rules!(
                    max-consecutive: 30;
                    maxlength: 20;
                    minlength: 12;
                    allowed: ascii;
                );

            custom_class_bracket_hyphen: "allowed: [-]]; required: [[]]; allowed:[-];" => password_rules!(
                allowed: ['-' ']'];
                required: ['[' ']'];
            );

            invalid_hyphen: "allowed: [a-];" => None;

            invalid_bracket: "allowed: []a];" => None;

            complex_input:
                "allowed:special;\
                max-consecutive:3;\
                required: upper, digit, ['*/];\
                allowed: [abc], digit,special;\
                minlength:20;"
                =>
                password_rules!(
                    max-consecutive: 3;
                    minlength: 20;
                    allowed: digit, special, ['a' 'b' 'c'];
                    required: upper, digit, ['\'' '*' '/'];
                );

            skip_unicode_characters: "allowed: [供应A商B责任C进展];" => password_rules!(
                allowed: ['A' 'B' 'C'];
            );

            unicode_overpowers_everything:
                "allowed: \
                [abcdefghijklmnopqrstuvwxyz], \
                upper, digit, ascii-printable, \
                special, unicode;"
                =>
                password_rules!(allowed: unicode;);

            ascii_overpowers_everything_else:
                "allowed: lower; \
                allowed: [ABCDEFGHIJKLMNOPQRSTUVWXYZ]; \
                allowed: special; \
                allowed: [0123456789]; \
                allowed: ascii-printable;"
                =>
                password_rules!(allowed: ascii;);


            allow_missing_trailing_semicolon: "allowed: lower; required: upper" => password_rules!(
                allowed: lower;
                required: upper;
            );

            multiple_required_sets:
                "required: upper, lower; required: digit; allowed: digit; allowed: upper;"
                =>
                password_rules!(
                    allowed: upper, digit;
                    required: upper, lower;
                    required: digit;
                );
        }

        /// Test cases taken from https://github.com/apple/password-manager-resources/issues/98#issuecomment-640105245,
        /// adopted for our implementation. They diverge in a few ways:
        /// - the original tests accept some custom character class inputs that are prohibited by the
        ///   spec, such as [a-].
        /// - the original tests return PasswordRules::default() in the event of a parse error;
        ///   we explicitly reject those cases with an error.
        mod apple_suite {
            use super::*;

            tests! {
                empty_string: "" => None;

                req_upper1: "    required: upper" => password_rules!(required: upper;);
                req_upper2: "    required: upper;" => password_rules!(required: upper;);
                req_upper3: "    required: upper             " => password_rules!(required: upper;);
                req_upper4: "required:upper" => password_rules!(required: upper;);
                req_upper6: "required:     upper" => password_rules!(required: upper;);

                req_upper_case "Test that character class names are case insensitive":
                "required: uPPeR" => password_rules!(required: upper;);

                all_upper1: "allowed:upper" => password_rules!(allowed: upper;);
                all_upper2: "allowed:     upper" => password_rules!(allowed: upper;);

                required_canonical "Test that a custom character set that overlaps a class is omitted":
                "required: upper, [AZ];" => password_rules!(required: upper;);

                allowed_reduction "Test that multiple allowed rules are collapsed together":
                "required: upper; allowed: upper; allowed: lower" => password_rules!(
                    allowed: upper, lower;
                    required: upper;
                );

                max_consecutive1: "max-consecutive:      5" => password_rules!(
                    max-consecutive: 5;
                    allowed: ascii;
                );
                max_consecutive2: "max-consecutive:5" => password_rules!(
                    max-consecutive: 5;
                    allowed: ascii;
                );
                max_consecutive3: "      max-consecutive:5" => password_rules!(
                    max-consecutive: 5;
                    allowed: ascii;
                );


                max_consecutive_min1 "Test that the lowest number wins for multiple max-consecutive":
                "max-consecutive: 5; max-consecutive: 3" => password_rules!(
                    max-consecutive: 3;
                    allowed: ascii;
                );
                max_consecutive_min2 "Test that the lowest number wins for multiple max-consecutive":
                "max-consecutive: 3; max-consecutive: 5" => password_rules!(
                    max-consecutive: 3;
                    allowed: ascii;
                );
                max_consecutive_min3 "Test that the lowest number wins for multiple max-consecutive":
                "max-consecutive: 3; max-consecutive: 1; max-consecutive: 5" => password_rules!(
                    max-consecutive: 1;
                    allowed: ascii;
                );
                max_consecutive_min4 "Test that the lowest number wins for multiple max-consecutive":
                "required: ascii-printable; max-consecutive: 5; max-consecutive: 3" => password_rules!(
                    max-consecutive: 3;
                    required: ascii;
                );

                require_allow1: "required: [*&^]; allowed: upper" => password_rules!(
                    allowed: upper;
                    required: ['&' '*' '^'];
                );
                require_allow2: "required: [*&^ABC]; allowed: upper" => password_rules!(
                    allowed: upper;
                    required: ['A' 'B' 'C' '&' '*' '^'];
                );
                required_allow3: "required: unicode; required: digit" => password_rules!(
                    required: unicode;
                    required: digit;
                );

                require_empty "Test that an empty required set is ignored":
                "required: ; required: upper" => password_rules!(
                    required: upper;
                );

                custom_unicode_dropped1 "Test that unicode characters in custom classes are ignored":
                "allowed: [供应商责任进展]" => password_rules!(
                    allowed: ascii;
                );
                custom_unicode_dropped2 "Test that unicode characters in custom classes are ignored":
                "allowed: [供应A商B责任C进展]" => password_rules!(
                    allowed: ['A' 'B' 'C'];
                );

                collapse_allow1 "Test that several allow rules are collapsed together":
                "required: upper; allowed: upper; allowed: lower; minlength: 12; maxlength: 73;" =>
                password_rules!(
                    maxlength: 73;
                    minlength: 12;
                    allowed: upper, lower;
                    required: upper;
                );
                collapse_allow2 "Test that several allow rules are collapsed together":
                "required: upper; allowed: upper; allowed: lower; maxlength: 73; minlength: 12;" =>
                password_rules!(
                    maxlength: 73;
                    minlength: 12;
                    allowed: upper, lower;
                    required: upper;
                );
                collapse_allow3 "Test that several allow rules are collapsed together":
                "required: upper; allowed: upper; allowed: lower; maxlength: 73" => password_rules!(
                    maxlength: 73;
                    allowed: upper, lower;
                    required: upper;
                );
                collapse_allow4 "Test that several allow rules are collapsed together":
                "required: upper; allowed: upper; allowed: lower; minlength: 12;" => password_rules!(
                    minlength: 12;
                    allowed: upper, lower;
                    required: upper;
                );

                minlength_max1 "Test that the largest number wins for multiple minlength":
                "minlength: 12; minlength: 7; minlength: 23" => password_rules!(
                    minlength: 23;
                    allowed: ascii;
                );
                minlength_max2 "Test that the largest number wins for multiple minlength":
                "minlength: 12; maxlength: 17; minlength: 10" => password_rules!(
                    maxlength: 17;
                    minlength: 12;
                    allowed: ascii;
                );

                bad_syntax1: "allowed: upper,," => None;
                bad_syntax2: "allowed: upper,;" => None;
                bad_syntax3: "allowed: upper [a]" => None;
                bad_syntax4: "dummy: upper" => None;
                bad_syntax5: "upper: lower" => None;
                bad_syntax6: "max-consecutive: [ABC]" => None;
                bad_syntax7: "max-consecutive: upper" => None;
                bad_syntax8: "max-consecutive: 1+1" => None;
                bad_syntax9: "max-consecutive: 供" => None;
                bad_syntax10: "required: 1" => None;
                bad_syntax11: "required: 1+1" => None;
                bad_syntax12: "required: 供" => None;
                bad_syntax13: "required: A" => None;
                bad_syntax14: "required: required: upper" => None;
                bad_syntax15: "allowed: 1" => None;
                bad_syntax16: "allowed: 1+1" => None;
                bad_syntax17: "allowed: 供" => None;
                bad_syntax18: "allowed: A" => None;
                bad_syntax19: "allowed: allowed: upper" => None;

                custom_class1
                "Test that a - and ] are only accepted as the first and last characters in a class":
                "required:         digit           ;                        required: [-]];" =>
                password_rules!(
                    required: digit;
                    required: ['-' ']'];
                );
                custom_class2
                "Test that a - and ] are only accepted as the first and last characters in a class":
                "required:         digit           ;                    required: [-ABC]];" =>
                password_rules!(
                    required: digit;
                    required: ['A' 'B' 'C' '-' ']'];
                );
                custom_class3
                "Test that a - and ] are only accepted as the first and last characters in a class":
                "required:         digit           ;                    required: [-];" =>
                password_rules!(
                    required: digit;
                    required: ['-'];
                );
                custom_class4
                "Test that a - and ] are only accepted as the first and last characters in a class":
                "required:         digit           ;                    required: []];" =>
                password_rules!(
                    required: digit;
                    required: [']'];
                );

                bad_custom_class1 "Test that a hyphen is only accepted as the first character in a class":
                "required:         digit           ;                        required: [a-];" => None;
                bad_custom_class2 "Test that a hyphen is only accepted as the first character in a class":
                "required:         digit           ;                        required: []-];" => None;
                bad_custom_class3 "Test that a hyphen is only accepted as the first character in a class":
                "required:         digit           ;                        required: [--];" => None;
                bad_custom_class4 "Test that a hyphen is only accepted as the first character in a class":
                "required:         digit           ;                        required: [-a--------];" => None;
                bad_custom_class5 "Test that a hyphen is only accepted as the first character in a class":
                "required:         digit           ;                        required: [-a--------] ];" => None;

                canonical1 "Test that a custom character class is converted into a named class":
                "required: [abcdefghijklmnopqrstuvwxyz]" => password_rules!(
                    required: lower;
                );
                canonical2 "Test that a custom character class is converted into a named class":
                "required: [abcdefghijklmnopqrstuvwxy]" => password_rules!(
                    required: [
                        'a''b''c''d''e''f''g''h''i''j''k''l''m''n''o''p''q''r''s''t''u''v''w''x''y'
                    ];
                );
            }
        }
    }
}
