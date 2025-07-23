//! Errors that can be returned from the parsing process

use std::fmt::{self, Display, Formatter, Write};
use std::{convert::TryInto, error::Error};

use itertools::{Itertools, Position::*};
use nom::error::{ErrorKind, FromExternalError, ParseError};
use pretty_lint::{Position, PrettyLint, Span};

/// Extension trait for nom::error::ParseError that allows for collecting the
/// failed tag in the event of a mismatch, similar to ParseError::from_char.
pub(crate) trait WithTagError<I> {
    /// Construct the error from the given input and tag
    fn from_tag(input: I, tag: &'static str) -> Self;
}

impl<I> WithTagError<I> for () {
    fn from_tag(_: I, _: &'static str) -> Self {}
}

/// Different kinds of things that can be expected at a given location
#[derive(Debug, Clone, Copy)]
pub enum Expected {
    /// Expected EoF (End of File)
    Eof,
    /// Expected a character
    Char(char),
    /// Expected a tag
    ///
    /// A tag is a particular string token (such as "upper").
    Tag(&'static str),
    /// Expected a number
    Number,
}

impl Display for Expected {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Expected::Eof => write!(f, "EoF"),
            Expected::Number => write!(f, "a number"),
            Expected::Char(c) => write!(f, "{c:?}"),
            Expected::Tag(tag) => write!(f, "{tag:?}"),
        }
    }
}

/// A single parse failure at a location– reports what was expected at what
/// location
#[derive(Debug, Clone, Copy)]
pub struct ExpectedAt {
    /// The character index of the error location
    pub index: usize,

    /// The line number (starting with 1) of the error location
    pub line: u32,

    /// The column number (starting with 1) of the error location
    pub column: u32,

    /// The specific element that was expected
    pub expected: Expected,
}

/// This error type is used while parsing is running; it knows only the tail
/// end of the input at the time an error occurred. It can be combined with the
/// original input to produce an absolute error location via `ExpectedAt`.
#[derive(Debug, Clone)]
pub(crate) struct ExpectedContext<'a> {
    input_tail: &'a str,
    expected: Expected,
}

impl<'a> ExpectedContext<'a> {
    /// Given the original input string, extract the absolute error location of
    /// an ErrorContext
    pub fn extract_context(self, input: &'a str) -> ExpectedAt {
        let offset = input
            .len()
            .checked_sub(self.input_tail.len())
            .expect("input size was smaller than the tail size");

        let prefix = &input[..offset];

        let line_number = prefix.chars().filter(|&c| c == '\n').count() + 1;
        let last_line_start = prefix
            .char_indices()
            .rev()
            .find(|&(_, c)| c == '\n')
            .map(|(index, _)| index + 1)
            .unwrap_or(0);
        let column_number = (offset - last_line_start) + 1;

        ExpectedAt {
            line: line_number
                .try_into()
                .expect("More than 4 billion lines of input"),
            column: column_number
                .try_into()
                .expect("More than 4 billion columns of input"),
            index: offset,
            expected: self.expected,
        }
    }
}

/// This error type is used while parsing is running; it knows only the tail
/// end of the input at the time an error occurred. It can be combined with the
/// original input to produce a absolute error locations in `PasswordRulesError`.
#[derive(Debug, Clone)]
pub(crate) struct PasswordRulesErrorContext<'a> {
    expectations: Vec<ExpectedContext<'a>>,
}

impl<'a> PasswordRulesErrorContext<'a> {
    /// Given the original input string, extract the absolute error location of
    /// an all the errors
    pub fn extract_context(self, input: &'a str) -> PasswordRulesError {
        let mut expectations: Vec<ExpectedAt> = self
            .expectations
            .into_iter()
            .map(|exp| exp.extract_context(input))
            .collect();

        expectations.sort_unstable_by_key(|exp| exp.index);

        PasswordRulesError { expectations }
    }
}

impl<'a> ParseError<&'a str> for PasswordRulesErrorContext<'a> {
    fn from_error_kind(input: &'a str, kind: ErrorKind) -> Self {
        match kind {
            ErrorKind::Eof => Self {
                expectations: vec![ExpectedContext {
                    input_tail: input,
                    expected: Expected::Eof,
                }],
            },
            ErrorKind::Digit => Self {
                expectations: vec![ExpectedContext {
                    input_tail: input,
                    expected: Expected::Number,
                }],
            },
            _ => Self {
                expectations: vec![],
            },
        }
    }

    fn append(input: &'a str, kind: nom::error::ErrorKind, other: Self) -> Self {
        Self::from_error_kind(input, kind).or(other)
    }

    fn or(mut self, other: Self) -> Self {
        self.expectations.extend(other.expectations);
        self
    }

    fn from_char(input: &'a str, c: char) -> Self {
        Self {
            expectations: vec![ExpectedContext {
                input_tail: input,
                expected: Expected::Char(c),
            }],
        }
    }
}

impl<'a> WithTagError<&'a str> for PasswordRulesErrorContext<'a> {
    fn from_tag(input: &'a str, tag: &'static str) -> Self {
        Self {
            expectations: vec![ExpectedContext {
                input_tail: input,
                expected: Expected::Tag(tag),
            }],
        }
    }
}

impl<'a> FromExternalError<&'a str, std::num::ParseIntError> for PasswordRulesErrorContext<'a> {
    fn from_external_error(input: &'a str, kind: ErrorKind, _: std::num::ParseIntError) -> Self {
        Self::from_error_kind(input, kind)
    }
}

/// Error that can result from parsing password rules
#[derive(Debug, Clone)]
pub struct PasswordRulesError {
    /// Elements (like a character, string tag, or EoF) that the parser was expecting,
    /// along with the location where the element was expected
    pub expectations: Vec<ExpectedAt>,
}

impl PasswordRulesError {
    pub(crate) fn empty() -> Self {
        Self {
            expectations: vec![],
        }
    }

    /// Build a pretty version of the error given the original input string.
    ///
    /// The default `Display` implementation produces helpful output:
    ///
    /// ```text
    /// Error: expected one of:
    ///   "required", "allowed", "max-consecutive", "minlength", "maxlength", or EoF at 1:71
    /// ```
    ///
    /// It doesn't have access to the original input string, however, so it's limited
    /// in what it can do.
    ///
    /// This method produces pretty output with colors if you're able to provide that:
    ///
    /// ```text
    /// error: parsing failed
    ///  --> 1:71
    ///   |
    /// 1 | minlength: 8; maxlength: 32; required: lower, upper; required: digit; allow
    ///   |                                                                       ^ expected one of "required", "allowed", "max-consecutive", "minlength", "maxlength", or EoF
    /// ```
    pub fn to_string_pretty(&self, s: &str) -> Result<String, fmt::Error> {
        let lint_base = PrettyLint::error(s).with_message("parsing failed");

        Ok(match self.expectations.as_slice() {
            [] => lint_base.with_inline_message("unknown error").to_string(),
            [exp] => lint_base
                .with_inline_message(&format!("expected {}", exp.expected))
                .at(Span {
                    start: Position {
                        line: exp.line as usize,
                        col: exp.column as usize,
                    },
                    end: Position {
                        line: exp.line as usize,
                        col: exp.column as usize,
                    },
                })
                .to_string(),
            expectations => {
                // Group the expectations by location, so that several expectations at the same
                // location can be shown together
                let groups = expectations.iter().chunk_by(|exp| (exp.line, exp.column));
                let mut lint_string = String::new();

                groups.into_iter().try_for_each(|((line, column), group)| {
                    let mut inline_message = String::from("expected one of ");

                    group
                        .with_position()
                        .try_for_each(|positioned_exp| match positioned_exp {
                            (Only, exp) => write!(inline_message, "{}", exp.expected),
                            (First, exp) | (Middle, exp) => {
                                write!(inline_message, "{}, ", exp.expected)
                            }
                            (Last, exp) => write!(inline_message, "or {}", exp.expected),
                        })?;

                    let lint = PrettyLint::error(s)
                        .with_message("parsing failed")
                        .with_inline_message(&inline_message)
                        .at(Span {
                            start: Position {
                                line: line as usize,
                                col: column as usize,
                            },
                            end: Position {
                                line: line as usize,
                                col: column as usize,
                            },
                        });

                    write!(lint_string, "{lint}")
                })?;

                lint_string
            }
        })
    }
}

impl Display for PasswordRulesError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self.expectations.as_slice() {
            [] => write!(f, "unknown error"),
            [exp] => write!(
                f,
                "expected {} at {}:{}",
                exp.expected, exp.line, exp.column
            ),
            expectations => {
                // Group the expectations by location, so that several expectations at the same
                // location can be shown together
                writeln!(f, "expected one of:")?;

                let groups = expectations.iter().chunk_by(|exp| (exp.line, exp.column));

                groups.into_iter().try_for_each(|((line, column), group)| {
                    write!(f, "  ")?;

                    group
                        .with_position()
                        .try_for_each(|positioned_exp| match positioned_exp {
                            (Only, exp) => write!(f, "{}", exp.expected),
                            (First, exp) | (Middle, exp) => write!(f, "{}, ", exp.expected),
                            (Last, exp) => write!(f, "or {}", exp.expected),
                        })?;

                    writeln!(f, " at {line}:{column}")
                })
            }
        }
    }
}

impl Error for PasswordRulesError {}
