# password-rules-parser

[![crate documentation](https://docs.rs/password-rules-parser/badge.svg)](https://docs.rs/password-rules-parser)
[![Crates.io version](https://img.shields.io/crates/v/password-rules-parser.svg)](https://crates.io/crates/password-rules-parser)
[![Crates.io downloads](https://img.shields.io/crates/d/password-rules-parser.svg)](https://crates.io/crates/password-rules-parser)
[![dependency status](https://deps.rs/repo/github/1Password/password-rules-parser/status.svg)](https://deps.rs/repo/github/1Password/password-rules-parser)
![CI](https://github.com/1Password/password-rules-parser/workflows/CI/badge.svg)

Rust parser for the HTML [`passwordrules` attribute](https://github.com/whatwg/html/issues/3518), a proposal for an HTML attribute that allows services to specify their password requirements in a machine-readable format.

This spec is primarily being backed by Apple, and their tools and docs can be found [here](https://developer.apple.com/password-rules/).

See this crate's documentation for our own primer.

## Example

This example can be run via `cargo run --example parse`.

```rust
use password_rules_parser::{parse_password_rules, CharacterClass};

let password_rules = "minlength: 8; maxlength: 32; required: lower, upper; required: digit; allowed: [-_./\\@$*&!#];";
let parsed_rules =
    parse_password_rules(password_rules, true).expect("failed to parse password rules");

assert_eq!(parsed_rules.min_length.unwrap(), 8);
assert_eq!(parsed_rules.max_length.unwrap(), 32);
// This password rule does not place a restriction on consecutive characters
assert!(parsed_rules.max_consecutive.is_none());
assert_eq!(
    parsed_rules.allowed,
    vec![CharacterClass::Custom(vec![
        '!', '#', '$', '&', '*', '-', '.', '/', '@', '\\', '_',
    ])]
);
assert_eq!(
    parsed_rules.required,
    vec![
        vec![CharacterClass::Upper, CharacterClass::Lower],
        vec![CharacterClass::Digit]
    ]
);

// The above information can be used to make informed decisions about what password
// to generate for use with a specific service
```

You can try parsing arbitrary rules with this tool via `cargo run --example cli`.

## MSRV

The Minimum Supported Rust Version is currently 1.46.0. This will be bumped to the latest stable version of Rust when needed.

## Credits

Made with ❤️ by the [1Password](https://1password.com/) team, with appreciation for the wonderful [nom](https://github.com/Geal/nom) parsing library.

#### License

<sup>
Licensed under either of <a href="LICENSE-APACHE">Apache License, Version
2.0</a> or <a href="LICENSE-MIT">MIT license</a> at your option.
</sup>

<br>

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
</sub>
