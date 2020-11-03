use password_rules_parser::{parse_password_rules, CharacterClass};

fn main() {
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
}
