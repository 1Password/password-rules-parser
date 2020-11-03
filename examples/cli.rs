use dialoguer::Input;
use password_rules_parser::parse_password_rules;

fn main() -> Result<(), anyhow::Error> {
    // Example rules that you can input:
    //
    // minlength: 8; maxlength: 32; required: lower, upper; required: digit; allowed: [-_./\\@$*&!#];
    let password_rules = Input::<String>::new()
        .with_prompt("Enter password rules string")
        .interact()?;

    match parse_password_rules(&password_rules, true) {
        Ok(parsed_rules) => println!("Parsed rules: {:#?}", parsed_rules),
        Err(e) => println!("{}\n", e.to_string_pretty(&password_rules)),
    }

    Ok(())
}
