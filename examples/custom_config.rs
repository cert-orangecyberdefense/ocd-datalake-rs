use std::fs;
use ocd_datalake_rs::{Datalake, DatalakeSetting};

fn main() {
    let example_filename = "examples/custom_config.ron";
    let contents = fs::read_to_string(example_filename).expect("Error reading the config file");
    let mut dtl = Datalake::new(
        "username".to_string(),
        "password".to_string(),
        DatalakeSetting::new(contents.as_str()),
    );
    println!("{}", dtl.get_token());  // will panick with "Could not fetch API https://custom_host/auth/token/""
}