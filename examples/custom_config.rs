use std::fs;
use ocd_datalake_rs::{Datalake, DatalakeSetting};

fn main() {
    let example_filename = "examples/custom_config.ron";
    let contents = fs::read_to_string(example_filename).expect("Error reading the config file");
    let mut dtl = Datalake::new(
        Some("username".to_string()),
        Some("password".to_string()),
        None,
        DatalakeSetting::new(contents.as_str()),
    ).unwrap();
    let result = dtl.get_access_token();
    let err = result.expect_err("Error expected");
    println!("{}", err.to_string());  // print "HTTP Error Could not fetch API for url https://custom_host/auth/token/"
}