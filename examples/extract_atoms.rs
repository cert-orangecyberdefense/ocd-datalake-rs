use std::env;
use ocd_datalake_rs::{Datalake, DatalakeSetting};

fn main() {
    let username = env::var("OCD_DTL_RS_USERNAME").unwrap();
    let password = env::var("OCD_DTL_RS_PASSWORD").unwrap();
    let mut dtl = Datalake::new(
        username,
        password,
        DatalakeSetting::preprod()
    );
    let atom_values: Vec<String> = vec!["domain.com", "4.4.4.4", "1.1.1.1"].iter().map(|x| x.to_string()).collect();
    let extracted = dtl.extract_atom_type(&atom_values).expect("API Error");
    for (atom_value, atom_type) in extracted {
        println!("{} is of type {}", atom_value, atom_type);
    }
}