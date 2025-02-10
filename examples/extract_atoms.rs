use std::env;
use ocd_datalake_rs::{Datalake, DatalakeSetting};

fn main() {
    let username = env::var("OCD_DTL_RS_USERNAME").ok();
    let password = env::var("OCD_DTL_RS_PASSWORD").ok();
    let long_term_token = env::var("OCD_DTL_RS_LONG_TERM_TOKEN").ok();
    let mut dtl = Datalake::new(
        username,
        password,
        long_term_token,
        DatalakeSetting::preprod()
    );
    let atom_values: Vec<String> = vec!["domain.com", "4.4.4.4", "1.1.1.1", "7ba226e0538c234638beae091ba53f0282fa9fb6"]
        .iter()
        .map(|x| x.to_string())
        .collect();
    let extracted = dtl.extract_atom_type(&atom_values, "certificate").expect("API Error");
    for (atom_value, atom_type) in extracted {
        println!("{} is of type {}", atom_value, atom_type);
    }
}