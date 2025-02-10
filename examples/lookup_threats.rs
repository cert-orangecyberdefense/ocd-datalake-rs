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
        DatalakeSetting::preprod(),
    );

    let atom_values: Vec<String> = vec![
        "enus.patch.battle.net",  // domain
        "fde26bc70eeb45d7db5c18f91739f263c96262ea9fe254c59d993dc44b248774",  // file
        "7ba226e0538c234638beae091ba53f0282fa9fb6",  // certificate
    ].iter().map(|x| x.to_string()).collect();
    let csv_result: String = match dtl.bulk_lookup(atom_values, "certificate") {
        Ok(result) => { result }
        Err(err) => {
            println!("{err}");  // User readable error
            panic!("{err:#?}");  // Error pretty printed for debug
        }
    };
    println!("{csv_result}");
}