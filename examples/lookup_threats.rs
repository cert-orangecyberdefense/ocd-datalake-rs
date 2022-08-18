use std::env;
use ocd_datalake_rs::{Datalake, DatalakeSetting};

fn main() {
    let username = env::var("OCD_DTL_RS_USERNAME").unwrap();
    let password = env::var("OCD_DTL_RS_PASSWORD").unwrap();
    let mut dtl = Datalake::new(
        username,
        password,
        DatalakeSetting::preprod(),
    );

    let atom_values: Vec<String> = vec![
        "620c28ece75af2ea227f195fc45afe109ff9f5c876f2e4da9e0d4f4aad68ee8e",
        "ef3363dfe2515b826584ab53c4bb7812",
        "jeithe7eijeefohch3qu.probes.site",
    ].iter().map(|x| x.to_string()).collect();
    let csv_result: String = match dtl.bulk_lookup(atom_values) {
        Ok(result) => { result }
        Err(err) => {
            println!("{err}");  // User readable error
            panic!("{err:#?}");  // Error pretty printed for debug
        }
    };
    println!("{csv_result}");
}