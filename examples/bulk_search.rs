use std::env;
use ocd_datalake_rs::{ATOM_VALUE_QUERY_FIELD, Datalake, DatalakeSetting};

fn main() {
    let username = env::var("OCD_DTL_RS_USERNAME").unwrap();
    let password = env::var("OCD_DTL_RS_PASSWORD").unwrap();
    let mut dtl = Datalake::new(
        username,
        password,
        DatalakeSetting::preprod(),
    );

    let query_hash = "fbecd3d440a7d439a2a1fd996c703a8d".to_string();  // IPs updated the last day
    let res = dtl.bulk_search(query_hash, vec![ATOM_VALUE_QUERY_FIELD.to_string()]);
    match res {
        Ok(atom_values) => println!("{atom_values}"),
        Err(err) => {
            println!("{err}");
            println!("{err:?}");
        }
    }
}