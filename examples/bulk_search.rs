use std::env;
use ocd_datalake_rs::{ATOM_VALUE_QUERY_FIELD, Datalake, DatalakeSetting};

fn main() {
    let username = env::var("OCD_DTL_RS_USERNAME").unwrap();
    let password = env::var("OCD_DTL_RS_PASSWORD").unwrap();
    let mut preprod_setting = DatalakeSetting::preprod();
    preprod_setting.bulk_search_timeout_sec = 10 * 60;  // Wait at max 10 minutes before timeout
    let mut dtl = Datalake::new(
        username,
        password,
        preprod_setting,
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