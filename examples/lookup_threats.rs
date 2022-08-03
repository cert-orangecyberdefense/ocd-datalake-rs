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
    println!("{}", dtl.get_token());
}