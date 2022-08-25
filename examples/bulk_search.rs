use std::{env, io, thread};
use std::sync::mpsc;
use std::sync::mpsc::TryRecvError;
use std::time::{Duration, Instant};
use std::io::Write;
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

    let (tx, rx) = mpsc::channel();
    let start_time = Instant::now();
    let ui_thread = thread::spawn(move || loop {
        thread::sleep(Duration::from_millis(500));
        print!("{esc}c", esc = 27 as char);  // Clear output
        match rx.try_recv() {
            Ok(_) | Err(TryRecvError::Disconnected) => {
                println!("Bulk search process is done ✅");
                thread::sleep(Duration::from_secs(1));
                break;
            }
            Err(TryRecvError::Empty) => {
                print!("Waiting for bulk search completion since {}s", start_time.elapsed().as_secs());
                io::stdout().flush().unwrap();
            }
        }
    });
    let bulk_search_thread = thread::spawn(move ||
        dtl.bulk_search(query_hash, vec![ATOM_VALUE_QUERY_FIELD.to_string()])
    );
    let res = bulk_search_thread.join().expect("Thread failed");
    tx.send(()).unwrap();  // Send the stop signal to ui thread
    ui_thread.join().unwrap();

    match res {
        Ok(atom_values) => println!("{atom_values}"),
        Err(err) => {
            println!("{err}");
            println!("{err:?}");
        }
    }
}