# OCD_DATALAKE_RS
`ocd_datalake_rs` is a Rust library to interact with Orange Cyberdefense's [Datalake](datalake.cert.orangecyberdefense.com).  

## Functionalities implemented
* Bulk lookup
* Bulk search

> :note:
> Only CSV format is returned as of now 

Check [open issues](https://github.com/cert-orangecyberdefense/ocd-datalake-rs/issues) to see what is planned
## Installation
put in Cargo.toml:
```
[dependencies]
ocd_datalake_rs = "0.1.0"
```

## Usage

Example: Lookup IOCs
````rust
    let mut dtl = Datalake::new(
        username,
        password,
        DatalakeSetting::prod(),
    );

    let atom_values: Vec<String> = vec![
        "620c28ece75af2ea227f195fc45afe109ff9f5c876f2e4da9e0d4f4aad68ee8e".to_string(),
        "ef3363dfe2515b826584ab53c4bb7812".to_string(),
        "jeithe7eijeefohch3qu.probes.site".to_string(),
        "8.8.8.8".to_string(),
    ];
    let csv_result = dtl.bulk_lookup(atom_values);
    println!("{csv_result:#?}");
````

check [all the examples](https://github.com/cert-orangecyberdefense/ocd-datalake-rs/tree/master/examples) to see the full list of functionality in action.

## Contribute

All contributions and/or feedbacks are welcome to improve the code and the package.  
Please [open an issue](https://github.com/cert-orangecyberdefense/ocd-datalake-rs/issues/new) to start the discussion.
