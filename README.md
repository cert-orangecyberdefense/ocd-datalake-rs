# OCD_DATALAKE_RS
`ocd_datalake_rs` is a Rust library to interact with Orange Cyberdefense's [Datalake](https://datalake.cert.orangecyberdefense.com/).  

## Functionalities implemented
* Bulk lookup
* Bulk search

> **Note**
> Only CSV format is returned as of now 

Check [open issues](https://github.com/cert-orangecyberdefense/ocd-datalake-rs/issues) to see what is planned
## Installation
put in Cargo.toml:
```toml
[dependencies]
ocd_datalake_rs = "0.3.0-pre.2"
```

## Using custom CA Certificates
By default, this library uses rustls-tls-native-roots, which enables reqwest to trust the system's native certificate store.
However, if you need to specify a custom CA file, you can set the SSL_CERT_FILE or SSL_CERT_DIR environment variables 
before running your application:
```bash
export SSL_CERT_FILE=/path/to/custom-ca.pem
export SSL_CERT_DIR=/path/to/certs/
```
On Windows : 
```powershell
$env:SSL_CERT_FILE="C:\path\to\custom-ca.pem"
$env:SSL_CERT_DIR="C:\path\to\certs\"
```
This allows the reqwest client to properly validate HTTPS connections using your organization's trusted certificates.

## Usage

Example: Lookup IOCs
````rust
    let mut dtl = Datalake::new(
        username,
        password,
        None,
        DatalakeSetting::prod(),
    );

    let atom_values: Vec<String> = vec![
        "620c28ece75af2ea227f195fc45afe109ff9f5c876f2e4da9e0d4f4aad68ee8e".to_string(),
        "ef3363dfe2515b826584ab53c4bb7812".to_string(),
        "jeithe7eijeefohch3qu.probes.site".to_string(),
        "8.8.8.8".to_string(),
    ];
    let csv_result = dtl.bulk_lookup(atom_values, "file");
    println!("{csv_result:#?}");
````
> Note: Defining the long_term_token parameter overwrites the username and password parameters

check [all the examples](https://github.com/cert-orangecyberdefense/ocd-datalake-rs/tree/master/examples) to see the full list of functionality in action.

## Use a Proxy

To use a http or https proxy, simply define either HTTP_PROXY or HTTPS_PROXY env variables to be your proxy url. If you ever stop using the proxy, don't forget to unset both env variables.
```Bash
export HTTP_PROXY='http://example-proxy.test'
unset HTTP_PROXY
```

## Contribute

All contributions and/or feedbacks are welcome to improve the code and the package.  
Please [open an issue](https://github.com/cert-orangecyberdefense/ocd-datalake-rs/issues/new) to start the discussion.
