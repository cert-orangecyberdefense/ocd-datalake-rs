# Contributing

When contributing to this repository, please first discuss the change you wish to make via issue, email, or any other method with the owners of this repository before making a change.

## Manual tests

In order to run some manual tests and the examples, you may first enter a shell: 
```Bash
make build
make shell
```
Then run the examples on the preprod Datalake API:
```Bash
cargo run --example bulk_search
cargo run --example custom_config
cargo run --example extract_atoms
cargo run --example lookup_threats
```
Those examples require your username and password, or longterm token environment variable to be set.

## Automatic tests

Automatic tests are launched using this command: 
```Bash
make test
```
This only requires the .env file to exist