client-rs
=========
This client provides an easy way to submit a vote to the blockchain.
To generate all required cryptographic proofs, it requires a
`public_key.json`, a `private_uciv.json` and a `public_uciv.json` 
in the same folder as the binary is executed.

These values can be generated using [generator-rs](https://github.com/provotum/generator-rs).

## Usage
```sh
USAGE:
    client [SUBCOMMAND]
FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information
SUBCOMMANDS:
    help           Prints this message or the help of the given subcommand(s)
    submit-vote    Submit a vote to the blockchain
```

### Submitting a vote
In order to submit a vote to the blockchain, some prerequisites must be met:
* The voting authorities must have created and published a public key by which votes are encrypted.
  This public key must be present in the same directory as this binary and called `public_key.json`.
* A registrar must have created universal cast-as-intended verifiability (UCIV) information which
  is tight to a specific voter and voting option. This information must be contained in the
  files `private_uciv.json` and `public_uciv.json` in the binary's directory.
Then, you can vote by using the following  command:
```sh
 client_rs submit-vote [yes | no] [voter_idx] [peer_address]
```
1. The first argument of the `submit-vote` sub-command is the chosen vote. As of now, these
   are only binary, i.e. yes or no.
2. The second argument is called `voter_idx` and reflects the index of the voter within
   the public and private UCIV. This is required in order to create a valid Cast-as-Intended
   proof.
3. Third, the address of a running blockchain node has to be provided. Such an address
   must follow the format of `<IPv4>:<Port>`, e.g. `127.0.0.1:3000`.
Substituting these values, an invocation could look as follows:
```sh
 client_rs submit-vote yes 1 127.0.0.1:3000
```
### Panics
Panics, if the following files are missing from the binary root:
* `public_key.json`
* `private_uciv.json`
* `public_uciv.json`

## Development

To build the library, run 
```
cargo build
```

To generate an updated set of the docs, run
```
cargo doc --no-deps
```