//! Client to submit a vote.
//! Requires a public_key.json, a private_uciv.json and a public_uciv.json in the project root.
//! These can be generated using [generator-rs](https://github.com/provotum/generator-rs).
//!
//! ```sh
//! USAGE:
//!     client [SUBCOMMAND]
//!
//! FLAGS:
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! SUBCOMMANDS:
//!     help           Prints this message or the help of the given subcommand(s)
//!     submit-vote    Submit a vote to the blockchain
//! ```
//!
//! # Example
//!
//! ## Submitting a vote
//!
//! In order to submit a vote to the blockchain, some prerequisites must be met:
//! * The voting authorities must have created and published a public key by which votes are encrypted.
//!   This public key must be present in the same directory as this binary and called `public_key.json`.
//! * A registrar must have created universal cast-as-intended verifiability (UCIV) information which
//!   is tight to a specific voter and voting option. This information must be contained in the
//!   files `private_uciv.json` and `public_uciv.json` in the binary's directory.
//!
//! Then, you can vote by using the following  command:
//!
//! ```sh
//!  client_rs submit-vote [yes | no] [voter_idx] [peer_address]
//! ```
//!
//! 1. The first argument of the `submit-vote` sub-command is the chosen vote. As of now, these
//!    are only binary, i.e. yes or no.
//! 2. The second argument is called `voter_idx` and reflects the index of the voter within
//!    the public and private UCIV. This is required in order to create a valid Cast-as-Intended
//!    proof.
//! 3. Third, the address of a running blockchain node has to be provided. Such an address
//!    must follow the format of `<IPv4>:<Port>`, e.g. `127.0.0.1:3000`.
//!
//! Substituting these values, an invocation could look as follows:
//!
//! ```sh
//!  client_rs submit-vote yes 1 127.0.0.1:3000
//! ```
//!
//!
//! # Panics
//!
//! Panics, if the following files are missing from the binary root:
//! * public_key.json
//! * private_uciv.json
//! * public_uciv.json
//!

extern crate clap;
extern crate crypto_rs;
extern crate env_logger;
#[macro_use]
extern crate log;
extern crate node;
extern crate num;
extern crate pretty_env_logger;
extern crate serde_json;

use clap::{App, Arg, SubCommand};
use crypto_rs::arithmetic::mod_int::From;
use crypto_rs::arithmetic::mod_int::ModInt;
use crypto_rs::cai::uciv::{CaiProof, ImageSet, PreImageSet};
use crypto_rs::el_gamal::ciphertext::CipherText;
use crypto_rs::el_gamal::encryption::{encrypt, PublicKey};
use crypto_rs::el_gamal::membership_proof::MembershipProof;
use env_logger::Target;
use node::chain::transaction::Transaction;
use node::p2p::codec::{Codec, JsonCodec, Message};
use num::{One, Zero};
use num::BigInt;
use std::fs::File;
use std::path::Path;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};

fn main() {
    // init logger
    pretty_env_logger::formatted_builder().unwrap()
        //let's just set some random stuff.. for more see
        //https://docs.rs/env_logger/0.5.0-rc.1/env_logger/struct.Builder.html
        .target(Target::Stdout)
        .parse("client_rs=trace")
        .init();

    let matches = App::new("client_rs")
        .version("0.1.0")
        .author("Raphael Matile <raphael.matile@gmail.com>")
        .about("Client to submit a vote. Requires a public_key.json, a private_uciv.json and a public_uciv.json in the project root")
        .subcommand(
            SubCommand::with_name("submit-vote")
                .about("Submit a vote to the blockchain")
                .arg(Arg::with_name("vote")
                    .required(true)
                    .takes_value(true)
                    .possible_values(&["yes", "no"])
                    .index(1)
                    .help("The voting option")
                )
                .arg(Arg::with_name("voter_index")
                    .required(true)
                    .takes_value(true)
                    .index(2)
                    .help("The index of the voter in the UCIV information")
                )
                .arg(Arg::with_name("peer_address")
                    .required(true)
                    .takes_value(true)
                    .index(3)
                    .help("The peer address to which the transaction should be sent. In the form <IPv4>:<Port> ")
                )
        )
        .get_matches();

    let voting_options: Vec<ModInt> = vec![
        ModInt::from_value(BigInt::one()),
        ModInt::from_value(BigInt::zero())
    ];

    match matches.subcommand_name() {
        Some("submit-vote") => {
            let subcommand_matches = matches.subcommand_matches("submit-vote").unwrap();

            let vote: &str = subcommand_matches.value_of("vote").unwrap();
            let voter_index: i64 = subcommand_matches.value_of("voter_index").unwrap().parse::<i64>().unwrap();
            let peer_address: SocketAddr = subcommand_matches.value_of("peer_address").unwrap().parse::<SocketAddr>().unwrap();

            let pub_key: PublicKey = read_public_key();
            let vote_modint: ModInt = transform_vote(vote, pub_key.clone());
            let cipher_text: CipherText = encrypt_vote(vote_modint.clone(), pub_key.clone());
            let membership_proof: MembershipProof = gen_membership_proof(pub_key.clone(), vote_modint.clone(), cipher_text.clone(), voting_options.clone());
            let uciv: (Vec<PreImageSet>, Vec<ImageSet>) = read_uciv_info();
            let cai_proof: CaiProof = gen_cai_proof(pub_key.clone(), cipher_text.clone(), voter_index, vote_modint.clone(), voting_options.clone(), uciv.clone());

            info!("Verifying membership proof...");
            assert!(membership_proof.clone().verify(pub_key.clone(), cipher_text.clone(), voting_options.clone()));
            info!("Membership proof is valid");
            info!("Verifying cast-as-intended proof...");
            assert!(cai_proof.clone().verify(pub_key.clone(), cipher_text.clone(), uciv.1.get(voter_index as usize).unwrap().clone(), voting_options.clone()));
            info!("Cast-as-intended proof is valid");

            info!("Submitting vote to node at {:?}", peer_address.clone());
            submit_vote(voter_index as usize, cipher_text, membership_proof, cai_proof, peer_address);
        }
        Some(&_) | None => {
            // an unspecified or no command was used
            println!("{}", matches.usage())
        }
    }
}

fn read_public_key() -> PublicKey {
    let path = Path::new("./public_key.json");
    if ! path.exists() {
        error!("Missing public key file at ./public_key.json");
        panic!();
    }

    trace!("Reading public key from public_key.json");
    PublicKey::new("public_key.json")
}

fn transform_vote(vote: &str, pub_key: PublicKey) -> ModInt {
    let message: ModInt;

    match vote {
        "yes" => {
            message = ModInt::from_value_modulus(BigInt::one(), pub_key.p.value);
        }
        "no" => {
            message = ModInt::from_value_modulus(BigInt::zero(), pub_key.p.value);
        }
        &_ => {
            panic!("Invalid vote. Must be one of ['yes', 'no']")
        }
    }

    trace!("Converted plain text vote {:?} into domain value {:?}", vote, message.clone());

    message
}

fn encrypt_vote(vote: ModInt, pub_key: PublicKey) -> CipherText {
    trace!("Encrypting vote {:?}", vote.clone());
    encrypt(&pub_key, vote)
}

fn gen_membership_proof(pub_key: PublicKey, plain_text: ModInt, cipher_text: CipherText, voting_options: Vec<ModInt>) -> MembershipProof {
    trace!("Generating membership proof ensuring cipher text encrypts a vote in [0,1]");
    MembershipProof::new(pub_key, plain_text, cipher_text, voting_options)
}

fn gen_cai_proof(pub_key: PublicKey, cipher_text: CipherText, voter_index: i64, plain_text: ModInt, voting_options: Vec<ModInt>, uciv: (Vec<PreImageSet>, Vec<ImageSet>)) -> CaiProof {
    trace!("Generating cast-as-intended proof ensuring cipher text encrypts actual plain text vote");
    let pre_image_set: PreImageSet = uciv.0.get(voter_index as usize).unwrap().clone();
    let image_set: ImageSet = uciv.1.get(voter_index as usize).unwrap().clone();

    let chosen_vote_index = voting_options.iter().position(|e| e.clone() == plain_text).unwrap();

    CaiProof::new(pub_key, cipher_text, pre_image_set, image_set, chosen_vote_index, voting_options)
}

fn read_uciv_info() -> (Vec<PreImageSet>, Vec<ImageSet>) {
    let path = Path::new("./public_uciv.json");
    if ! path.exists() {
        error!("Missing public UCIV file at ./public_uciv.json");
        panic!();
    }

    let path = Path::new("./private_uciv.json");
    if ! path.exists() {
        error!("Missing private UCIV file at ./private_uciv.json");
        panic!();
    }

    // Read the input file to string.
    trace!("Reading public UCIV information from 'public_uciv.json'");
    let mut public_uciv_file = File::open("./public_uciv.json".to_owned()).unwrap();
    let mut public_uciv_buffer = String::new();
    public_uciv_file.read_to_string(&mut public_uciv_buffer).unwrap();

    let public_uciv: Vec<ImageSet> = match serde_json::from_str(&public_uciv_buffer) {
        Ok(public_uciv_data) => {
            public_uciv_data
        }
        Err(e) => {
            panic!("Failed to transform file {:?} into ImageSet: {:?}", public_uciv_file, e);
        }
    };

    trace!("Reading private UCIV information from 'private_uciv.json'");
    let mut private_uciv_file = File::open("./private_uciv.json".to_owned()).unwrap();
    let mut private_uciv_buffer = String::new();
    private_uciv_file.read_to_string(&mut private_uciv_buffer).unwrap();

    let private_uciv: Vec<PreImageSet> = match serde_json::from_str(&private_uciv_buffer) {
        Ok(private_uciv_data) => {
            private_uciv_data
        }
        Err(e) => {
            panic!("Failed to transform file {:?} into PreImageSet: {:?}", private_uciv_file, e);
        }
    };

    (private_uciv, public_uciv)
}

fn submit_vote(voter_idx: usize, cipher_text: CipherText, membership_proof: MembershipProof, cai_proof: CaiProof, peer_addr: SocketAddr) {
    let stream = TcpStream::connect(peer_addr);

    match stream {
        Ok(mut stream) => {
            trace!("Successfully connected to {:?}", stream.peer_addr());

            let trx = Transaction {
                voter_idx,
                cipher_text,
                membership_proof,
                cai_proof,
            };

            trace!("Encoding transaction...");
            let request = JsonCodec::encode(Message::TransactionPayload(trx));
            trace!("Encoded transaction");

            // no multiplexing available here, so we need to close
            // the write portion of the stream before we can read from it again.
            stream.write_all(&request.into_bytes()).unwrap();
            stream.flush().unwrap();
            let shutdown_result = stream.shutdown(Shutdown::Write);
            match shutdown_result {
                Ok(()) => {}
                Err(e) => {
                    trace!("Could not shutdown outgoing write connection: {:?}", e);

                    return;
                }
            }

            trace!("Flushed transaction");

            // wait for some incoming data on the same stream
            let mut buffer_str = String::new();
            let read_result = stream.try_clone().unwrap().read_to_string(&mut buffer_str);

            match read_result {
                Ok(amount_bytes_received) => {
                    trace!("Read {:?} bytes from outgoing connection", amount_bytes_received);

                    if 0 == amount_bytes_received {
                        trace!("No bytes received on outgoing connection. Dropping connection without response");
                        let shutdown_result = stream.shutdown(Shutdown::Both);
                        match shutdown_result {
                            Ok(()) => {}
                            Err(e) => {
                                trace!("Failed to shutdown incoming connection: {:?}", e);
                            }
                        }

                        return;
                    }
                }
                Err(e) => {
                    trace!("Failed to read bytes from incoming connection: {:?}", e);

                    return;
                }
            }

            let response = JsonCodec::decode(buffer_str);
            trace!("Got response from outgoing stream: {:?}", response);

            if response == Message::TransactionAccept {
                info!("Successfully submitted vote to blockchain");
            } else {
                warn!("Your vote may not have been accepted. Please try again.");
            }
        }
        Err(e) => {
            warn!("Failed to connect due to {:?}", e);
        }
    }
}