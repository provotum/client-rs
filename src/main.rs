#[macro_use]
extern crate log;
extern crate pretty_env_logger;
extern crate env_logger;
extern crate clap;
extern crate node;
extern crate crypto_rs;
extern crate serde_json;
extern crate num;

use env_logger::Target;
use std::net::{SocketAddr, TcpStream, Shutdown};
use std::sync::{Arc, Mutex};
use std::iter::FromIterator;
use std::fs::File;
use std::io::{Read, Write};
use std::borrow::BorrowMut;

use node::p2p::codec::{Codec, JsonCodec, Message};
use node::config::genesis::Genesis;
use node::chain::transaction::Transaction;

use num::{Zero, One};
use num::BigInt;
use crypto_rs::arithmetic::mod_int::ModInt;
use crypto_rs::el_gamal::ciphertext::CipherText;
use crypto_rs::el_gamal::encryption::{encrypt, PublicKey};
use crypto_rs::el_gamal::membership_proof::MembershipProof;
use crypto_rs::cai::uciv::{PreImageSet, ImageSet, CaiProof};
use crypto_rs::arithmetic::mod_int::From;

use clap::{Arg, App, SubCommand};

fn main() {
    // init logger
    pretty_env_logger::formatted_builder().unwrap()
        //let's just set some random stuff.. for more see
        //https://docs.rs/env_logger/0.5.0-rc.1/env_logger/struct.Builder.html
        .target(Target::Stdout)
        .parse("client=trace")
        .init();

    let matches = App::new("client")
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

            info!("Verifying membership proof");
            assert!(membership_proof.clone().verify(pub_key.clone(), cipher_text.clone(), voting_options.clone()));
            info!("Verifying cast-as-intended proof");
            assert!(cai_proof.clone().verify(pub_key.clone(), cipher_text.clone(), uciv.1.get(voter_index as usize).unwrap().clone(), voting_options.clone()));

        },
        Some(&_) | None => {
            // an unspecified or no command was used
            println!("{}", matches.usage())
        },
    }
}

fn read_public_key() -> PublicKey {
    PublicKey::new("public_key.json")
}

fn transform_vote(vote: &str, pub_key: PublicKey) -> ModInt {
    let message: ModInt;

    match vote {
        "yes" =>  {
            message = ModInt::from_value_modulus(BigInt::one(), pub_key.p.value);
        },
        "no" => {
            message = ModInt::from_value_modulus(BigInt::zero(), pub_key.p.value);
        },
        &_ => {
            panic!("Invalid vote. Must be one of ['yes', 'no']")
        }
    }

    message
}

fn encrypt_vote(vote: ModInt, pub_key: PublicKey) -> CipherText {
    encrypt(&pub_key, vote)
}

fn gen_membership_proof(pub_key: PublicKey, plain_text: ModInt, cipher_text: CipherText, voting_options: Vec<ModInt>) -> MembershipProof {
    MembershipProof::new(pub_key, plain_text, cipher_text, voting_options)
}

fn gen_cai_proof(pub_key: PublicKey, cipher_text: CipherText, voter_index: i64, plain_text: ModInt, voting_options: Vec<ModInt>, uciv: (Vec<PreImageSet>, Vec<ImageSet>)) -> CaiProof{
    let pre_image_set: PreImageSet = uciv.0.get(voter_index as usize).unwrap().clone();
    let image_set : ImageSet = uciv.1.get(voter_index as usize).unwrap().clone();

    let chosen_vote_index = voting_options.iter().position(|e| e.clone() == plain_text).unwrap();

    CaiProof::new(pub_key, cipher_text, pre_image_set, image_set, chosen_vote_index, voting_options)
}

fn read_uciv_info() -> (Vec<PreImageSet>, Vec<ImageSet>) {
    // Read the input file to string.
    let mut public_uciv_file = File::open("./public_uciv.json".to_owned()).unwrap();
    let mut public_uciv_buffer = String::new();
    public_uciv_file.read_to_string(&mut public_uciv_buffer).unwrap();

    let public_uciv: Vec<ImageSet> = match serde_json::from_str(&public_uciv_buffer) {
        Ok(public_uciv_data) => {
            public_uciv_data
        },
        Err(e) => {
            panic!("Failed to transform file {:?} into ImageSet: {:?}", public_uciv_file, e);
        }
    };

    let mut private_uciv_file = File::open("./private_uciv.json".to_owned()).unwrap();
    let mut private_uciv_buffer = String::new();
    private_uciv_file.read_to_string(&mut private_uciv_buffer).unwrap();

    let private_uciv: Vec<PreImageSet> = match serde_json::from_str(&private_uciv_buffer) {
        Ok(private_uciv_data) => {
            private_uciv_data
        },
        Err(e) => {
            panic!("Failed to transform file {:?} into ImageSet: {:?}", private_uciv_file, e);
        }
    };

    (private_uciv, public_uciv)
}

fn submit_vote() {
    let peer_addr: SocketAddr = "127.0.0.1:3001".parse().unwrap();

    let stream = TcpStream::connect(peer_addr);

    match stream {
        Ok(mut stream) => {
            trace!("Successfully connected to {:?}", stream.peer_addr());

            let trx = Transaction {
                from: "hello".to_string()
            };

            let request = JsonCodec::encode(Message::TransactionPayload(trx));

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

            trace!("flushed written data");

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
        }
        Err(e) => {
            warn!("Failed to connect due to {:?}", e);
        }
    }
}