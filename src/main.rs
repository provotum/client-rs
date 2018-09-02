#[macro_use]
extern crate log;
extern crate simple_logger;

extern crate node;

use std::net::{SocketAddr, TcpStream, Shutdown};
use std::io::Write;
use std::io::Read;
use std::sync::{Arc, Mutex};
use std::iter::FromIterator;

use node::p2p::codec::{Codec, JsonCodec, Message};
use node::protocol::clique::{CliqueProtocol, ProtocolHandler};
use node::config::genesis::Genesis;
use node::chain::transaction::Transaction;


fn main() {
    // init logger
    simple_logger::init().unwrap();

    let peer_addr: SocketAddr = "127.0.0.1:3000".parse().unwrap();

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