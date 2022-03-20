extern crate dns_parser;

use std::env;
use std::error::Error;
use std::net::UdpSocket;
use std::process;

use std::net::{IpAddr, Ipv4Addr};

use dns_parser::rdata;
use dns_parser::{Builder, Packet, RData, ResponseCode};
use dns_parser::{QueryClass, QueryType};

fn main() {
    let mut code = 0;
    for name in env::args().skip(1) {
        match resolve(&name, 0) {
            Ok(ip) => println!("{}", ip),
            Err(e) => {
                eprintln!("Error resolving {:?}: {}", name, e);
                code = 1;
            }
        }
    }
    process::exit(code);
}

fn query_server<'a>(server_addr: &IpAddr, name: &str, response_buf: &'a mut Vec<u8>) -> Result<Packet<'a>, Box<dyn Error>> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.connect(server_addr.to_string() + ":53")?;

    let mut query = Builder::new_query(1, true);
    query.add_question(name, false, QueryType::A, QueryClass::IN);

    sock.send(&query.build().map_err(|_| "truncated packet")?)?;
    sock.recv(response_buf)?;

    Ok(Packet::parse(response_buf)?)
}

fn get_answer(response: &Packet) -> Option<IpAddr> {
    if response.answers.len() > 0 {
        for ans in &response.answers {
            match ans.data {
                RData::A(rdata::a::Record(ip)) => {
                    return Some(IpAddr::V4(ip))
                }
                _ => return None
            }
        }
    }
    None
}

fn get_additional(response: &Packet) -> Option<IpAddr> {
    if response.additional.len() > 0 {
        for glue in &response.additional {
            if let RData::A(rdata::a::Record(ip)) = glue.data {
                return Some(IpAddr::V4(ip))
            }
        }
    }
    None
}

fn get_ns(response: &Packet) -> Option<String> {
    if response.nameservers.len() > 0 {
        for ns in &response.nameservers {
            if let RData::NS(rdata::ns::Record(name)) = ns.data {
                return Some(name.to_string())
            }
        }
    }
    None
}


// TODO other ideas:
// - put all of this in a lib.rs
// - add a server functionallity in a lib.rs (then kick it off depending of stdargs when starting the app)
// - then make udp server multithreaded (async?)
// - then add other types support (CNAME, AAAA, MX, etc.)
// - then introduce some multi request logic (ask to several root server, keep a map on the faster ones to answer)

fn resolve(name: &str, debug_indent: u8) -> Result<IpAddr, Box<dyn Error>> {
    let mut server_ip = IpAddr::V4(Ipv4Addr::new(198, 41, 0, 4));
    let mut response_buf = vec![0u8; 4096];
    let indent: String = (0..debug_indent*2).into_iter().map(|_| ' ').collect();
    
    loop {
        println!("{}resolving {}@{}", indent, name, server_ip);
        let response = query_server(&server_ip, name, &mut response_buf)?;

        if response.header.response_code != ResponseCode::NoError {
            return Err(response.header.response_code.into());
        }

        if let Some(ip) = get_answer(&response) {
            println!("{} -> {} resolved into {}", indent, name, ip);
            return Ok(ip)
        } else if let Some(additional) = get_additional(&response) {
            println!("{} -> ask to ip {}", indent, additional);
            server_ip = additional
        } else if let Some(ns) = get_ns(&response) {
            println!("{} -> ask to ns {}", indent, ns);
            server_ip = resolve(&ns, debug_indent + 1)?.to_owned()
        } else {
            break;
        }

        // So we don't reallocate a buffer at each iteration - but we need to clear it to avoid confusing parser code
        response_buf.clear();
        response_buf.resize(4096, 0);
    }

    Err("nothing interesting found.".into())
}