mod resolver;

use std::env;
use std::process;

fn main() {
    let mut code = 0;
    for name in env::args().skip(1) {
        match resolver::resolve(&name, 0) {
            Ok(ip) => println!("{}", ip),
            Err(e) => {
                eprintln!("Error resolving {:?}: {}", name, e);
                code = 1;
            }
        }
    }
    process::exit(code);
}