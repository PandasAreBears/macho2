mod flags;
mod header;
mod load_command;
mod parser;

use header::MachHeader;
use macho2::LoadCommand;

use std::{env, fs::File, io::Read};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <file_path>", args[0]);
        return;
    }

    let file_path = &args[1];
    let mut file = match File::open(file_path) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("Failed to open file: {}", e);
            return;
        }
    };

    let mut buffer = Vec::new();
    if let Err(e) = file.read_to_end(&mut buffer) {
        eprintln!("Failed to read file: {}", e);
        return;
    }

    let (bytes, header) = MachHeader::parse(&buffer).unwrap();
    println!("Parsed MachHeader: {:#?}", header);

    let mut cmds = Vec::new();
    let mut remaining_bytes = bytes;
    for _ in 0..header.ncmds() {
        let (bytes, cmd) = LoadCommand::parse(remaining_bytes).unwrap();
        println!("Command: {:#?}", cmd);
        cmds.push(cmd);
        remaining_bytes = bytes;
    }
}
