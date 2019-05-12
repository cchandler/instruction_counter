extern crate capstone;
extern crate elf;

use capstone::prelude::*;

use sha2::{Sha256, Digest};

use serde::Serialize;

use std::fs::File;
use std::io::Read;
use std::env;
use std::collections::HashMap;

#[derive(Serialize)]
struct AnalysisResult {
    filename: String,
    sha256: String,
    instruction_count: u32,
    instructions: HashMap<String, u32>,
}
/*
/// Print register names
fn reg_names<T, I>(cs: &Capstone, regs: T) -> String
where
    T: Iterator<Item = I>,
    I: Into<RegId>,
{
    let names: Vec<String> = regs.map(|x| cs.reg_name(x.into()).unwrap()).collect();
    names.join(", ")
}

/// Print instruction group names
fn group_names<T, I>(cs: &Capstone, regs: T) -> String
where
    T: Iterator<Item = I>,
    I: Into<InsnGroupId>,
{
    let names: Vec<String> = regs.map(|x| cs.group_name(x.into()).unwrap()).collect();
    names.join(", ")
}*/

fn analyze(filename: String) -> CsResult<()> {
    println!("Analyzing {}", filename);

    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Att)
        .detail(true)
        .build()?;

    //let mut bytes_count: i32;
    let mut buffer = Vec::new();

    let path_to_file = filename;

    // Discover some elf properties
    let elf_file = match elf::File::open_path(&path_to_file) {
        Ok(f) => f,
        Err(e) => panic!("Error: {:?}", e),
    };

    let text_scn = match elf_file.get_section(".text") {
        Some(s) => s,
        None => panic!("Failed to look up .text section"),
    };

    let text_section_offset = text_scn.shdr.offset as usize;
    let text_section_size = text_scn.shdr.size as usize;
    println!("Text segment begins at 0x{:x?} and has size 0x{:x?}",text_scn.shdr.offset, text_scn.shdr.size);

    let _sym_tab = match elf_file.get_section(".symtab") {
        Some(s) => {
            println!("Symbol table was included...");

            let symbols = elf_file.get_symbols(s).expect("Should have read symbol table");

            let mut main_offset: usize = 0x00;
            let mut main_size: usize = 0x00;
            for x in symbols {
                if x.name == "main" && x.shndx == 14 {
                    main_offset = x.value as usize;
                    main_size = x.size as usize;
                }
            }
            println!("Main offset 0x{:x?} and size 0x{:x?}", main_offset, main_size);
            true
        },
        None => {
            println!("Symbol table was stripped. Skipping analysis.");
            false
        },
    };

    let mut file = File::open(&path_to_file).expect("Unable to open example file");

    //bytes_count = 0;
    buffer.clear();
    file.read_to_end(&mut buffer).expect("Unable to read file to buffer");

    let from_disk: &[u8] = &buffer;

    let mut hasher = Sha256::new();
    hasher.input(&from_disk);

    let result = hasher.result();
    let sha256_as_hex: String = result.into_iter().map(|d| format!("{:02x}", d)).collect();
    println!("{}", sha256_as_hex);

    let subset = &from_disk[text_section_offset..text_section_offset + text_section_size];

    let insns = cs.disasm_all(subset, text_section_offset as u64)?;
    println!("Found {} instructions", insns.len());

    let mut instructions: HashMap<String, u32> = HashMap::new();

    for i in insns.iter() {
        //println!("");
        //println!("{}", i);

        //let detail: InsnDetail = cs.insn_detail(&i);
        match i.mnemonic() {
            Some(s) => {
                //println!("{}",s);

                instructions.get_mut(s).
                    map(|count| { *count += 1;})
                    .unwrap_or_else(|| { instructions.insert(s.to_owned(), 1); });
           },
            _ => {},
        };
        //println!("{:x?}", i.mnemonic());


        /*
        let detail: InsnDetail = cs.insn_detail(&i)?;
        let output: &[(&str, String)] =
            &[
                ("read regs:", reg_names(&cs, detail.regs_read())),
                ("write regs:", reg_names(&cs, detail.regs_write())),
                ("insn groups:", group_names(&cs, detail.groups())),
            ];

        for &(ref name, ref message) in output.iter() {
            println!("    {:12} {}", name, message);
        }*/
    }

    /*for (k, v) in instructions.iter() {
        println!("{:?}: {:?}", k, v);
    }*/

    let analysis_result = AnalysisResult {
        filename:  path_to_file,
        sha256: sha256_as_hex,
        instruction_count: insns.len() as u32,
        instructions: instructions,
    };

    let json_result = serde_json::to_string(&analysis_result);
    println!("{}", json_result.unwrap());

    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    match args.len() {
        2 => {
            let filename = &args[1];
            if let Err(err) = analyze(filename.to_string()) {
                println!("Error: {}", err);
            }
        }
        _ => {
            println!("Filename is required");
        }
    }
}

