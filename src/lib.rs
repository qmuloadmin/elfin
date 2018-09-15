#[cfg(test)]
mod tests;
mod utils;

use std::io;
use std::fs::File;
use std::io::prelude::*;

// Constants mapping original C-constant values
const EIDENTSIZE: usize = 16;
const SHN_UNDEF: u16 = 0;

// Constants for various file types, machine types, etc
const TYPE_NONE: u16 = 0;
const TYPE_RELO: u16 = 1;
const TYPE_EXEC: u16 = 2;
const TYPE_DYN: u16 = 3;
const TYPE_CORE: u16 = 4;

#[derive(Debug)]
pub struct ElfError{
    desc: String,
    cause: Option<std::io::Error>
}

impl std::convert::From<io::Error> for ElfError {
    fn from(orig: io::Error) -> Self {
        ElfError{
            desc: String::from("An IO Error occurred"),
            cause: Some(orig)
        }
    }
}

impl std::error::Error for ElfError {
    fn description(&self) -> &str {
        &self.desc
    }
    fn cause(&self) -> Option<&std::error::Error> {
        match &self.cause {
            Some(x) => Some(x),
            None => None
        }
    }
}

impl std::fmt::Display for ElfError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.desc)
    }
}

// ElfHeaders represent the ELF headers of a given file
pub struct ElfHeaders {
    pub ident: [char; EIDENTSIZE],
    pub file_type: u16,
    pub machine: u16,
    pub version: u32,
    pub entry_addr: u64,
    pub program_offset: u64,
    pub section_offset: u64,
    pub cpu_flags: u32,
    pub ehead_size: u16,
    pub pheader_size: u16,
    pub pheader_count: u16,
    pub sheader_size: u16,
    pub sheader_count: u16,
    pub str_header_index: u16, 
}

impl std::fmt::Display for ElfHeaders {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f,
"Magic Bits: \t\t\t {:?}
File Type: \t\t\t {}
Version: \t\t\t {}
Entry Address: \t\t\t 0x{:x}
Start of Program Headers: \t {}
Start of Section headers: \t {}
CPU Flags: \t\t\t {}
ELF Header Size: \t\t {}
Prog Header Size: \t\t {}
Num Prog Headers: \t\t {}
Sect Header Size: \t\t {}
Num Sect Headers: \t\t {}
String Header Id: \t\t {}",
            self.ident,
            self.type_to_string(),
            self.version,
            self.entry_addr,
            self.program_offset,
            self.section_offset,
            self.cpu_flags,
            self.ehead_size,
            self.pheader_size,
            self.pheader_count,
            self.sheader_size,
            self.sheader_count,
            self.str_header_index
        )
    }
}

impl ElfHeaders {
    pub fn new() -> Self {
        ElfHeaders{
            ident: [0 as char; EIDENTSIZE],
            file_type: 0,
            machine: 0,
            version: 0,
            entry_addr: 0,
            program_offset: 0,
            section_offset: 0,
            cpu_flags: 0,
            ehead_size: 0,
            pheader_size: 0,
            pheader_count: 0,
            sheader_size: 0,
            sheader_count: 0,
            str_header_index: 0,
        }
    }

    fn type_to_string(&self) -> String {
        match self.file_type {
            x if x == TYPE_NONE => String::from("No file type"),
            x if x == TYPE_RELO => String::from("Relocatable File"),
            x if x == TYPE_EXEC => String::from("Executable File"),
            x if x == TYPE_DYN => String::from("Shared Object File"),
            x if x == TYPE_CORE => String::from("Core file"),
            _ => String::from("Unknown/Unsupported Type")
        }
    }
    
    // Read in headers from a binary ELF file by name
    pub fn from_file(&mut self, f: &mut File) -> Result<(), ElfError> {
        let mut buffer = [0; EIDENTSIZE];
        f.read(&mut buffer)?;
        // Check to ensure the file's magic bits are set to ELF spec
        if buffer[0..4] != [0x7f, 0x45, 0x4c, 0x46] {
            return Err(ElfError{
                desc: String::from("Invalid binary format; not an ELF file"),
                cause: None
            });
        }
        for (i, each) in buffer.into_iter().enumerate() {
            self.ident[i] = *each as char;
        };
        // Read in the next several u16s
        let mut buffer = [0; 2];
        f.read(&mut buffer)?;
        self.file_type = utils::bytes_to_u16(buffer);
        f.read(&mut buffer)?;
        self.machine = utils::bytes_to_u16(buffer);
        let mut buffer = [0; 4];
        f.read(&mut buffer)?;
        self.version = utils::bytes_to_u32(buffer);
        // 64 bit ELF uses 64 bit address size. 32 uses 32. Need to update this to support both
        // TODO will probably need an initial scan of magic bits to determine arch
        // then an appropriate struct
        let mut buffer64 = [0; 8];
        f.read(&mut buffer64)?;
        self.entry_addr = utils::bytes_to_u64(buffer64);
        f.read(&mut buffer64)?;
        self.program_offset = utils::bytes_to_u64(buffer64);
        f.read(&mut buffer64)?;
        self.section_offset = utils::bytes_to_u64(buffer64);
        f.read(&mut buffer)?;
        self.cpu_flags = utils::bytes_to_u32(buffer);
        let mut buffer = [0; 2];
        f.read(&mut buffer)?;
        self.ehead_size = utils::bytes_to_u16(buffer);
        f.read(&mut buffer)?;
        self.pheader_size = utils::bytes_to_u16(buffer);
        f.read(&mut buffer)?;
        self.pheader_count = utils::bytes_to_u16(buffer);
        f.read(&mut buffer)?;
        self.sheader_size = utils::bytes_to_u16(buffer);
        f.read(&mut buffer)?;
        self.sheader_count = utils::bytes_to_u16(buffer);
        f.read(&mut buffer)?;
        self.str_header_index = utils::bytes_to_u16(buffer);
        Ok(())
    }

    pub fn sections_from_file(&self, f:&mut File) -> Result<Vec<SectionHeader>, ElfError> {
        let mut headers = vec![];
        let mut str_tbl_bytes = vec![];
        for i in 0..self.sheader_count {
            let mut section_header = SectionHeader::new(self.section_offset + (self.sheader_size* i) as u64);
            section_header.from_file(f)?;
            headers.push(section_header);
        }
        // get the string header table and verify that its type is 3
        {
            let str_tbl = &headers[self.str_header_index as usize];
            if str_tbl.stype != 3 {
                return Err(ElfError{
                    desc: String::from("String Header Table is not a string table type section"),
                    cause: None
                })
            }
            f.seek(io::SeekFrom::Start(str_tbl.offset))?;
            let mut buffer = [0; 8]; // read 8 bytes at a time until we've exceeded length of str_tbl
            let mut i = 0;
            while i < str_tbl.size {
                f.read(&mut buffer)?;
                i += 8;
                str_tbl_bytes.extend_from_slice(&buffer);
            }
        }
        // expand each sections name from the string table data 
        for header in &mut headers {
            let start = header.name;
            let name = utils::read_null_term_str(start, &str_tbl_bytes);
            header.str_name = name;
        }
        Ok(headers)
    }

}

pub struct SectionHeader {
    ptr: u64,
    str_name: String,
    pub name: u32,
    pub stype: u32,
    pub flags: u64,
    pub img_addr: u64,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
    pub info: u32,
    pub align: u64,
    pub entry_size: u64,
}

impl SectionHeader {

    pub fn new(location: u64) -> Self {
        SectionHeader{
            ptr: location,
            str_name: String::from(""),
            name: 0,
            stype: 0,
            flags: 0,
            img_addr: 0,
            offset: 0,
            size: 0,
            link: 0,
            info: 0,
            align: 0,
            entry_size: 0,
        }
    }

    pub fn from_file(&mut self, f: &mut File) -> Result<(), ElfError> {
        f.seek(io::SeekFrom::Start(self.ptr))?;
        let mut buffer = [0; 4];
        f.read(&mut buffer)?;
        self.name = utils::bytes_to_u32(buffer);
        f.read(&mut buffer)?;
        self.stype = utils::bytes_to_u32(buffer);
        let mut buffer64 = [0; 8];
        f.read(&mut buffer64)?;
        self.flags = utils::bytes_to_u64(buffer64);
        f.read(&mut buffer64)?;
        self.img_addr = utils::bytes_to_u64(buffer64);
        f.read(&mut buffer64)?;
        self.offset = utils::bytes_to_u64(buffer64);
        f.read(&mut buffer64)?;
        self.size = utils::bytes_to_u64(buffer64);
        Ok(())
    }
}

impl std::fmt::Display for SectionHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, 
"name: {} \t\t type: {} \t\t flags: {}
address: {:x} \t offset: {:x} \t\t size: {:x}",
self.str_name,
self.stype,
self.flags,
self.img_addr,
self.offset,
self.size)
    }
}