#[cfg(test)]
mod tests;
mod utils;

use std::fs::File;
use std::io;
use std::io::prelude::*;

// Constants mapping original C-constant values
const EIDENTSIZE: usize = 16;
const SHN_UNDEF: u16 = 0;

// Section Header types
const SHT_NULL: u32 = 0;
const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_RELA: u32 = 4;
const SHT_HASH: u32 = 5;
const SHT_DYN: u32 = 6;
const SHT_NOTE: u32 = 7;
const SHT_NOBITS: u32 = 8;
const SHT_REL: u32 = 9;

// Constants for various file types, machine types, etc
const TYPE_NONE: u16 = 0;
const TYPE_RELO: u16 = 1;
const TYPE_EXEC: u16 = 2;
const TYPE_DYN: u16 = 3;
const TYPE_CORE: u16 = 4;

#[derive(Debug)]
pub struct ElfError {
    desc: String,
    cause: Option<std::io::Error>,
}

impl std::convert::From<io::Error> for ElfError {
    fn from(orig: io::Error) -> Self {
        ElfError {
            desc: String::from("An IO Error occurred"),
            cause: Some(orig),
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
            None => None,
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
        write!(
            f,
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
        ElfHeaders {
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
            TYPE_NONE => String::from("No file type"),
            TYPE_RELO => String::from("Relocatable File"),
            TYPE_EXEC => String::from("Executable File"),
            TYPE_DYN => String::from("Shared Object File"),
            TYPE_CORE => String::from("Core file"),
            _ => String::from("Unknown/Unsupported Type"),
        }
    }

    // Read in headers from a binary ELF file by name
    pub fn from_file(&mut self, f: &mut File) -> Result<(), ElfError> {
        let mut buffer = [0; EIDENTSIZE];
        f.read(&mut buffer)?;
        // Check to ensure the file's magic bits are set to ELF spec
        if buffer[0..4] != [0x7f, 0x45, 0x4c, 0x46] {
            return Err(ElfError {
                desc: String::from("Invalid binary format; not an ELF file"),
                cause: None,
            });
        }
        for (i, each) in buffer.into_iter().enumerate() {
            self.ident[i] = *each as char;
        }
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

    pub fn sections_from_file(&self, f: &mut File) -> Result<Vec<Section>, ElfError> {
        let mut headers = vec![];
        // Read in each header and parse them
        for i in 0..self.sheader_count {
            let mut section_header =
                SectionHeader::new(self.section_offset + (self.sheader_size * i) as u64);
            section_header.from_file(f)?;
            headers.push(section_header);
        }
        let mut sections = Vec::with_capacity(headers.len());
        // Read in data for each header
        for header in headers.into_iter() {
            let mut buffer = vec![0; header.size as usize];

            if header.sec_type != SectionType::NoBits {
                // move file pointer to start of section data
                f.seek(io::SeekFrom::Start(header.offset))?;
                // allocate new buffer for the size of the section data
                let read = f.read(&mut buffer)?;
                if read != buffer.len() {
                    return Err(ElfError{
                        desc: format!("Failed to read {} (size) bytes from section in file", buffer.capacity()),
                        cause: None,
                    })
                }
            }
            sections.push(Section{
                header: header,
                data: buffer,
            });
        }

        // get the string header table and verify that its type is StringTable
        let mut string_table_data: Vec<u8>;
        {
            let str_tbl = &sections[self.str_header_index as usize];
            if str_tbl.header.sec_type != SectionType::StringTable {
                return Err(ElfError {
                    desc: String::from("String Header Table is not a string table type section"),
                    cause: None,
                });
            }
            string_table_data = str_tbl.data.clone();
        }
        // expand each sections name from the string table data
        for section in &mut sections {
            let start = section.header.name;
            let name = utils::read_null_term_str(start, &string_table_data);
            section.header.str_name = name;
        }
        Ok(sections)
    }
}

pub struct Section {
    pub header: SectionHeader,
    pub data: Vec<u8>,
}

impl std::fmt::Display for Section {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}\n",self.header)
    }
}

pub struct SectionHeader {
    ptr: u64,
    pub str_name: String,
    name: u32,
    i_type: u32,
    pub sec_type: SectionType,
    pub flags: u64,
    pub img_addr: u64,
    offset: u64,
    size: u64,
    link: u32,
    pub info: u32,
    align: u64,
    pub entry_size: u64,
}

#[derive(PartialEq)]
pub enum SectionType {
    Unused,
    ProgramData,
    SymbolTable,
    StringTable,
    Rela,
    Hash,
    Dynamic,
    Notes,
    NoBits,
    Rel,
    Unknown
}

impl SectionHeader {
    pub fn new(location: u64) -> Self {
        SectionHeader {
            ptr: location,
            str_name: String::from(""),
            sec_type: SectionType::Unknown,
            name: 0,
            i_type: 0,
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
        self.i_type = utils::bytes_to_u32(buffer);
        // set type from raw integer type
        self.sec_type = match self.i_type {
            SHT_NULL => SectionType::Unused,
            SHT_PROGBITS => SectionType::ProgramData,
            SHT_SYMTAB => SectionType::SymbolTable,
            SHT_STRTAB => SectionType::StringTable,
            SHT_RELA => SectionType::Rela,
            SHT_HASH => SectionType::Hash,
            SHT_DYN => SectionType::Dynamic,
            SHT_NOTE => SectionType::Notes,
            SHT_NOBITS => SectionType::NoBits,
            SHT_REL => SectionType::Rel,
            _ => SectionType::Unknown
        };
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

    fn type_to_string(&self) -> String {
        match &self.sec_type {
            SectionType::Unused => "Unused",
            SectionType::ProgramData => "Program Data",
            SectionType::SymbolTable => "Linker Symbol Table",
            SectionType::StringTable => "String Table",
            SectionType::Rela => "Relocation (RELA)",
            SectionType::Hash => "Symbol Hash Table",
            SectionType::Dynamic => "Dynamic Linking Table",
            SectionType::Notes => "Notes",
            SectionType::NoBits => "No Space",
            SectionType::Rel => "Relocation (REL)",
            SectionType::Unknown => "Unknown Type",
        }.to_owned()
    }

    fn flags_to_string(&self) -> String {
        let mut flags = ['-'; 5];
        flags[0] = '[';
        if self.flags & 0b100 == 0b100 {
            flags[1] = 'X';
        }
        if self.flags & 0b010 == 0b010 {
            flags[2] = 'A';
        }
        if self.flags & 0b001 == 0b001 {
            flags[3] = 'W';
        }
        flags[4] = ']';
        flags.iter().collect()
    }
}

impl std::fmt::Display for SectionHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "name: {:25} type: {:20} flags: {}
address: {:<22x} offset: {:<18x} size: {:x}",
            self.str_name,
            self.type_to_string(),
            self.flags_to_string(),
            self.img_addr,
            self.offset,
            self.size
        )
    }
}
