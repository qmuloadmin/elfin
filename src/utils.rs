// These are hard-coded to little-endian, now
pub fn bytes_to_u16(bytes: [u8; 2]) -> u16 {
    bytes[0] as u16 | (bytes[1] as u16) << 8
}

pub fn bytes_to_u32(bytes: [u8; 4]) -> u32 {
    bytes[0] as u32 | (bytes[1] as u32) << 8 | (bytes[2] as u32) << 16 | (bytes[3] as u32) << 24
}

pub fn bytes_to_u64(bytes: [u8; 8]) -> u64 {
    let mut num = 0;
    for (i, each) in bytes.into_iter().enumerate() {
        num = num | (*each as u64) << (i as u64) * 8;
    }
    num
}

pub fn read_null_term_str(start: u32, bytes: &Vec<u8>) -> String {
    let mut s = String::new();
    for &byte in &bytes[start as usize..] {
        if byte == 0 {
            break;
        }
        s.push_str(&(byte as char).to_string());
    }
    s
}
