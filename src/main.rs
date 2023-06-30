use std::error::Error;
use std::collections::HashMap;
use cidr_utils::cidr::Ipv4Cidr;
use std::io::Write;
use std::fs::File;
use std::io::BufWriter;

const COUNTRY_BEGIN: u32 = 16776960;
const COUNTRY_EDITION: u8 = 1;
const STANDARD_RECORD_LENGTH: u8 = 3;
const SEGMENT_RECORD_LENGTH: u8 = 3;
const COUNTRY_CODES: &'static [&'static str] = &[
    "",
    "AP", "EU", "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AN", "AO", "AQ",
    "AR", "AS", "AT", "AU", "AW", "AZ", "BA", "BB", "BD", "BE", "BF", "BG",
    "BH", "BI", "BJ", "BM", "BN", "BO", "BR", "BS", "BT", "BV", "BW", "BY",
    "BZ", "CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN",
    "CO", "CR", "CU", "CV", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM", "DO",
    "DZ", "EC", "EE", "EG", "EH", "ER", "ES", "ET", "FI", "FJ", "FK", "FM",
    "FO", "FR", "FX", "GA", "GB", "GD", "GE", "GF", "GH", "GI", "GL", "GM",
    "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY", "HK", "HM", "HN",
    "HR", "HT", "HU", "ID", "IE", "IL", "IN", "IO", "IQ", "IR", "IS", "IT",
    "JM", "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN", "KP", "KR", "KW",
    "KY", "KZ", "LA", "LB", "LC", "LI", "LK", "LR", "LS", "LT", "LU", "LV",
    "LY", "MA", "MC", "MD", "MG", "MH", "MK", "ML", "MM", "MN", "MO", "MP",
    "MQ", "MR", "MS", "MT", "MU", "MV", "MW", "MX", "MY", "MZ", "NA", "NC",
    "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR", "NU", "NZ", "OM", "PA",
    "PE", "PF", "PG", "PH", "PK", "PL", "PM", "PN", "PR", "PS", "PT", "PW",
    "PY", "QA", "RE", "RO", "RU", "RW", "SA", "SB", "SC", "SD", "SE", "SG",
    "SH", "SI", "SJ", "SK", "SL", "SM", "SN", "SO", "SR", "ST", "SV", "SY",
    "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TM", "TN", "TO", "TL",
    "TR", "TT", "TV", "TW", "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA",
    "VC", "VE", "VG", "VI", "VN", "VU", "WF", "WS", "YE", "YT", "RS", "ZA",
    "ZM", "ME", "ZW", "A1", "A2", "O1", "AX", "GG", "IM", "JE", "BL", "MF",
    "BQ", "SS"
];

struct Location {
    continent_code: String,
    country_iso_code: String
}
struct Network {
    network: Ipv4Cidr,
    country_or_continent_code: String // Fallback to continent code if country code not found
}

// Node data
#[derive(Clone)]
struct RadixTreeNodeData {
    country_or_continent_code: String
}

// Nodes
#[derive(Clone)]
enum RadixTreeNodeKind {
    Node(usize),
    Data(RadixTreeNodeData)
}

// RHS/LHS Nodes can either be not set = None, A reference to another node = Node(usize), or data = Data(usize)
#[derive(Clone)]
struct RadixTreeNode {
    segment: usize,
    lhs: Option<RadixTreeNodeKind>,
    rhs: Option<RadixTreeNodeKind>
}

struct CountryRadixTree {
    remap_continent_codes: HashMap<String, String>,
    remap_country_codes: HashMap<String, String>,
    seek_depth: u8,
    locations: HashMap<u32, Location>,
    networks: Vec<Network>,
    edition: u8,
    reclen: u8,
    segreclen: u8,
    debug: bool,
    netcount: u32,
    segments: Vec<RadixTreeNode>,
    mmdb_data_size_max: usize
}

fn as_u32_le(array: &[u8; 4]) -> u32 {
    ((array[0] as u32) <<  0) +
    ((array[1] as u32) <<  8) +
    ((array[2] as u32) << 16) +
    ((array[3] as u32) << 24)
}
fn as_u32_be(array: &[u8; 4]) -> u32 {
    ((array[0] as u32) << 24) +
    ((array[1] as u32) << 16) +
    ((array[2] as u32) <<  8) +
    ((array[3] as u32) <<  0)
}
fn as_u16_be(array: &[u8; 2]) -> u16 {
    ((array[0] as u16) <<  8) +
    ((array[1] as u16) <<  0)
}
fn as_u16_le(array: &[u8; 2]) -> u16 {
    ((array[0] as u16) <<  0) +
    ((array[1] as u16) <<  8)
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}
fn find_rsubsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).rposition(|window| window == needle)
}
fn pad_bytes ( bytes: Vec<u8>, length: usize, left_or_right: bool, byte_value: u8 ) -> Vec<u8> {
    let blen = bytes.len();
    if blen > length {
        println!("Bytes are already larger than the padding requested. bytes len {}, pad len {}", bytes.len(), length);
        std::process::exit(1);
        let empty: Vec<u8> = std::iter::repeat(byte_value).take(length).collect();
        return empty.to_vec();
    }
    let padlen = length - blen;
    
    let mut padding: Vec<u8> = std::iter::repeat(byte_value).take(padlen).collect();
    let mut padded: Vec<u8> = Vec::new();

    if left_or_right {
        padded.append(&mut padding);
        padded.append(&mut bytes.to_vec());
        return padded;
    }
    else {
        padded.append(&mut bytes.to_vec());
        padded.append(&mut padding);
        return padded;
    }
}

// Find metadata offset
fn find_metadata_offset(mmdb: &Vec<u8>) -> usize {

    let metadata_terminator: &[u8;14] = b"\xab\xcd\xefMaxMind.com";
    let mut metadata_offset = 0;
    match mmdb.windows(metadata_terminator.len()).rposition(|window| window == metadata_terminator) {
        None => { 
            println!("No metadata section found, invalid MMDB file!");
            std::process::exit(1);
        }
        Some(_metadata_offset) => {
            println!("Found node metadata terminator at: {}", _metadata_offset);
            metadata_offset = _metadata_offset + metadata_terminator.len();
        }
    }
    if metadata_offset == 0 {
        println!("No metadata section found, invalid MMDB file!");
    }
    return metadata_offset;
}

// Find end of data - start at metadata_offset
fn find_data_offset(mmdb: &Vec<u8>, metadata_offset: usize) -> usize {
    let size = mmdb.len();
    let mut ptr = metadata_offset;
    let min_metadata_offset: usize = 128*1024 -1; // 128KiB max metadata size
    let mut data_offset = 0;
    while ptr > min_metadata_offset+2 {
        if mmdb[ptr-15] | mmdb[ptr-14] | mmdb[ptr-13] | mmdb[ptr-13] | mmdb[ptr-12] | mmdb[ptr-11] | mmdb[ptr-10] | mmdb[ptr-9] | mmdb[ptr-8] | mmdb[ptr-7] | mmdb[ptr-6] | mmdb[ptr-5] | mmdb[ptr-4] | mmdb[ptr-3] | mmdb[ptr-2] | mmdb[ptr-1] | mmdb[ptr] == 0 {
            println!("Found node tree terminator at: {}", ptr-15);
            data_offset = ptr-15;
            println!("Data should be at {} and {} long", data_offset, size-data_offset);
            break;
        }
        ptr -= 1;
    }
    return data_offset;
}

enum DataFormat {
    Pointer(usize), // - 1
    String(String), // - 2
    Double(f64), // - 3
    Bytes(Vec<u8>), // - 4
    U16(u16), // - 5
    U32(u32), // - 6
    Map(HashMap<String,DataFormat>), // - 7
    I32(i32), // - 8
    U64(u64), // - 9
    U128(u128), // - 10
    Array(Vec<DataFormat>), // - 11
    Cachecon(usize), // - 12
    End, // - 13
    Bool(bool), // - 14
    Float(f32), // - 15
    Invalid(),
}


impl CountryRadixTree {

    fn generate(&mut self) {

        let mut segment_index: usize = 1;
        let segments = &mut self.segments;
        let mut total: u32 = 0;

        // Iterate through each network block
        for network in &self.networks {

            self.netcount += 1;
            let cidr: Ipv4Cidr = network.network;
            let prefix: u32 = cidr.get_prefix();
            let data = &network.country_or_continent_code;

            // Current node - start at root
            let mut node_index: usize = 0;

            // Iterate through the ip address prefix
            let start_depth: u8 = self.seek_depth;
            let end_depth: u8 = self.seek_depth - (cidr.get_bits() - 1);
            
            let mut depth = start_depth;
            while depth > end_depth {

                // Bitwise test - Create a bit mask to with zeros, and a 1 in the current depth
                // If the corrosponding bit in the IP prefix is a zero, then when anded together the whole number will be 0
                // Right hand side of the tree
                if 0 != prefix & (1 << depth) { // True

                    // Create RHS node if empty
                    if segments[node_index].rhs.is_none() {
                        // Add a node to the segments
                        &mut segments.push(RadixTreeNode{ segment: segment_index, lhs: None, rhs: None });
                        // Set the current segment RHS to the new node kind
                        segments[node_index].rhs = Some( RadixTreeNodeKind::Node(segment_index) );
                        segment_index += 1;
                    }

                    // Set the current node to the RHS
                    match segments[node_index].rhs.as_ref().expect("Invalid RHS node") {
                        RadixTreeNodeKind::Data(data) => {
                        },
                        RadixTreeNodeKind::Node(index) => {
                            node_index = *index;
                        }
                    }
                }
                // Left hand side of the tree
                else {

                    // Create LHS node if empty
                    if segments[node_index].lhs.is_none() {
                        // Add a node to the segments
                        &mut segments.push(RadixTreeNode{ segment: segment_index, lhs: None, rhs: None });
                        // Set the current segment RHS to the new node kind
                        segments[node_index].lhs = Some( RadixTreeNodeKind::Node(segment_index) );
                        segment_index += 1;
                    }

                    // Set the current node to the LHS
                    match segments[node_index].lhs.as_ref().expect("Invalid LHS node") {
                        RadixTreeNodeKind::Data(data) => {
                        },
                        RadixTreeNodeKind::Node(index) => {
                            node_index = *index;
                        }
                    }
                }
                depth -= 1;
                total += 1;
            }

            if 0 != prefix & (1 << end_depth) { // True
                segments[node_index].rhs = Some( RadixTreeNodeKind::Data( RadixTreeNodeData { 
                    country_or_continent_code: data.clone()
                } ) );
            }
            else {
                segments[node_index].lhs = Some( RadixTreeNodeKind::Data( RadixTreeNodeData { 
                    country_or_continent_code: data.clone()
                } ) );
            }
        }

        println!("Total segments {} {:02X?}", total, total.to_le_bytes());
    }

    fn serialize_node(&self, node: &Option<RadixTreeNodeKind> ) -> u32 {

        // empty leaf
        if node.is_none() {
            return COUNTRY_BEGIN;
        }

        match node.as_ref().expect("Invalid node") {

            // internal node
            RadixTreeNodeKind::Node(index) => {
                return *index as u32;
            },

            // data leaf
            RadixTreeNodeKind::Data(data) => {
                let country_or_continent_code = &data.country_or_continent_code;

                // find country code in preset list
                if let Some( index ) = COUNTRY_CODES.iter().position(|&x| x == country_or_continent_code) {
                    return COUNTRY_BEGIN + index as u32;
                }
                return COUNTRY_BEGIN;
            }
        }

    }

    fn encode(&self, val: &u32 ) -> [u8; 3] {
        let val = val.to_le_bytes();
        return [val[0],val[1],val[2]];
    }

    fn encode_usize(&self, val: &usize ) -> [u8; 3] {
        let val = val.to_le_bytes();
        return [val[0],val[1],val[2]];
    }

    fn serialize(&self, dat_file_path: String) {
        
        // Open dat file for writing
        let mut dat_file = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(dat_file_path)
            .expect("Failed to open file for writing");

        // Write all trie segments
        for node in &self.segments {
            dat_file.write_all( &self.encode(&self.serialize_node( &node.lhs )) );
            dat_file.write_all( &self.encode(&self.serialize_node( &node.rhs )) );
        }

        // Comment
        dat_file.write_all(&[0x00, 0x00, 0x00]);
        dat_file.write_all(b"Converted with mmdb2dat by Warp Speed Computers - https://www.warp.co.nz");  // .dat file comment - can be anything
        dat_file.write_all(&[0xff, 0xff, 0xff]);

        // Edition and size
        dat_file.write_all(&[self.edition]);
        dat_file.write_all(&self.encode_usize(&self.segments.len()));

        println!("{:02X?}", &self.segments.len());

        // ff ff ff 01 79 15 06
        // ff ff ff 01 00 00 00 81 15 00 00
        // ff ff ff 01 81 15 00 00
        match dat_file.flush() {
            Ok(dat_file) => dat_file,
            Err(dat_file) => println!("Error flushing data to dat file")
        }
        
    }

    fn get_node_data(&self, mmdb: &Vec<u8>, location: usize, data_offset: usize) -> (String, String) {

        // Set variables to hold data
        let mut continent_code = String::new();
        let mut country_code = String::new();
        // Get data
        let (recordData, lastptr) = self.data_format(&mmdb, data_offset + location, data_offset, 0);
        match recordData {
            DataFormat::Map(_map) => {
                // Iterate through data
                for (key,value) in _map {
                    // Find continent data
                    if key == "continent" {
                        if let DataFormat::Map(_continent_val) = value {
                            // Iterate through continent data
                            for (key,value) in _continent_val {
                                // Find continent code
                                if key == "code" {
                                    if let DataFormat::String(_val) = value {
                                        continent_code = _val;
                                    }
                                }
                            }
                        }
                    }
                    // Find country data
                    else if key == "country" {
                        if let DataFormat::Map(_country_val) = value {
                            // Iterate through country data
                            for (key,value) in _country_val {
                                // Find country code
                                if key == "iso_code" {
                                    if let DataFormat::String(_val) = value {
                                        country_code = _val;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            DataFormat::String(_string) => {
                println!("string is: {}", _string);
            }
            _ => {
                println!("Unhandled data!");
            }
        }
    
        return (continent_code, country_code);
    }
    
    fn data_format(&self, mmdb: &Vec<u8>, p: usize, data_offset: usize, depth: usize) -> (DataFormat,usize) {

        // Pointer location exceeds the size of the data section
        if p > self.mmdb_data_size_max {
            println!("Pointer {} exceeds data max {}", p, self.mmdb_data_size_max);
            std::process::exit(1);
        }
        
        let mut hb: usize = 1; // header bytes
    
        // first 3 bits
        let mut fb: u8 = mmdb[p] >> 5;
    
        // extended type
        if fb == 0 {
            hb += 1;
            fb = mmdb[p+1];
            fb += 7;
        }
    
        // get next 5 bits
        let sb: u8 = mmdb[p] & 31;
        let mut s: usize = 0;
        if sb < 29 {
            s = usize::from(sb);
        } else if sb == 29 {
            s = 29 + usize::from(mmdb[p+hb]);
            hb += 1;
        } else if sb == 30 {
            s = 285 + (usize::from(mmdb[p+hb]) << 8) + usize::from(mmdb[p+hb+1]);
            hb += 2;
        } else if sb == 31 {
            s = 65821 + (usize::from(mmdb[p+hb]) << 16) + (usize::from(mmdb[p+hb+1]) << 8) + usize::from(mmdb[p+hb+2]);
            hb += 3;
        }
    
        let mut emitp: usize = p;
    
        let mut Data: DataFormat;
        match fb {
            // Pointers - Point to byte offset in data portion(excluding null header bytes)
            1 => {
                /*
                The size can be 0, 1, 2, or 3.
                If the size is 0, the pointer is built by appending the next byte to the last three bits to produce an 11-bit value.
                If the size is 1, the pointer is built by appending the next two bytes to the last three bits to produce a 19-bit value + 2048.
                If the size is 2, the pointer is built by appending the next three bytes to the last three bits to produce a 27-bit value + 526336.
                Finally, if the size is 3, the pointer’s value is contained in the next four bytes as a 32-bit value. In this case, the last three bits of the control byte are ignored.
                */
                let size = (mmdb[p] & 24) >> 3; // bits 4 and 5
                let mut fbval: u32 = u32::from(mmdb[p] & 7); // bits 6, 7 and 8
                let mut value: u32 = 0;
                match size {
                    0 => {
                        value = (u32::from(fbval) << 8) + u32::from(mmdb[p+1]);
                        emitp += hb + 1;
                    }
                    1 => {
                        value = (u32::from(fbval) << 16) + (u32::from(mmdb[p+1]) << 8) + u32::from(mmdb[p+2]) + 2048;
                        emitp += hb + 2;
                    }
                    2 => {
                        value = (u32::from(fbval) << 24) + (u32::from(mmdb[p+1]) << 16) + (u32::from(mmdb[p+2]) << 8) + u32::from(mmdb[p+3]) + 526336;
                        emitp += hb + 3;
                    }
                    3 => {
                        value = (u32::from(mmdb[p+1]) << 24) + (u32::from(mmdb[p+2]) << 16) + (u32::from(mmdb[p+3]) << 8) + u32::from(mmdb[p+4]);
                        emitp += hb + 4;
                    }
                    _ => {}
                }
    
                // Get data at pointer
                let (dataFormat, _lastp): (DataFormat, usize) = self.data_format( &mmdb, data_offset + (value as usize) + 16, data_offset, depth+1 );
                Data = dataFormat;
            }
            // String
            2 => {
                let start: usize = p+hb;
                let end: usize = p+hb+s;
                emitp = end;
                let _string = String::from_utf8_lossy(&mmdb[start..end]).into_owned();
                Data = DataFormat::String(_string);
            }
            3 => {
                let start: usize = p+hb;
                let end: usize = p+hb+s;
                emitp = end;
                let mut bytes: [u8; 8] = [0; 8];
                let slice = &mmdb[start..end];
                let offset = 8 - slice.len();
                bytes[offset..].copy_from_slice(slice);
                let double: f64 = f64::from_be_bytes(bytes).try_into().expect("Failed to load f64 - double");
                Data = DataFormat::Double(double);
            }
            4 => {
                let start: usize = p+hb;
                let end: usize = p+hb+s;
                emitp = end;
                let bytes: Vec<u8> = mmdb[start..end].to_vec();
                Data = DataFormat::Bytes(bytes);
            }
            5 => {
                let start: usize = p+hb;
                let end: usize = p+hb+s;
                emitp = end;
                let mut bytes: [u8; 2] = [0; 2];
                let slice = &mmdb[start..end];
                let offset = 2 - slice.len();
                bytes[offset..].copy_from_slice(slice);
                let num: u16 = u16::from_be_bytes(bytes).try_into().expect("Failed to load u16");
                Data = DataFormat::U16(num);
            }
            6 => {
                let start: usize = p+hb;
                let end: usize = p+hb+s;
                emitp = end;
                let mut bytes: [u8; 4] = [0; 4];
                let slice = &mmdb[start..end];
                let offset = 4 - slice.len();
                bytes[offset..].copy_from_slice(slice);
                let num: u32 = u32::from_be_bytes(bytes).try_into().expect("Failed to load u32");
                Data = DataFormat::U32(num);
            }
            7 => {
                // Byte offset into file for the map data
                let mut subp: usize = p+hb;
    
                // Make a new HashMap
                let mut map = HashMap::new();
                map.reserve(s);
    
                // Iterate through the Map entries expected in the file
                for _ in 0..s {
    
                    // Keys are always Strings or Pointers to Strings
                    // Parse what is expected to be the key for this map entry
                    let (mut dataFormat, mut lastp): (DataFormat, usize) = self.data_format( &mmdb, subp, data_offset, depth+1 );
                    let string = match dataFormat {
                        DataFormat::String(_string) => _string,
                        _ => "?".to_owned()
                    };
    
                    // Use the emitted pointer from the previous parsing of the key string
                    subp = lastp;
    
                    // Parse what is expected to be the value for this map entry
                    let (mut dataFormat, mut lastp): (DataFormat, usize) = self.data_format( &mmdb, subp, data_offset, depth+1 );
                    map.entry(string).or_insert(dataFormat);
    
                    // Use the emitted pointer from the previous parsing of the value
                    subp = lastp;
    
                }
                emitp = subp;
                Data = DataFormat::Map(map);
            }
            8 => {
                let start: usize = p+hb;
                let end: usize = p+hb+s;
                emitp = end;
                let bytes: Vec<u8> = mmdb[start..end].try_into().expect("Failed to load i32");
                let num: i32 = i32::from_be_bytes(pad_bytes(bytes, 4, true, 0).try_into().expect("Failed to load i32"));
                Data = DataFormat::I32(num);
            }
            9 => { 
                let start: usize = p+hb;
                let end: usize = p+hb+s;
                emitp = end;
                let bytes: Vec<u8> = mmdb[start..end].try_into().expect("Failed to load u64");
                let num: u64 = u64::from_be_bytes(pad_bytes(bytes, 8, true, 0).try_into().expect("Failed to pad u64"));
                Data = DataFormat::U64(num);
            }
            10 => {
                let start: usize = p+hb;
                let end: usize = p+hb+s;
                emitp = end;
                let bytes: Vec<u8> = mmdb[start..end].try_into().expect("Failed to load u128");
                let num: u128 = u128::from_be_bytes(pad_bytes(bytes, 16, true, 0).try_into().expect("Failed to load u128"));
                Data = DataFormat::U128(num);
            }
            11 => {
                let mut subp: usize = p+hb;
                let mut arr = Vec::new();
                for i in 0..s {
    
                    let (mut dataFormat, mut lastp): (DataFormat, usize) = self.data_format( &mmdb, subp, data_offset, depth+1 );
                    arr.push( dataFormat );
    
                    subp = lastp;
    
                }
                emitp = subp;
    
                Data = DataFormat::Array(arr);
            }
            12 => {
                let start: usize = p+hb;
                let end: usize = p+hb+s;
                emitp = end;
                Data = DataFormat::Cachecon(s);
            }
            13 => {
                // Zero size
                let end: usize = p+hb;
                emitp = end;
                Data = DataFormat::End;
            }
            14 => {
                // Zero size, the size attribute is 0 or 1 for boolean
                let end: usize = p+hb;
                emitp = end;
                Data = DataFormat::Bool(s != 0);
            }
            15 => {
                let start: usize = p+hb;
                let end: usize = p+hb+s;
                emitp = end;
                let bytes: Vec<u8> = mmdb[start..end].try_into().expect("Failed to load f32");
                let num: f32 = f32::from_be_bytes(pad_bytes(bytes, 8, true, 0).try_into().expect("Failed to load f32"));
                Data = DataFormat::Float(num);
            }
            _ => {
                Data = DataFormat::Invalid();
            }
        }
    
        return (Data, emitp);
    }
    
    fn convert_mmdb_to_dat(&mut self, mmdb_file_path: String, dat_file_path: String) {
        
        // Expecting records of 3 bytes in length and only looking at IPv4 atm
        
        // Open dat file for writing
        let dat_file = File::create(dat_file_path).expect("Failed to open file for writing");
        let mut dat_file = BufWriter::new(dat_file);

        // Open MMDB file for reading
        let mmdb = std::fs::read(mmdb_file_path).expect("Failed to load MMDB file");
        self.mmdb_data_size_max = mmdb.len();

        // Find metadata offset
        let metadata_offset = find_metadata_offset(&mmdb);
        // Decode metadata
        let (dataFormat, lastptr) = self.data_format(&mmdb, metadata_offset, 0, 0);

        // Set MetaData
        let mut record_size: usize = 0;
        let mut node_count: usize = 0;
        let mut ip_version: u16 = 0;
        if let DataFormat::Map(_datamapped) = dataFormat {
            for (key,value) in _datamapped {
                if key == "record_size" {
                    if let DataFormat::U16(_val) = value {
                        println!("{}: {}", key, _val);
                        record_size = _val as usize / 8; // convert to bytes
                        println!("record_size (bytes): {}", record_size);
                    }
                }
                if key == "node_count" {
                    if let DataFormat::U32(_val) = value {
                        println!("{}: {}", key, _val);
                        node_count = _val as usize;
                    }
                }
                if key == "ip_version" {
                    if let DataFormat::U16(_val) = value {
                        println!("{}: {}", key, _val);
                        ip_version = _val;
                    }
                }
                if key == "database_type" {
                    if let DataFormat::String(_val) = value {
                        println!("{}: {}", key, _val);
                    }
                }
            }
        }

        let node_size = record_size*2;
        let tree_size = node_size * node_count;
        let data_offset = tree_size;
        println!("node_size: {}", node_size);
        println!("tree_size: {}", tree_size);

        self.mmdb_data_size_max = metadata_offset;
        
        let record_count = node_count*2;

        // IPv4 in IPv6 Tree can skip first 96 nodes
        let record_offset: usize = 96;
        println!("record_count: {}", record_count);

        let mut record = record_offset;

        // Iterate through records until the end
        while record < record_count {
            
            let p = record * node_size;

            let left_bytes: Vec<u8> = mmdb[p..p+record_size].to_vec();
            let right_bytes: Vec<u8> = mmdb[p+record_size..p+node_size].to_vec();

            let left_record: usize = u32::from_be_bytes(pad_bytes(left_bytes, 4, true, 0).try_into().expect("Failed to load u32")).try_into().unwrap();
            let right_record: usize = u32::from_be_bytes(pad_bytes(right_bytes, 4, true, 0).try_into().expect("Failed to load u32")).try_into().unwrap();

            if left_record < record_offset || right_record < record_offset {
                break;
            }

            if left_record == node_count {
                dat_file.write_all( &self.encode( &COUNTRY_BEGIN ) );
            }
            else if left_record < node_count {
                dat_file.write_all( &self.encode_usize( &(left_record - record_offset) ) );
            }
            else if left_record > node_count {
                // Get data
                let (continent_code, country_code) = self.get_node_data(&mmdb, left_record - node_count, data_offset);
                
                let mut country_or_continent_code = country_code;
                if country_or_continent_code == "" {
                    country_or_continent_code = continent_code;
                }
                // find country code in preset list
                if let Some( index ) = COUNTRY_CODES.iter().position(|&x| x == country_or_continent_code) {
                    dat_file.write_all( &self.encode( &(COUNTRY_BEGIN + index as u32) ) );
                }
                else {
                    dat_file.write_all( &self.encode( &COUNTRY_BEGIN ) );
                }
            }

            if right_record == node_count {
                dat_file.write_all( &self.encode( &COUNTRY_BEGIN ) );
            }
            else if right_record < node_count {
                dat_file.write_all( &self.encode_usize( &(right_record - record_offset) ) );
            }
            else if right_record > node_count {
                // Get data
                let (continent_code, country_code) = self.get_node_data(&mmdb, right_record - node_count, data_offset);
                
                let mut country_or_continent_code = country_code;
                if country_or_continent_code == "" {
                    country_or_continent_code = continent_code;
                }
                // find country code in preset list
                if let Some( index ) = COUNTRY_CODES.iter().position(|&x| x == country_or_continent_code) {
                    dat_file.write_all( &self.encode( &(COUNTRY_BEGIN + index as u32) ) );
                }
                else {
                    dat_file.write_all( &self.encode( &COUNTRY_BEGIN ) );
                }
            }

            record += 1;
        }

        // Comment
        dat_file.write_all(&[0x00, 0x00, 0x00]);
        dat_file.write_all(b"Converted with mmdb2dat by Warp Speed Computers - https://www.warp.co.nz");  // .dat file comment - can be anything
        dat_file.write_all(&[0xff, 0xff, 0xff]);

        // Edition and size
        dat_file.write_all(&[self.edition]);
        dat_file.write_all(&self.encode_usize( &(record_count - record_offset) ));

        println!("{:02X?}", record_count - record_offset);

        // ff ff ff 01 79 15 06
        // ff ff ff 01 00 00 00 81 15 00 00
        // ff ff ff 01 81 15 00 00
        match dat_file.flush() {
            Ok(dat_file) => dat_file,
            Err(dat_file) => println!("Error flushing data to dat file")
        }
            
    }
}

fn main() {
    
    println!("Converting GeoIP2-Country.mmdb to GeoIP.dat");

    let mut r = CountryRadixTree {
        remap_continent_codes: HashMap::from([
            (String::from("AS"), String::from("AP")), // Asia -> Asia Pacific
        ]),
        remap_country_codes: HashMap::from([
            (String::from("CW"), String::from("AN")), // Curacao -> Netherlands Antilles
            (String::from("UK"), String::from("GB")), // UK -> Great Britain
            (String::from("SX"), String::from("FX")), // Island of Saint Martin -> French Metropolitan
            (String::from("XK"), String::from("RS")), // Kosovo -> Serbia
        ]),
        seek_depth: 31,
        locations: HashMap::new(),
        networks: Vec::new(),
        edition: COUNTRY_EDITION,
        reclen: STANDARD_RECORD_LENGTH,
        segreclen: SEGMENT_RECORD_LENGTH,
        debug: true,
        netcount: 0,
        segments: vec![ RadixTreeNode{ segment: 0, lhs: None, rhs: None } ],
        mmdb_data_size_max: 0,
    };

    r.convert_mmdb_to_dat("GeoIP2-Country.mmdb".to_string(), "GeoIP.dat".to_string());
}
