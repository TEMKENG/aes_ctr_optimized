use crate::thread_pool::*;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::str;
use std::sync::{Arc, Mutex};

const RCON: [u8; 15] = [
    1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
];

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const BLOCK_SIZE: usize = 16; // AES block size
const CHUNK_SIZE: usize = 1_048_576 * 4; //  < 1 MB pro thread

/// Encrypt a chunk in CTR mode (mock implementation)
fn process_chunk(chunks: &mut [u8], keys: &[u8], counter: &[u8], nr: usize, starting_block: u64) {
    // Create a mutable buffer to store the incremented counter
    let mut cipher_block = [0u8; BLOCK_SIZE];
    let mut c: u64;
    // Iterate over each chunk of data
    for (i, chunk) in chunks.chunks_mut(BLOCK_SIZE).enumerate() {
        c = starting_block + i as u64;
        // Increment the counter using the provided ctr128_inc logic
        for i in (0..BLOCK_SIZE).rev() {
            c += counter[i] as u64;
            cipher_block[i] = c as u8;
            c >>= 8;
            if c == 0 {
                break;
            }
        }
        // Encrypt the counter block
        aes_v2(&mut cipher_block, keys, nr);
        // XOR the encrypted counter block with the current chunk
        for (j, byte) in chunk.iter_mut().enumerate() {
            *byte ^= cipher_block[j];
        }
    }
}

/// Funktion fuer die Schlüsselerweiterung
/// * `key` - The key to expand
/// * `nk` - Number  of  32-bit  words  comprising  the  Cipher  Key. For  this standard, Nk = 4, 6, or 8.
/// * `nr` - Number of rounds, which is  a  function  of  Nk  and  Nb  (which  is fixed). For this standard, Nr = 10, 12, or 14.
fn key_expansion_v2(key: &[u8], nk: usize, nr: usize) -> Vec<u8> {
    let mut words: Vec<u8> = vec![0; (nr + 1) * 4 * 4];
    // Copy the original key into the first part of the words vector
    words[..key.len()].copy_from_slice(key);

    for i in nk..(nr + 1) * 4 {
        let previous_index = (i - nk) * 4;
        let index = (i - 1) * 4;
        let tmp_key: [u8; 4];

        if i % nk == 0 {
            tmp_key = [
                SBOX[words[index + 1] as usize] ^ RCON[i / nk - 1] ^ words[previous_index],
                SBOX[words[index + 2] as usize] ^ words[previous_index + 1],
                SBOX[words[index + 3] as usize] ^ words[previous_index + 2],
                SBOX[words[index] as usize] ^ words[previous_index + 3],
            ];
        } else if nk > 6 && i % nk == 4 {
            tmp_key = [
                SBOX[words[index] as usize] ^ words[previous_index],
                SBOX[words[index + 1] as usize] ^ words[previous_index + 1],
                SBOX[words[index + 2] as usize] ^ words[previous_index + 2],
                SBOX[words[index + 3] as usize] ^ words[previous_index + 3],
            ];
        } else {
            tmp_key = [
                words[index] ^ words[previous_index],
                words[index + 1] ^ words[previous_index + 1],
                words[index + 2] ^ words[previous_index + 2],
                words[index + 3] ^ words[previous_index + 3],
            ];
        }
        for (j, v) in tmp_key.iter().enumerate() {
            words[i * 4 + j] = *v;
        }
    }
    // Transpose the words matrix
    for offset in (0..nr + 1).map(|x| x * 16) {
        for i in 0..4 {
            for j in i + 1..4 {
                words.swap(offset + i * 4 + j, offset + j * 4 + i);
            }
        }
    }
    words
}

/// Die Funktion führt die XOR Operation zwischen 'stage' und 'key' durch
#[inline]
fn add_round_keys_v2(stage: &mut [u8], expanded_key: &[u8], round: usize) {
    let offset = round * 16;
    for i in 0..stage.len() {
        stage[i] ^= expanded_key[offset + i];
    }
}

#[inline]
fn rotate(input: &mut [u8]) {
    input.swap(1, 4);
    input.swap(2, 8);
    input.swap(3, 12);
    input.swap(6, 9);
    input.swap(7, 13);
    input.swap(11, 14);
}

#[inline]
fn aes_v2(mut stage: &mut [u8], keys: &[u8], nr: usize) {
    rotate(stage);
    add_round_keys_v2(&mut stage, &keys, 0);

    for i in 1..nr + 1 {
        shift_rows_v3(&mut stage);
        if i < nr {
            mix_columns_v2(&mut stage);
        }
        add_round_keys_v2(&mut stage, &keys, i);
    }
    rotate(stage);
}

#[inline]
fn shift_rows_v3(stage: &mut [u8]) {
    stage.copy_from_slice(&mut [
        SBOX[stage[0] as usize] , SBOX[stage[1] as usize] , SBOX[stage[2] as usize] , SBOX[stage[3] as usize] , // 1. row
        SBOX[stage[5] as usize] , SBOX[stage[6] as usize] , SBOX[stage[7] as usize] , SBOX[stage[4] as usize] , // 2. row
        SBOX[stage[10]as usize] , SBOX[stage[11]as usize] , SBOX[stage[8] as usize] , SBOX[stage[9] as usize] , // 3. row
        SBOX[stage[15]as usize] , SBOX[stage[12]as usize] , SBOX[stage[13]as usize] , SBOX[stage[14]as usize] , // 4. row
    ]);
}

/// Funktion zur Mischung einer Spalte
#[inline]
fn mix_columns_v2(stage: &mut [u8]) {
    for column in 0..4 {
        let t0: u8 = stage[column];
        let t1: u8 = stage[column + 4];
        let t2: u8 = stage[column + 8];
        let t3: u8 = stage[column + 12];
        // Matrixmultiplkation wie in die originale Artikel
        stage[column] = gmul(t0, 0x2) ^ gmul(t1, 0x3) ^ t2 ^ t3;
        stage[column + 4] = t0 ^ gmul(t1, 0x2) ^ gmul(t2, 0x3) ^ t3;
        stage[column + 8] = t0 ^ t1 ^ gmul(t2, 0x2) ^ gmul(t3, 0x3);
        stage[column + 12] = gmul(t0, 0x3) ^ t1 ^ t2 ^ gmul(t3, 0x2);
    }
}

/// Funktion zur Multiplikation von zwei Zahlen in GF(2^8)
#[inline]
fn gmul(p: u8, q: u8) -> u8 {
    let mut a = p;
    let mut b = q;
    let mut r: u8 = 0;
    for _ in 0..8 {
        if b & 0x01 != 0 {
            r ^= a;
        }
        if a & 0x80 != 0 {
            a <<= 1;
            a ^= 0x1b;
        } else {
            a <<= 1;
        }
        b >>= 1;
    }
    r
}

/// Function to print bytes
fn println_bytes(name_str: &str, bytes: &Vec<u8>) {
    println!("{name_str} {:02x?}", bytes);
}

/// Function to handle encryption/decryption command with given parameters
pub fn handle_aes_ctr_command(
    command: String,
    key_size: u16,
    key_bytes: Vec<u8>,
    iv_bytes: Vec<u8>,
    input_file_path: PathBuf,
    output_file_path: PathBuf,
) {
    println!("\n### Dummy printing ...");
    println!(" - command           = {}", command);
    println!(" - key_size          = {}", key_size);
    println_bytes(" - key_bytes         = ", &key_bytes);
    println_bytes(" - iv_bytes          = ", &iv_bytes);
    println!(" - input_file_path   = {}", input_file_path.display());
    println!(" - output_file_path  = {}", output_file_path.display());

    // Determine key and round count based on key size
    let (nk, nr) = match key_size {
        128 => (4, 10),
        192 => (6, 12),
        256 => (8, 14),
        _ => panic!("Unsupported key size"),
    };

    let iv_bytes = Arc::new(iv_bytes);
    let keys = Arc::new(key_expansion_v2(&key_bytes, nk, nr));

    let input_file = File::open(&input_file_path).expect("Failed to open input file");
    let file_size = input_file.metadata().unwrap().len();

    let output_file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(&output_file_path)
        .expect("Failed to open output file");
    let writer = Arc::new(Mutex::new(BufWriter::with_capacity(
        CHUNK_SIZE,
        output_file,
    )));

    let nr_t: u64 = 4; //Anzahl von Thread.
    let num_chunks = (file_size as f64 / CHUNK_SIZE as f64).ceil() as usize;
    let pool = ThreadPool::new(nr_t as usize);
    let reader = Arc::new(Mutex::new(BufReader::with_capacity(CHUNK_SIZE, input_file)));

    for chunk_id in 0..num_chunks {
        let keys = Arc::clone(&keys);
        let iv = Arc::clone(&iv_bytes);
        let writer = writer.clone();
        let reader = reader.clone();

        pool.execute(move || {
            let mut chunk = vec![0; CHUNK_SIZE];
            let starting_pos = chunk_id * CHUNK_SIZE;
            let starting_block = (starting_pos / BLOCK_SIZE) as u64;

            {
                let mut reader = reader.lock().unwrap();
                reader.seek(SeekFrom::Start(starting_pos as u64)).unwrap();
                let bytes_read = reader.read(&mut chunk).unwrap_or(0);
                chunk.truncate(bytes_read);
            }

            process_chunk(&mut chunk, &keys, &iv, nr, starting_block);

            let mut writer = writer.lock().unwrap();
            writer
                .seek(SeekFrom::Start((chunk_id * CHUNK_SIZE) as u64))
                .unwrap();
            writer.write_all(&chunk).unwrap();
        });
    }
}
