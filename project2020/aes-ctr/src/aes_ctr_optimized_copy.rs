#![allow(unused)]
use hex;
use std::any::type_name;
use std::cmp::min;
use std::fs::{File, OpenOptions};
use std::io;
use std::io::prelude::*;
use std::io::SeekFrom;
use std::io::{BufReader, BufWriter};
use std::mem;
use std::path::PathBuf;
use std::str;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

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

/// Die Funktion führt die XOR Operation zwischen 'stage' und 'key' durch
fn add_round_keys_v2(stage: &mut [u8], expanded_key: &[u8], round: usize) {
    let offset = round * 16;
    for i in 0..stage.len() {
        stage[i] ^= expanded_key[offset + i];
    }
}

fn type_of<T>(_: T) -> &'static str {
    type_name::<T>()
}

/// Funktion fuer die Initialisierung von sbox und Ibox
fn initialize_aes_sbox(sbox: &mut Vec<u8>, boxe: &mut Vec<u8>) {
    let mut p: u8 = 1;
    let mut q: u8 = 1;
    let rotl8 = |x: u8, shift: i32| -> u8 { (x << shift) | (x >> (8 - shift)) };
    loop {
        p = p ^ (p << 1) ^ if p & 0x80 != 0 { 0x1B } else { 0 };
        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        q ^= if q & 128 != 0 { 0x9 } else { 0 };
        let xformed: u8 = q ^ rotl8(q, 1) ^ rotl8(q, 2) ^ rotl8(q, 3) ^ rotl8(q, 4);
        sbox[p as usize] = xformed ^ 0x63;
        boxe[sbox[p as usize] as usize] = p;
        if p == 1 {
            break;
        }
    }

    sbox[0] = 0x63;
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
        let mut tmp_key = [0u8; 4];

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

        words[(i * 4)..(i * 4 + 4)].copy_from_slice(&tmp_key);
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

/// Funktion zur XOR Addition von zwei Vektoren.
fn xor_for_vec(v1: &Vec<u8>, v2: &Vec<u8>) -> Vec<u8> {
    let v3: Vec<u8> = v1.iter().zip(v2.iter()).map(|(&x1, &x2)| x1 ^ x2).collect();
    v3
}

fn rotate(input: &mut [u8]) {
    for i in 0..4 {
        for j in i + 1..4 {
            input.swap(i * 4 + j, j * 4 + i);
        }
    }
}

fn paround(input: &[u8]) {
    for i in 0..input.len() / 4 {
        println!(
            "{:02x} {:02x} {:02x} {:02x}",
            input[i * 4],
            input[i * 4 + 1],
            input[i * 4 + 2],
            input[i * 4 + 3]
        );
    }
    println!();
}

fn aes_v2(mut stage: &mut Vec<u8>, keys: &Vec<u8>, nr: usize) {
    add_round_keys_v2(&mut stage, &keys, 0);

    for i in 1..nr+1 {
        sub_bytes_v2(&mut stage);
        shift_rows_v2(&mut stage);
        if i < nr {
            mix_columns_v2(&mut stage);
        }
        add_round_keys_v2(&mut stage, &keys, i);
    }
}

fn sub_bytes_v2(stage: &mut [u8]) {
    stage.iter_mut().for_each(|x| *x = SBOX[*x as usize]);
}

fn shift_rows_v2(stage: &mut [u8]) {
    stage.copy_from_slice(&mut [
        stage[0], stage[1], stage[2], stage[3], // 1. row
        stage[5], stage[6], stage[7], stage[4], // 2. row
        stage[10], stage[11], stage[8], stage[9], // 3. row
        stage[15], stage[12], stage[13], stage[14], // 4. row
    ]);
}

/// Funktion zur Mischung einer Spalte
fn mix_columns_v2(mut stage: &mut Vec<u8>) {
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

/// Inkrementierung der Zaeler um c
fn ctr128_inc(counter: &Vec<u8>, mut c: u64) -> Vec<u8> {
    let mut n: usize = 16;
    let mut count: Vec<u8> = counter.clone();

    loop {
        n -= 1;
        c += count[n] as u64;
        count[n] = c as u8;
        c >>= 8;
        if n == 0 {
            break count;
        }
    }
}

/// Die Funktion liest 'OFFSET' Bytes im Datei von OFFSET*index bis OFFSET*(index + 1)
fn reader(file: &PathBuf, sequence_nr: u64, offset: usize, size: usize) -> Vec<u8> {
    let file_str = file.to_str().unwrap_or_default();
    let start: u64 = (offset as u64) * sequence_nr;
    let mut f = File::open(file).expect(format!("Can't open the file `{file_str}").as_str());
    let mut buffer: Vec<u8> = vec![0u8; size];
    f.seek(SeekFrom::Start(start))
        .expect("Problem by moving the cursor"); //bewegen Sie den Cursor
    f.read(&mut buffer)
        .expect(format!("Problem by reading the file `{file_str}`").as_str());
    buffer
}

/// Function to print bytes
fn println_bytes(name_str: &str, bytes: &Vec<u8>) {
    print!("{}", name_str);
    for b in bytes {
        print!("{:02x}", b);
    }
    print!("\n");
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

    let mut sbox: Vec<u8> = vec![0; 256];
    let mut ibox: Vec<u8> = vec![0; 256];
    let (nk, nr) = match key_size {
        128 => (4 as usize, 10 as usize),
        _ => (8 as usize, 14 as usize),
    };

    initialize_aes_sbox(&mut sbox, &mut ibox); //Initialisierung von sbox und Ibox
    let keys: Vec<u8> = key_expansion_v2(&key_bytes, nk, nr); // Schluessel erweitern.
    println!("nk: {nk} nr: {nr} keys: {} x 4 x 4)", keys.len() / 16,);

    /// Globale Informationen
    const NR_T: u64 = 64; //Anzahl von Thread.
    const OFFSET: u64 = 16 * NR_T;
    let mut f = BufReader::new(File::open(&input_file_path).unwrap());
    let len = f.seek(SeekFrom::End(0)).ok().unwrap(); //Datei Laenge
    let mut nbs: u64 = len / OFFSET; //Anzahl der sequentielle Ausführung
    let mut rest: usize = (len % OFFSET) as usize;

    let mut output_file = BufWriter::new(
        OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true) // This will create the file if it doesn't exist
            .open(&output_file_path)
            .expect("Problem by creating output file"),
    );

    println!("Rest: {rest}");
    println!("Laenge der Datei: {len}");
    println!("Anzahl der sequentielle Ausführung: {nbs}");

    /// create atomic reference
    /// // Channel to collect results
    let sbox = Arc::new(sbox);
    let ibox = Arc::new(ibox);
    let keys = Arc::new(keys);
    let iv_bytes = Arc::new(iv_bytes);
    let (tx, rx) = mpsc::channel();
    // let mut results = Arc::new(Mutex::new(results));

    for sequence in 0..nbs {
        let mut results = vec![0; 16 * NR_T as usize];
        let t_data: Vec<u8> = reader(&input_file_path, sequence, OFFSET as usize, OFFSET as usize);
        for j in (0..NR_T) {
            /// Klone Daten
            let keys = keys.clone();
            let iv_bytes = iv_bytes.clone();
            let thread_tx = tx.clone();
            /// aes parallele ausführen
            thread::spawn(move || {
                let block_nr = sequence * NR_T + j;
                let mut input = ctr128_inc(&iv_bytes, block_nr);
                println!("Input: {} Block: {block_nr:02x}", hex::encode(&input));
                rotate(&mut input);
                aes_v2(&mut input, &keys, nr);
                rotate(&mut input);
                thread_tx.send((j as usize * 16, input));
            });
        }
        let mut counter = 0;
        for (offset, result) in &rx {
            for j in 0..16 {
                results[offset + j] = result[j] ^ t_data[offset + j];
            }
            counter += 1;
            if (counter == NR_T) {
                break;
            }
        }
        // Teilergernisse hinzufügen
        output_file
            .seek(SeekFrom::Start(sequence * 16 * NR_T))
            .expect("Problem by shifting the cursor");
        output_file.write(&results);
        println!("Results: {}", hex::encode(&results));
        println!("ungladsdfsdf: {}", results.len());
    }
    drop(tx);

    let mut cursor_position = nbs * NR_T;
    let mut iv_in: Vec<u8> = ctr128_inc(&iv_bytes, cursor_position);
    let blocks_bytes: Vec<u8> = reader(&input_file_path, cursor_position, OFFSET as usize, rest);
    println!("Laenge index {:?}", blocks_bytes.len());
    let mut results = vec![0; blocks_bytes.len()];
    output_file
        .seek(SeekFrom::Start(cursor_position * 16))
        .expect("Problem by shifting the cursor");
    if rest != 0 && rest >= 16 {
        nbs = (rest / 16) as u64;
        cursor_position += nbs;
        for i in (0..nbs).map(|x| x as usize * 16) {
            let mut input = iv_in.clone();
            rotate(&mut input);
            aes_v2(&mut input, &keys, nr);
            rotate(&mut input);

            for j in 0..16 {
                results[i + j] = input[j] ^ blocks_bytes[i + j];
            }
            iv_in = ctr128_inc(&iv_in, 1);
        }

        rest = rest % 16;

    }
    if rest != 0 {
        let mut input = match nbs {
            0 => (*iv_bytes).clone(),
            _ => iv_in,
        };
        rotate(&mut input);
        aes_v2(&mut input, &keys, nr);
        rotate(&mut input);
        let pos = cursor_position as usize * 16;
        for i in 0..rest {
            results[pos + i] = blocks_bytes[pos + i] ^ input[i];
        }
    }

    output_file.write(&results);
}
