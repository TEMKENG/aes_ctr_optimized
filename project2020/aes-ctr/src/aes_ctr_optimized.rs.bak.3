#![allow(unused)]

use std::fs::{File, OpenOptions};
use std::io;
use std::io::prelude::*;
use std::io::SeekFrom;
use std::path::PathBuf;
use std::str;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use std::any::type_name;

fn type_of<T>(_: T) -> &'static str {
    type_name::<T>()
}
//~ Funktion fuer die Initialisierung von sbox und Ibox
fn initialize_aes_sbox(sbox: &mut Vec<u8>, boxe: &mut Vec<u8>) {
    let mut p: u8 = 1;
    let mut q: u8 = 1;
    let rotl8 = |x, shift| -> u8 { (x << shift) | (x >> (8 - shift)) };
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

fn get_column(stage: &Vec<Vec<u8>>, index: usize) -> Vec<u8> {
    let mut column: Vec<u8> = Vec::new();
    for i in 0..stage.len() {
        column.push(stage[i][index]);
    }
    column
}

fn rot(stage: &Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut temp_keys: Vec<Vec<u8>> = Vec::new();
    for i in 0..stage.len() {
        temp_keys.push(get_column(&stage, i));
    }
    temp_keys
}

//~ Funktion fuer die Schlüsselerweiterung
fn key_expansion(key: &Vec<u8>, nk: usize, nr: usize, sbox: &Vec<u8>) -> Vec<Vec<Vec<u8>>> {
    const NB: usize = 4;
    let mut temp: Vec<u8>;
    let mut w: Vec<Vec<u8>> = Vec::new();
    // Der originale Schlüssel kopieren.
    //~ println!("{:02x?} ", key);
    for i in 0..nk {
        w.push(vec![
            key[4 * i],
            key[4 * i + 1],
            key[4 * i + 2],
            key[4 * i + 3],
        ]);
    }
    //~ mprint(&w);
    //~ println!("");
    //~ w = rot(&w);
    //~ mprint(&w);
    for i in nk..(NB * (nr + 1)) {
        temp = (*w[i - 1]).to_vec();

        if i % nk == 0 {
            temp = shift_row(&temp, 1); // temp = RotWord(temp)
            sub_word(&mut temp, &sbox); //temp = SubWord(temp)
            temp = xor_for_vec(&mut temp, &rcon(i / nk - 1)); //temp = SubWord(RotWord(temp)) xor Rcon[i/Nk]
        } else if (nk > 6) & (i % nk == 4) {
            sub_word(&mut temp, &sbox); // temp = SubWord(temp)
        }
        w.push(xor_for_vec(&w[i - nk], &temp)); // w[i] = w[i-Nk] xor temp
    }
    let mut result: Vec<Vec<Vec<u8>>> = Vec::new();
    let mut temp: Vec<Vec<u8>>;
    for i in 0..w.len() / 4 {
        temp = Vec::new();
        for j in 0..4 {
            temp.push(w[i * 4 + j].to_vec());
        }
        //~ result.push(rot(&temp));
        result.push(temp);
    }
    //~ print(&result);
    result
}

fn print(matrix: &Vec<Vec<Vec<u8>>>) {
    println!("key expens");
    for i in 0..matrix.len() {
        println!("{}", i);
        mprint(&matrix[i]);
    }
}

//~ Subtitution von einer Vector
fn sub_word(row: &mut Vec<u8>, sbox: &Vec<u8>) {
    for i in 0..row.len() {
        row[i] = sbox[row[i] as usize];
    }
}

//~ RCON Konstant
fn rcon(round: usize) -> Vec<u8> {
    let a: Vec<u8> = vec![
        1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    ];
    let mut result: Vec<u8> = vec![0; 4];
    result[0] = a[round];
    result
}

//~ Funktion zur XOR Addition von zwei Vektoren.
fn xor_for_vec(v1: &Vec<u8>, v2: &Vec<u8>) -> Vec<u8> {
    let v3: Vec<u8> = v1.iter().zip(v2.iter()).map(|(&x1, &x2)| x1 ^ x2).collect();
    v3
}

fn aes(mut stage: &mut Vec<Vec<u8>>, keys: &Vec<Vec<Vec<u8>>>, nr: usize, sbox: &Vec<u8>) {
    //~ println!("{:02x?}", keys[0][0]);
    //~ println!("Init cipher ");
    //~ mprint(&stage);
    add_round_keys(&mut stage, &keys[0]);
    //~ prk(&stage);
    for i in 1..nr {
        //~ println!("round{:?}", i);
        sub_bytes(&mut stage, &sbox);
        //~ psb(&stage);
        shift_rows(&mut stage);
        //~ psr(&stage);
        mix_columns(&mut stage);
        //~ pmc(&stage);
        add_round_keys(&mut stage, &keys[i]);
        //~ pk(&keys[i]);
        //~ prk(&stage);
        if i == nr - 1 {
            //~ println!("round{:?}", i+1);
            //~ pk(&keys[i+1]);
            sub_bytes(&mut stage, &sbox);
            //~ psb(&stage);
            shift_rows(&mut stage);
            //~ psr(&stage);
            //~ mix_columns(&mut stage);
            add_round_keys(&mut stage, &keys[i + 1]);
            //~ prk(&stage);
        }
    }
    //~ println!("fin cipher ");
    //~ mprint(&stage);
}

//~ Die Funktion führt die XOR Operation zwischen 'stage' und 'key' durch
fn add_round_keys(stage: &mut Vec<Vec<u8>>, key: &Vec<Vec<u8>>) {
    stage
        .iter_mut()
        .zip(key.iter())
        .for_each(|(row1, row2)| *row1 = xor_for_vec(&row1, &row2));
}

fn sub_bytes(stage: &mut Vec<Vec<u8>>, boxe: &Vec<u8>) {
    for i in 0..stage.len() {
        sub_word(&mut stage[i], &boxe);
    }
}

fn shift_rows(stage: &mut Vec<Vec<u8>>) {
    let len: usize = stage.len();
    for i in 1..len {
        let result = shift_row(&vec![stage[0][i], stage[1][i], stage[2][i], stage[3][i]], i);
        stage[0][i] = result[0];
        stage[1][i] = result[1];
        stage[2][i] = result[2];
        stage[3][i] = result[3];
    }
}

//~ Die Funktion rotiert die Eintraege von 'vector' um 'shift'
fn shift_row(vector: &Vec<u8>, shift: usize) -> Vec<u8> {
    let mut temp: Vec<u8> = vector[shift..].to_vec();
    temp.extend(vector[0..shift].to_vec());
    temp
}
//~ Funktion zur Mischung der Spalten einer Matrix
fn mix_columns(mut stage: &mut Vec<Vec<u8>>) {
    for index in 0..stage[0].len() {
        mix_column(&mut stage, index);
    }
}
//~ Funktion zur Mischung einer Spalte
fn mix_column(stage: &mut Vec<Vec<u8>>, index: usize) {
    let t0: u8 = stage[index][0];
    let t1: u8 = stage[index][1];
    let t2: u8 = stage[index][2];
    let t3: u8 = stage[index][3];

    //~ Matrixmultiplkation wie in die originale Artikel
    stage[index][0] = gmul(t0, 0x2) ^ gmul(t1, 0x3) ^ t2 ^ t3;
    stage[index][1] = t0 ^ gmul(t1, 0x2) ^ gmul(t2, 0x3) ^ t3;
    stage[index][2] = t0 ^ t1 ^ gmul(t2, 0x2) ^ gmul(t3, 0x3);
    stage[index][3] = gmul(t0, 0x3) ^ t1 ^ t2 ^ gmul(t3, 0x2);
}
//~ Funktion zur Multiplikation von zwei Zahlen in GF(2^8)
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
//~ Inkrementierung der Zaeler um c
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
//~ Die Funktion liest 'OFFSET' Bytes im Datei von OFFSET*index bis OFFSET*(index + 1)
fn reader(file: &PathBuf, index: u64, offset: usize, size: usize) -> io::Result<Vec<u8>> {
    let start: u64 = (offset as u64) * index;
    let mut f = File::open(file)?;
    let mut buffer: Vec<u8> = Vec::new();
    buffer.resize(size, 0);
    f.seek(SeekFrom::Start(start))?; //bewegen Sie den Cursor
    f.read(&mut buffer)?;
    Ok(buffer)
}

//~ fn append(f: &PathBuf, data: &[Vec<u8>]) {
//~ let mut f = OpenOptions::new()
//~ .write(true)
//~ .append(true)
//~ .open(f)
//~ .unwrap();
//~ let
//~ let dat = data.into_iter().flatten().collect();
//~ f.write(&dat);
//~ }

// Function to print bytes
fn println_bytes(name_str: &str, bytes: &Vec<u8>) {
    print!("{}", name_str);
    for b in bytes {
        print!("{:02x}", b);
    }
    print!("\n");
}
// Function to handle encryption/decryption command with given parameters
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
    let keys: Vec<Vec<Vec<u8>>> = key_expansion(&key_bytes, nk, nr, &sbox); // Schluessel erweitern.

    //~ Globale Informationen
    const NR_T: u64 = 64; //Anzahl von Thread.
    const OFFSET: u64 = 16 * NR_T;
    let mut f = File::open(&input_file_path).ok().unwrap();
    let len = f.seek(SeekFrom::End(0)).ok().unwrap(); //Datei Laenge
    let mut nbs: u64 = len / OFFSET; //Anzahl der sequentielle Ausführung
    let mut rest: usize = (len % OFFSET) as usize;

    //~ create atomic reference
    let sbox = Arc::new(sbox);
    let ibox = Arc::new(ibox);
    let keys = Arc::new(keys);
    let iv_bytes = Arc::new(iv_bytes);
    //~ let mut results = Arc::new(Mutex::new(results));

    //~ fn block_cipher(t_data: &Vec<u8>, input_file_path: &PathBuf, output_file_path: &PathBuf,
    //~ index: u64, offset: usize, size: usize, sbox: &Vec<u8>, keys: &Vec<Vec<Vec<u8>>>,
    //~ iv_bytes: &Vec<u8>)

    for i in 0..nbs {
        let mut handle_vec = vec![];
        let mut results: Vec<Vec<u8>> = vec![vec![0; 16]; NR_T as usize];
        let t_data: Vec<u8> = reader(&input_file_path, i, OFFSET as usize, OFFSET as usize)
            .ok()
            .unwrap();
        for j in 0..NR_T {
            //~ Klone Daten
            let sbox = sbox.clone();
            let keys = keys.clone();
            let t_data = t_data.clone();
            let mut results = results.clone();
            let iv_bytes = iv_bytes.clone();

            //~ aes parallele ausführen
            let handle = thread::spawn(move || {
                let mut input = to2d(&ctr128_inc(&iv_bytes, i * NR_T + j));
                aes(&mut input, &keys, nr, &sbox);
                let cipher: Vec<u8> = input.clone().into_iter().flatten().collect();
                let index: usize = 16 * j as usize;
                let pt: Vec<u8> = t_data[index..index + 16].to_vec();
                results[j as usize] = xor_for_vec(&cipher, &pt);
            });
            handle_vec.push(handle);
        }
        //~ Threads warten und beenden.
        for handle in handle_vec {
            handle.join().unwrap();
        }
        //~ Teilergernisse hinzufügen
        let results: Vec<u8> = results.into_iter().flatten().collect();
        if !std::path::Path::new(&input_file_path).exists() {
            File::create(&output_file_path).ok().unwrap();
        }
        let mut f = OpenOptions::new()
            .write(true)
            .append(true)
            .open(&output_file_path)
            .unwrap();
        f.write(&results);
    }
    let index = nbs * NR_T;
    println!("nbs index {:?}", index);
    let mut results: Vec<Vec<u8>> = Vec::new();
    let mut iv_in: Vec<u8> = ctr128_inc(&iv_bytes, index);
    let blocks_bytes: Vec<u8> = reader(&input_file_path, index, OFFSET as usize, rest)
        .ok()
        .unwrap();
    if rest != 0 && rest >= 16 {
        let offset: usize = 16;
        nbs = (rest / offset) as u64;

        let zeros: Vec<u8> = vec![0; 16];
        results = vec![zeros.clone()];
        results.resize(nbs as usize, zeros);
        for i in 0..nbs as usize {
            println!("i={} iv {:02x?}", i, iv_in);
            let mut input = to2d(&iv_in);
            aes(&mut input, &keys, nr, &sbox);

            input = rot(&input);
            mprint(&input);
            let cipher: Vec<u8> = input.into_iter().flatten().collect();
            println!("cipher {:02x?}", cipher);
            let pt: Vec<u8> = blocks_bytes[i * offset..(i + 1) * offset].to_vec();
            println!("pt {:02x?}", pt);
            results[i] = xor_for_vec(&cipher, &pt);
            println!("xor pt and cipher {:02x?}", results[i]);
            iv_in = ctr128_inc(&iv_in, 1);
            //~ mprint(&results);
        }
        rest = rest % offset;
    }
    if rest != 0 {
        println!("TEMKENG rest: {:?}", rest);
        mprint(&results);
        //~ iv_in = ctr128_inc(&iv_in, 1 as u64);
        let mut input = match nbs {
            0 => to2d(&iv_bytes),
            _ => to2d(&iv_in),
        };
        aes(&mut input, &keys, nr, &sbox);
        let mut cipher: Vec<u8> = input.into_iter().flatten().collect();
        let pt: Vec<u8> = blocks_bytes[nbs as usize * 16..].to_vec();
        cipher = cipher[0..rest].to_vec();
        results.push(xor_for_vec(&cipher, &pt));
    }
    //~ Teilergernisse hinzufügen
    //~ println!("type: {}", type_of(&results));
    let result: Vec<u8> = results.into_iter().flatten().collect();
    if !std::path::Path::new(&output_file_path).exists() {
        File::create(&output_file_path).ok().unwrap();
    }
    let mut f = OpenOptions::new()
        .write(true)
        .append(true)
        .open(&output_file_path)
        .unwrap();
    f.write(&result);
}

fn to2d(input: &Vec<u8>) -> Vec<Vec<u8>> {
    let mut stage: Vec<Vec<u8>> = Vec::new();
    for i in 0..input.len() / 4 {
        stage.push(input[i * 4..(i + 1) * 4].to_vec());
    }
    stage
}

fn mprint(s: &Vec<Vec<u8>>) {
    for i in s {
        println!("{:02x?}", i);
    }
}

fn prk(s: &Vec<Vec<u8>>) {
    println!("add round key");
    for i in s {
        println!("{:02x?}", i);
    }
}

fn pk(s: &Vec<Vec<u8>>) {
    println!("round key");
    for i in s {
        println!("{:02x?}", i);
    }
}

fn psb(s: &Vec<Vec<u8>>) {
    println!("sub byte ");
    for i in s {
        println!("{:02x?}", i);
    }
}

fn psr(s: &Vec<Vec<u8>>) {
    println!("sift rows ");
    for i in s {
        println!("{:02x?}", i);
    }
}
fn pmc(s: &Vec<Vec<u8>>) {
    println!("mix coluns ");
    for i in s {
        println!("{:02x?}", i);
    }
}
