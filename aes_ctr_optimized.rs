use hex;
use hex::ToHex;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;
use std::str;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

fn reader(file: PathBuf) -> std::io::Result<Vec<u8>> {
    let mut file = File::open(file)?;
    let mut buffer = Vec::<u8>::new();
    file.read_to_end(&mut buffer)?;
    println!("file: {:?}", buffer.len());
    //~ buffer = hex::decode(&buffer[..]).ok().unwrap();
    Ok(buffer)
}

//~ Funktion fuer die Initialisierung von sbox und Ibox
fn initialize_aes_sbox(sbox: &mut Vec<u8>, boxe: &mut Vec<u8>) {
    let mut p: u8 = 1;
    let mut q: u8 = 1;
    let rotl8 = |x, shift| -> u8 { (x << shift) | (x >> (8 - shift)) };
    loop {
        p = p ^ (p << 1) ^ if p & 0x80 != 0 { 0x1B } else { 0 };

        /* divide q by 3 (equals multiplication by 0xf6) */
        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        q ^= if q & 128 != 0 { 0x9 } else { 0 };
        /* compute the affine transformation */
        let xformed: u8 = q ^ rotl8(q, 1) ^ rotl8(q, 2) ^ rotl8(q, 3) ^ rotl8(q, 4);
        sbox[p as usize] = xformed ^ 0x63;
        boxe[sbox[p as usize] as usize] = p;
        if p == 1 {
            break;
        }
    }

    /* 0 ist ein spezieller Fall, denn 0 hat keine Inverse */
    sbox[0] = 0x63;
}

//~ Funktion zur Erweiterung des Schlüssels
//~ fn key_expansion(key: &Vec<u8>, nk: usize, nr: usize, sbox: &Vec<u8>) -> Vec<Vec<Vec<u8>>> {
//~ const NB: usize = 4;
//~ let mut temp: Vec<u8>;
//~ let mut w: Vec<Vec<u8>> = Vec::new();
//~ // Der originale Schlüssel kopieren.
//~ for i in 0..nk {
//~ w.push(vec![
//~ key[4 * i],
//~ key[4 * i + 1],
//~ key[4 * i + 2],
//~ key[4 * i + 3],
//~ ]);
//~ }
//~ // println!("keyyyy ");
//~ // mprint(&w);
//~ for i in nk..(NB * (nr + 1)) {
//~ temp = (*w[i - 1]).to_vec();
//~ if i % nk == 0 {
//~ shift_row(&mut temp, 1); // temp = RotWord(temp)
//~ sub_word(&mut temp, &sbox); //temp = SubWord(temp)
//~ temp = xor_for_vec(&mut temp, &rcon(i / nk - 1)); //temp = SubWord(RotWord(temp)) xor Rcon[i/Nk]
//~ } else if (nk > 6) & (i % nk == 4) {
//~ sub_word(&mut temp, &sbox); // temp = SubWord(temp)
//~ }
//~ w.push(xor_for_vec(&w[i - nk], &temp)); // w[i] = w[i-Nk] xor temp
//~ }
//~ let mut result: Vec<Vec<Vec<u8>>> = Vec::new();
//~ let mut temp: Vec<Vec<u8>>;
//~ for i in 0..w.len() / 4 {
//~ temp = Vec::new();
//~ for j in 0..4 {
//~ temp.push(w[i * 4 + j].to_vec());
//~ // println!(" {:02x?}" , w[i * 4 + j]);
//~ }
//~ // println!("ok");
//~ // mprint(&temp);
//~ result.push(temp);
//~ }
//~ result
//~ }

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
        //~ println!("{:02x?} ", (key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]));
    }

    for i in nk..(NB * (nr + 1)) {
        temp = (*w[i - 1]).to_vec();

        if i % nk == 0 {
            shift_row(&mut temp, 1); // temp = RotWord(temp)
            sub_word(&mut temp, &sbox); //temp = SubWord(temp)
            temp = xor_for_vec(&mut temp, &rcon(i / nk - 1)); //temp = SubWord(RotWord(temp)) xor Rcon[i/Nk]
        } else if (nk > 6) & (i % nk == 4) {
            sub_word(&mut temp, &sbox); // temp = SubWord(temp)
        }
        w.push(xor_for_vec(&w[i - nk], &temp)); // w[i] = w[i-Nk] xor temp
                                                //~ println!("{:02x?} ", xor_for_vec(&w[i-nk], &temp));
    }
    let mut result: Vec<Vec<Vec<u8>>> = Vec::new();
    let mut temp: Vec<Vec<u8>>;
    for i in 0..w.len() / 4 {
        temp = Vec::new();
        for j in 0..4 {
            temp.push(w[i * 4 + j].to_vec());
            //~ println!("{:02x?} ", w[i*4 + j]);
        }
        //~ println!("");
        result.push(rot(&temp));
    }
    //~ print(&result);
    result
}

//~ Funktion um eine Zeile oder eine Spalte zu rotieren
fn shift_row(vector: &mut Vec<u8>, shift: usize) {
    let mut temp: Vec<u8> = vector[shift..].to_vec();
    temp.extend(vector[0..shift].to_vec());
    *vector = temp;
}

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

fn cipher(mut stage: &mut Vec<Vec<u8>>, keys: &Vec<Vec<Vec<u8>>>, nr: usize, sbox: &Vec<u8>) {
    //~ let mut stage:Vec<Vec<u8>> = Vec::new();
    //~ stage = input.to_vec();
    //~ println!("{:?}", input);
    //~ println!("Init cipher ");
    //~ mprint(&stage);

    add_round_keys(&mut stage, &keys[0]);
    //~ prk(&stage);
    for i in 1..nr {
        sub_bytes(&mut stage, &sbox);
        //~ psb(&stage);
        shift_rows(&mut stage);
        //~ psr(&stage);
        mix_columns(&mut stage);
        //~ pmc(&stage);
        add_round_keys(&mut stage, &keys[i]);
        //~ prk(&stage);
        if i == nr - 1 {
            sub_bytes(&mut stage, &sbox);
            shift_rows(&mut stage);
            //~ mix_columns(&mut stage);
            add_round_keys(&mut stage, &keys[i + 1]);
        }
    }
    //~ println!("fin cipher ");
    mprint(&stage);
}

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
        shift_row(&mut stage[i], i);
    }
}

//~ Funktion zur Mischung der Spalten einer Matrix
fn mix_columns(mut stage: &mut Vec<Vec<u8>>) {
    for index in 0..stage[0].len() {
        mix_column(&mut stage, index);
    }
}

//~ Funktion zur Mischung einer Spalte
fn mix_column(stage: &mut Vec<Vec<u8>>, index: usize) {
    let t0: u8 = stage[0][index];
    let t1: u8 = stage[1][index];
    let t2: u8 = stage[2][index];
    let t3: u8 = stage[3][index];
    //~ Matrixmultiplkation wie in die originale Artikel
    stage[0][index] = gmul(t0, 0x2) ^ gmul(t1, 0x3) ^ t2 ^ t3;
    stage[1][index] = t0 ^ gmul(t1, 0x2) ^ gmul(t2, 0x3) ^ t3;
    stage[2][index] = t0 ^ t1 ^ gmul(t2, 0x2) ^ gmul(t3, 0x3);
    stage[3][index] = gmul(t0, 0x3) ^ t1 ^ t2 ^ gmul(t3, 0x2);
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

fn ctr128_inc(counter: &Vec<u8>, mut c: u64) -> Vec<u8> {
    //let mut c:u16 = 20;
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
    input_file_path: std::path::PathBuf,
    output_file_path: std::path::PathBuf,
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
    //Initialisierung von sbox und Ibox
    initialize_aes_sbox(&mut sbox, &mut ibox);
    println!("Initialisierung von sbox und Ibox");

    // Schluessel erweitern.
    let keys: Vec<Vec<Vec<u8>>> = key_expansion(&key_bytes, nk, nr, &sbox);
    println!("Schluessel erweitern");

    //~ Text lesen und in Bloeke aufteilen.
    let blocks_bytes: Vec<u8> = reader(input_file_path).ok().unwrap();

    let offset: usize = 16;
    let len:usize = blocks_bytes.len();
    let nbs: usize = len / offset; //16*2
    let rest: usize = len % offset;
    println!("Text lesen und in Bloeke aufteilen.");
    let zeros: Vec<u8> = vec![0; 16];
    let mut results = vec![zeros.clone()];
    results.resize(nbs, zeros);
    println!("Result buffer Size:{}", results.len());
    println!("Anzahl von bloecke:{}", nbs);
    //~ let mut results: Vec<Vec<Vec<u8>>> = Vec::new();

    //~ create atomic reference
    //~ let sbox = Arc::new(sbox);
    //~ let ibox = Arc::new(ibox);
    //~ let keys = Arc::new(keys);
    //~ let iv_bytes = Arc::new(iv_bytes);
    //~ let blocks_bytes = Arc::new(blocks_bytes);
    //~ let mut results = Arc::new(Mutex::new(results));

    //~ let mut handle_vec = vec![];
    let start = Instant::now();
    //~ println!("start= {:?}", start);
    //~ mprint(&results);
    println!("Input data length:{:?}", results.len());
    let mut iv_in: Vec<u8> = iv_bytes;
    //~ let mut iv_in: Vec<u8> = ctr128_inc(&iv_bytes, i as u64);
    for i in 0..nbs {
        //~ clone
        //~ let sbox_c = sbox.clone();
        //~ let ibox_c = ibox.clone();
        //~ let keys_c = keys.clone();
        //~ let results = results.clone();
        //~ let iv_bytes_c = iv_bytes.clone();
        //~ let blocks_bytes_c = blocks_bytes.clone();
        //~ let blocks_bytes_c = blocks_bytes[i*16..(i+1)*16].to_vec();

        //~ let handle = thread::spawn(move || {           // erstellt neue Threads
        //~ println!("i= {}", i);
        if i == 0 {
        } else {
            iv_in = ctr128_inc(&iv_in, 1 as u64);
        }

        //~ println!("{:?}", hex_bytes_to_byte_vector(&blocks_bytes[i*32..(i+1)*32].to_vec()));
        let pt: Vec<u8> = blocks_bytes[i * offset..(i + 1) * offset].to_vec();
        //~ let pt:Vec<u8> = hex_bytes_to_byte_vector(&blocks_bytes[i*offset..(i+1)*offset].to_vec()).ok().unwrap();
        //~ pt = blocks_bytes[i*16..(i+1)*16].to_vec();
        //~ let pt = blocks_bytes_c[i*16..(i+1)*16].to_vec();
        //~ let pt = blocks_bytes_c;
        let mut input = rot(&to2d(&iv_in));
        cipher(&mut input, &keys, nr, &sbox);
        // input = rot(&input);
        //~ cipher(&mut input, &keys, nk, nr, &sbox);
        //~ let mut results_c = results.lock().unwrap();   // Sperre auf Ergebniswert erhalten
        // let mut my:Vec<u8> = 
        // let me:Vec<u8> = input.clone().into_iter().flatten().collect();
        let my:Vec<u8> = rot(&input).into_iter().flatten().collect();
        // println!("me {:?}", me);
        // println!("my {:?}", my);
        // println!("pt {:?}", pt);
        // add_round_keys(&mut input, &rot(&to2d(&pt)));
        // input = rot(&input);
        results[i] = xor_for_vec(&my, &pt);
        // results[i] = input.into_iter().flatten().collect();
        //~ });
        //~ handle_vec.push(handle);
        //~ let mut iv_in:Vec<u8> = add_vec(&iv_bytes, &dec_to_hex(i));
        //~ let pt = blocks_bytes[i*16..(i+1)*16].to_vec();
        //~ let mut input = rot(&to2d(&iv_in));
        //~ cipher(&mut input, &keys, nk, nr, &sbox);
        //~ add_round_keys(&mut input, &to2d(&pt));
        //~ results[i] =input;
    }
    if rest != 0{
        iv_in = ctr128_inc(&iv_in, 1 as u64);
        let mut input = rot(&to2d(&iv_in));
        cipher(&mut input, &keys, nr, &sbox);
        let mut my:Vec<u8> = rot(&input).into_iter().flatten().collect();
        let pt: Vec<u8> = blocks_bytes[nbs * offset..].to_vec();
        my = my[0..rest].to_vec();
        results.push(xor_for_vec(&my, &pt));




    }

    let duration = start.elapsed();
    println!("End= {:?}", duration);
    //~ for handle in handle_vec {                         // wait for all threads to finish
    //~ handle.join().unwrap();
    //~ }
    //~ let results = results.lock().unwrap();
    let end_result: Vec<u8> = results.into_iter().flatten().collect();
    // let end_result = hex::encode(&end_result);
    // let end_result = end_result.as_bytes();

    //~ for i in 0..results.len() {
    //~ for j in 0..results[0].len() {
    //~ end_result.extend(results[i][j].iter().copied());
    //~ }
    //~ }
    //~ let end_result = hex::encode(&end_result); //hex  string
    let mut file = File::create(output_file_path).ok().unwrap();
    println!("output data length: {:?}", end_result.len() / 2);
    //~ file.write_all(&end_result).ok();
    file.write(&end_result[..]).ok();
    println!("end result {:02x?}", end_result);
    //~ let file1 = read("test.txt").ok();
    //~ let file2 = read("testout1.txt").ok();
    //~ println!("{:?}", (file1 == file2));
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
