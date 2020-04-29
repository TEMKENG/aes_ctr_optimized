use std::env;

const NUMBER_MAX: u64 = 1000000;

fn generate_table (table: &mut Vec<u64>) {
    for n in 3..NUMBER_MAX {
        let mut prime = true;
        for p in table.iter() {
            if n % p == 0 {
                prime = false;
                break;
            }
        }
        if prime == true {
            table.push(n);
        }
    }
}

fn is_prime(n: u64, table: &Vec<u64>) -> bool {
    if table.iter().any(|&x| x == n) {
        true
    }
    else {
        false
    }
}

fn main () {

    let mut numbers_vec: Vec<u64> = Vec::new();

    // parse command line arguments
    for argument in env::args().skip(1) {
        match argument.parse() {
            Ok(number) => numbers_vec.push(number),
            Err(e)     => println!("ARGUMENT PARSING ERROR: {}", e),
        }
    }

    // generate prime table
    let mut primes_vec: Vec<u64> = Vec::new();
    primes_vec.push(2);
    generate_table(&mut primes_vec);

    // check numbers for primality
    for i in 0..numbers_vec.len() {
        if numbers_vec[i] < NUMBER_MAX {
            if is_prime(numbers_vec[i], &primes_vec) {
                println!("{} is prime!", numbers_vec[i]);
            }
            else {
                println!("{} is not prime!", numbers_vec[i]);
            }
        }
        else {
            println!("{} is too large! Must be less than {}!", numbers_vec[i], NUMBER_MAX);
        }
    }
}
