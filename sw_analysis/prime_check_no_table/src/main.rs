use std::env;

const NUMBER_MAX: u64 = 1000000;

fn is_prime(n: u64) -> bool {

    // check if n is less or equal to 1 --> not prime
    if n <= 1  {
        return false
    }
    // check if n is equal to 2 or 3 --> prime
    if n > 1 && n <= 3 {
        return true
    }
    // check if n is divisible by 2 or 3 --> not prime
    else if (n % 2 == 0) || (n % 3 == 0) {
        return false
    }

    // check for primality with 6k +/-1 optimization
    // see https://en.wikipedia.org/wiki/Primality_test
    let mut i = 5;
    while i * i <= n {
        if (n % i == 0) || (n % (i + 2) == 0) {
            return false
        }
        i = i + 6;
    }
    
    true
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

    // check numbers for primality
    for i in 0..numbers_vec.len() {
        if numbers_vec[i] < NUMBER_MAX {
            if is_prime(numbers_vec[i]) {
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
