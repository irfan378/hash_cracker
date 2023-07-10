use md5;
use sha1::Digest;
use std::{
    env,
    error::Error,
    fs::File,
    io::{BufRead, BufReader},
    process,
};

const SHA1_HEX_STRING_LENGTH: usize = 40;

fn main() -> Result<(), Box<dyn Error>> {
    // collect the args in the args vector
    let args: Vec<String> = env::args().collect();
    // check wheather the args length is not equal to 3
    if args.len() == 2 {
        let help = args[1].trim();
        if help == "help" {
            println!("Usage:");
            println!("hash_cracker: <wordlist.txt> <hash> <hash_type_number>");
            println!(
                "Number    hash_type\n
1         sha-1\n
2         md5  "
            );

            process::exit(0);
        }
    }
    if args.len() != 4 {
        println!("Usage:");
        println!("hash_cracker: <wordlist.txt> <hash> <hash_type>\nhash_type: hash_cracker help");
        process::exit(0);
    }

    // take the second argument as hash
    let hash_to_crack = args[2].trim();
    // type of hash
    let hash_type = args[3].trim();
    let hash_type_number: i32 = hash_type.parse().unwrap();
    let wordlist_file = File::open(&args[1])?;

    // check the type of hash
    if hash_type_number == 1 {
        let _ = sha1_crack(hash_to_crack, wordlist_file);
    } else {
        let _ = md5_crack(hash_to_crack, wordlist_file);
    }

    Ok(())
}
fn sha1_crack(hash_to_crack: &str, wordlist_file: File) -> Result<(), Box<dyn Error>> {
    // check wheather the length of the hash is greater than 40
    if hash_to_crack.len() != SHA1_HEX_STRING_LENGTH {
        print!("sha1 hash is not valid\n");
        return Err("sha1 hash is not valid".into());
    } // open the wordlist file
    let reader = BufReader::new(&wordlist_file);

    // read the wordlist file line by liune
    for line in reader.lines() {
        let line = line?;
        let common_password = line.trim();
        // hash the password in wordlist and check wheather it is equal to hash provided in args
        if hash_to_crack == &hex::encode(sha1::Sha1::digest(common_password.as_bytes())) {
            println!("Password found: {}", &common_password);
            return Ok(());
        }
    }
    // if not found print the message
    println!("password not found in wordlist :(");
    Ok(())
}
fn md5_crack(hash_to_crack: &str, wordlist_file: File) -> Result<(), Box<dyn Error>> {
    // check wheather the length of hash in hex is equal to hash provided in args
    // read the wordlist file line by liune
    let reader = BufReader::new(&wordlist_file);

    for line in reader.lines() {
        let line = line?;
        let common_password = line.trim();

        let digest = md5::compute(common_password.as_bytes());
        let reference: &[u8] = digest.as_ref();

        if hash_to_crack == hex::encode(reference) {
            println!("Password found: {}", &common_password);
            return Ok(());
        }
    }
    // hash the password in wordlist and check wheather it is equal to hash provided in args

    // if not found print the message
    println!("password not found in wordlist :(");
    Ok(())
}
