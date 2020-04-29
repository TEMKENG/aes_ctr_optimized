# Software Project - Summer Semester 2020

In the following, all information about the software project is detailed.

## Scenario

File encryption is a common task to protect confidential data on Linux systems.
Command line tools like ``openssl`` can be of great use when automating file encryption.
In scenarios of large amounts of files to be encrypted and/or large individual file sizes,
optimized performance and memory management of such tools is of great value.

However, not only functional requirements dominate the development of security tools.
Also, the secure implementation of these tools is essential.
Therefore, the Rust programming language is a perfect candidate
for the development of a file encryption tool.

## Requirements

1. Develop a command line application for the encryption and decryption of files
   based on the provided template.
   - You may only change the contents of the file ``aes-ctr/src/aes_ctr_optimized.rs``.
     (This is the only source code file that will be submitted!)
   - The tool has to encrypt and decrypt files with AES in counter mode (CTR)
     and it has to be able to handle 128-bit and 256-bit AES keys.
   - The format of input and output files has to compatible with the ``openssl``
     command line tool.
2. Optimize the application for the following goals:
   - 1st priority: achieve highest possible throughput/smallest possible execution time
     (MIN, MAX, AVG time measured by ``perf`` and Python script)
   - 2nd priority: use as less dynamic memory as possible, max. 104857600 bytes
     (peak consumption measured by ``valgrind --tool=dhat``)
   - 3rd priority: achieve smallest possible binary size, max. 2097152 bytes
     (binary compiled by ``cargo build --release`` and stripped afterwards)
3. Do not work in groups and do not share code. There will be code similarity
   checks after submission. Plagiarism will lead to disqualification.

## Test Platform

The final submissions will be tested on the following hardware and software:
- Intel(R) Core(TM) i7-6600U CPU @ 2.60 GHz, 20 GB RAM
- Ubuntu 19.10, Linux 5.3.0 x86_64
- rustc 1.40.0, cargo 1.40.0

## Submissions

1. File ``aes-ctr/src/aes_ctr_optimized.rs`` which contains all your code
2. Documentation (PDF, max. 10 pages, German or English) in sound scientific style that contains:
   - Introduction and motivation of the task (1/2 page)
   - Your implementation and test environment (VM, native, CPU, etc.)
   - Overall concept and choice of AES software implementation type
   - Step-by-step optimizations
     - What is the idea of the optimization step?
     - How was it implemented?
     - Which (relative) improvement, if any, was achieved? (measurement data!)
   - Conclusion
   - Personal comments and feedback regarding your Rust learning phase (1/2 page)
   - References

## Hints

- There are several ways to implement AES. Do some research to get an overview!
- Checkout the OpenSSL implementation of CTR mode, in order to get compatibility
(and IV-counter-combination) right!
- Use ``openssl`` to generate test files, e.g. as follows:
```
echo -n "0123456789abcdef" > test.txt
openssl enc -aes-128-ctr -K 00112233445566778899aabbccddeeff -iv 00112233445566778899aabbccddeeff -in test.txt -out test.txt.enc128
openssl enc -d -aes-128-ctr -K 00112233445566778899aabbccddeeff -iv 00112233445566778899aabbccddeeff -in test.txt.enc128 -out test.dec128.txt
openssl enc -aes-256-ctr -K 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff -iv 00112233445566778899aabbccddeeff -in test.txt -out test.txt.enc256
openssl enc -d -aes-256-ctr -K 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff -iv 00112233445566778899aabbccddeeff -in test.txt.enc256 -out test.dec256.txt
```
- Mind the endianness of byte representations!

