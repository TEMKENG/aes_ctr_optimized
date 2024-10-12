all:
	clear && rm -rf data/test_coded.hex && cargo run --release -- -c encrypt -i data/to_cipher/test_2gb.txt -v 00112233445566778899aabbccddeeff -k 000102030405060708090a0b0c0d0e0f -o data/test_coded.hex > data/output.log
py:
	clear && python aes-ctr_tests.py target/debug/aes-ctr.exe data/output.log
DECODE:
	cargo run -- -c encrypt -i data/test_coded.txt -v 00112233445566778899aabbccddeeff -k 000102030405060708090a0b0c0d0e0f -o ./data/test_decoded.desc
ssl:
	clear && openssl enc -d -aes-128-ctr -K 000102030405060708090a0b0c0d0e0f -iv 00112233445566778899aabbccddeeff -in data/test_1kb.txt -out data/test_coded_openssl.hex