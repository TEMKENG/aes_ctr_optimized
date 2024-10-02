all:
	clear && cargo run -- -c encrypt -i data/test.txt -v 00112233445566778899aabbccddeeff -k 000102030405060708090a0b0c0d0e0f -o data/test_coded.hex
py:
	clear && python aes-ctr_tests.py target/debug/aes-ctr.exe data/output.log

DECODE:
	cargo run -- -c encrypt -i data/test_coded.txt -v 00112233445566778899aabbccddeeff -k 000102030405060708090a0b0c0d0e0f -o ./data/test_decoded.desc
