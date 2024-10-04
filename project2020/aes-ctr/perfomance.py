import os
import subprocess
import pandas as pd
from icecream import ic
from datetime import datetime
from collections import defaultdict

os.chdir('.')
if __name__ == '__main__':
    results = defaultdict(list)
    remove_file = 'rm -rf {}'
    dirname = 'data/to_cipher'
    output_file = 'data/test_coded.hex'
    file = open("data/output.log", "w")
    for filename in os.listdir(dirname):
        filename = os.path.join(dirname, filename)
        if os.path.exists(output_file):
            os.remove(output_file)
        command = 'cargo run --release -- -c encrypt -i %s -v 00112233445566778899aabbccddeeff -k 000102030405060708090a0b0c0d0e0f -o data/test_coded.hex'
        command = command % filename
        print(command)
        # Run the command and redirect the output to the file
        for _ in range(10):
            now = datetime.now()
            subprocess.run(command.split(' '), stdout=file,
                           text=True, stderr=subprocess.STDOUT)
            results[filename].append((datetime.now() - now).total_seconds())
        results[filename] = sum(results[filename]) / len(results[filename])
        ic(filename, results[filename])
    file.close()

    print(*results.items(), sep="\n")
