# Test-Framework for AES-CTR Software Project

import sys
import os
import time
import subprocess
import re
import secrets
from tqdm import tqdm
from icecream import ic

# Print usage
def print_usage():
    print()
    print('Usage:')
    print('  ', sys.argv[0], '<path-to-executable-under-test> <path-to-result-file>')
    print()

# Test compatibility to openssl tool
def test_openssl_compatibility(exec_path, result_file):
    test_name = 'OpenSSL Compatibility Test'
    print('--- Performing >>', test_name, '<< ...')
    # Create test directories
    openssl_tmp_dir = './tmp-openssl/'
    aes_ctr_tmp_dir = './tmp-aes-ctr/'
    os.makedirs(openssl_tmp_dir, exist_ok=True)
    os.makedirs(aes_ctr_tmp_dir, exist_ok=True)
    # Initialize test data
    key_128 = '000102030405060708090a0b0c0d0e0f'
    key_256 = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
    iv      = '00112233445566778899aabbccddeeff'
    data    = '0123456789abcdef'
    # Initialize test files
    test_file        = 'test.txt'
    test_enc128_file = 'test.txt.enc128'
    test_dec128_file = 'test.txt.dec128'
    test_enc256_file = 'test.txt.enc256'
    test_dec256_file = 'test.txt.dec256'
    # Perform commands with openssl tool
    with open(openssl_tmp_dir + 'test.txt', 'w') as f: 
        f.write(data)
    
    openssl_cmd = 'openssl enc -aes-128-ctr -K ' + key_128 + ' -iv ' + iv + ' -in ' + test_file + ' -out ' + test_enc128_file
    print(openssl_cmd)
    subprocess.run(openssl_cmd.split(' '), cwd=openssl_tmp_dir, capture_output=True, text=True)
    openssl_cmd = 'openssl enc -d -aes-128-ctr -K ' + key_128 + ' -iv ' + iv + ' -in ' + test_enc128_file + ' -out ' + test_dec128_file
    subprocess.run(openssl_cmd.split(' '), cwd=openssl_tmp_dir, capture_output=True, text=True)
    openssl_cmd = 'openssl enc -aes-256-ctr -K ' + key_256 + ' -iv ' + iv + ' -in ' + test_file + ' -out ' + test_enc256_file
    subprocess.run(openssl_cmd.split(' '), cwd=openssl_tmp_dir, capture_output=True, text=True)
    openssl_cmd = 'openssl enc -d -aes-256-ctr -K ' + key_256 + ' -iv ' + iv + ' -in ' + test_enc256_file + ' -out ' + test_dec256_file
    subprocess.run(openssl_cmd.split(' '), cwd=openssl_tmp_dir, capture_output=True, text=True)
    # Perform command with executable under test and compare
    with open(aes_ctr_tmp_dir + 'test.txt', 'w') as f: 
        f.write(data)
    aes_ctr_cmd = './' + exec_path + ' -c encrypt -k ' + key_128 + ' -v ' + iv + ' -i ' + test_file + ' -o ' + test_enc128_file
    foo = subprocess.run(aes_ctr_cmd.split(' '), cwd=aes_ctr_tmp_dir, capture_output=True, text=True)
    print(foo.stdout)
    aes_ctr_cmd = './' + exec_path + ' -c decrypt -k ' + key_128 + ' -v ' + iv + ' -i ' + test_enc128_file + ' -o ' + test_dec128_file
    subprocess.run(aes_ctr_cmd.split(' '), cwd=aes_ctr_tmp_dir, capture_output=True, text=True)
    aes_ctr_cmd = './' + exec_path + ' -c encrypt -k ' + key_256 + ' -v ' + iv + ' -i ' + test_file + ' -o ' + test_enc256_file
    subprocess.run(aes_ctr_cmd.split(' '), cwd=aes_ctr_tmp_dir, capture_output=True, text=True)
    aes_ctr_cmd = './' + exec_path + ' -c decrypt -k ' + key_256 + ' -v ' + iv + ' -i ' + test_enc256_file + ' -o ' + test_dec256_file
    subprocess.run(aes_ctr_cmd.split(' '), cwd=aes_ctr_tmp_dir, capture_output=True, text=True)
    # Compare files
    list_of_files = [
       test_enc128_file,
       test_dec128_file,
       test_enc256_file,
       test_dec256_file,
       ]
    for filename in list_of_files:
        file1 = openssl_tmp_dir + filename
        file2 = aes_ctr_tmp_dir + filename
        file_cmp = subprocess.run(['cmp', '-s', file1, file2], cwd='./')
        if file_cmp.returncode == 0:
            result_file.write(test_name + ', ' + filename + ', OK, \n')
        else:
            result_file.write(test_name + ', ' + filename + ', MISMATCH, \n')
    # Delete temporary files
    subprocess.run(['rm', '-r', openssl_tmp_dir], cwd='./', capture_output=True, text=True)
    subprocess.run(['rm', '-r', aes_ctr_tmp_dir], cwd='./', capture_output=True, text=True)

# Get file size
def get_file_size(exec_path, result_file):
    test_name = 'File Size Test'
    print('--- Performing >>', test_name, '<< ...')
    exec_size = os.path.getsize(exec_path)
    result_file.write(test_name + ', File Size, ' + str(exec_size) + ', bytes\n')

# Get section sizes
def get_section_sizes(exec_path, result_file):
    test_name = 'Section Sizes Test'
    print('--- Performing >>', test_name, '<< ...')
    print('--- Performing >>', exec_path, '<< ...')
    # size = subprocess.run(['size', '-A', exec_path], cwd='./', capture_output=True, text=True)
    
    # size_text_sec = re.search('\.text\s+([0-9]+)', size.stdout).group(1)
    # size_rodata_sec = re.search('\.rodata\s+([0-9]+)', size.stdout).group(1)
    # size_data_sec = re.search('\.data\s+([0-9]+)', size.stdout).group(1)
    # size_bss_sec = re.search('\.bss\s+([0-9]+)', size.stdout).group(1)
    # result_file.write(test_name + ', .text, ' + size_text_sec + ', bytes\n')
    # result_file.write(test_name + ', .rodata, ' + size_rodata_sec + ', bytes\n')
    # result_file.write(test_name + ', .data, ' + size_data_sec + ', bytes\n')
    # result_file.write(test_name + ', .bss, ' + size_bss_sec + ', bytes\n')
    
    
    
    size = subprocess.run(['objdump', '-h', exec_path], cwd='./', capture_output=True, text=True)
    sections = size.stdout.split('\n')

    size_text_sec = 0
    size_rodata_sec = 0
    size_data_sec = 0
    size_bss_sec = 0

    for section in sections:
        match = re.search('\.text\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)', section)
        if match:
            if match.group(2) == 'AX':
                size_text_sec = int(match.group(3), 16)
        match = re.search('\.rodata\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)', section)
        if match:
            if match.group(2) == 'AR':
                size_rodata_sec = int(match.group(3), 16)
        match = re.search('\.data\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)', section)
        if match:
            if match.group(2) == 'WA':
                size_data_sec = int(match.group(3), 16)
        match = re.search('\.bss\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)', section)
        if match:
            if match.group(2) == 'WA':
                size_bss_sec = int(match.group(3), 16)

    result_file.write(test_name + ',.text,' + str(size_text_sec) + ', bytes\n')
    result_file.write(test_name + ',.rodata,' + str(size_rodata_sec) + ', bytes\n')
    result_file.write(test_name + ',.data,' + str(size_data_sec) + ', bytes\n')
    result_file.write(test_name + ',.bss,' + str(size_bss_sec) + ', bytes\n')

# Get global heap maximum
def get_global_heap_max(exec_path, result_file):
    test_name = 'Global Heap Maximum Test'
    print('--- Performing >>', test_name, '<< ...')
    # Test parameters
    filesizes     = [1024, 1024*1024, 1024*1024*1024]
    test_in_file  = 'dhat-test.tmp'
    test_out_file = 'dhat-test.out.tmp'
    key_128 = ''.join('{:02x}'.format(x) for x in secrets.token_bytes(16))
    key_256 = ''.join('{:02x}'.format(x) for x in secrets.token_bytes(32))
    iv      = ''.join('{:02x}'.format(x) for x in secrets.token_bytes(16))
    commands      = [
        exec_path + ' -c encrypt -k ' + key_128 + ' -v ' + iv + ' -i ' + test_in_file + ' -o ' + test_out_file,
        exec_path + ' -c decrypt -k ' + key_128 + ' -v ' + iv + ' -i ' + test_in_file + ' -o ' + test_out_file,
        exec_path + ' -c encrypt -k ' + key_256 + ' -v ' + iv + ' -i ' + test_in_file + ' -o ' + test_out_file,
        exec_path + ' -c decrypt -k ' + key_256 + ' -v ' + iv + ' -i ' + test_in_file + ' -o ' + test_out_file,
        ]
    # Loop through tests with different file sizes and commands
    with tqdm(total=len(filesizes)*len(commands)) as pbar:
        for filesize in filesizes:
            for cmd in commands:
                # Initialize random test data
                subprocess.run(['openssl', 'rand', '-out', test_in_file, str(filesize)])
                # Call valgrind
                valgrind = subprocess.run(['valgrind', '--tool=dhat', '--dhat-out-file=dhat-output.tmp'] + cmd.split(' '),
                                           cwd='./', capture_output=True, text=True)
                global_heap_max = re.sub(',', '',  re.search('At.t-gmax:.(\d+|\d{1,3}(,\d{3})*)\s', valgrind.stderr).group(1))
                # Write result to file
                result_file.write(test_name + ', AES-CTR-' + str((len(cmd)-len(commands[0]))*4+128) + ' '
                                  + cmd[len(exec_path)+4:len(exec_path)+11] + ' ' + str(filesize) + ' bytes, '
                                  + global_heap_max + ', ' + cmd + '\n')
                # Remove temporary files
                subprocess.run(['rm', 'dhat-output.tmp'], cwd='./', capture_output=True, text=True)
                subprocess.run(['rm', test_in_file], cwd='./', capture_output=True, text=True)
                subprocess.run(['rm', test_out_file], cwd='./', capture_output=True, text=True)
                pbar.update(1)

# Get exection time
def get_execution_time(exec_path, result_file):
    test_name = 'Execution Time Test'
    print('--- Performing >>', test_name, '<< ...')
    # Get rights to use perf counters
    os.system('sudo -S sh -c \'echo 0 > /proc/sys/kernel/perf_event_paranoid\'')
    # Test parameters
    filesizes     = [1024, 1024*1024, 1024*1024*1024]
    test_in_file  = 'perf-test.tmp'
    test_out_file = 'perf-test.out.tmp'
    key_128 = ''.join('{:02x}'.format(x) for x in secrets.token_bytes(16))
    key_256 = ''.join('{:02x}'.format(x) for x in secrets.token_bytes(32))
    iv      = ''.join('{:02x}'.format(x) for x in secrets.token_bytes(16))
    commands      = [
        exec_path + ' -c encrypt -k ' + key_128 + ' -v ' + iv + ' -i ' + test_in_file + ' -o ' + test_out_file,
        exec_path + ' -c decrypt -k ' + key_128 + ' -v ' + iv + ' -i ' + test_in_file + ' -o ' + test_out_file,
        exec_path + ' -c encrypt -k ' + key_256 + ' -v ' + iv + ' -i ' + test_in_file + ' -o ' + test_out_file,
        exec_path + ' -c decrypt -k ' + key_256 + ' -v ' + iv + ' -i ' + test_in_file + ' -o ' + test_out_file,
        ]
    n_measurements = 3
    # Loop through tests with different file sizes and commands
    with tqdm(total=len(filesizes)*len(commands)*n_measurements) as pbar:
        for filesize in filesizes:
            for cmd in commands:
                time_data = []
                # Loop through several measurement runs
                for n in range(n_measurements):
                    # Initialize random test data
                    subprocess.run(['openssl', 'rand', '-out', test_in_file, str(filesize)])
                    # Call perf
                    perf = subprocess.run(['perf', 'stat'] + cmd.split(' '), cwd='./', capture_output=True, text=True)
                    time_str = re.sub(',', '.', re.search('([0-9]*,[0-9]*).seconds.time', perf.stderr).group(1))
                    time_data.append(float(time_str))
                    # Remove temporary files
                    subprocess.run(['rm', test_in_file], cwd='./', capture_output=True, text=True)
                    subprocess.run(['rm', test_out_file], cwd='./', capture_output=True, text=True)
                    pbar.update(1)
                # Write results to file
                result_file.write(test_name + ', AES-CTR-' + str((len(cmd)-len(commands[0]))*4+128) + ' '
                                  + cmd[len(exec_path)+4:len(exec_path)+11] + ' ' + str(filesize) + ' bytes MIN, '
                                  + str(min(time_data)) + ', ' + cmd + '\n')
                result_file.write(test_name + ', AES-CTR-' + str((len(cmd)-len(commands[0]))*4+128) + ' '
                                  + cmd[len(exec_path)+4:len(exec_path)+11] + ' ' + str(filesize) + ' bytes MAX, '
                                  + str(max(time_data)) + ', ' + cmd + '\n')
                result_file.write(test_name + ', AES-CTR-' + str((len(cmd)-len(commands[0]))*4+128) + ' '
                                  + cmd[len(exec_path)+4:len(exec_path)+11] + ' ' + str(filesize) + ' bytes AVG, '
                                  + str(sum(time_data)/len(time_data)) + ', ' + cmd + '\n')

# List of tests
list_of_tests = [
    test_openssl_compatibility,
    # get_file_size,
    # get_section_sizes,
    # get_global_heap_max,
    # get_execution_time,
    ]

# Main function
def main():

    # Check command line arguments
    if len(sys.argv) != 3:
        print('!!! ERROR: Number of arguments does not match!')
        print_usage()
        sys.exit(1)

    # Check executable path    
    exec_under_test_path = sys.argv[1]
    if not (os.path.isfile(exec_under_test_path) and os.access(exec_under_test_path, os.X_OK)):
        print('!!! ERROR: No executable found at given path!')
        print_usage()
        sys.exit(1)

    # Check result file path    
    result_file_path = sys.argv[2]
    try:
        result_file = open(result_file_path, 'w')
        result_file.write('Test, Result Name, Result Value, Comment\n')
    except OSError:
        print('!!! ERROR: Cannot open result file for writing!')
        print_usage()
        sys.exit(1)
    
    # Perform tests
    local_time = time.ctime(time.time())
    print('### Starting Test Procedures (' + local_time + ') ...')
    for test in list_of_tests:
        test(exec_under_test_path, result_file)
    local_time = time.ctime(time.time())
    print('### Finished Testing! (' + local_time + ')')

    # Close result file
    result_file.close()

if __name__ == "__main__":
    main()

