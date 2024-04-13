import string
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from hashlib import sha256
from base64 import b64decode

# Name: get_cli_args
# Input: args
# Output: lines
def get_cli_args(args):
	'''
	This function validates the user input, ensuring that the program exits
	gracefully in case of user error. Also reads the contents of the given
	file, sending them back to main.'''

	# Throws an error if the wrong number of arguments are specified
	if len(args) != 2:
		print('Usage: python3 script.py <path_to_output.txt>')
		sys.exit(1)
	else:
		try:
			# Open the given file and read the lines
			output_file = args[1]
			with open(output_file, 'r') as file:
				lines = file.readlines()
			return lines
		except:
			# Gracefully exit, informing the user why this didn't work
			print(f'Error: {output_file} not found! Please double-check your spelling')
			sys.exit(1)

# Name: extract_content
# Input: lines
# Output: password, ciphertext
def extract_content(lines):
	'''
	This function parses the lines and grabs the password and encrypted flag for
	reversing. Gracefully exits if they cannot be found.
	'''

	try:
		# Pull the final string in each line, applying it to the respective var
		password = lines[0].split(' ')[-1].strip()
		encrypted_flag = lines[1].split(' ')[-1].strip()

		return password, encrypted_flag
	except:
		# If the strings can't be found for some reason, let the user know
		print('Unable to find password or flag. Please ensure that the file \
			hasn\'t been edited.')

# Name: crack_master_key
# Inputs: password
# Outputs: master_key
def crack_master_key(password):
	'''
	This function is responsible for the cracking of the master key. It essentially
	does the exact opposite of what the original code does. It reverses the password,
	and performs bitwise shifts based on the characters it finds.
	'''

	# Flip the password, deconstructing it in reverse order
	password = ''.join(reversed(password))
	alphabet = string.ascii_letters + string.digits + '~!@#$%^&*'
	# We'll build on this binary representation of the key until we have the full thing
	master_key = 0b0

	# Go through each character, determining the bit that generated it
	for char in password:
		# Check if the character is in the range a-zA-I
		if char in alphabet[:len(alphabet) // 2]:
			# left bitwise shift (double the binary number) and change LSB to 1
			master_key <<= 1
			master_key += 1
		# Check in the character is in the range J-Z1-9 or a special character
		elif char in alphabet [len(alphabet) //2:]:
			# left bitwise shift (double the binary number)
			master_key <<= 1
	# Get the number of bytes. The + 7 is to ensure that non-exact division works
	number_of_bytes = (master_key.bit_length() + 7) // 8
	# Convert the binary to bytes
	master_key = master_key.to_bytes(number_of_bytes,'little')
	return master_key

# Name: decrypt_flag
# Input: master_key, encrypted_flag
# Output: flag
def decrypt_flag(master_key, encrypted_flag):
	'''
	This function takes the key that we just decrypted and uses it to decrypt
	the flag.
	'''

	# Revert the encrypted flag to bytes
	ciphertext = b64decode(encrypted_flag)
	# Create the key and cipher using the master_key
	encryption_key = sha256(master_key).digest()
	cipher = AES.new(encryption_key, AES.MODE_ECB)
	# Decrypt the flag
	flag = cipher.decrypt(ciphertext)
	# Get rid of the extra bytes
	flag = unpad(flag, 16)
	# Decode the flag to human-readable UTF-8
	flag = flag.decode('UTF-8')

	return flag

def main():
	# Get user input and read file
	lines = get_cli_args(sys.argv)
	# Pull the useful values from lines
	password, encrypted_flag = extract_content(lines)
	# Reverse engineer the master key
	master_key = crack_master_key(password)
	# Decrypt the flag
	flag = decrypt_flag(master_key, encrypted_flag)
	print(f'\nThe flag is {flag}\n\nThank you for using my script!')
	print(f'Remember to read through the code to understand what it\'s doing!')
	print(f'Have a great day, and happy hacking!')

if __name__ == '__main__':
	main()
