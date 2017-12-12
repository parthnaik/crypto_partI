'''
Week 2

In this project you will implement two encryption/decryption systems, one using AES in CBC mode and another using AES in counter mode (CTR). In both cases the 16-byte encryption IV is chosen at random and is prepended to the ciphertext.

For CBC encryption we use the PKCS5 padding scheme discussed in the lecture (14:04). While we ask that you implement both encryption and decryption, we will only test the decryption function. In the following questions you are given an AES key and a ciphertext (both are hex encoded ) and your goal is to recover the plaintext and enter it in the input boxes provided below.

For an implementation of AES you may use an existing crypto library such as PyCrypto (Python), Crypto++ (C++), or any other. While it is fine to use the built-in AES functions, we ask that as a learning experience you implement CBC and CTR modes yourself.
'''

import sys
from Crypto.Cipher import AES
from Crypto.Util import Counter

AES_BLOCK_SIZE = 16
AES_KEY_LENGTH = 128

class AESDecrypt:

	# CBC
	def cbcdecrypt(self, key, ciphertext):
		key = key.decode('hex')
		vi = ciphertext.decode('hex')[:AES_BLOCK_SIZE]
		obj = AES.new(key, AES.MODE_CBC, vi)
		return obj.decrypt(ciphertext.decode('hex'))[AES_BLOCK_SIZE:]

	def ctrdecrypt(self, key, ciphertext):
		key = key.decode('hex')
		vi = ciphertext.decode('hex')[:AES_BLOCK_SIZE]
		ctr = Counter.new(AES_KEY_LENGTH, initial_value = long(vi.encode('hex'), AES_BLOCK_SIZE))
	 	obj = AES.new(key,AES.MODE_CTR,counter=ctr)	
	 	return obj.decrypt(ciphertext.decode('hex')[AES_BLOCK_SIZE:])

	def run(self):
		print 'Choose mode:'
		print '1. AES-CBC'
		print '2. AES-CTR'
		mode = int(raw_input('Enter mode (1 or 2): '))
		key = raw_input('Enter key: ')
		ciphertext = raw_input('Enter ciphertext: ')

		if mode == 1:
			print '\nDecrypted message:'
			print self.cbcdecrypt(key, ciphertext)
		else:
			print '\nDecrypted message:'
			print self.ctrdecrypt(key, ciphertext)

a = AESDecrypt()
a.run()			


