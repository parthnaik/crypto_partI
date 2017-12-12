'''
In this project you will experiment with a padding oracle attack against a toy web site hosted at crypto-class.appspot.com . Padding oracle vulnerabilities affect a wide variety of products, including secure tokens (http://arstechnica.com/security/2012/06/securid-crypto-attack-steals-keys/).

This project will show how they can be exploited. We discussed CBC padding oracle attacks in week 4 (segment number 6 - https://www.coursera.org/learn/crypto/lecture/8s23o/cbc-padding-attacks), but if you want to read more about them, see a short description here (https://crypto.stanford.edu/~dabo/cryptobook/BonehShoup_0_4.pdf#page=373) or Vaudenay's paper (http://www.iacr.org/archive/eurocrypt2002/23320530/cbc02_e02d.pdf) on this topic.

Now to business. Suppose an attacker wishes to steal secret information from our target web site crypto-class.appspot.com . The attacker suspects that the web site embeds encrypted customer data in URL parameters such as this:

http://crypto-class.appspot.com/po?er
    =f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4

That is, when customer Alice interacts with the site, the site embeds a URL like this in web pages it sends to Alice. The attacker intercepts the URL listed above and guesses that the ciphertext following the "po?er=" is a hex encoded AES CBC encryption with a random IV of some secret data about Alice's session.

After some experimentation the attacker discovers that the web site is vulnerable to a CBC padding oracle attack. In particular, when a decrypted CBC ciphertext ends in an invalid pad the web server returns a 403 error code (forbidden request). When the CBC padding is valid, but the message is malformed, the web server returns a 404 error code (URL not found).

Armed with this information your goal is to decrypt the ciphertext listed above. To do so you can send arbitrary HTTP requests to the web site of the form

http://crypto-class.appspot.com/po?er="your ciphertext here"
and observe the resulting error code. The padding oracle will let you

decrypt the given ciphertext one byte at a time. To decrypt a single byte you will need to send up to 256 HTTP requests to the site. Keep in mind that the first ciphertext block is the random IV. The decrypted message is ASCII encoded.

To get you started here is a short Python script (http://spark-university.s3.amazonaws.com/stanford-crypto/projects/pp4-attack_py.html) that sends a ciphertext supplied on the command line to the site and prints the resulting error code. You can extend this script (or write one from scratch) to implement the padding oracle attack. Once you decrypt the given ciphertext, please enter the decrypted message in the box below.

This project shows that when using encryption you must prevent padding oracle attacks by either using encrypt-then-MAC as in EAX or GCM, or if you must use MAC-then-encrypt then ensure that the site treats padding errors the same way it treats MAC errors.
'''

import urllib2
import sys

TARGET = 'http://crypto-class.appspot.com/po?er='
CIPHERTEXT = 'f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4'
CHAR_GUESS_LIST = [' ', 'e', 't', 'a', 'o', 'n', 'i', 's', 'r', 'h', 'l', 'd', 'c', 'u', 'p', 'f', 'm', 'w', 'y', 'b', 'g', 'v', 'k', 'q', 'x', 'j', 'z', 'E', 'T', 'A', 'O', 'N', 'I', 'S', 'R', 'H', 'L', 'D', 'C', 'U', 'P', 'F', 'M', 'W', 'Y', 'B', 'G', 'V', 'K', 'Q', 'X', 'J', 'Z', ',', '.', '!'] # list of guesses in order of probablity, numbers represent guesses for padding
PADDING_GUESS_LIST = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
AES_BLOCK_SIZE = 16
#--------------------------------------------------------------
# padding oracle
#--------------------------------------------------------------
class PaddingOracle:

  def __init__(self):
    self.blocks = [CIPHERTEXT[i : i + AES_BLOCK_SIZE * 2] for i in range(0, len(CIPHERTEXT), AES_BLOCK_SIZE * 2)] # split string into array of 4 16-byte strings
    self.decryptedString = ''

  def query(self, q):
    target = TARGET + urllib2.quote(q)    # Create query URL
    req = urllib2.Request(target)         # Send HTTP request to server
    try:
      f = urllib2.urlopen(req)            # Wait for response
    except urllib2.HTTPError, e:          
      # print 'We got: %d' % e.code         # Print response code
      if e.code == 404:
          return True # good padding
      return False # bad padding   

  # xor two strings of different lengths
  def strxor(self, a, b):      
    if len(a) > len(b):
      return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])
    else:
      return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])])

  # xor two hex strings and return hex string
  def strxorHex(self, a, b):
    return self.strxor(a.decode('hex'), b.decode('hex')).encode('hex')

  def constructPaddingString(self, paddingLength):
    nonZeroBits = format(paddingLength, '02x') * paddingLength
    return str(nonZeroBits).zfill(AES_BLOCK_SIZE * 2) # prepend with appropriate amount of zeroes

  def decryptBlock(self, prefixBlocks, prevBlock, currBlock, findPad = False):
    decryptedStringSoFar = ''
    decryptedBlockSoFar = ['00'] * 16
    i = AES_BLOCK_SIZE - 1

    while i >= 0:
      pad = self.constructPaddingString(AES_BLOCK_SIZE - i)

      # find pad for currBlock (if it is the final block of the list)
      if findPad:
        for g in PADDING_GUESS_LIST:
          decryptedBlockSoFar[i] = format(g, '02x')
          guess = ''.join(decryptedBlockSoFar)
          resultBlock = self.strxorHex(prevBlock, self.strxorHex(guess, pad))

          if self.query(prefixBlocks + resultBlock + currBlock):
            if g == AES_BLOCK_SIZE: # it would mean this whole block is a pad and does not need decryption
              return
            else: # otherwise we change the last g elements of decryptedBlockSoFar to the numerical pad
              decryptedBlockSoFar[-g:] = [decryptedBlockSoFar[i]] * g
              findPad = False # we have found the pad at this point so there is no need to look for it again
              i = AES_BLOCK_SIZE - g # reset index to work correctly on next iteration
              break
      else:
        for g in CHAR_GUESS_LIST:
          decryptedBlockSoFar[i] = g.encode('hex')
          guess = ''.join(decryptedBlockSoFar)
          resultBlock = self.strxorHex(prevBlock, self.strxorHex(guess, pad))

          if self.query(prefixBlocks + resultBlock + currBlock):
            decryptedStringSoFar += g
            print 'Found character: %s' % g
            break

      i -= 1   

    self.decryptedString += ''.join(reversed(decryptedStringSoFar))        

  def run(self):
    for i in range(0, len(self.blocks) - 1):
      prefixBlocks = ''
      for j in range(0, i):
        prefixBlocks += self.blocks[j]

      if (i + 1) == (len(self.blocks) - 1): # when decrypting the last block
        self.decryptBlock(prefixBlocks, self.blocks[i], self.blocks[i + 1], True)
      else:
        self.decryptBlock(prefixBlocks, self.blocks[i], self.blocks[i + 1])

    print ''
    print 'Decrypion Complete!'
    print 'The decrypted string is: '
    print self.decryptedString

po = PaddingOracle()
po.run()