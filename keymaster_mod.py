import sys
import hmac
import hashlib
import struct
from Crypto.Cipher import AES
from structures import read_qcom_key_blob

def verify_keyblob_hmac(keyblob, hmac_key):
	
	#Verifying the SHA256-HMAC of the blob
	original_hmac = keyblob['hmac'].encode("hex")
	keyblob_data = keyblob['raw_data'][0:keyblob['object_size']-0x20]
	calculated_hmac = hmac.new(hmac_key, keyblob_data, hashlib.sha256).hexdigest()
	if original_hmac != calculated_hmac:
		print "[-] HMAC mismatch!"
		print "[-] Stored HMAC: %s" % orignal_hmac
		print "[-] Calculated HMAC: %s" % calculated_hmac
		return False
	print "[+] HMAC match!"
	return True

def decrypt_keyblob_key(keyblob, enc_key, hmac_key):
	
	#Making sure the HMAC is valid
	if not verify_keyblob_hmac(keyblob, hmac_key):
		return None

	#Extracting the public exponent and modulus
	modulus = keyblob['modulus']
	modulus = int(modulus[0:keyblob['modulus_size']].encode("hex"), 16)

	public_exp = keyblob['public_exponent']
	public_exp = int(public_exp[0:keyblob['public_exponent_size']].encode("hex"), 16)

	#Decrypting the private exponent!
	priv_exp_enc = keyblob['encrypted_private_exponent']
	priv_exp_enc = priv_exp_enc[0:keyblob['encrypted_private_exponent_size']]
	iv = keyblob['iv']
	priv_exp_dec = AES.new(enc_key, AES.MODE_CBC, IV=iv).decrypt(priv_exp_enc)
	priv_exp_dec = int(priv_exp_dec.encode("hex"), 16)
	
	#Checking that the key is valid
	if pow(pow(0x1337, public_exp, modulus), priv_exp_dec, modulus) == 0x1337:
		print "[+] Key is valid!"
		print "[+] pow(pow(0x1337, e, N), d, N) == 0x1337"
	else:
		print "[-] Key is invalid. Please make sure you have the right decryption key."
		return None

	return (modulus, public_exp, priv_exp_dec)
	

def main():

	#Reading the commandline arguments
	if len(sys.argv) != 4:
		print "USAGE: %s <ENC_KEY> <HMAC_KEY> <KEYMASTER_BLOB>" % sys.argv[0]
		return
	enc_key = sys.argv[1].decode("hex")
	hmac_key = sys.argv[2].decode("hex")
	keyblob = read_qcom_key_blob(sys.argv[3].decode("hex"))

	#Decrypting the key
	(N,e,d) = decrypt_keyblob_key(keyblob, enc_key, hmac_key)	
	
	#Printing the key information
	print "-----------------------------"
	print "Decrypted Private Key:"
	print "N=%d" % N
	print "e=%d" % e
	print "d=%d" % d
	print "-----------------------------"


if __name__ == "__main__":
	main()
