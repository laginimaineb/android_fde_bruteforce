import struct
from StringIO import StringIO

#The crypt_mnt_ftr structure - see /system/vold/cryptfs.h
CRYPT_MNT_FTR = [('magic'                    , 'I'),
				 ('major_version'            , 'H'),
				 ('minor_version'            , 'H'),
				 ('ftr_size'                 , 'I'),
				 ('flags'                    , 'I'),
				 ('keysize'                  , 'I'),
				 ('crypt_size'               , 'I'),
				 ('fs_size'                  , 'Q'),
				 ('failed_decrypt_count'     , 'I'),
				 ('crypto_type_name'         , '64s'),
				 ('spare2'                   , 'I'),
				 ('master_key'               , '48s'),
				 ('salt'                     , '16s'),
				 ('persist_data_offset_0'    , 'Q'),
				 ('persist_data_offset_1'    , 'Q'),
				 ('persist_data_size'        , 'I'),
				 ('kdf_type'                 , 'B'),
				 ('N_factor'                 , 'B'),
				 ('r_factor'                 , 'B'),
				 ('p_factor'                 , 'B'),
				 ('encrypted_upto'           , 'Q'),
				 ('hash_first_block'         , '32s'),
				 ('keymaster_blob'           , '2048s'),
				 ('keymaster_blob_size'      , 'I'),
				 ('scrypted_intermediate_key', '32s')]

#The qcom_km_key_blob structure - see /hardware/qcom/keymaster/keymaster_qcom.h
QCOM_KEY_BLOB = [('magic_num'                       , 'I'),
				 ('version_num'                     , 'I'),
				 ('modulus'                         , '512s'),
				 ('modulus_size'                    , 'I'),
				 ('public_exponent'                 , '512s'),
				 ('public_exponent_size'            , 'I'),
				 ('iv'                              , '16s'),
				 ('encrypted_private_exponent'      , '512s'),
				 ('encrypted_private_exponent_size' , 'I'),
				 ('hmac'                            , '32s')]

def read_object(data, definition):
	'''
	Unpacks a structure using the given data and definition.
	'''
	reader = StringIO(data)
	obj = {}
	object_size = 0
	for (name, stype) in definition:
		object_size += struct.calcsize(stype)
		obj[name] = struct.unpack(stype, reader.read(struct.calcsize(stype)))[0]
	obj['object_size'] = object_size
	obj['raw_data'] = data
	return obj
	
def read_crypt_mnt_ftr(data): 
	return read_object(data, CRYPT_MNT_FTR)

def read_qcom_key_blob(data): 
	return read_object(data, QCOM_KEY_BLOB)
