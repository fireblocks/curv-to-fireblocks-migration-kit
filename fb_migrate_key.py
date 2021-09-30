#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import csv
import getpass
import hashlib
import json
import os
import secrets
import struct
import sys
from typing import List, Tuple
from uuid import UUID

from bip32 import BIP32
from bip32.utils import _privkey_to_pubkey
from bip32.utils import coincurve as curve
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Util import Padding
from password_strength import PasswordPolicy
from termcolor import colored

SECP256K1_ORDER = curve.utils.GROUP_ORDER_INT 

# CSV Column constants 
CSV_ID      = "Wallet ID"
CSV_NAME    = "Wallet Name"
CSV_SYMBOL  = "Currency Global Symbol"
CSV_NETWORK = "Currency Network"
CSV_ERC20   = "Currency Contract Address (For ERC20)"
CSV_PATH    = "BIP32 Path"
CSV_ADDRESS = "Address"
CSV_PRIV    = "Private Key (hex)"
CSV_XPUB    = "Extended Public Key"
CSV_XPRIV   = "Extended Private Key"
CSV_PRV_WIF = "Private Key (WIF)"
CSV_FILE    = "Filename"

JSON_DEVICES       = "devices"
JSON_NAME          = "name"
JSON_KEY_ID        = "keyId"
JSON_USER_ID       = "userId"
JSON_DEVICE_ID     = "deviceId"
JSON_CHAINCODE     = "chaincode"
JSON_PUBKEY        = "pubkey"
JSON_ENC_PRIVKEY   = "enc_privkey"

DICT_PARTY_ID   = "partyId"
DICT_PRIVKEY    = "privkey"
DICT_RSA_PEM    = "RSA_pem"
DICT_RSA_KEY    = "RSA_pub"
DICT_PASSPHRASE = "passphrase"


PASSPHRASE_MIN_LENGTH  = 10
PASSPHRASE_MIN_UPPER   = 1
PASSPHRASE_MIN_DIGITS  = 1
PASSPHRASE_MIN_SPECIAL = 1


class MigrationError(Exception):
    def __init__(self, msg):
        self._msg = msg

    def __str__(self):
        return colored(f'ERROR: {self._msg}', "red")


def _set_if_root(row: dict, curr_root: dict):
    if row[CSV_PATH] == 'm/':
        if curr_root:
            if curr_root[CSV_PRIV] != row[CSV_PRIV]:
                raise MigrationError("Found two different root private keys in csv file")
            return
    
        curr_root.update(row)


def parse_recovery_csv(csv_path:str) -> Tuple[str, List[dict]]:
    keys_list = list()
    root_key = dict()

    with open(csv_path, newline='') as csvfile:
        reader = csv.DictReader(csvfile)

        for row in reader:
            _set_if_root(row, root_key) 
            keys_list.append(row)

    return root_key[CSV_XPRIV], keys_list


def _verify_derived_private_key(root_wallet:BIP32, key_path:str, derived_key:dict):
    if root_wallet.get_privkey_from_path(key_path).hex() != derived_key[CSV_PRIV]:
        raise MigrationError(f'Invalid private key derivation for wallet {derived_key[CSV_NETWORK]}')


def _verify_derived_xpub(root_wallet:BIP32, key_path:str, derived_key:dict):
    if root_wallet.get_xpub_from_path(key_path) != derived_key[CSV_XPUB]:
        raise MigrationError(f'Invalid public key derivation derivation for wallet {derived_key[CSV_NETWORK]}')


def verify_derived_keys(root_xprv:str, derived_keys_list:List[dict]):

    root_wallet = BIP32.from_xpriv(root_xprv)

    for key in derived_keys_list:
        key_path = key[CSV_PATH].strip("/")
        _verify_derived_private_key(root_wallet, key_path, key)
        _verify_derived_xpub(root_wallet, key_path, key)


def _load_RSA_pub(party: dict):    
    RSA_key = RSA.importKey(party[DICT_RSA_PEM])

    if RSA_key.n.bit_length() < 4096:
        MigrationError(f'RSA key is too short: {RSA_key.n.bit_length()}, should be at least 4096 bits')
        
    party[DICT_RSA_KEY] = RSA_key

def _get_secret_input(prompt_text):
    if sys.stdin.isatty():
        return getpass.getpass(prompt_text)
    else:
        print(prompt_text, end='')
        return sys.stdin.readline().rstrip()

def _get_passphrase(party, name):
    
    passphrase_policy = PasswordPolicy.from_names(
        length    =PASSPHRASE_MIN_LENGTH,
        uppercase =PASSPHRASE_MIN_UPPER,
        numbers   =PASSPHRASE_MIN_DIGITS,
        special   =PASSPHRASE_MIN_SPECIAL,
    )

    confirmed_passphrase = False
    while not confirmed_passphrase:
        
        
        passphrase = _get_secret_input(f'Choose strong recovery passphrase for {name}: ')
        # If no policy rule was broken, passphrase is valid
        if not passphrase_policy.test(passphrase):

            reentered = _get_secret_input('Confirm passphrase: ')

            if passphrase == reentered:
                confirmed_passphrase = True
            else:
                print(colored("Passphrase does not match, restart...", "cyan"))
        else:
            print("Passphrase not strong enough, enter strong passphrase...")
            print(colored(f'Minimum: {PASSPHRASE_MIN_LENGTH} char length, {PASSPHRASE_MIN_UPPER} uppercase, {PASSPHRASE_MIN_DIGITS} digit, {PASSPHRASE_MIN_SPECIAL} special char', "cyan"))
            if not sys.stdin.isatty():
                # stdin is not interactive, no point in trying to ask again
                raise RuntimeError('Passphrase not strong enough')
    
    party[DICT_PASSPHRASE] = passphrase


def _sample_uuid() -> UUID:
    return UUID(bytes=secrets.token_bytes(16), version=4)


def _get_party_id(key_id:UUID, device_id:UUID, is_cosigner:bool) -> int:
    if is_cosigner:
        key_id_first_word = struct.unpack("I", key_id.int.to_bytes(16,'big')[0:4])[0]
        device_id_first_word = struct.unpack("I", device_id.int.to_bytes(16, 'big')[0:4])[0]
        party_id = (device_id_first_word << 32) | key_id_first_word
    else:
        device_prefix = list(device_id.int.to_bytes(16, 'big')[0:6])
        device_prefix.reverse()
        party_id = struct.unpack("Q", bytes(device_prefix) + struct.pack("h", 0))[0]

    return party_id


def _has_RSA(party: dict) -> bool:
    return DICT_RSA_PEM in party


def _populate_ids(parties:dict):

    key_id = parties[JSON_KEY_ID]
    
    imported_ids = set()
    for party in parties[JSON_DEVICES]:
        
        party_id = _get_party_id(key_id, party[JSON_DEVICE_ID], _has_RSA(party))

        if party_id == 0:
            raise MigrationError(f'Invalid party id 0 for {party[JSON_NAME]}')
        if party_id in imported_ids:
            raise MigrationError(f'Duplicate party id {party_id} for {party[JSON_NAME]}')
        imported_ids.add(party_id)

        party[DICT_PARTY_ID] = party_id


def _populate_encryption_keys(parties:dict):
    for party in parties[JSON_DEVICES]:        
        if _has_RSA(party):
            _load_RSA_pub(party)
        else:
            _get_passphrase(party, party[JSON_NAME])
        

def init_parties(mobile_data_path, cosigner1_pem, cosigner2_pem):
    
    try:
        with open(mobile_data_path) as mobile_file:
            mobile = json.load(mobile_file)
            mobile_device_uuid = UUID(mobile[JSON_DEVICE_ID])
            mobile_user_uuid = UUID(mobile[JSON_USER_ID])
    except ValueError:
        raise MigrationError(f'Bad json format for mobile data file {mobile_data_path}')

    key_id = _sample_uuid()
    
    parties = {
        JSON_KEY_ID : key_id, 
        JSON_USER_ID: mobile_user_uuid,
        JSON_DEVICES: [ 
            {
                JSON_NAME: "Fireblocks Co-Signer 1",
                JSON_DEVICE_ID: UUID("21926ecc-4a8a-4614-bbac-7c591aa7efdd"),
                DICT_RSA_PEM: open(cosigner1_pem, 'r').read()
            },
            {
                JSON_NAME: "Fireblocks Co-Signer 2",
                JSON_DEVICE_ID: UUID("27900737-46f6-4097-a169-d0ff45649ed5"),
                DICT_RSA_PEM: open(cosigner2_pem, 'r').read()
            },
            {
                JSON_NAME: "Client Mobile",
                JSON_DEVICE_ID: mobile_device_uuid,
            }
        ]
    }

    _populate_ids(parties)
    _populate_encryption_keys(parties)
                
    return parties


def _sample_random_in_range(range:int):
    val = secrets.randbelow(range)
    if (val < 2**100):
        raise MigrationError("Suspicious randomness samples")
    return val


def _sample_shamir_poly(secret:int, threshold:int) -> List[int]:
    poly_coeff = [_sample_random_in_range(SECP256K1_ORDER) for _ in range(0, threshold)]
    poly_coeff[0] = secret
    return poly_coeff


def _eval_shamir_poly_at_point(shamir_poly:List[int], point:int) -> int:
    share = 0
    for i, coeff in enumerate(shamir_poly):
        share = (share + coeff * point**i) % SECP256K1_ORDER

    return share


def share_privkey_and_pubkey(root_xprv: str, parties: dict):
    
    wallet = BIP32.from_xpriv(root_xprv)

    chaincode, privkey = wallet.get_extended_privkey_from_path("m")    
    privkey_num = int.from_bytes(privkey, byteorder="big")

    parties[JSON_PUBKEY] = _privkey_to_pubkey(privkey).hex()
    parties[JSON_CHAINCODE] = chaincode.hex()
    
    shamir_poly = _sample_shamir_poly(privkey_num, len(parties[JSON_DEVICES]))
    
    for party in parties[JSON_DEVICES]:
        privkey_share_num = _eval_shamir_poly_at_point(shamir_poly, party[DICT_PARTY_ID])
        privkey_share = privkey_share_num.to_bytes(32, byteorder="big")

        party[DICT_PRIVKEY] = privkey_share
        party[JSON_PUBKEY] = _privkey_to_pubkey(privkey_share).hex()


def _encrypt_with_RSA(rsa_key: RSA.RsaKey, secret_data: bytes) -> bytes:
    cipher = PKCS1_OAEP.new(rsa_key, SHA256)
    return cipher.encrypt(secret_data)


def _encrypt_with_passphrase(passphrase:str, user_id:UUID, secret_data:bytes) -> bytes:
    salt = str(user_id).encode()
    iterations = 10000
    derived_key_length = 32
    wrap_key = hashlib.pbkdf2_hmac("sha1", passphrase.encode(), salt, iterations, derived_key_length)
    iv = bytes(chr(0) * 16, 'utf-8')
    cipher = AES.new(wrap_key, AES.MODE_CBC, iv)
    return cipher.encrypt(Padding.pad(secret_data, AES.block_size))


def encrypt_privkey_shares(parties: dict):

    for party in parties[JSON_DEVICES]:
        privkey_share = party[DICT_PRIVKEY]

        if DICT_RSA_KEY in party:
            party[JSON_ENC_PRIVKEY] = _encrypt_with_RSA(party[DICT_RSA_KEY], privkey_share).hex()
        elif DICT_PASSPHRASE in party:
            passphrase = party[DICT_PASSPHRASE]
            user_id = parties[JSON_USER_ID]
            share = privkey_share
            party[JSON_ENC_PRIVKEY] = _encrypt_with_passphrase(passphrase, user_id, share).hex()
        else:
            raise MigrationError(f'No encryption method for {party[JSON_NAME]}')


def export_migration_data(parties: dict):
    out_devices = list()
    for party in parties[JSON_DEVICES]:
        curr_device = {
            JSON_NAME       : party[JSON_NAME],
            JSON_DEVICE_ID  : str(party[JSON_DEVICE_ID]),
            JSON_PUBKEY     : party[JSON_PUBKEY],
            JSON_ENC_PRIVKEY: party[JSON_ENC_PRIVKEY]
        }
        out_devices.append(curr_device)
    
    out_data = {
        JSON_KEY_ID    : str(parties[JSON_KEY_ID]),
        JSON_USER_ID   : str(parties[JSON_USER_ID]),
        JSON_CHAINCODE : parties[JSON_CHAINCODE],
        JSON_PUBKEY    : parties[JSON_PUBKEY],
        JSON_DEVICES   : out_devices
    }

    out_filename = f'fireblocks_migration_key_id_{str(parties[JSON_KEY_ID])}.json'
    with open(out_filename, "w") as out_file:
        json.dump(out_data, out_file, indent=4)
    
    print(colored(f'Succesfully exported migration data to file: {out_filename}', "green"))

# Functions for Privkey Verification with Lagrange Interpolation 

def _prime_mod_inverse(x:int, p:int):
    return pow(x, p-2, p)


def _lagrange_coefficient(my_id:int , ids: List[int], field:int) -> int:
    coefficient = 1
    for id in ids:
        if id == my_id:
            continue

        tmp = _prime_mod_inverse((id - my_id) % field, field)
        tmp = (tmp * id) % field
        coefficient = (coefficient * tmp) % field
    return coefficient


def _reconstruct_privkey_from_shares(shares: dict) -> bytes:
    privkey = 0
    for key, value in shares.items():
        lagrange_num = _lagrange_coefficient(key, shares.keys(), SECP256K1_ORDER)
        privkey = (privkey + value * lagrange_num) % SECP256K1_ORDER
              
    return privkey.to_bytes(32, byteorder="big")


def verify_privkey_shares_reconstruction(xprv: str, parties:dict):

    shares = {}
    for party in parties[JSON_DEVICES]:
        shares[party[DICT_PARTY_ID]] = int.from_bytes(party[DICT_PRIVKEY], byteorder="big")
    
    rec_privkey = _reconstruct_privkey_from_shares(shares)
    chaincode = bytes.fromhex(parties[JSON_CHAINCODE])

    reconstructed_wallet = BIP32(chaincode=chaincode, privkey=rec_privkey)
    
    if xprv != reconstructed_wallet.get_xpriv_from_path("m"):
        raise MigrationError("Wrong reconstruction of xprv from all shares")
    
    
def _reconstruct_pubkey_from_shares(shares: dict) -> bytes:
    
    one = 1
    accumulator_point = curve.PublicKey.from_secret(one.to_bytes(32, byteorder="big"))
    
    for key, value in shares.items():
        curr_pubkey_share = curve.PublicKey(value)
        lagrange_num = _lagrange_coefficient(key, shares.keys(), SECP256K1_ORDER)
        curr_pubkey_share.multiply(lagrange_num.to_bytes(32, byteorder="big"), update=True)
        accumulator_point.combine([curr_pubkey_share], update=True)
    
    minus_one = SECP256K1_ORDER - 1
    accumulator_point.add(minus_one.to_bytes(32, byteorder="big"), update=True)
    
    return accumulator_point.format()
    
    
def verify_pubkey_shares_reconstruction(parties:dict):
        
    shares = {}
    for party in parties[JSON_DEVICES]:
        shares[party[DICT_PARTY_ID]] = bytes.fromhex(party[JSON_PUBKEY])

    rec_pubkey = _reconstruct_pubkey_from_shares(shares)
    
    if parties[JSON_PUBKEY] != rec_pubkey.hex():
        raise MigrationError("Wrong reconstruction of pubkey from all shares")
        

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("curv_recovery_csv", type=str, help="Curv recovery file (csv)")
    parser.add_argument("fireblocks_user_data_json", type=str, help="Fireblocks user migration data (json)")
    parser.add_argument("cloud_cosigner1_pem", type=str, help="Path to the public key of the first cloud cosigner")
    parser.add_argument("cloud_cosigner2_pem", type=str, help="Path to the public key of the second cloud cosigner")
    args = parser.parse_args()
    
    if not os.path.exists(args.curv_recovery_csv): 
        print(colored(f'Recovery file {args.curv_recovery_csv} not found.',"cyan"))
        exit(-1)
        
    if not args.curv_recovery_csv.endswith(".csv"):
        print(colored(f'Recovery file {args.curv_recovery_csv} not of csv extension.',"cyan"))
        parser.print_help()
        exit(-1)
    
    if not os.path.exists(args.fireblocks_user_data_json): 
        print(colored(f'User data file {args.fireblocks_user_data_json} not found.',"cyan"))
        exit(-1)
        
    if not args.fireblocks_user_data_json.endswith(".json"):
        print(colored(f'User data file {args.fireblocks_user_data_json} not of json extension.',"cyan"))
        parser.print_help()
        exit(-1)
    
    root_xprv, keys_list = parse_recovery_csv(args.curv_recovery_csv)
    verify_derived_keys(root_xprv, keys_list)
 
    parties = init_parties(args.fireblocks_user_data_json, args.cloud_cosigner1_pem, args.cloud_cosigner2_pem)
    share_privkey_and_pubkey(root_xprv, parties)

    verify_privkey_shares_reconstruction(root_xprv, parties)
    verify_pubkey_shares_reconstruction(parties)

    encrypt_privkey_shares(parties)
    export_migration_data(parties)

    return 

if __name__ == "__main__" :   
    main()
