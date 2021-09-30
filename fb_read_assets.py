#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import csv
import json
import sys
from termcolor import colored

def parse_recovery_csv(input_file, output_file):

    reader = csv.DictReader(input_file)
    
    accounts = dict()
    for r in reader:
        bip32_path = r['BIP32 Path']
        bip32_path_split = bip32_path.split('/')
        if len(bip32_path_split) <= 2:
            continue
        assert bip32_path_split[0] == 'm'
        assert bip32_path_split[1] == '44'

        account_number = int(bip32_path_split[3])
        
        vault_account_list  = accounts.setdefault(account_number, list())
        asset_info = dict()

        asset_info['name'] = r['Wallet Name']
        asset_info['network'] = r['Currency Network']
        asset_info['symbol'] = r['Currency Global Symbol']
        contractAddress = r['Currency Contract Address (For ERC20)']
        asset_info['contractAddress'] = contractAddress
        if contractAddress:
            asset_info['type'] = 'ERC20'
        else:
            asset_info['type'] = 'BASE_WALLET'
        asset_info['address'] = r['Address']
        asset_info['bip32_path'] = bip32_path


        vault_account_list.append(asset_info)

    json.dump(accounts, output_file, indent=1)

def main():
    help_message = "Script to extract (only) public account information from your recovery CSV"
    epilog = "Note: its possible not all assets types are supported."
    epilog += "It is your responsibility to maintain a copy of the CSV."
    parser = argparse.ArgumentParser(description=help_message, epilog=epilog)
    parser.add_argument("-i", "--input", type=argparse.FileType('r'), default=sys.stdin, help="Curv recovery file (csv). Defaults to standard input")
    parser.add_argument("-o", "--output", type=argparse.FileType('w'), default=None, help="JSON Output file. Defaults to standard output")
    args = parser.parse_args()
    
    if args.input.isatty() or not args.input.name.lower().endswith('.csv'):
        print(colored("Please pass a CSV file as input", "red"))
        sys.exit(1)

    if args.output is None:
        args.output = sys.stdout
    elif args.output.name.lower().endswith('.json') is False:
        print(colored("The output file path must have the .json file extension", "red"))
        sys.exit(1)

    parse_recovery_csv(args.input, args.output)



if __name__ == "__main__" :   
    main()