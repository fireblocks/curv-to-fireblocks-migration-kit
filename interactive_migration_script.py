import json
import subprocess
import uuid
import os
import prompt_toolkit
import sys

def search_for_csv_file(candidate_file_path):
    return candidate_file_path.endswith('.csv') or os.path.isdir(candidate_file_path)

class UUIDValidator(prompt_toolkit.validation.Validator):
    def validate(self, document):
        candidate_input = document.text
        try:
            uuid.UUID(candidate_input)
        except ValueError:
            raise prompt_toolkit.validation.ValidationError(message='INPUT ERROR: must be the valid UUID given to you by Fireblocks', cursor_position=0)

class CSVValidator(prompt_toolkit.validation.Validator):
    def validate(self, document):
        candidate = document.text
        if not candidate.endswith('.csv'):
            raise prompt_toolkit.validation.ValidationError(message='INPUT ERROR: CSV file', cursor_position=len(candidate))
        if not os.path.exists(candidate):
            raise prompt_toolkit.validation.ValidationError(message='INPUT ERROR: does not exist', cursor_position=len(candidate))

def main():
    filesystem_completer = prompt_toolkit.completion.PathCompleter()
    filesystem_completer.file_filter = search_for_csv_file
    uuid_validator = UUIDValidator()

    recovery_csv = prompt_toolkit.prompt("Enter path to your recovery CSV: ", completer=filesystem_completer, validator=CSVValidator())
    user_api_key = uuid.UUID(prompt_toolkit.prompt("Enter Fireblocks User ID: ", validator=uuid_validator))
    device_id = uuid.UUID(prompt_toolkit.prompt("Fireblocks Device ID key: ", validator=uuid_validator))

    fireblocks_json = dict()
    fireblocks_json['deviceId'] = str(device_id)
    fireblocks_json['userId'] =  str(user_api_key)
    fireblocks_json_path = 'fireblocks.json'

    if not os.path.exists(fireblocks_json_path):
        with open(fireblocks_json_path, 'w') as f:
            json.dump(fireblocks_json, f, indent=1)

    package_dir = os.path.dirname(os.path.abspath(__file__))
    keys_export_script = os.path.join(package_dir, 'fb_migrate_key.py')
    assets_export_script = os.path.join(package_dir, 'fb_read_assets.py')
    cosigner1_pem = os.path.join(package_dir, 'cosigner1.pem')
    cosigner2_pem = os.path.join(package_dir, 'cosigner2.pem')

    subprocess.check_call([sys.executable, keys_export_script, recovery_csv, fireblocks_json_path, cosigner1_pem, cosigner2_pem])
    with open("assets.json", "w") as assets_json:
        subprocess.check_call([sys.executable , assets_export_script, '-i' ,recovery_csv], stdout=assets_json)


if __name__ == "__main__" :   
    main()

