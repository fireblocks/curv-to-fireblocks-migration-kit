#!/bin/bash

# Exit immediately if any of the following commands fail
set -o errexit

echo "PLEASE READ README.md BEFORE DOING ANYTHING FURTHER"

echo "Setting up a python virtual environment to install dependencies in, please wait"
python3 -m venv .env
source .env/bin/activate
yes | python3 -m pip install -r requirements.txt --quiet

if [ -d "./migration_kit_results" ] 
then
    echo "ERROR: Result directory already exists - Exiting"
    exit 1 
fi


mkdir migration_kit_results

cd migration_kit_results
python3 ../interactive_migration_script.py
cd ..

zip -r send_to_fb.zip migration_kit_results/*

deactivate

echo "Done"