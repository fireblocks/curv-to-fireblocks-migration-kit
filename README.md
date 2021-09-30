# Curv to Fireblocks Migration Kit
Enabling the secure migration of Curv MPC wallets into Fireblocks.

## How does the migration kit work?
**A) It breaks your private keys into three shards then encrypts them.**

The kit reads your recovery CSV and splits your private key into three MPC key shares.

Two of these key shares are encrypted with public keys of the Fireblocks cloud cosigners, and are eventually imported into the system.

The third key share is encrypted with a passphrase you provide. This ensures that one key shard is accessible to you alone, not to Fireblocks. 

**B) It exports the data of your Curv wallets and addresses.**

To fully migrate your assets (either coins/tokens) into Fireblocks, the kit reads your recovery CSV and identifies which asset types you hold.

It writes these asset types to a file called assets.json, which contains only safe public information.

**C) The encrypted key shards and addresses are shared and loaded into Fireblocks to create your MPC environment.**

## Step-by-Step Guide
### Before you run the script
1. Contact Fireblocks support to get your User ID and device ID. Both are structured as a UUID (E.g. `f74d03da-f451-4c49-91b9-33fa1dd9e80a`).

2. Activate your Fireblocks account. You should receive an activation email for your Fireblocks account. Follow the instructions in the email to activate your account, **BUT do not pair your mobile device yet!**

3. Restore your Curv Wallet Key Shares as instructed here. Make sure to run this step in an **offline secure environment!**


### Run the script
Run the following steps in an offline secure environment:
1. Extract the repository into its own directory
2. Make sure python3 + python3-venv is installed. For debian: `apt-get install -y python3 python3-venv`
3. Run `chmod +x ./runme.sh`
4. Run `./runme.sh`

The script will ask you to enter the `User ID` and `Device ID` previously provided by Fireblocks, as well as a recovery passphrase with the following characteristics:
* Minimum length: 10 characters
* At least 1 upper case letter
* At least 1 digit
* At least 1 special character

**Please make sure to back up your recovery passphrase securely!**

The results are automatically packed into `send-to-fb.zip`, which you are requested to verify before copying it out of the secure environment.

### After you run the script
Share `send-to-fb.zip` to Fireblocks support. We will contact you once you are able to proceed to the next step. The steps are as follows:
1. Log into the Fireblocks Console.
2. Pair your mobile device.
3. Your mobile device will request you to type the same passphrase entered before. Please make sure to back it up securely.

## Sanity Checks
To avoid any critical data loss or loss of assets as a result of human error, be sure to verify your balance in the Fireblocks console and complete a few transactions to ensure the process was properly completed. Until you have done so, please keep all your data backed up.
