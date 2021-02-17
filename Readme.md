# Description: 

This GUI program will allow the user to select multiple files to encrypt with AES-256 bit encryption algorithm. This program utilizes GUI design | encryption | decryption | SMTP(optionally). The encryption key will by default be stored locally, but if an email is provided and SMTP settings are configured, it can be emailed as well. Encrypted files will be stored in the 'Encryption' folder similarly for decrypted files, 'Decryption' folder. Decryption can be done either by a key and a single file at a time, or if a key is not entered it will search 'Keys' directory for an aptly named key.

## Last successful test: 02/16/2021
    Windows 10 
    10.0.19041 Build 19041 
	
# Usage: 

    * Please have the file(s) that youwish to encrypt located in the / root directory of the program
    * Once the files have been processed, they will and must be stored in the corresponding folders
		If you do not an SMTP servr pre-configured, it is essentially a useless functionality [I simply included it to demonstrate the functionality]
	NOTE: YOU MUST LEAVE THE EMAIL FIELD BLANK OR ELSE THE KEY WILL NOT BE SAVED LOCALLY!!!
    * Please use the clear button to reset the tool! 
	NOTE: DO NOT ENCRYPT AND DECRYPT IN THE SAME GO WITHOUT CLEARING!!!

## TO DO: 
	1: Add an option to send files and keys to a remote server

	2: Implement a check for a generated key from database

	3: Present a dynamic welcome message based on first run or re-run with registry key 

	4: Support more file types! 

	5: Multithreading for multiple files 

## Install Requirements: 
	Windows: 
		#pip install tk
		#pip install Pillow
		#pip install urllib3
		#pip install cryptography
		#pip install pycryptodome
	Linux: 

		#sudo apt-get install python-tk
		#sudo apt-get install python3-pil python3-pil.imagetk
		#sudo apt install pillow 
		#sudo apt install urllib3

## Video Demonstration: 


_Source for Encryption/Decryption algorithm = https://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto_
   
