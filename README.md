# Intel(R) Arria(R) 10 SoC FPGA Authentication Signing Utility
Intel(R) Arria(R) 10 SoC FPGA Authentication Signing Utility, formerly known as Altera secure boot tool (alt-secure-boot), is a tool that help to apply the security settings to the image to be loaded by BootROM. The security settings are authentication and encryption.
This tool is only available for Intel SoC FPGA Arria10 Family Device.

## How to use
## Steps
1) Download python 3.6.3 and install
2) Install python module using pip3 run, pip3 install pyasn1 pyasn1_modules, or pip3 install --upgrade -r requirements.txt
3) Download openssl 1.1.1g and install (Please refer to the steps below for Windows users)
4) Set the environment in path for both python and openssl
5) Git clone the repository and use the Secure boot tool

For Windows User
- Download Python3 from https://www.python.org/downloads/release/python-363/
- Install GIT for windows from https://gitforwindows.org/
- Add the GIT MinGW binary path to the PATH Environment so that we can use the openssl (C:\Program Files\Git\mingw64\bin)

Note: Make sure you have already installed Intel Quartus Software Before using this tool.

## Generate Key pair
Create a trusted key pair using openssl (Example below will generate keypair into output file root_key.pem)

   $ openssl ecparam -genkey -name prime256v1 -out root_key.pem

## Authentication
For the bootloader to be authenticated, the secure boot image tool will help to signs the boot loader image with the private key from the generated key pair file. The boot loader generator invokes the tool with the “sign” option and associated parameters from the security settings, as follow

   $ python alt_authtool.py -B -E sign [&lt;param1&gt; &lt;param2&gt; …]

Example

   $ python alt_authtool.py -B -E sign -t user -k root_key.pem -i u-boot-mkimage.bin -o u-boot-signed.abin

## Encryption
For the bootloader to be encrypted, the secure boot image tool will help to encrypt the boot loader image with the encryption key from the generated AES key file. The bootloader generator invokes the tool with the “encrypt” option and associated parameters from the security settings, as follow

   $ python alt_authtool.py -B -E encrypt [&lt;param1&gt; &lt;param2&gt; …]
   
Example

   $ python alt_authtool.py -B -E encrypt -k key_file.key:key1 -i u-boot-mkimage.bin -o uboot-encrypted.abin

## Authentication and Encryption
In order to perform the two tasks, Encryption must be done first or else, the signature field of the image will be encrypted, and you will not able to authenticate with the correct key
The steps are
   1) Follow the steps to create an encrypted image
   2) Sign the encrypted image output from the first step

## Reference
For more information on how to use the secure boot tool please refer to
https://www.intel.com/content/www/us/en/programmable/documentation/cru1452898171006.html#cru1452898115026

