# AES-ERAU
[![License](https://img.shields.io/github/license/illusion173/AES-ERAU)](https://github.com/illusion173/AES-ERAU/blob/main/LICENSE)
![Repo Size](https://img.shields.io/github/repo-size/illusion173/AES-ERAU)
![Language](https://img.shields.io/github/languages/top/illusion173/AES-ERAU)
<br>Created by:<br>
Jeremiah Webb <Jeremiah_L_Webb@hotmail.com> <br>
Sarah Gleixner
## Description
This is an implementation of the NIST defined AES [symmetric-key algorithm](https://en.wikipedia.org/wiki/Symmetric-key_algorithm) written in C++. AES is a variant of the Rijndael [block cipher](https://en.wikipedia.org/wiki/Block_cipher).


This is a class project for **Embry-Riddle Aeronautical University**, class **CS428** (Applied Cryptography).

For further sources see [Links](#Links)

# Usage
To compile:
```

g++ AES.cpp main.cpp -o AES
```
## Command Line Usage

ECB, CBC, CFB modes are supported. <br>
However, padding has not been implemented. <br>
This library does not provide any padding. <br>
The plaintext/ciphertext length in bytes must be divisible by 16. <br>
To Run User Test Cases:
```
./AES 1
```
Currently, a menu runs and asks for user inputs.
Users can do encryption and decryption of all three modes and byte sizes from command line.

## Code Usage
```c++
...
unsigned char plain[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }; //plaintext example
unsigned char key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f }; //key example
unsigned int plainLen = 16 * sizeof(unsigned char);  //bytes in plaintext

AES aes(AESKeyLength::AES_128);  ////128 - key length, can be 128, 192 or 256
c = aes.EncryptECB(plain, plainLen, key);
//now variable c contains plainLen bytes - ciphertext
...
```
Or for vectors:
```c++
...


vector<unsigned char> plain = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }; //plaintext example
vector<unsigned char> key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f }; //key example

AES aes(AESKeyLength::AES_128);
c = aes.EncryptECB(plain, key);
//now vector c contains ciphertext
...
```




# Links
[AES NIST Documentation](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)<br>
[Wikipedia](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
