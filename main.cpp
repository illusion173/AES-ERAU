#include "AES.h"
#include <cctype>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <sstream>
#include <stdio.h>
#include <string.h>
#include <vector>

struct userTest {
  std::vector<unsigned char> swap;
  std::vector<unsigned char> user_cipher_text;
  std::vector<unsigned char> user_plain_vec;
  std::vector<unsigned char> user_key_vec;
  std::vector<unsigned char> user_iv_vec;
  std::string user_key;
  std::string user_plain;
  std::string user_iv;
  int user_choice;
  int user_choice_encryption_decryption;
};
void run_test_cases();
void run_user_test_128();
void run_user_test_192();
void run_user_test_256();
void run_user_test_final(AES, userTest);
int main(int argc, char **argv) {
  run_test_cases();
  // Check if user inputted anything
  if (argc > 1) {
    int user_choice_bytes = 0;
    printf("Enter a choice:\n");
    printf("1 for 128 bits\n");
    printf("2 for 192 bits\n");
    printf("3 for 256 bits\n");
    scanf("%d", &user_choice_bytes);

    std::cin.clear();
    switch (user_choice_bytes) {
    case 1:
      run_user_test_128();
      break;
    case 2:
      run_user_test_192();
      break;
    case 3:
      run_user_test_256();
      break;
    default:
      printf("Select a byte length to run user tests.");
      exit(1);
    }
  }
  return 0;
}

// SARAH BEGIN
void run_test_cases() {

  std::vector<unsigned char> plain = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                      0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                                      0xcc, 0xdd, 0xee, 0xff};
  std::vector<unsigned char> key = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                    0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                    0x0c, 0x0d, 0x0e, 0x0f};
  std::vector<unsigned char> iv = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                   0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                   0x0c, 0x0d, 0x0e, 0x0f};

  std::vector<unsigned char> first_test;
  std::vector<unsigned char> first_test_check;

  AES aes(AESKeyLength::AES_128);

  first_test = aes.EncryptECB(plain, key);
  first_test_check = aes.DecryptECB(first_test, key);

  printf("RUN BASE TEST CASES\n");
  if (plain == first_test_check) {
    printf("ECB - 128 - PASS\n");
  } else {

    printf("ECB - 128 - FAIL\n");
  }

  std::vector<unsigned char> second_test;
  std::vector<unsigned char> second_test_check;

  second_test = aes.EncryptCFB(plain, key, iv);
  second_test_check = aes.DecryptCFB(second_test, key, iv);

  if (plain == second_test_check) {
    printf("CFB - 128 - PASS\n");
  } else {
    printf("CFB - 128 - FAIL\n");
  }

  std::vector<unsigned char> third_test;
  std::vector<unsigned char> third_test_check;

  third_test = aes.EncryptCBC(plain, key, iv);
  third_test_check = aes.DecryptCBC(third_test, key, iv);
  if (third_test_check == plain) {
    printf("CBC - 128 - PASS\n");
  } else {

    printf("CBC - 128 - FAIL\n");
  }
}
// SARAH END

// JEREMIAH BEGIN
//
// I am extremely happy with this
std::vector<unsigned char> convert_to_vec(std::string hex_string) {
  std::vector<unsigned char> output;

  for (std::size_t i = 0; i < hex_string.length(); i += 2) {
    unsigned char byte = 0;

    for (int j = 0; j < 2; j++) {
      char c = hex_string[i + j];

      if (std::isupper(c)) {
        byte += (c - 'A' + 10) << (4 * (1 - j));
      } else if (std::islower(c)) {
        byte += (c - 'a' + 10) << (4 * (1 - j));
      } else {
        byte += (c - '0') << (4 * (1 - j));
      }
    }

    output.push_back(byte);
  }

  return output;
}

userTest create_user_test() {
  userTest user_test_case;
  std::vector<unsigned char> swap;
  std::vector<unsigned char> user_cipher_text;
  std::vector<unsigned char> user_plain_vec;
  std::vector<unsigned char> user_key_vec;
  std::vector<unsigned char> user_iv_vec;
  std::string user_key;
  std::string user_plain;
  std::string user_iv;

  int user_choice = 0;
  int user_choice_encryption_decryption = 0;
  printf("Enter a choice:\n");
  printf("1 for Encrypt\n");
  printf("2 for Decrypt\n");
  std::cin >> user_choice_encryption_decryption;
  std::cin.clear();
  // Switch statement to deliver menu
  printf("Enter a choice:\n");
  printf("1 for CFB\n");
  printf("2 for ECB\n");
  printf("3 for CBC\n");
  std::cin >> user_choice;
  std::cin.clear();
  printf("Enter the secret key, in hex:\n");
  std::cin >> user_key;
  std::cin.clear();
  printf("Enter the plaintext/ciphertext, in hex: \n");
  std::cin >> user_plain;
  std::cin.clear();

  user_plain_vec = convert_to_vec(user_plain);
  user_key_vec = convert_to_vec(user_key);

  user_test_case.user_plain_vec = user_plain_vec;
  user_test_case.user_key_vec = user_key_vec;
  user_test_case.user_choice = user_choice;
  user_test_case.user_choice_encryption_decryption =
      user_choice_encryption_decryption;

  return user_test_case;
}

void run_user_test_final_decrypt(AES user_aes, userTest user_test_case) {
  switch (user_test_case.user_choice) {
  case 1:
    printf("\n");
    printf("Enter IV: \n");
    std::cin >> user_test_case.user_iv;
    user_test_case.user_iv_vec = convert_to_vec(user_test_case.user_iv);
    printf("Performing user test - CFB\n");
    printf("\nDecrypted Hex: \n");
    user_test_case.user_cipher_text = user_aes.DecryptCFB(
        user_test_case.user_plain_vec, user_test_case.user_key_vec,
        user_test_case.user_iv_vec);
    user_aes.printHexVector(user_test_case.user_cipher_text);
    break;
  case 2:
    printf("\n");
    printf("Performing user test - ECB\n");
    printf("\nDecrypted Hex: \n");
    user_test_case.user_cipher_text = user_aes.DecryptECB(
        user_test_case.user_plain_vec, user_test_case.user_key_vec);
    user_aes.printHexVector(user_test_case.user_cipher_text);
    break;
  case 3:
    printf("\n");
    printf("Enter IV: \n");
    std::cin >> user_test_case.user_iv;
    user_test_case.user_iv_vec = convert_to_vec(user_test_case.user_iv);
    printf("Performing user test - CBC\n");

    printf("\nDecrypted Hex: \n");
    user_test_case.user_cipher_text = user_aes.DecryptCBC(
        user_test_case.user_plain_vec, user_test_case.user_key_vec,
        user_test_case.user_iv_vec);
    user_aes.printHexVector(user_test_case.user_cipher_text);
    break;
  default:
    std::cout << "Usage: ./AES T to run user tests." << std::endl;
    std::cout << "Must enter valid choices." << std::endl;
    exit(0);
  }
}

void run_user_test_final_encrypt(AES user_aes, userTest user_test_case) {
  switch (user_test_case.user_choice) {
  case 1:
    printf("\n");
    printf("Enter IV: \n");
    std::cin >> user_test_case.user_iv;
    user_test_case.user_iv_vec = convert_to_vec(user_test_case.user_iv);
    printf("Performing user test - CFB\n");
    printf("Encrypted Hex: \n");
    user_test_case.user_cipher_text = user_aes.EncryptCFB(
        user_test_case.user_plain_vec, user_test_case.user_key_vec,
        user_test_case.user_iv_vec);
    user_aes.printHexVector(user_test_case.user_cipher_text);
    break;
  case 2:
    printf("\n");
    printf("Performing user test - ECB\n");
    printf("Encrypted Hex: \n");
    user_test_case.user_cipher_text = user_aes.EncryptECB(
        user_test_case.user_plain_vec, user_test_case.user_key_vec);
    user_aes.printHexVector(user_test_case.user_cipher_text);
    break;
  case 3:
    printf("\n");
    printf("Enter IV: \n");
    std::cin >> user_test_case.user_iv;
    user_test_case.user_iv_vec = convert_to_vec(user_test_case.user_iv);
    printf("Performing user test - CBC\n");
    printf("Encrypted Hex: \n");
    user_test_case.user_cipher_text = user_aes.EncryptCBC(
        user_test_case.user_plain_vec, user_test_case.user_key_vec,
        user_test_case.user_iv_vec);
    user_aes.printHexVector(user_test_case.user_cipher_text);
    break;
  default:
    std::cout << "Usage: ./AES 1 to run user tests." << std::endl;
    std::cout << "Must enter valid choices." << std::endl;
    exit(0);
  }
}

void run_user_test_128() {
  userTest user_test_case = create_user_test();
  AES user_aes(AESKeyLength::AES_128);
  if (user_test_case.user_choice_encryption_decryption == 1) {
    run_user_test_final_encrypt(user_aes, user_test_case);
  } else if (user_test_case.user_choice_encryption_decryption == 2) {
    run_user_test_final_decrypt(user_aes, user_test_case);
  } else {
    printf("Enter a valid choice for encryption/decryption");
    exit(0);
  }
}

void run_user_test_192() {
  userTest user_test_case = create_user_test();
  AES user_aes(AESKeyLength::AES_192);
  if (user_test_case.user_choice_encryption_decryption == 1) {
    run_user_test_final_encrypt(user_aes, user_test_case);
  } else if (user_test_case.user_choice_encryption_decryption == 2) {
    run_user_test_final_decrypt(user_aes, user_test_case);
  } else {
    printf("Enter a valid choice for encryption/decryption");
    exit(0);
  }
}

void run_user_test_256() {
  userTest user_test_case = create_user_test();
  AES user_aes(AESKeyLength::AES_256);
  if (user_test_case.user_choice_encryption_decryption == 1) {
    run_user_test_final_encrypt(user_aes, user_test_case);
  } else if (user_test_case.user_choice_encryption_decryption == 2) {
    run_user_test_final_decrypt(user_aes, user_test_case);
  } else {
    printf("Enter a valid choice for encryption/decryption");
    exit(0);
  }
}
// JEREMIAH END
