#include "AES.h"
#include <cstdio>
#include <cstring>
#include <iostream>
#include <map>
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

void run_user_test_128();
void run_user_test_192();
void run_user_test_256();
void run_user_test_final(AES, userTest);

int main(int argc, char **argv) {

  std::cout << "------ ENCRYPTION ------" << std::endl;
  // Begin first with 128 bits. ENCRYPTION
  std::vector<unsigned char> initial_plain = {
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

  std::vector<unsigned char> initial_key = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                            0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                            0x0c, 0x0d, 0x0e, 0x0f};

  std::vector<unsigned char> initial_iv = {0x2d, 0xde, 0xee, 0x3d, 0x2b, 0x60,
                                           0x6d, 0xd8, 0x08, 0x4f, 0xf1, 0x4c,
                                           0x64, 0x07, 0x62, 0xfd};

  AES aes(AESKeyLength::AES_128);
  std::vector<unsigned char> first_cipher_test;
  first_cipher_test = aes.EncryptECB(initial_plain, initial_key);

  std::vector<unsigned char> initial_test = {0xf8, 0xd4, 0x55, 0x63, 0x6c, 0xaa,
                                             0x13, 0x63, 0x5d, 0x80, 0x5a, 0x78,
                                             0x18, 0xe1, 0xec, 0xcd};
  if (first_cipher_test == initial_test) {
    std::cout << "128 bit ECB TEST PASS" << std::endl;
  } else {
    std::cout << "128 bit ECB TEST FAIL" << std::endl;
  }
  std::vector<unsigned char> second_cipher_test;
  second_cipher_test = aes.EncryptCFB(initial_plain, initial_key, initial_iv);

  std::vector<unsigned char> CFB_answer = {0x21, 0x65, 0x07, 0x32, 0xfe, 0xee,
                                           0xb7, 0x3d, 0xf9, 0x5a, 0x93, 0x18,
                                           0x03, 0x78, 0xee, 0xf6};

  if (second_cipher_test == CFB_answer) {
    std::cout << "128 bit CFB TEST PASS" << std::endl;
  } else {
    std::cout << "128 bit CFB TEST FAIL" << std::endl;
  }

  std::vector<unsigned char> third_cipher_test;
  third_cipher_test = aes.EncryptCBC(initial_plain, initial_key, initial_iv);

  std::vector<unsigned char> CBC_answer = {0x1d, 0x6b, 0x02, 0xb8, 0x11, 0x77,
                                           0xc9, 0xe9, 0xe1, 0xd1, 0x35, 0x02,
                                           0x02, 0x5c, 0x73, 0x05};

  if (third_cipher_test == CBC_answer) {
    std::cout << "128 bit CBC TEST PASS" << std::endl;
  } else {
    std::cout << "128 bit CBC TEST FAIL" << std::endl;
  }
  std::cout << "------ DECRYPTION ------" << std::endl;
  std::vector<unsigned char> first_decrypt_test;
  first_decrypt_test = aes.DecryptECB(first_cipher_test, initial_key);

  if (first_decrypt_test == initial_plain) {
    std::cout << "128 bit ECB TEST PASS" << std::endl;
  } else {
    std::cout << "128 bit ECB TEST FAIL" << std::endl;
  }

  std::vector<unsigned char> second_decrypt_test;
  second_decrypt_test =
      aes.DecryptCFB(second_cipher_test, initial_key, initial_iv);
  if (second_decrypt_test == initial_plain) {
    std::cout << "128 bit CFB TEST PASS" << std::endl;
  } else {
    std::cout << "128 bit CFB TEST FAIL" << std::endl;
  }
  std::vector<unsigned char> third_decrypt_test;
  third_decrypt_test =
      aes.DecryptCBC(third_cipher_test, initial_key, initial_iv);
  if (third_decrypt_test == initial_plain) {
    std::cout << "128 bit CBC TEST PASS" << std::endl;
  } else {
    std::cout << "128 bit CBC TEST FAIL" << std::endl;
  }

  // Check if user inputted anything
  // For now we can only take 128 bits
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

std::vector<unsigned char> convert_to_vec(std::string hex_string) {
  std::vector<unsigned char> result;
  // Iterate over the string two characters at a time
  for (std::string::size_type i = 0; i < hex_string.size(); i += 2) {
    // Convert the two characters to an unsigned char
    unsigned char hex_value = std::stoi(hex_string.substr(i, 2), nullptr, 16);
    result.push_back(hex_value);
  }

  return result;
}

userTest create_user_test() {
  // this is pretty grosss, but works.
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
    std::cout << "Usage: ./AES T to run user tests." << std::endl;
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
  }
}
void run_user_test_192() {
  userTest user_test_case = create_user_test();
  AES user_aes(AESKeyLength::AES_192);
  if (user_test_case.user_choice_encryption_decryption == 1) {
    run_user_test_final_encrypt(user_aes, user_test_case);
  } else if (user_test_case.user_choice_encryption_decryption == 2) {
    run_user_test_final_decrypt(user_aes, user_test_case);
  }
}

void run_user_test_256() {
  userTest user_test_case = create_user_test();
  AES user_aes(AESKeyLength::AES_256);

  if (user_test_case.user_choice_encryption_decryption == 1) {
    run_user_test_final_encrypt(user_aes, user_test_case);
  } else if (user_test_case.user_choice_encryption_decryption == 2) {
    run_user_test_final_decrypt(user_aes, user_test_case);
  }
}
