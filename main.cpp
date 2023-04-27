#include "AES.h"
#include <cstdio>
#include <cstring>
#include <iostream>
#include <map>
#include <stdio.h>
#include <string.h>
#include <vector>

enum user_input_code { CFB, CBC, ECB, UNDEFINED };

struct UserData {
  std::vector<unsigned char> key;
  std::vector<unsigned char> iv;
  std::vector<unsigned char> plain_text;
};

void run_user_test(char **);
user_input_code hashit(char *);

int main(int argc, char **argv) {
  std::cout << "Begin AES test program" << std::endl;

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
  if (argc > 2) {
    run_user_test(argv);
  }
  return 0;
}

user_input_code hashit(char *selection) {

  if (strcmp("ECB", selection)) {
    return ECB;
  }
  if (strcmp("CFB", selection)) {
    return CFB;
  }
  if (strcmp("CBC", selection)) {
    return CBC;
  }
  return UNDEFINED;
}

std::vector<unsigned char> convert_to_vec(char *item) {
  std::vector<unsigned char> result;
  for (char c = *item; c; c = *++item) {
    result.push_back(c);
  }
  return result;
}

UserData createUserTest(char *user_key, char *user_iv, char *user_plain_text) {
  UserData newUserTest;

  std::vector<unsigned char> user_iv_vec, user_plain_vec, user_key_vec;
  user_key_vec = convert_to_vec(user_key);
  user_iv_vec = convert_to_vec(user_iv);
  user_plain_vec = convert_to_vec(user_plain_text);

  newUserTest.key = user_key_vec;
  newUserTest.iv = user_iv_vec;
  newUserTest.plain_text = user_plain_vec;

  return newUserTest;
}

void run_user_test(char **argv) {
  // Take first argument as CBC, CFB, or ECB
  char *user_type_selection = argv[1];
  UserData userTest;

  AES user_aes(AESKeyLength::AES_128);
  std::vector<unsigned char> user_cipher_text;
  switch (hashit(user_type_selection)) {
  case CFB:
    userTest = createUserTest(argv[2], argv[3], argv[4]);
    user_cipher_text =
        user_aes.EncryptCBC(userTest.plain_text, userTest.key, userTest.iv);
    user_aes.printHexVector(user_cipher_text);
    break;
  case ECB:
    // IGNORE THIS PTR, wow that's bad
    char *dummyptr;
    userTest = createUserTest(argv[2], dummyptr, argv[4]);
    user_cipher_text = user_aes.EncryptECB(userTest.plain_text, userTest.key);
    user_aes.printHexVector(user_cipher_text);
    break;
  case CBC:
    userTest = createUserTest(argv[2], argv[3], argv[4]);
    user_cipher_text =
        user_aes.EncryptCFB(userTest.plain_text, userTest.key, userTest.iv);
    user_aes.printHexVector(user_cipher_text);
    break;
  default:
    std::cout << "Usage: ./AES mode user_key_input, user_iv, user_plain_text"
              << std::endl;
    exit(0);
  }
}
