#include "AES.h"

// Constructor
AES::AES(const AESKeyLength keylength) {

  // Depending on AES keylength input
  // assign NK & NR.
  switch (keylength) {
  case AESKeyLength::AES_128:
    this->Nk = 4;
    this->Nr = 10;
    break;
  case AESKeyLength::AES_192:
    this->Nk = 6;
    this->Nr = 12;
    break;
  case AESKeyLength::AES_256:
    this->Nk = 8;
    this->Nr = 12;
    break;
  }
}

// Functions here
