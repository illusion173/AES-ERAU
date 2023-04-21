#include "AES.h"

//still need keyLength switch statement

unsigned char * AES::EncryptECB (const unsigned char* in, unsigned int inLen, const unsigned char* key){
    CheckLength(inLen);
    
    unsigned char* out = new unsigned char [inLen];
    
    //calculate number of blocks
    const unsigned in numBlocks = inLen / blockBytesLen;
    
    //allocate memory for round keys
    std::vector<unsigned char> roundKeys(4 * Nb * (Nr + 1));
    
    //expand key
    KeyExpansion(key, roundKeys.data());
    
    //encrypt each block
    for (unsigned int i = 0; i < numBlocks; ++i){
        EncryptBlock(in + i * blockBytesLen, out + i * blockBytesLen, roundKeys.data());
    }
    return out;
}
std::vector<unsigned char> AES::DecryptECB(const unsigned char* in, unsigned int inLen, const unsigned char* key){
    CheckLength(inLen);
    
    std::vector <unsigned char> out(inLen);
    std::unique_ptr <unsigned char[]> roundKeys(new unsigned char[4 * Nb * (Nr + 1)]);
    KeyExpansion(key, roundKeys.get());
    
    for (unsigned int i = 0; i < inLen; i += blockBytesLen){
        DecryptBlock(in + i, out.data() + i, roundKeys.get());
    }
    return out;
}
std::vector<unsigned char> AES::EncryptCBC(const unsigned char * in, unsigned int inLen, const unsigned char * key, const unsigned char * iv){
    CheckLength(inLen);
    
    std::vector<unsigned char> out(inLen);
    std::unique_ptr<unsigned char[]> roundKeys(new unsigned char[4 * Nb * (Nr + 1)]);
    KeyExpansion(key, roundKeys.get());
    
    std::vector<unsigned char> block(blockBytes);
    std::memcpy(block.data(), iv, blockBytesLen);
    
    for(unsigned int i = 0; i < inLen; i += blockBytesLen){
        XorBlocks(block.data(), in + i, block.data(), blockBytesLen);
        EncryptBlock(block.data(), out.data() + i, roundKeys.get());
        std::memcpy(block.data(), out.data() + i, blockBytesLen);
    }
    return out;
}
unsigned char * AES::DecryptCBC(const unsigned char in[], unsigned int inLen, const unsigned char key[], const unsigned char * iv){
    CheckLength(inLen);
    unsigned char * out = new unsigned char[inLen];
    unsigned char * roundKeys = new unsigned char [4 * Nb * (Nr + 1)];
    KeyExpansion(key, roundKeys);
    
    for (unsigned int i = 0; i < inLen; i += blockBytesLen){
        unsigned char temp[blockBytesLen];
        DecryptBlock(in + i, temp, roundKeys);
        XorBlocks(temp, iv, temp, blockBytesLen);
        memcpy(out + i, temp, blockBytesLen);
        memcpy(iv, in + i, blockBytesLen);
    }
    delete[] roundKeys;
    
}
unsigned char* AES::EncryptCFB(const unsigned char in[], unsigned int inLen, const unsigned char key[], const unsigned char* iv) {
  CheckLength(inLen);
  unsigned char* out = new unsigned char[inLen];
  unsigned char block[blockBytesLen];
  unsigned char encryptedBlock[blockBytesLen];
  unsigned char roundKeys[4 * Nb * (Nr + 1)];
  KeyExpansion(key, roundKeys);
  memcpy(block, iv, blockBytesLen);

  for (unsigned int i = 0; i < inLen; i += blockBytesLen) {
    EncryptBlock(block, encryptedBlock, roundKeys);
    for (int j = 0; j < blockBytesLen; j++) {
      out[i + j] = in[i + j] ^ encryptedBlock[j];
    }
    memcpy(block, out + i, blockBytesLen);
  }

  return out;
}
unsigned char* AES::DecryptCFB(const unsigned char in[], unsigned int inLen, const unsigned char key[], const unsigned char* iv) {
  CheckLength(inLen);
  unsigned char* out = new unsigned char[inLen];
  unsigned char block[blockBytesLen];
  unsigned char encryptedBlock[blockBytesLen];
  unsigned char roundKeys[4 * Nb * (Nr + 1)];
  KeyExpansion(key, roundKeys);
  memcpy(block, iv, blockBytesLen);

  for (unsigned int i = 0; i < inLen; i += blockBytesLen) {
    EncryptBlock(block, encryptedBlock, roundKeys);
    for (int j = 0; j < blockBytesLen; j++) {
      out[i + j] = in[i + j] ^ encryptedBlock[j];
    }
    memcpy(block, in + i, blockBytesLen);
  }

  delete[] roundKeys;

  return out;
}
//AES check length function needed

void AES::EncryptBlock(const unsigned char* input, unsigned char* output, const unsigned char* roundKeys){
    
    //create 4x4 and copy the input into it :)
    
    unsigned char state[4][Nb];
    for (int col = 0; col < Nb; col++){
        for(int row = 0; row < 4; row++){
            state[row][col] = input[col * 4 + row];
        }
    }
    
    //add round key
    AddRoundKey(state, roundKeys);
    
    //Nr-1 rounds of subbytes, shiftrows, mixcolumns, and addroundkey
    for (int round = 1; round < Nr; round++){
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, roundKeys + round * Nb * 4);
    }
    
    //final round
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, roundKeys + Nr * Nb * 4);
    
    //copy state matrix
    for (int col = 0; col < Nb; col++){
        for (int row = 0; row < 4; row++){
            output[col * 4 + row] = state[row][col];
            
        }
    }
}
void AES::DecryptBlock (const unsigned char* input, unsigned char* output, const unsigned char* roundKeys){
    //create 4x4 and copy the input into it
    unsigned char state[4][Nb];
    for (int col = 0; col < Nb; col++){
        for (int row = 0; row < 4; row++){
            state[row][col] = input[col * 4 + row];
        }
    }
    //add round key
    AddRoundKey(state, roundKeys + Nr * Nb * 4);
    
    for (int round = Nr - 1; round >= 1; round--){
        InvSubBytes(state);
        InvShiftRows(state);
        AddRoundKey(state, roundKeys + round * Nb * 4);
        InvMixColumns(state)
    }
    
    //final round
    InvSubBytes(state);
    InvShiftRows(state);
    AddRoundKey(state, roundKeys);
    
    for (int col = 0; col < Nb; col++){
        for (int row = 0; row < 4; row++){
            output[col * 4 + row] = state[row][col];
        }
    }
    
}
void AES::SubBytes(unsigned char state[4][Nb]){
    //S-box substitution to each byte
    
    for (int row = 0; row < 4; row++){
        for (int col = 0; col < Nb; col++){
            state[row][col] = sbox [state[row][col] / 16][state[row][col] % 16];
        }
    }
}
void AES::ShiftRows(unsigned char state[4][Nb], unsigned int row. unsigned int shift){
    unsigned char tmp[Nb];
    for (int col = 0; col < Nb; col++){
        tmp[col] = state[row][(col + shift) % Nb];
    }
    memcpy(state[row], tmp, Nb * sizeof(unsigned char));
}
void AES::ShiftRows(unsigned char state[4][Nb]){
    ShiftRow(state, 1, 1);
    ShiftRow(state, 2, 2);
    ShiftRow(state, 3, 3);
    
}
unsigned char AES::xtime(unsigned char b){
    return (b<< 1) ^ (((b >> 7) & 1) * 0x1b);
}
void AES::MixColumns(unsigned char state[4][Nb]){
    
}

