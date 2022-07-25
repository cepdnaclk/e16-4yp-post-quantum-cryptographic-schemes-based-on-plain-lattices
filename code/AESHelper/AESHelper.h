#include <iostream>
#include <cstddef>
// for AES
// #include "../cryptopp/aes.h"
// #include "../cryptopp/hex.h"
// #include "../cryptopp/filters.h"
// #include "../cryptopp/ccm.h"
// #include "../cryptopp/files.h"
// #include "../cryptopp/osrng.h"

#include "crypto++/aes.h"
#include "crypto++/hex.h"
#include "crypto++/filters.h"
#include "crypto++/ccm.h"
#include "crypto++/files.h"
#include "crypto++/osrng.h"

// for AES
using CryptoPP::AES;
using CryptoPP::AutoSeededRandomPool;
// using CryptoPP::byte;
using CryptoPP::CTR_Mode;
using CryptoPP::Exception;
using CryptoPP::FileSink;
using CryptoPP::FileSource;
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;
using CryptoPP::MeterFilter;
using CryptoPP::Redirector;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::word64;
using CryptoPP::ArraySink;
using CryptoPP::ArraySource;
using CryptoPP::ECB_Mode;

#define AESKeyLength 16
#define AESIvLength 16

// AES Keys
struct AESKeyAndIv
{
    byte key[AESKeyLength], iv[AESKeyLength];
};

// to generate AES Keys
AESKeyAndIv generateAESKey();

// genarate A matrix with seed
union un
{
    byte buff[16];
    // std::bitset<128> bitset_buff;
    int int_buf[4];
    int16_t short_buff[8];
};
union un1
{
    byte buff[32];
    // std::bitset<128> bitset_buff;
    int int_buf[8];
    int16_t short_buff[16];
};

// printing the seed value
void printSeed(union un key);

// convert byte array to bin
short *AESDataToBinConvert(AESKeyAndIv data);

// convert binary to AES key and IV
AESKeyAndIv binToAESData(short bitstream[(AESKeyLength + AESIvLength)]);

// AES Helper funciton
inline bool EndOfFile(const FileSource &file);

// AES Encryption Function
void encryptAES(AESKeyAndIv data);

// AES Decryption Function
void decryptAES(AESKeyAndIv data);