// #include <iosttream>
#include <iomanip>
#include <string>
#include <map>
#include <random>
#include <cmath>
#include "sodium.h"
#include "../Matrix/Matrix.h"
// #include "../FileHelper/FileHelper.h"
// #include "../cryptopp/aes.h"
// #include "../cryptopp/hex.h"
// #include "../cryptopp/files.h"
// #include "../cryptopp/sha.h"

#include "crypto++/aes.h"
#include "crypto++/hex.h"
#include "crypto++/files.h"
#include "crypto++/sha.h"

// using CryptoPP::byte;
using CryptoPP::SHA256;
using std::string;

// typedef long long dtype;
typedef int dtype;

// do the hashing to a byte array
void byteHash(byte *message, int size, byte *output);

// do the hashing for a string
void stringHash(string message, byte *output);

// concatinating string and byte array to a String
void appendBytesToString(string &str, byte *array, size_t num_bytes);

// initialize random number genaration with hash functions
byte *initHash(byte *initalByteArray, byte *hashBytes, string message);

// fill with Gaussian vlues
void fillWithGaussianValues(double sigma, dtype q, dtype **mat, short row, short col, byte *hashBytes);

// fill with random binary numbers
void fillWithRandomBinary(dtype **mat, short row, short col, byte *hashBytes);

// fill with random dtype numbers
void fillWithRandomDtype(dtype **mat, short row, short col, byte *hashBytes, dtype q);

void printMatrix(dtype **mat, int row, int col);