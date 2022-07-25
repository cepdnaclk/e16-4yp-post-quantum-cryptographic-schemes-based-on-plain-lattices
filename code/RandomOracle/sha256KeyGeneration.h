#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <stdio.h>
#include <string.h>
#include <crypto++/hex.h>
#include <crypto++/sha.h>
#include <crypto++/files.h>
#include <openssl/rand.h> // remove this
// #include <crypto++/cryptlib.h>
// #include <crypto++/filters.h>
using namespace std;

using namespace CryptoPP;



string stringHash(string message);
bool* generateBinArray(short size, string key);
string byteHash(byte *message);
string appendString(string &str1, string &str2);




