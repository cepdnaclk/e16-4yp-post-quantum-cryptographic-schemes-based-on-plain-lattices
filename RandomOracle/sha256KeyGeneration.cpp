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

using namespace std;
using namespace CryptoPP;

string stringHash(string message)
{
    SHA256 hash;
    string digest;
    hash.Update((const byte*)message.data(), message.size());
    digest.resize(hash.DigestSize());
    hash.Final((byte*)&digest[0]);

    return digest;
}

string byteHash(byte *message)
{
    /*
    inputs:
        message : a byte array for message to hash
        size    : size of the message
        output  : a byte array for message to output
    */
    SHA256 hash;
    string digest;
    hash.Update(message, sizeof(message));
    digest.resize(hash.DigestSize());
    hash.Final((byte*)&digest[0]);

    return digest;
}

string appendString(string &str1, string &str2)
{
    return str1 + str2;
}

bool* generateBinArray(short size, string key)
{
    if(size % 256 != 0)
    {
        size = (size - (size % 256)) > 256 ? : 256;
    }
    bool* r = new bool[size];
    short bitPosition;

    for(int segment = 0; segment < size/256; segment++)
    { 
       key = stringHash(key);

       for(short byte = 0; byte < 32; byte++)
        {
            bitPosition = byte * 8 + segment * 256;

            r[bitPosition] = key[byte] & 128;
            r[bitPosition + 1] = key[byte] & 64; 
            r[bitPosition + 2] = key[byte] & 32;
            r[bitPosition + 3] = key[byte] & 16;
            r[bitPosition + 4] = key[byte] & 8;
            r[bitPosition + 5] = key[byte] & 4;
            r[bitPosition + 6] = key[byte] & 2;
            r[bitPosition + 7] = key[byte] & 1;        
        }
    }

    return r;
}