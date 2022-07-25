#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <stdio.h>
#include <string.h>
#include <crypto++/hex.h>
#include <crypto++/sha.h>
#include <crypto++/files.h>
// #include <crypto++/cryptlib.h>
// #include <crypto++/filters.h>
// #include <crypto++/osrng.h>
// using namespace std;

// compile g++ ___.cpp -lcrypto++

union un
{
    byte buff[16];
    int int_buf[4];
    int16_t short_buff[8];
};
union un1
{
    byte buff[32];
    int int_buf[8];
    int16_t short_buff[16];
};
using namespace CryptoPP;

// void initiate(byte *currentHash)
// {
//     SHA256 hash;
//     byte *output;
//     hash.Update(currentHash, sizeof(currentHash));
//     hash.Final(output);
//     memcpy(currentHash, output, sizeof(output));
//     // return currentHash;
// }

void byteHash(byte *message, int size, byte *output)
{
    /*
    inputs:
        message : a byte array for message to hash
        size    : size of the message
        output  : a byte array for message to output
    */
    SHA256 hash;
    hash.Update(message, size);
    hash.Final(output);
}

byte *populate(std::string message, int size, byte *initializer)
{
    return initializer;
}

void printBytes(byte *array, int byteSize)
{
    std::cout << "Size of array: " << sizeof(array) << std::endl;
    HexEncoder encoder(new FileSink(std::cout));
    encoder.Put(array, byteSize);
    encoder.MessageEnd();
    std::cout << std::endl;
}

void stringHash(std::string message, byte *output)
{
    // This will take string as the input and generate a hash value.
    std::cout << message << std::endl;
    SHA256 hash;
    hash.Update((const byte *)message.data(), message.size());
    std::cout << hash.DigestSize() << std::endl;
    hash.Final(output);
}

void appendBytesToString(std::string &str, byte *array, size_t num_bytes)
{
    // This will concatanate the sigma(random key) and a given message in string format
    str.append((char *)array, num_bytes);
}

void addEntries(long **matrix, int n, int m, byte *input, byte *output)
{

   

    /*
    m=100,n=20
    count = ceil(n*m/256)
    output = hash(input)
    // check we need more iterations
    for i=0 -> count:
        256 m=2,
        output[] == 0:
            [m][n]=0
        else:
            [m][n]=1
        output = hash(output)

    */
}

void generateValues(size_t count, byte *array)
{
    // generate binary values
    int iterations = (count / 32);
    if (count % 32 != 0)
    {
        iterations++;
    }
    std::cout << iterations << std::endl;
}

void printArray(int *array, int length)
{

    for (size_t i = 0; i < length; i++)
    {
        std::cout << array[i] << " ";
    }
    std::cout << std::endl;
}

int main(int argc, char const *argv[])
{
    /*
    union un1 hash_digest;
    HexEncoder encoder(new FileSink(std::cout));

    std::string msg = "Yoda said, Do or do not. There is no try.";
    std::string digest;

    SHA256 hash;
    hash.Update((const byte *)msg.data(), msg.size());
    digest.resize(hash.DigestSize());
    // hash.Final((byte *)&digest[0]);
    hash.Final(hash_digest.buff);
    std::cout << "Digest size " << hash.DigestSize() << std::endl;
    std::cout << "Message: " << msg << std::endl;

    std::cout << "Digest: ";
    // StringSource(digest, true, new Redirector(encoder));
    // std::cout << std::endl;
    // // ArraySource(hash_digest.buff, true, new Redirector(encoder));
    // // std::cout << std::endl;
    // std::cout << sizeof(digest) << std::endl;
    // std::cout << "Key : " << std::endl;
    encoder.Put(hash_digest.buff, sizeof(hash_digest.buff));
    encoder.MessageEnd();
    std::cout << std::endl;
    printBytes(hash_digest.buff, sizeof(hash_digest.buff));

    // initiate(hash_digest.buff);

    // populate(msg, 16, hash_digest.buff);
    // union un1 returnHash;
    byteHash(hash_digest.buff, sizeof(hash_digest.buff), hash_digest.buff);
    printBytes(hash_digest.buff, sizeof(hash_digest.buff));
    stringHash(msg, hash_digest.buff);
    printBytes(hash_digest.buff, sizeof(hash_digest.buff));
    printArray(hash_digest.int_buf, 8);
    generateValues(10, hash_digest.buff);
    */

        std::string msg = "Yoda said, Do or do not. There is no try.";
        std::string digest;
        HexEncoder encoder(new FileSink(std::cout));

        /*
        SHA256 hash;
        hash.Update((const byte*)msg.data(), msg.size());
        digest.resize(hash.DigestSize());
        hash.Final((byte*)&digest[0]);

        std::cout << "Message: " << msg << std::endl;

        std::cout << "Digest: ";
        StringSource(digest, true, new Redirector(encoder));
        std::cout << std::endl;
        std::cout << sizeof(digest) << std::endl;
        */
    



}
