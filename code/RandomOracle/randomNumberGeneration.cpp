#include "randomNumberGeneration.h"

using namespace std;
// using CryptoPP::byte;
// using CryptoPP::SHA256;
using std::string;

// initial random arry size
#define initialRandomByteArraySize 10

// byte array to hols the hash values
// byte *sigma;
// // hash value
// byte *hashBytes = new byte[32];

// do the hashing to a byte array
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

// do the hashing for a string
void stringHash(string message, byte *output)
{
    // This will take string as the input and generate a hash value.
    // std::cout << message << std::endl;
    SHA256 hash;
    hash.Update((const byte *)message.data(), message.size());
    // std::cout << hash.DigestSize() << std::endl;
    hash.Final(output);
}

// concatinating string and byte array to a String
void appendBytesToString(string &str, byte *array, size_t num_bytes)
{
    // This will concatanate the sigma(random key) and a given message in string format
    str.append((char *)array, num_bytes);
}

// initialize random number genaration with hash functions
byte *initHash(byte *initalByteArray, byte *hashBytes, string message)
{
    // initializing new byte array
    initalByteArray = new byte[initialRandomByteArraySize];
    randombytes_buf(initalByteArray, initialRandomByteArraySize);

    // concatinate the byte array with message
    string initialString;
    appendBytesToString(initialString, initalByteArray, initialRandomByteArraySize);
    // cout << initialString << endl;
    // initial hash
    stringHash(initialString, hashBytes);
    return hashBytes;
}

// fill with Gaussian vlues
void fillWithGaussianValues(double sigma, dtype q, dtype **mat, short row, short col, byte *hashBytes)
{
    // recalculating the hash
    byteHash(hashBytes, sizeof(hashBytes), hashBytes);
    // genarating the seed value
    uint32_t randomSeed = hashBytes[0];
    randomSeed = (randomSeed << 8) | hashBytes[1];
    randomSeed = (randomSeed << 8) | hashBytes[2];
    randomSeed = (randomSeed << 8) | hashBytes[3];

    mt19937 gen(randomSeed);
    normal_distribution<double> gauss_dis(0, sigma);
    // filling tge matrix
    for (int rowIndex = 0; rowIndex < row; rowIndex++)
    {
        for (int colIndex = 0; colIndex < col; colIndex++)
        {
            double val = gauss_dis(gen);
            if (val > 0.5)
                val = val - 1.0;
            else if (val < -0.5)
                val = val + 1;
            mat[rowIndex][colIndex] = (dtype)(val * q);
        }
    }
}

// fill with random binary numbers
void fillWithRandomBinary(dtype **mat, short row, short col, byte *hashBytes)
{
    int numberOfPositions = row * col;
    int positionCounter = 0;

    int rowPos;
    int colPos;
    int byteArrayPos;
    int byteArraySegment;
    int byteArraySegmentPos;

    // looping through the positions
    while (positionCounter < numberOfPositions)
    {
        if (positionCounter % 256 == 0)
        {
            // recalculating the hash
            byteHash(hashBytes, sizeof(hashBytes), hashBytes);
        }

        // calculating the positions
        rowPos = positionCounter / col;
        colPos = positionCounter % col;
        byteArrayPos = positionCounter % 256;
        byteArraySegment = byteArrayPos / 8;
        byteArraySegmentPos = byteArrayPos % 8;

        // cout << rowPos << ", " << colPos << ", " << byteArraySegment << ", " << byteArraySegmentPos << endl;
        // filing the matrix
        if ((hashBytes[byteArraySegment] & (1 << byteArraySegmentPos)) == 0)
            mat[rowPos][colPos] = 0;
        else
            mat[rowPos][colPos] = 1;

        positionCounter++;
    }
}

// fill with random dtype numbers
void fillWithRandomDtype(dtype **mat, short row, short col, byte *hashBytes, dtype q)
{
    int numberOfPositions = row * col;
    int positionCounter = 0;

    int rowPos;
    int colPos;
    int byteArrayPos = 0;
    int numOfSegmentsForDtype = 32 / sizeof(dtype);

    // looping through the positions
    while (positionCounter < numberOfPositions)
    {
        if (positionCounter % numOfSegmentsForDtype == 0)
        {
            // recalculating the hash
            byteHash(hashBytes, sizeof(hashBytes), hashBytes);
        }

        // calculating the positions
        rowPos = positionCounter / col;
        colPos = positionCounter % col;
        byteArrayPos = byteArrayPos % 32;

        // filling the dtype slot
        for (int pos = 0; pos < (32 / numOfSegmentsForDtype); pos++)
        {
            mat[rowPos][colPos] = (mat[rowPos][colPos] << 8) | hashBytes[byteArrayPos];
            byteArrayPos++;
        }

        mat[rowPos][colPos] = mod(mat[rowPos][colPos], q);

        // cout << rowPos << ", " << colPos << ", " << byteArraySegment << ", " << byteArraySegmentPos << endl;
        // incrementing the position
        positionCounter++;
    }
}

void printMatrix(dtype **mat, int row, int col)
{
    for (int r = 0; r < row; r++)
    {
        for (int c = 0; c < col; c++)
        {
            cout << mat[r][c] << "\t";
        }
        cout << endl;
    }
    cout << endl;
}

// int main()
// {

//     // genarate random numbers array with sodium
//     string message = "Hello";
//     hashBytes = initHash(sigma, hashBytes, message);

//     // matrix
//     dtype **mat;
//     mat = initMatrix(mat, 5, 10);
//     fillWithRandomDtype(mat, 5, 10, hashBytes);
//     printMatrix(mat, 5, 10);

//     // cout << 7/4 << endl;
//     return 0;
// }