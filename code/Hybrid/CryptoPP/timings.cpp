#include <iostream>
#include <random>
#include <ctime>
#include "sodium.h"
#include "../../Matrix/Matrix.h"
// #include "../AESHelper/AESHelper.h"
#include "../../FileHelper/FileHelper.h"
#include "../../RandomOracle/randomNumberGeneration.h"
#include <cmath>
#include <chrono>

using namespace std;
using namespace std::chrono;

// defining the parameters
// #define q 2000
dtype q = 20000;
// #define n 30
// #define m 270
#define n 500
#define m 1000
#define e_min -1
#define e_max 1
#define PI 3.14
// define the number of bits in the bit stream
#define numberBits 256
// value of k according to the document k = numberBits = 256
// #define k 256

byte *sigma;
// hash value
byte *hashBytes = new byte[32];
int main(int argc, char const *argv[])
{
    double time;
    cout << "q = " << q << endl;

    assert(sodium_init() == 0);

    // check timing for 500*1000 matrix multiplied by 500*1000 binary matrix

    return 0;
}
