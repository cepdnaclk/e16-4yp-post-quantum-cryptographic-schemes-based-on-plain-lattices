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

// byte array to hols the hash values
byte *sigma;
// hash value
byte *hashBytes = new byte[32];

// structures
// public key
struct publicKey
{
    // Matrix<dtype, n, m> A;
    // Matrix<dtype, 1, m> bT;
    dtype **A;
    dtype **bT;
    // U size => (n x k)
    dtype **U;
};

// private key
struct privateKey
{
    // Matrix<dtype, n, m> A;
    // Matrix<dtype, 1, n> sT;
    dtype **A;
    dtype **sT;
    // D size => (m x k)
    dtype **D;
};

// cipher text
struct cipherText
{
    // Matrix<dtype, n, numberBits> c0;
    // Matrix<dtype, 1, numberBits> c1T;
    dtype **c0;
    dtype **c1T;
    // c2T size => (1 x m)
    dtype **c2T;
    // c3T size => (1 x numberBits)
    dtype **c3T;
};

// recoverd text
struct recoverdText
{
    short *aesKey;
    short *hashBits;
};

// genarate A matrix using a seed
void gen_A(union un key, dtype **A)
{
    union un plain;
    plain.short_buff[0] = 0;
    plain.short_buff[1] = 0;
    plain.short_buff[2] = 0;
    plain.short_buff[3] = 0;
    plain.short_buff[4] = 0;
    plain.short_buff[5] = 0;
    plain.short_buff[6] = 0;
    plain.short_buff[7] = 0;
    union un1 cipher;
    ECB_Mode<AES>::Encryption encrypt;
    encrypt.SetKey(key.buff, sizeof(key.buff));
    // printSeed(key);
    for (int16_t i = 0; i < n; i++)
    {
        for (int16_t j = 0; j < m; j = j + 4)
        {
            plain.short_buff[0] = i;
            plain.short_buff[1] = j;
            ArraySink cs(&cipher.buff[0], sizeof(cipher.buff));
            ArraySource(plain.buff, sizeof(plain.buff), true, new StreamTransformationFilter(encrypt, new Redirector(cs)));
            // encoder.Put(cipher.buff,sizeof(cipher));
            // encoder.MessageEnd();
            for (size_t k = 0; k < 4; k++)
            {
                // cout << cipher.int_buf[k] << " ";

                if (j + k < m)
                {
                    // mod function needs to be implemented
                    A[i][j + k] = mod(cipher.int_buf[k], q);
                }
            }
            // cout << endl;
        }
    }
}
// end genarating A matrix with seed

dtype half(dtype q)
{
    if ((q & 1) == 1)
    {
        return (q >> 1) + 1;
    }
    else
    {
        return q >> 1;
    }
}

// load private key
void loadSpecificPrivateKey(privateKey *private_key, char *filename)
{
    // initializing bT
    private_key->sT = initMatrix(private_key->sT, 1, n);
    // initializing D
    private_key->D = initMatrix(private_key->D, m, numberBits);
    // input file stream
    ifstream fin;
    fin.open(filename, ios::binary | ios::in);
    // loadMatrix(&fin, private_key->sT, 1, n);
    hashBytes = loadHash(&fin, hashBytes);
    // filling sT matrix
    fillWithRandomDtype(private_key->sT, 1, n, hashBytes, q);
    // filling D matix
    fillWithRandomBinary(private_key->D, m, numberBits, hashBytes);

    // key for the A matrix
    union un key;
    key = loadKey(&fin, key);

    fin.close();

    // initializing A matrix
    private_key->A = initMatrix(private_key->A, n, m);
    // genarating the matrix
    gen_A(key, private_key->A);
}

struct cipherText loadSpecificRegevCipherText(char *filename)
{
    struct cipherText ct;
    ct.c0 = initMatrix(ct.c0, n, numberBits);
    ct.c1T = initMatrix(ct.c1T, 1, numberBits);
    ct.c2T = initMatrix(ct.c2T, 1, m);
    ct.c3T = initMatrix(ct.c3T, 1, numberBits);

    // loading the cipher text
    ifstream fin;
    fin.open(filename, ios::binary | ios::in);
    loadMatrix(&fin, ct.c0, n, numberBits);
    loadMatrix(&fin, ct.c1T, 1, numberBits);
    loadMatrix(&fin, ct.c2T, 1, m);
    loadMatrix(&fin, ct.c3T, 1, numberBits);

    fin.close();

    return ct;
}

bool checkPlainTextEquality(cipherText ctx1, cipherText ctx2, privateKey private1, privateKey private2)
{
    // @change
    // we are only interested in c3,c2 of cipher text and D of private key.
    // calculate vT = c3T - c2T*D and v_T = c_3T - c_2T*D_
    // calculate h,h_ using vT. same logic as the regev decision for bit 0,1
    // if h == h_: return true else return false
    // c2T: 1xm
    // c3T: 1x256
    // D : mx256
    // vT -> 1x256
    dtype **vT1;
    dtype **vT2;
    vT1 = initMatrix(vT1, 1, 256);
    vT2 = initMatrix(vT2, 1, 256);
    matMul(ctx1.c2T, private1.D, vT1, 1, m, 256, q);
    matMul(ctx2.c2T, private2.D, vT2, 1, m, 256, q);

    dtype val1, val2;
    bool first, second;
    for (size_t i = 0; i < 256; i++)
    {
        // c3T is a 1x256 matrix.
        val1 = mod(ctx1.c3T[0][i] - vT1[0][i], q);
        // OR
        // val1 = mod(ctx1.c3T[1][i] - vT1[1][i], q);
        val2 = mod(ctx2.c3T[0][i] - vT2[0][i], q);
        // decide making
        // (difference > (q / 4)) & (difference < (3 * q / 4))
        first = (val1 > q / 4) & (val1 < 3 * q / 4);
        second = (val2 > q / 4) & (val2 < 3 * q / 4);
        if (first != second)
        {
            return false;
        }
    }
    return true;
}
int main(int argc, char const *argv[])
{
    double time;

    // calculating q
    // unsigned long tmp1 = 1;
    // tmp1 = tmp1 << 31;
    // q = tmp1 - 19;

    cout << "q = " << q << endl;

    assert(sodium_init() == 0);

    struct privateKey privatekey1;
    struct privateKey privatekey2;
    // load private keys specific
    auto start = high_resolution_clock::now();
    loadSpecificPrivateKey(&privatekey1, (char *)"private_key_1.bin");
    auto stop = high_resolution_clock::now();
    auto duration = duration_cast<microseconds>(stop - start);
    time = duration.count();
    time = time / 1000000;
    cout << "private key 1 load time = " << time << " s" << endl;

    start = high_resolution_clock::now();
    loadSpecificPrivateKey(&privatekey2, (char *)"private_key_2.bin");
    stop = high_resolution_clock::now();
    duration = duration_cast<microseconds>(stop - start);
    time = duration.count();
    time = time / 1000000;
    cout << "private key 2 load time = " << time << " s" << endl;
    cout << "privatekeys loaded successfully" << endl;

    cipherText ciphertext1;
    cipherText ciphertext2;

    start = high_resolution_clock::now();
    ciphertext1 = loadSpecificRegevCipherText((char *)"cipher_2_1.bin");
    stop = high_resolution_clock::now();
    duration = duration_cast<microseconds>(stop - start);
    time = duration.count();
    time = time / 1000000;
    cout << "cipher text 1 load time = " << time << " s" << endl;

    start = high_resolution_clock::now();
    ciphertext2 = loadSpecificRegevCipherText((char *)"cipher_2_2.bin");
    stop = high_resolution_clock::now();
    duration = duration_cast<microseconds>(stop - start);
    time = duration.count();
    time = time / 1000000;
    cout << "cipher text 1 load time = " << time << " s" << endl;
    // load regev cipher text specific
    cout << "ciphertexts loaded successfully" << endl;
    start = high_resolution_clock::now();
    if (checkPlainTextEquality(ciphertext1, ciphertext2, privatekey1, privatekey2))
    {
        cout << "Same cipher texts" << endl;
    }
    else
    {
        cout << "not the same cipher text" << endl;
    };
    stop = high_resolution_clock::now();
    duration = duration_cast<microseconds>(stop - start);
    time = duration.count();
    time = time / 1000000;
    cout << "check equality time = " << time << " s" << endl;

    return 0;
}