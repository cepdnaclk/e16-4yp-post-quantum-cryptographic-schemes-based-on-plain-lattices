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

// load public key
void loadPublicKey(publicKey *public_key)
{
    // initializing bT
    public_key->bT = initMatrix(public_key->bT, 1, m);
    // initalizing U
    public_key->U = initMatrix(public_key->U, n, numberBits);
    // input file stream
    ifstream fin;
    fin.open("public_key.bin", ios::binary | ios::in);
    loadMatrix(&fin, public_key->bT, 1, m);
    loadMatrix(&fin, public_key->U, n, numberBits);
    // cout << "hello" << public_key->bT[0][0] << endl;

    // key for the A matrix
    union un key;
    key = loadKey(&fin, key);

    fin.close();

    // initializing A matrix
    public_key->A = initMatrix(public_key->A, n, m);
    // genarating the matrix
    gen_A(key, public_key->A);
}

// load private key
void loadPrivateKey(privateKey *private_key)
{
    // initializing bT
    private_key->sT = initMatrix(private_key->sT, 1, n);
    // initializing D
    private_key->D = initMatrix(private_key->D, m, numberBits);
    // input file stream
    ifstream fin;
    fin.open("private_key.bin", ios::binary | ios::in);
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

// dump regev ciper text
void dumpRegevCipherText(struct cipherText ct)
{
    // dumping the cipher text
    ofstream fout;
    fout.open("cipher_2.bin", ios::binary | ios::out);
    dumpMatrix(&fout, ct.c0, n, numberBits);
    dumpMatrix(&fout, ct.c1T, 1, numberBits);
    dumpMatrix(&fout, ct.c2T, 1, m);
    dumpMatrix(&fout, ct.c3T, 1, numberBits);
    fout.close();
}

// dump regev ciper text
struct cipherText loadRegevCipherText()
{
    struct cipherText ct;
    ct.c0 = initMatrix(ct.c0, n, numberBits);
    ct.c1T = initMatrix(ct.c1T, 1, numberBits);
    ct.c2T = initMatrix(ct.c2T, 1, m);
    ct.c3T = initMatrix(ct.c3T, 1, numberBits);

    // loading the cipher text
    ifstream fin;
    fin.open("cipher_2.bin", ios::binary | ios::in);
    loadMatrix(&fin, ct.c0, n, numberBits);
    loadMatrix(&fin, ct.c1T, 1, numberBits);
    loadMatrix(&fin, ct.c2T, 1, m);
    loadMatrix(&fin, ct.c3T, 1, numberBits);

    fin.close();

    return ct;
}

// function to genarate keys
void dumpRegevKeys()
{
    // initiating the random number genarator with hash
    hashBytes = initHash(sigma, hashBytes, "");

    struct privateKey private_key;
    struct publicKey public_key;

    public_key.A = initMatrix(public_key.A, n, m);
    // random seed for genarating A matrix
    AutoSeededRandomPool prng;
    union un key;
    // genarating the random seed
    prng.GenerateBlock(key.buff, sizeof(key.buff));
    // genarating the matrix
    gen_A(key, public_key.A);

    private_key.sT = initMatrix(private_key.sT, 1, n);

    // dumping the private key
    ofstream fout;
    fout.open("private_key.bin", ios::binary | ios::out);
    // dumpMatrix(&fout, private_key.sT, 1, n);
    // dumping the hash for sT
    dumpHash(&fout, hashBytes);
    dumpKey(&fout, key);
    fout.close();

    // filling the sT matrix
    fillWithRandomDtype(private_key.sT, 1, n, hashBytes, q);
    // filling the D matrix
    private_key.D = initMatrix(private_key.D, m, numberBits);
    fillWithRandomBinary(private_key.D, m, numberBits, hashBytes);

    // calculating U
    public_key.U = initMatrix(public_key.U, n, numberBits);
    matMul(public_key.A, private_key.D, public_key.U, n, m, numberBits, q);

    double alpha = sqrt(double(n)) / q;
    double sigma = alpha / sqrt(2 * PI);

    // Matrix<dtype, 1, m> eT;
    dtype **eT;
    eT = initMatrix(eT, 1, m);

    // dtype total = 0;
    fillWithGaussianValues(sigma, q, eT, 1, m, hashBytes);

    // calculating bT
    // public_key->bT = (private_key->sT) * (public_key->A) + eT;
    public_key.bT = initMatrix(public_key.bT, 1, m);
    matMulAdd(private_key.sT, public_key.A, eT, public_key.bT, 1, n, m, q);
    // sharig A among public and private key
    // private_key->A = public_key->A;

    // dumping the public key
    fout.open("public_key.bin", ios::binary | ios::out);
    dumpMatrix(&fout, public_key.bT, 1, m);
    dumpMatrix(&fout, public_key.U, n, numberBits);
    dumpKey(&fout, key);
    fout.close();
}

// function to genarate keys
void genarateRegevKeys(privateKey *private_key, publicKey *public_key)
{
    // initiating the random number genarator with hash
    hashBytes = initHash(sigma, hashBytes, "");

    // Genarating the matrix A
    // initializing matrix A
    public_key->A = initMatrix(public_key->A, n, m);

    AutoSeededRandomPool prng;
    union un key;
    prng.GenerateBlock(key.buff, sizeof(key.buff));
    gen_A(key, public_key->A);

    // initializing matrix sT
    private_key->sT = initMatrix(private_key->sT, 1, n);
    fillWithRandomDtype(private_key->sT, 1, n, hashBytes, q);

    // genarating the error matrix
    // cout << "[LOG] Generating Matrix e" << endl;
    double alpha = sqrt(double(n)) / q;
    double sigma = alpha / sqrt(2 * PI);

    // Matrix<dtype, 1, m> eT;
    dtype **eT;
    eT = initMatrix(eT, 1, m);
    fillWithGaussianValues(sigma, q, eT, 1, m, hashBytes);

    // calculating bT
    // public_key->bT = (private_key->sT) * (public_key->A) + eT;
    public_key->bT = initMatrix(public_key->bT, 1, m);
    matMulAdd(private_key->sT, public_key->A, eT, public_key->bT, 1, n, m, q);

    // sharig A among public and private key
    private_key->A = public_key->A;

    // Task 3
    private_key->D = initMatrix(private_key->D, m, numberBits);
    fillWithRandomBinary(private_key->D, m, numberBits, hashBytes);
    // calculating U
    public_key->U = initMatrix(public_key->U, n, numberBits);
    matMul(private_key->A, private_key->D, public_key->U, n, m, numberBits, q);
}

// Regev Encrypting Function
cipherText encryptRegev(publicKey public_key, short *message_bit)
{
    struct cipherText cipher_text;

    // Genarating the X matrix with random values
    // Matrix<dtype, m, numberBits> X;
    dtype **R;
    // initializing the matrix
    R = initMatrix(R, m, numberBits);

    // filling R matrix
    fillWithRandomBinary(R, n, numberBits, hashBytes);

    cipher_text.c0 = initMatrix(cipher_text.c0, n, numberBits);
    // cipher_text.c0 = (public_key.A) * X;
    matMul(public_key.A, R, cipher_text.c0, n, m, numberBits, q);

    // defining bTx
    // Matrix<dtype, 1, numberBits> bTx;
    dtype **bTR;
    // initializing the matrix
    bTR = initMatrix(bTR, 1, numberBits);

    // bTR = public_key.bT * R;
    matMul(public_key.bT, R, bTR, 1, m, numberBits, q);

    // // encrypting the bits
    // initalizing c1T
    cipher_text.c1T = initMatrix(cipher_text.c1T, 1, numberBits);
    for (int i = 0; i < numberBits; i++)
    {
        cipher_text.c1T[0][i] = mod((bTR[0][i] + (message_bit[i] * half(q))), q);
    }

    // Task 3
    dtype **rT, **xT, **yT;
    rT = initMatrix(rT, 1, n);
    xT = initMatrix(xT, 1, m);
    yT = initMatrix(yT, 1, numberBits);
    cipher_text.c2T = initMatrix(cipher_text.c2T, 1, m);
    cipher_text.c3T = initMatrix(cipher_text.c3T, 1, numberBits);

    // filling the matrices
    fillWithRandomDtype(rT, 1, n, hashBytes, q);

    double alpha = sqrt(double(n)) / q;
    double sigma = alpha / sqrt(2 * PI);
    fillWithGaussianValues(sigma, q, xT, 1, m, hashBytes);
    fillWithGaussianValues(sigma, q, yT, 1, numberBits, hashBytes);
    // c2T = rTA + xT
    matMulAdd(rT, public_key.A, xT, cipher_text.c2T, 1, n, m, q);

    // temporarily hold rTU + yT in c3T
    matMulAdd(rT, public_key.U, yT, cipher_text.c3T, 1, n, numberBits, q);

    // hashing the file
    char *name = (char *)"plain.jpg";
    short *fileHashBits = hashFile(name);

    // calclulating c3T = rTU + yT + H(u).[q/2]
    for (int i = 0; i < numberBits; i++)
    {
        cipher_text.c3T[0][i] = mod((cipher_text.c3T[0][i] + (fileHashBits[i] * half(q))), q);
    }

    return cipher_text;
}

// Regev Decrypting Funciton
recoverdText decryptRegev(privateKey private_key, cipherText cipher_text)
{
    // structure for sending the recovered text
    struct recoverdText recovered;

    // defining sTu
    // Matrix<dtype, 1, numberBits> sTu;
    dtype **sTu;
    // initializing the matrix
    sTu = initMatrix(sTu, 1, numberBits);

    // sTu = (private_key.sT) * (cipher_text.c0);
    matMul(private_key.sT, cipher_text.c0, sTu, 1, n, numberBits, q);
    // array to hold the recoverd bits
    recovered.aesKey = new short[numberBits];
    dtype difference = 0;

    for (dtype i = 0; i < numberBits; i++)
    {
        // recovering the single bit message
        difference = mod(cipher_text.c1T[0][i] - sTu[0][i], q);
        if ((difference > (q / 4)) & (difference < (3 * q / 4)))
        { // bit is 1
            recovered.aesKey[i] = 1;
        }
        else
        {
            recovered.aesKey[i] = 0;
        }
    }

    // part 3

    dtype **c2TD;
    // initializing the matrix
    c2TD = initMatrix(c2TD, 1, numberBits);
    // c2TD = c2T x D
    matMul(cipher_text.c2T, private_key.D, c2TD, 1, m, numberBits, q);
    // array to hold the recoverd bits of hash
    recovered.hashBits = new short[numberBits];
    difference = 0;

    for (dtype i = 0; i < numberBits; i++)
    {
        // recovering the single bit message
        difference = mod(cipher_text.c3T[0][i] - c2TD[0][i], q);
        if ((difference > (q / 4)) & (difference < (3 * q / 4)))
        { // bit is 1
            recovered.hashBits[i] = 1;
        }
        else
        {
            recovered.hashBits[i] = 0;
        }
    }

    return recovered;
}

// do the full hybrid encryption
cipherText encryptHybrid(publicKey public_key)
{
    // initiating the random number genarator with hash
    // hashing the file
    char *name = (char *)"plain.jpg";
    hashBytes = initHash(sigma, hashBytes, hashFileToString(name));

    // Genarating AES Key and Iv
    AESKeyAndIv aesData = generateAESKey();
    // conver to bits
    short *aesDataBin = AESDataToBinConvert(aesData);
    // encrypting AES Key Data using Regev
    cipherText cipher_text = encryptRegev(public_key, aesDataBin);
    // AES Encryption Process
    encryptAES(aesData);

    return cipher_text;
}

// do the full Hybrid decryption
void decryptHybrid(privateKey private_key, cipherText cipher_text)
{
    // initiating the random number genarator with hash
    hashBytes = initHash(sigma, hashBytes, "");

    // decrypting AES Key data using Regev
    recoverdText recovered = decryptRegev(private_key, cipher_text);
    // Converting binary data back to AES key and Iv
    AESKeyAndIv convertedData = binToAESData(recovered.aesKey);
    // AES Decryption
    decryptAES(convertedData);

    // do the hash check
    // hashing the file
    char *name = (char *)"recovered.jpg";
    short *fileHashBits = hashFile(name);

    // validating the hash 
    short validation = 1;
    for (int i = 0; i < numberBits; i++) {
        if (recovered.hashBits[i] != fileHashBits[i]) {
            validation = 0;
            break;
        }
    }

    if (validation == 1) cout << "Validation Success" << endl;
    else cout << "Validation Faild" << endl;
}

// check the correctness
bool checkAnswer(dtype message_bits[numberBits], dtype recovered_bits[numberBits])
{
    dtype correctBits = 0;
    for (dtype i = 0; i < numberBits; i++)
    {
        if (message_bits[i] == recovered_bits[i])
        {
            correctBits++;
        }
    }
    // cout << "correct bits: " << correctBits << endl;
    if (correctBits == numberBits)
    {
        return true;
    }
    return false;
}

// print an array of bits
void printBits(dtype bit_array[numberBits])
{
    for (dtype i = 0; i < numberBits; i++)
    {
        cout << bit_array[i];
    }
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

    // Menu system
    int option;
    cout << "Hybrid Encryption System. Select the option you want" << endl;
    cout << "1. Generate Key pair" << endl;
    cout << "2. Encrypt" << endl;
    cout << "3. Decrypt" << endl;
    cout << "4. All in one" << endl;
    cout << "Enter your option: ";

    // taking user input
    cin >> option;

    if (option == 1)
    {
        auto start = high_resolution_clock::now();
        // Generating Regev keys
        dumpRegevKeys();

        auto stop = high_resolution_clock::now();
        auto duration = duration_cast<microseconds>(stop - start);
        time = duration.count();
        time = time / 1000000;
        cout << "Key Genaration time = " << time << " s" << endl;
    }
    else if (option == 2)
    {
        auto start = high_resolution_clock::now();
        // Encryptions process ==============================================================
        // loading the public key
        struct publicKey public_key;
        loadPublicKey(&public_key);
        cipherText cipher_text = encryptHybrid(public_key);
        // dump the ciper text
        dumpRegevCipherText(cipher_text);

        auto stop = high_resolution_clock::now();
        auto duration = duration_cast<microseconds>(stop - start);
        time = duration.count();
        time = time / 1000000;
        cout << "Encryption time = " << time << " s" << endl;
    }
    else if (option == 3)
    {
        auto start = high_resolution_clock::now();
        // Decryption process ==============================================================
        // loading the private key
        struct privateKey private_key;
        loadPrivateKey(&private_key);
        // loading the cipher text from the file
        cipherText cipher_text_2 = loadRegevCipherText();
        decryptHybrid(private_key, cipher_text_2);

        auto stop = high_resolution_clock::now();
        auto duration = duration_cast<microseconds>(stop - start);
        time = duration.count();
        time = time / 1000000;
        cout << "Decryption time = " << time << " s" << endl;
    }
    else if (option == 4)
    {
        // structures for the function
        struct publicKey public_key;
        struct privateKey private_key;

        auto start = high_resolution_clock::now();
        // Generating Regev keys
        genarateRegevKeys(&private_key, &public_key);

        auto stop = high_resolution_clock::now();
        auto duration = duration_cast<microseconds>(stop - start);
        time = duration.count();
        time = time / 1000000;
        cout << "Key Genaration time = " << time << " s" << endl;

        start = high_resolution_clock::now();
        // Encryptions process ==============================================================
        cipherText cipher_text = encryptHybrid(public_key);

        stop = high_resolution_clock::now();
        duration = duration_cast<microseconds>(stop - start);
        time = duration.count();
        time = time / 1000000;
        cout << "Encryption time = " << time << " s" << endl;

        start = high_resolution_clock::now();
        // Decryption process ==============================================================
        decryptHybrid(private_key, cipher_text);

        stop = high_resolution_clock::now();
        duration = duration_cast<microseconds>(stop - start);
        time = duration.count();
        time = time / 1000000;
        cout << "Decryption time = " << time << " s" << endl;
    }
    else
    {
        cout << "invalid option" << endl;
    }

    return 0;
}