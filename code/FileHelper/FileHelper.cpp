#include"FileHelper.h"

using namespace std;
using namespace CryptoPP;

// dump matrix to a file
// need to provide an opend ostream
void dumpMatrix(ofstream *fout, dtype **A, int rows, int cols)
{
    for (int row = 0; row < rows; row++)
    {
        (*fout).write((char *)&A[row][0], sizeof(dtype) * cols);
    }
}

// dump the hash 
void dumpHash(ofstream *fout, byte *array) {
    (*fout).write((char *)&array[0], 32);
}

// dump array to a file
// need to provide an opend ostream
void dumpKey(ofstream *fout, union un key)
{
    (*fout).write((char *)&key, sizeof(key));
}

// load matrix from a file
// need to provide an opend istream
dtype **loadMatrix(ifstream *fin, dtype **A, int rows, int cols)
{
    for (int row = 0; row < rows; row++)
    {
        (*fin).read((char *)&A[row][0], sizeof(dtype) * cols);
    }
    return A;
}
// load hash from the file 
byte* loadHash(ifstream *fin, byte* array) {
    (*fin).read((char *)&array[0], 32);
    return array;
}
// load array from a file
// need to provide an opend istream
union un loadKey(ifstream *fin, union un key)
{
    (*fin).read((char *)&key, sizeof(key));
    return key;
}

// hash a file
short* hashFile(char *fileName)
{
    // array to return
    short *hashBits = new short[256];

    std::string hashValue;
    try
    {
        SHA256 sha256;
        HashFilter f1(sha256, new HexEncoder(new StringSink(hashValue)));
        ChannelSwitch cs;
        cs.AddDefaultRoute(f1);
        FileSource(fileName, true /*pumpAll*/, new Redirector(cs));
    }
    catch (const Exception &ex)
    {
        std::cerr << ex.what() << std::endl;
    }
    short bit;
    for (short byte = 0; byte < 32; byte++)
    {
        bit = byte * 8;
        hashBits[bit] = (hashValue[byte] & 128) ? 1 : 0;
        hashBits[bit + 1] = (hashValue[byte] & 64) ? 1 : 0;
        hashBits[bit + 2] = (hashValue[byte] & 32) ? 1 : 0;
        hashBits[bit + 3] = (hashValue[byte] & 16) ? 1 : 0;
        hashBits[bit + 4] = (hashValue[byte] & 8) ? 1 : 0;
        hashBits[bit + 5] = (hashValue[byte] & 4) ? 1 : 0;
        hashBits[bit + 6] = (hashValue[byte] & 2) ? 1 : 0;
        hashBits[bit + 7] = (hashValue[byte] & 1) ? 1 : 0;
    }

    return hashBits;
}

// hash a file to string
std::string hashFileToString(char *fileName)
{
    // array to return
    short *hashBits = new short[256];

    std::string hashValue;
    try
    {
        SHA256 sha256;
        HashFilter f1(sha256, new HexEncoder(new StringSink(hashValue)));
        ChannelSwitch cs;
        cs.AddDefaultRoute(f1);
        FileSource(fileName, true /*pumpAll*/, new Redirector(cs));
    }
    catch (const Exception &ex)
    {
        std::cerr << ex.what() << std::endl;
    }

    return hashValue;
}


