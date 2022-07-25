#include <iostream>
#include <fstream>
#include"../AESHelper/AESHelper.h"

#include <crypto++/cryptlib.h>
#include <crypto++/channels.h>
#include <crypto++/filters.h>
#include <crypto++/files.h>
#include <crypto++/sha.h>
#include <crypto++/crc.h>
#include <crypto++/hex.h>

using namespace std;

// typedef long long dtype;
typedef int dtype;

// dump matrix to a file
// need to provide an opend ostream
void dumpMatrix(ofstream *fout, dtype **A, int rows, int cols);
// dump the hash to a file
// need to provide an opend ostream
void dumpHash(ofstream *fout, byte *array);
// dump array to a file
// need to provide an opend ostream
void dumpKey(ofstream *fout, union un key);

// load matrix from a file
// need to provide an opend istream
// load array from a file
dtype **loadMatrix(ifstream *fin, dtype **A, int rows, int cols);
// load hash from the file 
// need to provide an opend istream
byte* loadHash(ifstream *fin, byte* array);
// need to provide an opend istream
union un loadKey(ifstream *fin, union un key);

// hash a file
short * hashFile(char *fileName);
// hash a file to string
std::string hashFileToString(char *fileName);