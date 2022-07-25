#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include <string>
#include<cstring>
#include <iostream>

using std::string;
using namespace std;

struct InputFile
{
	unsigned char* data;
	unsigned long data_size;
};



InputFile readFile(const char * filename);
int writeFile(unsigned char out[], unsigned long out_size, const char * filename);
