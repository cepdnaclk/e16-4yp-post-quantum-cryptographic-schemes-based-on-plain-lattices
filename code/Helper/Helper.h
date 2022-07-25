#include <iostream>
#include <random>
#include "sodium.h"
#include <boost/multiprecision/cpp_int.hpp>

typedef long long dtype;
long gaussian(double sigma, dtype q);

dtype mod(dtype value, dtype mod_value);
dtype large_product(dtype val1,dtype val2,dtype q);
dtype half(dtype q);
long genUniformRandomLong(int lowerBound, int upperBound);
// short * binConvert(std::byte* input,int AESKeyLength); 