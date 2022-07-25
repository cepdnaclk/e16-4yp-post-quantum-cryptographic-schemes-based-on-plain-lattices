#include "Helper.h"

using namespace std;
using namespace boost::multiprecision;

long gaussian(double sigma, dtype q){

    mt19937 gen(randombytes_random()); 
    normal_distribution<double> gauss_dis{0,sigma};
    double val = gauss_dis(gen);
    if (val > 0.5)
        val = val -1.0;
    else if(val<-0.5)
        val = val+1;
    return long(val*q); 
}


dtype mod(dtype value, dtype mod_value)
{
    return ((value % mod_value) + mod_value) % mod_value;
}

dtype large_product(dtype val1,dtype val2,dtype q){

    if (val1 ==0 || val2==0){
        return (dtype)0;
    }
    int128_t result = (int128_t) val1* val2;
    //first get modulo by q and then cast it to dtype
    dtype mod_res = (dtype)(result%q);
    //use mod again to map between[0,q)
    return mod(mod_res,q);
}

dtype half(dtype q){
    if (q&1==1){
        return (q>>1)+1;
    }else{
        return q>>1;
    }
}

long genUniformRandomLong(int lowerBound, int upperBound)
{
	long range = (upperBound - lowerBound) + 1;
	uint32_t randomNumber;
	randomNumber = randombytes_uniform(range);
	long randomNumberModified = ((long)randomNumber) + lowerBound;
	return randomNumberModified;
}


