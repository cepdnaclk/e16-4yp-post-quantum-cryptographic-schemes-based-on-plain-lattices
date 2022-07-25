

#include "Regev.h"

long gaussian(double sigma){

	mt19937 gen(randombytes_random()); 
	normal_distribution<double> gauss_dis{0,sigma};
	double val = gauss_dis(gen);
	if (val > 0.5)
		val = val -1.0;
	else if(val<-0.5)
		val = val+1;
	return long(val*q); 

}

long mod(long value, long mod_value)
{
	return ((value % mod_value) + mod_value) % mod_value;
}

short * binConvert(unsigned char input[AESKeyLength]) 
{

  short*  bitstream = new short[AESKeyLength * 8];

  
  for (int i = 0; i < AESKeyLength; ++i)
   {
	for (int j = 0; j < 8; ++j) 
		{
		  bitstream[ (i*8 - j + 7)] = (input[i] >> j) & 1;    
		}
   } 
   
   return bitstream;
}




unsigned char* binToByteConvert(short bitstream[AESKeyLength]) 
{

  unsigned char*  bytestream = new unsigned char[AESKeyLength];

  short binValues[8] = {128, 64, 32, 16, 8, 4, 2, 1};
  short total = 0;
  short bytePosition = 0;   

  for (int i = 1; i < AESKeyLength * 8 + 1; ++i)
   {
		total = total + bitstream[i - 1] * binValues[(i - 1) % 8];

		if(i % 8 == 0)
		{
			bytestream[bytePosition] = (unsigned char)total;
			total = 0;
			bytePosition++;
		}
   }   

   return bytestream;
}
// genarate uniform random numbers including the boundaries
long genUniformRandomLong(int lowerBound, int upperBound)
{
	long range = (upperBound - lowerBound) + 1;
	uint32_t randomNumber;
	randomNumber = randombytes_uniform(range);
	long randomNumberModified = ((long)randomNumber) + lowerBound;
	return randomNumberModified;
}


// function to genarate keys
void genarateRegevKeys(privateKeyRegev *private_key, publicKeyRegev *public_key)
{
	// /cout << "[LOG] Generating Matrix A" << endl;

	// Genarating the matrix A
	long number = 0;
	for (long i = 0; i < n; i++)
	{
		for (long j = 0; j < m; j++)
		{
			// filling the A matrix from the numbers taken from the distribution
			public_key->A(i, j) = genUniformRandomLong(0, q - 1);
		}
	}


	for (long col = 0; col < private_key->sT.cols(); col++)
	{
		private_key->sT(col) = genUniformRandomLong(0, q - 1);
	}

	double alpha = sqrt(double(n))/q;
	double sigma = alpha/sqrt(2*PI);
	Matrix<long, 1, m> eT;
	// long total = 0;
	for (long col = 0; col < eT.cols(); col++)
	{
		eT(col) = gaussian(sigma);
	}

	public_key->bT = (private_key->sT) * (public_key->A) + eT;

	for (long col = 0; col < public_key->bT.cols(); col++)
	{
		public_key->bT(col) = mod(public_key->bT(col), q);
	}

	private_key->A = public_key->A;
}

// Encrypting Function
cipherTextRegev RegevEncrypt(publicKeyRegev public_key, short message_bit[numberBits])
{
	struct cipherTextRegev cipher_text;
	// Genarating the X matrix with random values
	Matrix<long, m, numberBits> X;
	for (long i = 0; i < m; i++)
	{
		for (long j = 0; j < numberBits; j++)
		{
			X(i, j) = genUniformRandomLong(0, 1);
		}
	}
	// cout<<"[DEBUG] min of X : "<<X.minCoeff()<<" max of X : "<<X.maxCoeff()<<endl;
	// u = AX
	// should take mod q
	cipher_text.u = (public_key.A) * X;
	// cout<<"[DEBUG] min of u : "<<cipher_text.u.minCoeff()<<" max of u : "<<cipher_text.u.maxCoeff()<<endl;
	// defining bTx
	Matrix<long, 1, numberBits> bTx;
	bTx = public_key.bT * X;
	// taking the modulus of bTx
	for (long i = 0; i < numberBits; i++)
	{
		bTx(0, i) = mod(bTx(0, i), q);
	}

	// encrypting the bits
	for (long i = 0; i < numberBits; i++)
	{
		cipher_text.u_(0, i) = mod((bTx(0, i) + (message_bit[i] * (q / 2))), q);
	}

	// cout<<"[DEBUG] u' : " <<cipher_text.u_ <<endl;
	return cipher_text;
}

// Decrypting Funciton
unsigned char *RegevDecrypt(privateKeyRegev private_key, cipherTextRegev cipher_text)
{
	// defining sTu
	Matrix<long, 1, numberBits> sTu;
	sTu = (private_key.sT) * (cipher_text.u);
	// array to hold the recoverd bits
	short*  recovered = new short[numberBits];
	long difference = 0;

	for (long i = 0; i < numberBits; i++)
	{
		sTu(0, i) = mod(sTu(0, i), q);
		// recovering the single bit message
		difference = mod(cipher_text.u_(0, i) - sTu(0, i), q);
		if ((difference > (q / 4)) & (difference < (3 * q / 4)))
		{ // bit is 1
			recovered[i] = 1;
		}
		else
		{
			recovered[i] = 0;
		}
	}

	return binToByteConvert(recovered);
}

