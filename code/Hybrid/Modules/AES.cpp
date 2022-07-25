#include "AES.h"


unsigned char* encryptAES(AES_KEY enc_key, unsigned char key[], unsigned char iv[], const char * filename)
{	
	

	struct InputFile rawData = readFile(filename);
	//unsigned char* decrypted


	unsigned long data_size = rawData.data_size;
	unsigned long out_size = ((data_size/AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
	unsigned char* encrypted = new unsigned char[out_size];

	for(int i=data_size; i<out_size; i++) 
		rawData.data[i] = (out_size-data_size);

  AES_set_encrypt_key(key, 128, &enc_key); // 128bit = 16byte
  AES_cbc_encrypt(rawData.data, encrypted, out_size, &enc_key, iv, AES_ENCRYPT);

  writeFile(encrypted, out_size, "enc.aes");

  rawData.data_size = data_size;
  return rawData.data;
}


unsigned char* decryptAES(AES_KEY enc_key, unsigned char key[], unsigned char iv[], const char * OutputFilename)
{
  struct InputFile rawData = readFile("enc.aes");	
  unsigned long data_size = rawData.data_size;
  unsigned char* decrypted = new unsigned char[data_size];
  AES_set_decrypt_key(key, 128, &enc_key);
  //memset(iv, 0x01, AES_BLOCK_SIZE);
  AES_cbc_encrypt(rawData.data , decrypted, data_size, &enc_key, iv, AES_DECRYPT);
  
  unsigned char tail = decrypted[data_size-1];

   
   int valid = (tail > 0 && tail<=AES_BLOCK_SIZE) ;

  	
  	for(int i=1;i<tail && valid;i++)
		valid = (decrypted[data_size-1-i] == tail);

		data_size -= tail;
	 
	 writeFile(decrypted, data_size, OutputFilename);

  return decrypted;
}

// check the correctness
bool checkAnswer(unsigned char message[], unsigned char recovered[])
{
	int i = 0;
	while(message[i] != '\0')
	{

		if(message[i] != recovered[i])
		{
			//cout<<message[i]<<endl;
				return false;
		}
		i++;
	}

	return true;

}