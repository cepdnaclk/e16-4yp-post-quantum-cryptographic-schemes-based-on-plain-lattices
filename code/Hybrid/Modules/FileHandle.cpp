#include "FileHandle.h"

InputFile readFile(const char * filename)
{  


	struct InputFile rawData;
	rawData.data = new unsigned char[2000000];
	unsigned long data_size;
	//unsigned char* data = new unsigned char[2000000];
	
	FILE *fp = fopen(filename ,"rb");
	int c;

	if(fp == NULL)
	{
		fprintf(stderr,"file input error.\n");
		exit (EXIT_FAILURE);	
	} 
		
//cout << "read file size: "<< data_size << endl;
	for(data_size=0; data_size<2000000 && (c=fgetc(fp))!=EOF; data_size++) 
	{	
		//cout << (char)c << endl;
		rawData.data[data_size] = c;
	}
	fclose(fp);

//	cout << "opened file stored "<< filename << endl;
//cout << "read file: "<< data_size << endl;
	rawData.data_size = data_size;
	return rawData;
}

int writeFile(unsigned char out[], unsigned long out_size, const char * filename)
{
	FILE *fp = fopen(filename,"wb");

	if(fp == NULL)
	{
		fprintf(stderr,"file output error.\n");
		return -1;	
	}
		
//cout << "write file: "<< out_size << endl;
	int i = 0;
	while(i < out_size)
	{
		//cout << (char)out[i];
		fputc(out[i], fp);
		i++;
	}
		
	fclose(fp);

	return 0;
}