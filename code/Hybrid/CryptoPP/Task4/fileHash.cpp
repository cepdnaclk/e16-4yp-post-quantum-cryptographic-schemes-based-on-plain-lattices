#include <crypto++/cryptlib.h>
#include <crypto++/channels.h>
#include <crypto++/filters.h>
#include <crypto++/files.h>
#include <crypto++/sha.h>
#include <crypto++/crc.h>
#include <crypto++/hex.h>

#include <string>
#include <iostream>

using namespace CryptoPP;
using namespace std;

string hashFile(char* fileName)
{   
  std::string hashValue;
    
  try
    {
        SHA256 sha256;
       
        HashFilter f1(sha256, new HexEncoder(new StringSink(hashValue)));

        ChannelSwitch cs;
        cs.AddDefaultRoute(f1);

        FileSource(fileName ,true /*pumpAll*/, new Redirector(cs));

    }
    catch(const Exception& ex)
    {
        std::cerr << ex.what() << std::endl;
    }

    return hashValue;

}


