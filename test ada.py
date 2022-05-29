dSource:AadSource(Source& aad, Source& data, bool pumpAll,
    BufferedTransformation *attachment) : Source(attachment),
    m_aad(&aad), m_data(&data), m_headerSet(false) { if (pumpAll)
    PumpAll(); }

size_t AadSource::Pump2(lword &byteCount, bool blocking)
{
    lword transferCount, blockedBytes;

    transferCount = std::min(byteCount, m_aad->MaxRetrievable());
    blockedBytes = 0;

    if (transferCount)
    {
        blockedBytes = m_aad->TransferTo2(*AttachedTransformation(), transferCount, AAD_CHANNEL, blocking);
        byteCount -= transferCount - blockedBytes;
    }

    if (blockedBytes != 0)
        return blockedBytes;

    if (m_aad->SourceExhausted())
        AttachedTransformation()->ChannelMessageEnd(AAD_CHANNEL);

    transferCount = std::min(byteCount, m_data->MaxRetrievable());
    blockedBytes = 0;

    if (transferCount)
    {
        blockedBytes = m_data->TransferTo2(*AttachedTransformation(), transferCount, DEFAULT_CHANNEL, blocking);
        byteCount -= transferCount - blockedBytes;
    }

    if (blockedBytes != 0)
        return blockedBytes;

    if (m_data->SourceExhausted())
        AttachedTransformation()->ChannelMessageEnd(DEFAULT_CHANNEL);

    return byteCount;
}

size_t AadSource::PumpAll2(bool blocking)
{
    lword transferCount, blockedBytes;

    transferCount = m_aad->MaxRetrievable();
    blockedBytes = 0;

    if (transferCount)
    {
        blockedBytes = m_aad->TransferTo2(*AttachedTransformation(), transferCount, AAD_CHANNEL, blocking);
    }

    if (blockedBytes != 0)
        return blockedBytes;

    if (m_aad->SourceExhausted())
        AttachedTransformation()->ChannelMessageEnd(AAD_CHANNEL);

    transferCount = m_data->MaxRetrievable();
    blockedBytes = 0;

    if (transferCount)
    {
        blockedBytes = m_data->TransferTo2(*AttachedTransformation(), transferCount, DEFAULT_CHANNEL, blocking);
    }

    if (blockedBytes != 0)
        return blockedBytes;

    if (m_data->SourceExhausted())
        AttachedTransformation()->ChannelMessageEnd(DEFAULT_CHANNEL);

    return 0;
}

size_t AadSource::PumpMessages2(unsigned int &messageCount, bool blocking)
{
    size_t blockedBytes = 0;

    if (messageCount)
        blockedBytes = m_aad->TransferMessagesTo2(*AttachedTransformation(), messageCount, AAD_CHANNEL, blocking);

    if (blockedBytes != 0)
        return blockedBytes;

    if (m_aad->SourceExhausted())
        AttachedTransformation()->ChannelMessageEnd(AAD_CHANNEL);

    if (messageCount)
        blockedBytes = m_data->TransferMessagesTo2(*AttachedTransformation(), messageCount, DEFAULT_CHANNEL, blocking);

    if (blockedBytes != 0)
        return blockedBytes;

    if (m_data->SourceExhausted())
        AttachedTransformation()->ChannelMessageEnd(DEFAULT_CHANNEL);

    return 0;
}

bool AadSource::SourceExhausted() const
{
    return m_aad->SourceExhausted() && m_data->SourceExhausted();
}

NAMESPACE_END
StringSources
The code below uses two StringSources. The first is for aad data, and the second is for confidential data. confidential data is encrypted and authenticated. aad is authenticated only.

All the rules of pumping data apply. Note the StringSources set pumpAll=true (the second argument in the constructor). If pumpAll=false, then MaxRetrievable()==0. If pumpAll=false, then there is no data to encrypt or authenticate.

std::string HexEncode(const std::string& str)
{
    using namespace CryptoPP;

    std::string ret;
    StringSource(str, true, new HexEncoder(new StringSink(ret)));
    return ret;
}

int main (int argc, char* argv[])
{
    using namespace CryptoPP;

    std::string aad = "unique public data";
    std::string plain = "super secret data";
    std::string cipher, recover;

    SecByteBlock key(32), iv(16);
    std::memset(key, 0x00, key.size());
    std::memset( iv, 0x00,  iv.size());

    EAX<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv, iv.size());

    StringSource s1(aad, true);
    StringSource s2(plain, true);
    AuthenticatedEncryptionFilter encryptor(enc, new StringSink(cipher));    
    AadSource(s1, s2, true, new Redirector(encryptor));

    EAX<AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv, iv.size());

    StringSource s3(aad, true);
    StringSource s4(cipher, true);
    AuthenticatedDecryptionFilter decryptor(dec, new StringSink(recover));    
    AadSource(s3, s4, true, new Redirector(decryptor));

    std::cout << "AAD: " << aad << std::endl;
    std::cout << "Plain: " << plain << std::endl;
    std::cout << "Cipher: " << HexEncode(cipher) << std::endl;
    std::cout << "Recover: " << recover << std::endl;

    return 0;
}
Running the program results in the following using AES/EAX authenticated encryption mode.

$ ./test.exe
AAD: unique public data
Plain: super secret data
Cipher: DF43F5E6CFC0727F580140D1376F37A4AE2FB0DEED82C0641085F76537A0FB1574
Recover: super secret data
FileSource
The code below uses a FileSource and a StringSource. The FileSource is for aad data, and the StringSource is for confidential data. confidential data is encrypted and authenticated. aad is authenticated only.



#The AAD requires some random data larger than 4k. The command below creates a 16KB file of binary data. 4K is significant because it is the "chunk size" used by the library. That is, the library pumps in chunks of 4KB blocks.

All the rules of pumping data apply. Note the StringSource and FileSource set pumpAll=true (the second argument in the constructors). If pumpAll=false, then MaxRetrievable()==0. If pumpAll=false, then there is no data to encrypt or authenticate.

$ head -c 16384 /dev/urandom > aad.bin

$ hexdump -C aad.bin
00000000  ee 10 82 70 d7 2a 55 5d  e8 4b 92 fb 29 59 0c d7  |...p.*U].K..)Y..|
00000010  c4 67 1d 58 b1 ee 5c ea  25 7f 79 bb b4 c1 fe 77  |.g.X..\.%.y....w|
00000020  95 d7 f3 d8 ff f0 be 9a  09 d8 f7 d8 8f fc 51 0b  |..............Q.|
...
00003fd0  7d e1 7c 4c 91 b1 f9 94  c9 d9 e0 00 fa 07 dc 28  |}.|L...........(|
00003fe0  73 5d 55 36 d9 5a 1d 50  24 3a 7a fd ea 91 51 97  |s]U6.Z.P$:z...Q.|
00003ff0  ce 53 65 57 f0 9e 3b fe  95 ee dc 14 62 95 77 ff  |.SeW..;.....b.w.|
Then, use the FileSource as follows. The aad data is not printed since it is a large binary file.

int main (int argc, char* argv[])
{
    using namespace CryptoPP;

    std::string aad_file = "aad.bin";
    std::string plain = "super secret data";
    std::string cipher, recover;

    SecByteBlock key(32), iv(16);
    std::memset(key, 0x00, key.size());
    std::memset( iv, 0x00,  iv.size());

    EAX<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv, iv.size());

    FileSource s1(aad_file.c_str(), true);
    StringSource s2(plain, true);
    AuthenticatedEncryptionFilter encryptor(enc, new StringSink(cipher));
    AadSource(s1, s2, true, new Redirector(encryptor));

    EAX<AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv, iv.size());

    FileSource s3(aad_file.c_str(), true);
    StringSource s4(cipher, true);
    AuthenticatedDecryptionFilter decryptor(dec, new StringSink(recover));
    AadSource(s3, s4, true, new Redirector(decryptor));

    std::cout << "Plain: " << plain << std::endl;
    std::cout << "Cipher: " << HexEncode(cipher) << std::endl;
    std::cout << "Recover: " << recover << std::endl;

    return 0;
}
