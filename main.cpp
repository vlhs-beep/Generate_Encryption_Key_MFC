#include <iostream>
#include <CkGlobalW.h>
#include <CkCrypt2W.h>
#include <CkPrngW.h>

void UnlockChilkat();
void GenerateKey();

int main() {
    std::cout << "Generate Encryption Key: " << std::endl;
    UnlockChilkat();
    GenerateKey();
    return 0;
}

void UnlockChilkat(void)
{
    // The Chilkat API can be unlocked for a fully-functional 30-day trial by passing any
    // string to the UnlockBundle method.  A program can unlock once at the start. Once unlocked,
    // all subsequently instantiated objects are created in the unlocked state.
    //
    // After licensing Chilkat, replace the "Anything for 30-day trial" with the purchased unlock code.
    // To verify the purchased unlock code was recognized, examine the contents of the LastErrorText
    // property after unlocking.  For example:
    CkGlobalW glob;
    bool success = glob.UnlockBundle(L"Anything for 30-day trial");
    if (success != true) {
        wprintf(L"%ls\n",glob.lastErrorText());
        return;
    }

    int status = glob.get_UnlockStatus();
    if (status == 2) {
        wprintf(L"Unlocked using purchased unlock code.\n");
    }
    else {
        wprintf(L"Unlocked in trial mode.\n");
    }

    // The LastErrorText can be examined in the success case to see if it was unlocked in
    // trial more, or with a purchased unlock code.
    wprintf(L"%ls\n",glob.lastErrorText());
}

void GenerateKey(void)
{
    //  Symmetric encryption algorithms are such that the encryptor and decryptor
    //  share a pre-known secret key.  This could be a "single-use" key that is
    //  derived from a secure key exchange algorithm using RSA, ECC, or Diffie-Hellman,
    //  or it could be a password known to both sides, or
    //  it could simply be the binary bytes of the secret key known in advance on both
    //  sides.

    //  A secret key has no structure.  It's nothing more than N bytes of data.
    //  It should typically be random data, or bytes that resemble random data such
    //  as the hash of a password.

    //  The number of bytes in the secret key defines the bit-strength of an encryption
    //  algorithm.  For example, AES with a 32-byte key is 256-bit AES.  Most algorithms
    //  define restrictions on key sizes.  For example, AES has 3 choices: 128-bit, 192-bit,
    //  or 256-bit.  In the ChaCha20 algorithm, the key size must always be 256-bits (32-bytes).

    //  Both sides (encryptor and decryptor) must be in possession of the same secret key
    //  in order to communicate.   Whichever side generates the key, it must somehow
    //  deliver the key to the other side beforehand.  Key exchange algorithms, such as RSA, ECC,
    //  and Diffie-Hellman define secure ways of exchanging symmetric encryption keys.
    //  They do so using asymmetric encryption algorithms (public/private keys).  It is not
    //  required to use a key exchange algorithm to achieve the goal of having both sides
    //  in possession of the same secret key.  A long-living secret key could be exchanged
    //  via any secure out-of-band means.  For example, exchanging the information over a secure
    //  TLS (HTTPS) or SSH connection...

    //  This example assumes the Chilkat API to have been previously unlocked.
    //  See Global Unlock Sample for sample code.

    bool success;

    CkCrypt2W crypt;
    crypt.put_CryptAlgorithm(L"aes");
    crypt.put_KeyLength(256);

    //  Generate a 32-byte random secret key,
    //  and use it in the crypt object.
    CkPrngW prng;
    const wchar_t *secretKeyHex = prng.genRandom(32,L"hex");
    //  It is important that the number of bytes in the secret key
    //  matches the value specified in the KeyLength property (above).
    crypt.SetEncodedKey(secretKeyHex,L"hex");
    wprintf(L"randomly generated key: %ls\n",secretKeyHex);

    //  Alternatively, a password could be hashed using a hash algorithm
    //  the results in the desired key length.  Our desired key length
    //  in this case is 32 bytes, so we wouldn't want MD5 (16 bytes),
    //  nor would we want to use SHA-1 (20 bytes).  SHA256 would be the
    //  hash of choice because it results in 32-bytes of random-looking
    //  key material.
    crypt.put_HashAlgorithm(L"SHA256");
    crypt.put_EncodingMode(L"hex");
    secretKeyHex = crypt.hashStringENC(L"mypassword");
    crypt.SetEncodedKey(secretKeyHex,L"hex");
    wprintf(L"password-based key: %ls\n",secretKeyHex);

}