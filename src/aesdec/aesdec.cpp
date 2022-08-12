#include <stdio.h>
#include <string.h>

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/aes.h>

int main(int argc, char* argv[])
{
	if (argc == 2 && strcmp(argv[1], "getpublickeys") == 0)
	{
		FILE* publicFile = fopen("pub.key", "r");
		EVP_PKEY* publicKey = PEM_read_PUBKEY(publicFile, NULL, NULL, NULL);

		RSA* rsa = EVP_PKEY_get1_RSA(publicKey);
		printf("n = %s\n", BN_bn2dec(rsa->n));
		printf("e = %s\n", BN_bn2dec(rsa->e));

		EVP_PKEY_free(publicKey);
		RSA_free(rsa);

		fclose(publicFile);
		return 0;
	}

	BIGNUM* n = BN_new();
	BIGNUM* e = BN_new();

	BN_dec2bn(&n, "1827700881180020961087568768788024747837552898711832066633012170617731396283665548738830421");
	BN_dec2bn(&e, "65537");

	BIGNUM* p = BN_new();
	BIGNUM* q = BN_new();
	BIGNUM* d = BN_new();

	BN_dec2bn(&p, "1371293089587387292180481293784036793076837889");
	BN_dec2bn(&q, "1332830227949273521465367319234277279439624789");

	BN_CTX* ctx = BN_CTX_new();
	BN_CTX_start(ctx);

	BN_sub(p, p, BN_value_one());
	BN_sub(q, q, BN_value_one());
	BN_mul(d, p, q, ctx);
	BN_mod_inverse(d, e, d, ctx);

	RSA* rsa = RSA_new();
	rsa->n = n;
	rsa->d = d;
	rsa->e = e;
	rsa->p = p;
	rsa->q = q;

	int keyCipherSize;
	char keyCipher[64];

	char decrypted[256];
	memset(decrypted, 0, sizeof(decrypted));

	FILE* in = fopen("key.cipher", "rb");
	if (in)
	{
		fseek(in, 0, SEEK_END);
		long sizeFile = ftell(in);
		fseek(in, 0, SEEK_SET);

		keyCipherSize = sizeFile;
		fread(keyCipher, sizeFile, 1, in);
		fclose(in);

		int sizeAesKey = RSA_private_decrypt(keyCipherSize, (const unsigned char*)keyCipher, (unsigned char*)decrypted, rsa, RSA_PKCS1_PADDING);

		printf("%s\n", decrypted);
	}

	return 0;
}

