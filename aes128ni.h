#pragma once
// Шифрование AES-128
// Взято тут https://stackoverflow.com/questions/32297088/how-to-implement-aes128-encryption-decryption-using-aes-ni-instructions-and-gcc

#include <stdint.h>     //for int8_t
#include <string.h>     //for memcmp
#include <wmmintrin.h>  //for intrinsics for AES-NI
#include <assert.h>
#if defined(_MSC_VER)
#include <intrin.h> // __cpuid()
#else
#include <cpuid.h>
#endif
//compile using gcc and following arguments: -g;-O0;-Wall;-msse2;-msse;-march=native;-maes

//internal stuff

#define AES_128_key_exp(k, rcon) aes_128_key_expansion(k, _mm_aeskeygenassist_si128(k, rcon))

static __m128i aes_128_key_expansion(__m128i key, __m128i keygened) {
	keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3, 3, 3, 3));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	return _mm_xor_si128(key, keygened);
}

//public API
static void aes128ni_load_key_enc_only(const void *enc_key, __m128i *key_schedule) {
	key_schedule[0] = _mm_loadu_si128((const __m128i*) enc_key);
	key_schedule[1] = AES_128_key_exp(key_schedule[0], 0x01);
	key_schedule[2] = AES_128_key_exp(key_schedule[1], 0x02);
	key_schedule[3] = AES_128_key_exp(key_schedule[2], 0x04);
	key_schedule[4] = AES_128_key_exp(key_schedule[3], 0x08);
	key_schedule[5] = AES_128_key_exp(key_schedule[4], 0x10);
	key_schedule[6] = AES_128_key_exp(key_schedule[5], 0x20);
	key_schedule[7] = AES_128_key_exp(key_schedule[6], 0x40);
	key_schedule[8] = AES_128_key_exp(key_schedule[7], 0x80);
	key_schedule[9] = AES_128_key_exp(key_schedule[8], 0x1B);
	key_schedule[10] = AES_128_key_exp(key_schedule[9], 0x36);
}

static void aes128ni_load_key(const void *enc_key, __m128i *key_schedule) {
	aes128ni_load_key_enc_only(enc_key, key_schedule);

	// generate decryption keys in reverse order.
	// k[10] is shared by last encryption and first decryption rounds
	// k[0] is shared by first encryption round and last decryption round (and is the original user key)
	// For some implementation reasons, decryption key schedule is NOT the encryption key schedule in reverse order
	key_schedule[11] = _mm_aesimc_si128(key_schedule[9]);
	key_schedule[12] = _mm_aesimc_si128(key_schedule[8]);
	key_schedule[13] = _mm_aesimc_si128(key_schedule[7]);
	key_schedule[14] = _mm_aesimc_si128(key_schedule[6]);
	key_schedule[15] = _mm_aesimc_si128(key_schedule[5]);
	key_schedule[16] = _mm_aesimc_si128(key_schedule[4]);
	key_schedule[17] = _mm_aesimc_si128(key_schedule[3]);
	key_schedule[18] = _mm_aesimc_si128(key_schedule[2]);
	key_schedule[19] = _mm_aesimc_si128(key_schedule[1]);
}

static void aes128ni_enc(__m128i *key_schedule, __m128i *plainText, __m128i *cipherText) {
	__m128i m = _mm_loadu_si128(plainText);

	m = _mm_xor_si128(m, key_schedule[0]);
	m = _mm_aesenc_si128(m, key_schedule[1]);
	m = _mm_aesenc_si128(m, key_schedule[2]);
	m = _mm_aesenc_si128(m, key_schedule[3]);
	m = _mm_aesenc_si128(m, key_schedule[4]);
	m = _mm_aesenc_si128(m, key_schedule[5]);
	m = _mm_aesenc_si128(m, key_schedule[6]);
	m = _mm_aesenc_si128(m, key_schedule[7]);
	m = _mm_aesenc_si128(m, key_schedule[8]);
	m = _mm_aesenc_si128(m, key_schedule[9]);
	m = _mm_aesenclast_si128(m, key_schedule[10]);
	_mm_storeu_si128(cipherText, m);
}

static void aes128ni_enc(__m128i *key_schedule, void *plainText, void *cipherText) {
	aes128ni_enc(key_schedule, (__m128i *)plainText, (__m128i *)cipherText);
}

static void aes128ni_dec(__m128i *key_schedule, __m128i *cipherText, __m128i *plainText) {
	__m128i m = _mm_loadu_si128(cipherText);

	m = _mm_xor_si128(m, key_schedule[10 + 0]);
	m = _mm_aesdec_si128(m, key_schedule[10 + 1]);
	m = _mm_aesdec_si128(m, key_schedule[10 + 2]);
	m = _mm_aesdec_si128(m, key_schedule[10 + 3]);
	m = _mm_aesdec_si128(m, key_schedule[10 + 4]);
	m = _mm_aesdec_si128(m, key_schedule[10 + 5]);
	m = _mm_aesdec_si128(m, key_schedule[10 + 6]);
	m = _mm_aesdec_si128(m, key_schedule[10 + 7]);
	m = _mm_aesdec_si128(m, key_schedule[10 + 8]);
	m = _mm_aesdec_si128(m, key_schedule[10 + 9]);
	m = _mm_aesdeclast_si128(m, key_schedule[0]);

	_mm_storeu_si128(plainText, m);
}

static void aes128ni_dec(__m128i *key_schedule, void *cipherText, void *plainText) {
	aes128ni_dec(key_schedule, (__m128i *) cipherText, (__m128i *) plainText);
}

// Провевка поддержки AES процессором
static bool aes128ni_is_supported() {
	#if defined(_MSC_VER)
		int info[4];
		__cpuid(info, 0x01);
		return (info[2] & 0x2000000) != 0;
	#else
		unsigned int eax, ebx, ecx, edx;
		__get_cpuid(0x01, &eax, &ebx, &ecx, &edx);
		return (ecx & 0x2000000) != 0;
	#endif
}
//*****************************************************************************************
//*****************************************************************************************
//*****************************************************************************************

class aes128ni_t {
	__m128i key_schedule[20];

public:
	aes128ni_t() {}

	aes128ni_t(const void* key) {
		init(key);
	}

	// Инициализация ключа
	void init(const void* key) {
		aes128ni_load_key(key, key_schedule);
	}

	// Шифрование блока размером кратно 16 байт
	void encrypt(void *buffer, size_t size) {
		assert((size % 16) == 0); // Размер должен быть кратен 16
		__m128i *end = ((__m128i *)buffer) + size / 16;
		for (__m128i *p = (__m128i *)buffer; p < end; p++) {
			aes128ni_enc(key_schedule, p, p);
		}
	}

	// Расшифровка блока размером кратно 16 байт
	void decrypt(void *buffer, size_t size) {
		assert((size % 16) == 0); // Размер должен быть кратен 16
		__m128i *end = ((__m128i *)buffer) + size/16;
		for (__m128i *p = (__m128i *)buffer; p < end; p++) {
			aes128ni_dec(key_schedule, p, p);
		}
	}

	// Шифрование блока размером кратно 16 байт c CBC
	void cbc_encrypt(void *buffer, size_t size) {
		assert((size % sizeof(__m128i)) == 0); // Размер должен быть кратен 16
		__m128i *end = ((__m128i *)buffer) + size / sizeof(__m128i);
		__m128i prev = { 0 };
		for (__m128i *p = (__m128i *)buffer; p < end; p++) {
			__m128i v = _mm_xor_si128(_mm_loadu_si128(p), prev);
			aes128ni_enc(key_schedule, &v, p);
			prev = _mm_loadu_si128(p);
		}
	}

	// Расшифровка блока размером кратно 16 байт c CBC
	void cbc_decrypt(void *buffer, size_t size) {
		assert((size % sizeof(__m128i)) == 0); // Размер должен быть кратен 16
		__m128i *end = ((__m128i *)buffer) + size / sizeof(__m128i);
		__m128i prev = { 0 };
		for (__m128i *p = (__m128i *)buffer; p < end; p++) {
			__m128i v, b = _mm_loadu_si128(p);
			aes128ni_dec(key_schedule, p, &v);
			_mm_storeu_si128(p, _mm_xor_si128(v, prev));
			prev = b;
		}
	}

	// Шифрование данных XOR с предыдущим
	void xor_encrypt(void* buf, size_t size) {
		assert((size % 16) == 0); // Размер должен быть кратен 16
		__m128i prev = {0}, *end = ((__m128i *)buf) + size / 16;
		for (__m128i *p = (__m128i *)buf; p < end; p++) {
			prev = _mm_xor_si128(*p, prev);
			*p = prev;
		}
	}

	// Расшифровка данных XOR с предыдущим
	void xor_decrypt(void* buf, size_t size) {
		assert((size % 16) == 0); // Размер должен быть кратен 16
		__m128i prev = { 0 }, *end = ((__m128i *)buf) + size / 16;
		for (__m128i *p = (__m128i *)buf; p < end; p++) {
			__m128i b = *p;
			prev = _mm_xor_si128(*p, prev);
			prev = b;
		}
	}
};

#ifdef _DEBUG
#include <stdio.h>

static void aes128ni_t_test() {
	uint8_t plain[] = { 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };
	uint8_t enc_key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
	uint8_t cipher[] = { 0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32 };

	aes128ni_t aes(enc_key);
	uint8_t buf[16];
	memcpy(buf, plain, 16);
	aes.encrypt(buf, 16);
	if (memcmp(buf, cipher, 16) != 0) printf("AES-128 encrypt error\n");
	aes.decrypt(buf, 16);
	if (memcmp(buf, plain, 16) != 0) printf("AES-128 decrypt error\n");
}
#endif