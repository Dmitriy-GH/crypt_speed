#pragma once

// CBC xor дешифрование буфера buf ключем key
void cbc_decrypt(const void* key, size_t key_len, void* buf, size_t buf_len) {
	const uint8_t* k = (const uint8_t*)key;
	uint8_t* b = (uint8_t*)buf;
	uint8_t* end = b + buf_len;
	uint8_t x = 0;
	uint8_t y = 0;
	size_t i = 0;
	while (b < end) {
		x = *b;
		*b ^= k[i] ^ y;
		y = x;
		i++;
		if (i == key_len) {
			i = 0;
		}
		b++;
	}
}

// CBC xor шифрование буфера buf ключем key
void cbc_encrypt(const void* key, size_t key_len, void* buf, size_t buf_len) {
	const uint8_t* k = (const uint8_t*)key;
	uint8_t* b = (uint8_t*)buf;
	uint8_t* end = b + buf_len;
	uint8_t y = 0;
	size_t i = 0;
	while (b < end) {
		*b ^= k[i] ^ y;
		y = *b;
		i++;
		if (i == key_len) {
			i = 0;
		}
		b++;
	}
}

//*************************************************************************
// Примеры использования
#ifdef _DEBUG
#include <stdio.h>

void printf_cbc(const char* text, void* buf, size_t size) {
	printf(text);
	uint8_t* b = (uint8_t*)buf;
	for (size_t i = 0; i < size; i++) printf("%02X ", b[i]);
	printf("\n");
}

#pragma warning( disable : 4309 )
void cbc_test()
{
	uint32_t k = 0x78563412;
	printf_cbc("key: ", &k, sizeof(k));
	//char buf[] = { 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99 };
	char buf[24] = { 0 };
	printf_cbc("buf: ", buf, sizeof(buf));

	cbc_encrypt(&k, sizeof(k), buf, sizeof(buf));
	printf_cbc("\ncrp: ", buf, sizeof(buf));

	cbc_decrypt(&k, sizeof(k), buf, sizeof(buf));
	printf_cbc("\nbuf: ", buf, sizeof(buf));

	buf[0] = 170;
	buf[12] = 85;
	cbc_encrypt(&k, sizeof(k), buf, sizeof(buf));
	printf_cbc("\ncrp: ", buf, sizeof(buf));

	cbc_decrypt(&k, sizeof(k), buf, sizeof(buf));
	printf_cbc("\nbuf: ", buf, sizeof(buf));

}
#pragma warning( default : 4309 )
#endif