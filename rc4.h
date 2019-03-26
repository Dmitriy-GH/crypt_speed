#pragma once
// Шифрование RC4
#include <stdint.h>
#include <string.h>

class rc4_t {
	uint8_t s[256];

public:
	rc4_t() {
	}

	rc4_t(const rc4_t& rc) {
		memcpy(s, rc.s, 256);
	}

	rc4_t(const void* key, size_t key_size) {
		init(key, key_size);
	}

	// Инициализация
	void init(const void* key, size_t key_size) {
		for (size_t i = 0; i < 256; i++) {
			s[i] = (i & 0xFF);
		}

		uint8_t* k = (uint8_t*)key;
		size_t j = 0;
		size_t n = 0;
		for (size_t i = 0; i < 256; i++) {
			j = ((j + s[i] + k[n]) & 0xFF);
			n++;
			if (n == key_size) n = 0;
			uint8_t x = s[i];
			s[i] = s[j];
			s[j] = x;
		}
	}

	// Шифрование/дешифрование блока
	void crypt(const void* buf, size_t buf_size) {
		uint8_t* b = (uint8_t*)buf;
		size_t i = 0, j = 0;
		for (size_t n = 0; n < buf_size; n++) {
			i = (i + 1) & 0xFF;
			j = (j + s[i]) & 0xFF;
			uint8_t x = s[i];
			s[i] = s[j];
			s[j] = x;
			b[n] ^= s[(s[i] + s[j]) & 0xFF];
		}
	}
};

//*************************************************************************
// Примеры использования
#ifdef _DEBUG
#include <stdio.h>

void printf_rc4_t(const char* text, void* buf, size_t size) {
	printf(text);
	uint8_t* b = (uint8_t*)buf;
	for (size_t i = 0; i < size; i++) printf("%02X ", b[i]);
	printf("\n");
}

void rc4_t_test()
{
	uint32_t k = 0x12345678;
	printf_rc4_t("key: ", &k, sizeof(k));
	//char buf[] = { 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99 };
	char buf[24] = { 0 };
	printf_rc4_t("buf: ", buf, sizeof(buf));

	rc4_t rc(&k, sizeof(k));
	rc4_t rc2;
	rc2 = rc;
	rc2.crypt(buf, sizeof(buf));
	printf_rc4_t("\ncrp: ", buf, sizeof(buf));

	rc2 = rc;
	rc2.crypt(buf, sizeof(buf));
	printf_rc4_t("\nbuf: ", buf, sizeof(buf));

	buf[0] = 1;
	rc2 = rc;
	rc2.crypt(buf, sizeof(buf));
	printf_rc4_t("\ncrp: ", buf, sizeof(buf));

	rc2 = rc;
	rc2.crypt(buf, sizeof(buf));
	printf_rc4_t("\nbuf: ", buf, sizeof(buf));
}
#endif