// Тест скорости шифрования/дешифрования разных алгоритмов

#include <stdio.h>
#include <stdint.h>
#include <time.h>

#include "cbc.h"
#include "rc4.h"
#include "aes128.h"

int time_fill = 0; // Время на заполнение, мс

// Генератор потока данных для шифрования
void fill_data(void *buffer, int size, int init = 0) {
	static uint32_t state = 0; // Текущее состояние
	if (init != 0) { // Инициализация состояния
		state = init;
	}

	uint8_t *end = ((uint8_t *)buffer) + size;
	for (uint8_t *p = (uint8_t *)buffer; p != end; p++) {
		state = state * 1103515245;
		*p = (uint8_t)(state >> 16);
	}
}

// Контрольная сумма
int checksum(void *buffer, int size) {
	int ret = 0; // Текущее состояние
	uint8_t *end = ((uint8_t *)buffer) + size;
	for (uint8_t *p = (uint8_t *)buffer; p != end; p++) {
		ret += *p;
	}
	return ret;
}

// Замер скорости заполнения
void fill_speed(int block_size, int block_count) {
	uint8_t *buf = new uint8_t[block_size]; // буфер под данные
	fill_data(0, 0, 12345); // Инициализация генератора данных
	int cs = 0;
	printf("test speed fill %d blocks of %d bytes each ... \n", block_count, block_size);
	uint32_t start = clock(); // Начало замера
	for (int i = 0; i < block_count; i++) {
		fill_data(buf, block_size);
		cs += checksum(buf, block_size); // Расчет контрольной суммы чтобы оптимизатор ничего не убрал
	}
	// Вывод результата
	int time = clock() - start;
	if (time == 0) time = 1;
	int64_t total = (int64_t)block_size * block_count;
	printf("filled %d Mb in %d ms %d Mb/s   \n%u\r", (int)(total >> 20), time, (int)((total * CLOCKS_PER_SEC / time) >> 20), cs);
	time_fill = time;
}

// Замер скорости cbc
void cbc_speed(int block_size, int block_count) {
	uint8_t *key = new uint8_t[block_size]; // Ключ шифрования размером с блок
	// генерация ключа
	rc4_t rc4("My secret key", 13);
	memset(key, 0, block_size);
	rc4.crypt(key, block_size); 

	uint8_t *buf = new uint8_t[block_size]; // буфер под данные
	fill_data(0, 0, 12345); // Инициализация генератора данных
	int cs = 0;
	printf("test speed CBC XOR encrypt %d blocks of %d bytes each ... \n", block_count, block_size);
	uint32_t start = clock(); // Начало замера
	for (int i = 0; i < block_count; i++) {
		fill_data(buf, block_size);
		cbc_encrypt(key, block_size, buf, block_size);
		cs += checksum(buf, block_size); // Расчет контрольной суммы чтобы оптимизатор ничего не убрал
	}
	// Вывод результата
	int time = clock() - start - time_fill;
	if (time == 0) time = 1;
	int64_t total = (int64_t)block_size * block_count;
	printf("%d ms %d Mb/s\n%u\r", time, (int)((total * CLOCKS_PER_SEC / time) >> 20), cs);
}

// Замер скорости RC4
void rc4_speed(int block_size, int block_count) {
	rc4_t rc4("My secret key", 13);
	uint8_t *buf = new uint8_t[block_size]; // буфер под данные
	fill_data(0, 0, 12345); // Инициализация генератора данных
	int cs = 0;
	printf("test speed RC4 encrypt %d blocks of %d bytes each ... \n", block_count, block_size);
	uint32_t start = clock(); // Начало замера
	for (int i = 0; i < block_count; i++) {
		fill_data(buf, block_size);
		rc4.crypt(buf, block_size);
		cs += checksum(buf, block_size); // Расчет контрольной суммы чтобы оптимизатор ничего не убрал
	}
	// Вывод результата
	int time = clock() - start - time_fill;
	if (time == 0) time = 1;
	int64_t total = (int64_t)block_size * block_count;
	printf("%d ms %d Mb/s\n%u\r", time, (int)((total * CLOCKS_PER_SEC / time) >> 20), cs);
}

// Замер скорости AES-128
void aes_speed(int block_size, int block_count) {
	aes128_t aes("My secret key");

	uint8_t *buf = new uint8_t[block_size]; // буфер под данные
	fill_data(0, 0, 12345); // Инициализация генератора данных
	int cs = 0;
	printf("test speed AES-128 encrypt %d blocks of %d bytes each ... \n", block_count, block_size);
	uint32_t start = clock(); // Начало замера
	for (int i = 0; i < block_count; i++) {
		fill_data(buf, block_size);
		aes.encrypt(buf, block_size);
		cs += checksum(buf, block_size); // Расчет контрольной суммы чтобы оптимизатор ничего не убрал
	}
	// Вывод результата
	int time = clock() - start - time_fill;
	if (time == 0) time = 1;
	int64_t total = (int64_t)block_size * block_count;
	printf("%d ms %d Mb/s\n%u\r", time, (int)((total * CLOCKS_PER_SEC / time) >> 20), cs);
}

// Замер скорости AES-128 + CBC
void aes_cbc_speed(int block_size, int block_count) {
	aes128_t aes("My secret key");

	uint8_t *buf = new uint8_t[block_size]; // буфер под данные
	fill_data(0, 0, 12345); // Инициализация генератора данных
	int cs = 0;
	printf("test speed AES-128 + CBC encrypt %d blocks of %d bytes each ... \n", block_count, block_size);
	uint32_t start = clock(); // Начало замера
	for (int i = 0; i < block_count; i++) {
		fill_data(buf, block_size);
		aes.cbc_encrypt(buf, block_size);
		cs += checksum(buf, block_size); // Расчет контрольной суммы чтобы оптимизатор ничего не убрал
	}
	// Вывод результата
	int time = clock() - start - time_fill;
	if (time == 0) time = 1;
	int64_t total = (int64_t)block_size * block_count;
	printf("%d ms %d Mb/s\n%u\r", time, (int)((total * CLOCKS_PER_SEC / time) >> 20), cs);
}

int main()
{
	printf("compile %s %s\n", __DATE__, __TIME__);

#ifdef _DEBUG
	aes128_t_test();
	int size = 4096, count = 5000;
#else
	int size = 4096, count = 500000;
#endif
	fill_speed(size, count);
	cbc_speed(size, count);
	rc4_speed(size, count);
	aes_speed(size, count);
	aes_cbc_speed(size, count);
}