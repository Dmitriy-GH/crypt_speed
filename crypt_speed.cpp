// Тест скорости шифрования/дешифрования разных алгоритмов

#include <stdio.h>
#include <stdint.h>
#include <time.h>

//#define LT_STAT
#include "lite_thread.h"
#include "cbc.h"
#include "rc4.h"
#include "md5.h"
#include "aes128ni.h"

#define MSG_SIZE 1472
#ifdef _DEBUG
#define MSG_COUNT 100
#else
#define MSG_COUNT 1000000
#endif
#define MSG_USE 256

// Сообщение
class msg_t : public lite_msg_t {
	// Генератор потока данных для шифрования
	void fill_data(void *buffer) {
		static uint32_t state = 12345; // Текущее состояние
		uint8_t *end = ((uint8_t *)buffer) + MSG_SIZE;
		for (uint8_t *p = (uint8_t *)buffer; p != end; p++) {
			state = state * 1103515245;
			*p = (uint8_t)(state >> 16);
		}
	}

public:
	uint8_t data[MSG_SIZE];

	msg_t() {
		fill_data(data);
	}
};

// Базовый класс для остальных замеров
class base_actor_t : public lite_actor_t {
	lite_actor_t* next; // следующий обработчик

	void recv(lite_msg_t* msg) override {
		msg_t* m = work(static_cast<msg_t*>(msg));
		if(m != NULL) next->run(m);
	}
public:
	base_actor_t() : next(NULL) {
	}

	void next_set(lite_actor_t* next) {
		this->next = next;
		type_add(lite_msg_type<msg_t>());
	}

	// Обработка сообщения, прописывается в дочернем классе
	// Возвращает сообщения для передачи дальше или NULL
	virtual msg_t* work(msg_t*) = 0;

};

// Подготовка сообщений, запуск на шифрование, замер времени и подсчет результатов
class sender_t : public lite_actor_t {
	lite_actor_t* next = NULL; // следующий обработчик
	uint32_t msg_count; // Счетчик количества отправляемых сообщений
	int time_start;

	// Обработчик сообщений
	void recv(lite_msg_t* msg) override {
		switch(msg_count) {
		case 0:
			return;
		case 1: // Пришло последнее сообщение
			msg_count--;
			int time = (int)lite_time_now() - time_start;
			if (time == 0) time = 1;
			int64_t total = (int64_t)MSG_SIZE * MSG_COUNT;
			lite_log(0, "%d ms %d Mb/s", time, (int)((total * 1000 / time) >> 20));
			return;
		}
		msg_count--;
		next->run(msg);
	}

public:
	sender_t(lite_actor_t* next) {
		this->next = next;
		this->msg_count = MSG_COUNT;
		this->time_start = (int)lite_time_now();
		type_add(lite_msg_type<msg_t>());
	}
};

// Запуск теста 
void test(const char* descr, base_actor_t* ba) {
	sender_t* s = new sender_t(ba); // Генератор сообщений
	ba->next_set(s);
	lite_log(0, "test speed %s %d blocks of %d bytes each ...", descr, MSG_COUNT, MSG_SIZE);
	for (size_t i = 0; i != MSG_USE; i++) s->run(new msg_t); // Запуск MSG_USE сообщений
	lite_thread_end(); // Ожидание завершения
}

// Пересылка далее, используется для замера скорости пересылки
class empty_t : public base_actor_t {
	msg_t* work(msg_t* msg) override {
		return msg;
	}
};

// Шифрование XOR сдвинутым ключом
class xor_shift_t : public base_actor_t {
	uint8_t key[MSG_SIZE + 256];

	msg_t* work(msg_t* msg) override {
		uint64_t *k = (uint64_t *)(key + (msg->data[0] & 0xF8)), *d = (uint64_t *)(msg->data); // Начало последовательности для шифрования текущего блока
		msg->data[0] ^= k[0]; // buf[0] нельзя шифровать, а если цикл начать с 1 почему-то медленнее работает
		for (size_t i = 0; i != MSG_SIZE / sizeof(uint64_t); i++) d[i] ^= k[i]; // Шифрование
		return msg;
	}

public:
	void init_key(const void* password, size_t pass_size) {
		md5_t md5;
		rc4_t rc4(md5.calc(password, pass_size), 16); // Инициализация ключевой последовательности
		rc4.crypt(key, sizeof(key)); // Заполнение ключевой последовательности
	}

	xor_shift_t() {
		init_key("My secret key", 13);
	}
};

// Шифрование CBC + XOR сдвинутым ключом
class cbc_xor_encrypt_t : public base_actor_t {
	uint8_t key[MSG_SIZE + 256];

	msg_t* work(msg_t* msg) override {
		uint64_t *k = (uint64_t *)(key + (msg->data[0] & 0xF8)), *d = (uint64_t *)(msg->data); // Начало последовательности для шифрования текущего блока
		msg->data[0] ^= k[0]; // buf[0] нельзя шифровать
		uint64_t prev = 0;
		for (size_t i = 0; i != MSG_SIZE / sizeof(uint64_t); i++) {
			d[i] ^= prev ^ k[i];
			prev = d[i];
		}
		return msg;
	}

public:
	void init_key(const char* password) {
		md5_t md5;
		rc4_t rc4(md5.calc(password), 16); // Инициализация ключевой последовательности
		rc4.crypt(key, sizeof(key)); // Заполнение ключевой последовательности
	}

	cbc_xor_encrypt_t() {
		init_key("My secret key");
	}
};

// Шифрование AES-128
class aes_encrypt_t : public base_actor_t {
	aes128ni_t aes;

	msg_t* work(msg_t* msg) override {
		aes.encrypt(msg->data, MSG_SIZE);
		return msg;
	}

public:
	aes_encrypt_t() {
		aes.init("My secret key");
	}
};

// Шифрование AES-128 + CBC
class aes_cbc_encrypt_t : public base_actor_t {
	aes128ni_t aes;

	msg_t* work(msg_t* msg) override {
		aes.cbc_encrypt(msg->data, MSG_SIZE);
		return msg;
	}

public:
	aes_cbc_encrypt_t() {
		aes.init("My secret key");
	}
};

// Расшифровка AES-128 + CBC
class aes_cbc_decrypt_t : public base_actor_t {
	aes128ni_t aes;

	msg_t* work(msg_t* msg) override {
		aes.cbc_decrypt(msg->data, MSG_SIZE);
		return msg;
	}

public:
	aes_cbc_decrypt_t() {
		aes.init("My secret key");
	}
};

// Расшифровка AES-128 + XOR
class aes_xor_encrypt_t : public base_actor_t {
	aes128ni_t aes;

	msg_t* work(msg_t* msg) override {
		aes.xor_encrypt(msg->data, MSG_SIZE);
		//aes.cbc_encrypt(msg->data, MSG_SIZE);
		return msg;
	}

public:
	aes_xor_encrypt_t() {
		aes.init("My secret key");
	}
};


// Расшифровка AES-128 + XOR
class aes_xor_decrypt_t : public base_actor_t {
	aes128ni_t aes;

	msg_t* work(msg_t* msg) override {
		aes.xor_decrypt(msg->data, MSG_SIZE);
		return msg;
	}

public:
	aes_xor_decrypt_t() {
		aes.init("My secret key");
	}
};



int main() {
	printf("compile %s %s\n", __DATE__, __TIME__);
	
	test("send to next", new empty_t());
	test("XOR SHIFT crypt", new xor_shift_t());
	test("XOR SHIFT + CBC encrypt", new cbc_xor_encrypt_t());
	
	if (!aes128ni_is_supported()) {
		printf("CPU not supported AES\n");
		return 1;
	}
	test("AES-128 encrypt", new aes_encrypt_t());
	test("AES-128 + CBC encrypt", new aes_cbc_encrypt_t());
	test("AES-128 + CBC decrypt", new aes_cbc_decrypt_t());
}