# Readme #
## Сборка ##
См. readme библиотеки libakrypt
## Что сделано ##
Было реализовано встраивание реализации алгоритма блочного шифрования AES-128, регламентированного стандартом FIPS 197 https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf

Для лучшего понимания шифра была также использована данная литература - https://www.nrjetix.com/fileadmin/doc/publications/Lectures_security/Lecture3-1.pdf

Для встраивания реализции алгоритма шифрования AES-128 в библиотеку были внесены следующие изменения:
* Добавлен файл `source/ak_aes128.c`
* Добавлен файл `examples/test-aes128.c`
* Добавлены 2 строчки в CMakeList:

         source/ak_aes128.c  на 76 строке
            
         aes128              на 196 строке
            
* Добавлено описание следующих функций в файл `libakrypt.h`:

        aes128_test( void )            на строке 171
        
        int ak_bckey_create_aes128( ak_bckey bkey )      на строке 682
        

Файл `ak_aes128.c` содержит реализацию алгоритма блочного шифрования AES-128. В файле определены следующие функции:
              
        static void shift_rows(uint8_t * state)
        static void inv_shift_rows(uint8_t * state)     
        static void aes_encrypt_128(ak_skey skey, const uint8_t * plaintext, uint8_t * ciphertext)
        static void aes_decrypt_128(ak_skey skey, const uint8_t * ciphertext, uint8_t * plaintext)
        
Функции для работы с ключами:
        static int ak_aes128_delete_keys(ak_skey skey)
        static int aes_key_schedule_128(ak_skey skey) 
        static int ak_skey_set_special_aes128_mask(ak_skey skey)
        static int ak_skey_set_special_aes128_unmask(ak_skey skey)
    
Функции шифрования и дешифрования:

        static void aes_encrypt_128(ak_skey skey, const uint8_t * plaintext, uint8_t * ciphertext)
        static void aes_decrypt_128(ak_skey skey, const uint8_t * ciphertext, uint8_t * plaintext)

Функция для тестирования работоспособности:

        bool_t aes128_test()
        
