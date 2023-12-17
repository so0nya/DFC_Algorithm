import numpy as np

import my_utils
from my_utils import cyclic_shift, cast_np_uint, to_bits
import random


key = ''.join([str(random.randint(0, 9)) for _ in range(81)])
print(key)


def split_key(key):
    if len(key) != 32:
        raise ValueError("Длина ключа должна быть 256 бит (32 байта)")

    key_parts = []

    for i in range(0, len(key), 4):
        part = key[i:i + 4]
        key_parts.append(part)

    return key_parts

key_parts = split_key(key)

if len(key_parts) != 8:
    raise ValueError("Неверное количество частей ключа")

PK1, PK2, PK3, PK4, PK5, PK6, PK7, PK8 = key_parts

print("PK1:", PK1)
print("PK2:", PK2)
print("PK3:", PK3)
print("PK4:", PK4)
print("PK5:", PK5)
print("PK6:", PK6)
print("PK7:", PK7)
print("PK8:", PK8)


_SKEY: np.uint256 = key  # секретный ключ

_ROUNDS: int = 8  # количество проходов по сети Фейстеля

_ROUND_KEYS: list = list()  # Создаём раундовые ключи
for index in range(_ROUNDS):
    _ROUND_KEYS.append(cast_np_uint((cyclic_shift(_SKEY, 256, -(index + 1)) ^ _SKEY), 256, np.uint64, 64))

_IV: list = list()  # Вектор инициализации для режима шифрования CBC (увы, не получилось сделать одним числом)
for _ in range(4):
    _IV.append(np.uint64(random.randint(1, 65535)))


# def _f1(m0: np.uint16, m1: np.uint16) -> np.uint16:
#     """ (m0 <<< 4) + (m1 >> 2) """
#     return (cyclic_shift(m0, 16, 4)) + (cyclic_shift(m1, 16, -2))

def _f1(m0: np.uint64, m1: np.uint64) -> np.uint64:
    """ (m0 <<< 4) + (m1 >> 2) """
    return np.uint64((cyclic_shift(m0, 64, 4) & 0xFFFF) + ((cyclic_shift(m1, 64, -2) & 0xFFFF) >> 2))


def _f2(m2: np.uint64, m3: np.uint64.numerator) -> np.uint64:
    """ (m2 <<< 7) ^ ~m3 """
    return cyclic_shift(m2, 64, 7) ^ (~m3)


def _Ek(message: list) -> list:
    #  ...выполняем преобразование по раундам в соответствии с заданием
    cipher: list = np.copy(message)
    for i in range(_ROUNDS):
        cipher[0] = message[2] ^ (~_ROUND_KEYS[i])
        cipher[1] = _f1(message[0] ^ _ROUND_KEYS[i], message[1]) ^ message[3]
        cipher[2] = _f2(cipher[0], cipher[1]) ^ message[1]
        cipher[3] = message[0] ^ _ROUND_KEYS[i]
        message = np.copy(cipher)
    return cipher


def _Dk(cipher: list) -> list:
    #  ...выполняем обратное преобразование по раундам в соответствии
    #  с заданием, но не трогаем f (f^-1 - недопустимо)
    message: list = np.copy(cipher)
    for r_i in range(_ROUNDS - 1, -1, -1):
        message[0] = cipher[3] ^ _ROUND_KEYS[r_i]
        message[1] = _f2(cipher[0], cipher[1]) ^ cipher[2]
        message[2] = cipher[0] ^ (~_ROUND_KEYS[r_i])
        message[3] = _f1(cipher[3], message[1]) ^ cipher[1]
        cipher = np.copy(message)
    return message


def crypt_ecb(path_from: str, path_to: str) -> bool:
    try:
        # Открываем файл, сообщение которого нужно зашифровать
        with open(path_from, 'rb') as rfile:
            while True:
                # Проверка конца файла
                file_eof: bytes = rfile.read(1)
                rfile.seek(rfile.tell() - 1)
                if file_eof == b'':
                    break

                # Блок состоит из 4 частей
                message: list = list()
                for _ in range(4):
                    message.append(np.uint64(int.from_bytes(rfile.read(2), byteorder="little", signed=False)))

                #  Шифрование
                cipher: list = _Ek(message)
                #  записываем результат в файл
                my_utils.add_bin_data_to_file(path_to, cipher)
            return True
    except FileNotFoundError:
        print("Невозможно открыть файл")
        return False


def decrypt_ecb(path_from: str, path_to: str) -> bool:
    try:
        # Открываем файл, сообщение которого нужно расшифровать, и файл, куда записываем расшифрованное сообщение
        with open(path_from, 'rb') as rfile:
            while True:
                # Проверка конца файла
                file_eof: bytes = rfile.read(1)
                rfile.seek(rfile.tell() - 1)
                if file_eof == b'':
                    break

                # Блок состоит из 4 частей
                cipher: list = list()
                for _ in range(4):
                    cipher.append(np.uint64(int.from_bytes(rfile.read(2), byteorder="little", signed=False)))

                #  Дешифрование
                message: list = _Dk(cipher)
                #  записываем результат в файл
                my_utils.add_bin_data_to_file(path_to, message)
            return True
    except FileNotFoundError:
        print("Невозможно открыть файл")
        return False


def _xor_for_cbc(message: list, cipher: list) -> list:
    temp: list = list()
    for i in range(4):
        temp.append(np.uint64(message[i] ^ cipher[i]))
    return temp


def crypt_cbc(path_from: str, path_to: str) -> bool:
    try:
        # Открываем файл, сообщение которого нужно зашифровать
        with open(path_from, 'rb') as rfile:
            # блок зашифрованного текста и синхропосылка одновременно
            cipher: list = np.copy(_IV)
            while True:
                # Проверка конца файла
                file_eof: bytes = rfile.read(1)
                rfile.seek(rfile.tell() - 1)
                if file_eof == b'':
                    break

                # Блок состоит из 4 частей
                message: list = list()
                for _ in range(4):
                    message.append(np.uint64(int.from_bytes(rfile.read(2), byteorder="little", signed=False)))

                #  Шифрование
                cipher = _Ek(_xor_for_cbc(message, cipher))
                #  записываем результат в файл
                my_utils.add_bin_data_to_file(path_to, cipher)
            return True
    except FileNotFoundError:
        print("Невозможно открыть файл")
        return False


def decrypt_cbc(path_from: str, path_to: str) -> bool:
    try:
        # Открываем файл, сообщение которого нужно расшифровать, и файл, куда записываем расшифрованное сообщение
        with open(path_from, 'rb') as rfile:
            # синхропосылка
            iv: list = np.copy(_IV)
            while True:
                # Проверка конца файла
                file_eof: bytes = rfile.read(1)
                rfile.seek(rfile.tell() - 1)
                if file_eof == b'':
                    break

                # Блок состоит из 4 частей
                cipher: list = list()
                for _ in range(4):
                    cipher.append(np.uint64(int.from_bytes(rfile.read(2), byteorder="little", signed=False)))

                #  Дешифрование
                message: list = _xor_for_cbc(iv, _Dk(cipher))
                #  Сохраняем синхропосылку
                iv = np.copy(cipher)
                #  записываем результат в файл
                my_utils.add_bin_data_to_file(path_to, message)
            return True
    except FileNotFoundError:
        print("Невозможно открыть файл")
        return False
