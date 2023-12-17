# import libs
import random as rnd


# кодировщик
# входной параметр: текстовое сообщение
# выходной параметр: битовая последовательность :: 128
def encode_msg(text, encoding='UTF-8'):
    bits = bin(int.from_bytes(text.encode(encoding), 'little'))[2:]
    k = 0
    while (128 * k < len(bits)):
        k += 1
    return bits.zfill(128 * k)


# декодировщик
# входной параметр: битовая последовательность :: 128
# выходной параметр: text message
def decode_msg(bits, encoding='UTF-8'):
    n = int(bits, 2)
    return n.to_bytes(n.bit_length(), 'little').decode(encoding) or '\0'


# разрезание сообщения на 128-битные части
# входной параметр: полное сообщение
# выходной параметр: нарезанное сообщение
def slicer(message):

    sliced_message = []
    k = 0
    while (k < len(message) / 128):
        right_part = k * 128
        left_part = (k + 1) * 128
        sliced_message.append(message[right_part:left_part])
        k += 1
    return sliced_message


# hex константы
KC = 0xeb64749a
KD = 0x86d1bf275b9b241d
KA1 = 0xb7e151628aed2a6a
KA2 = 0xbf7158809cf4f3c7
KA3 = 0x62e7160f38b4da56
KB1 = 0xa784d9045190cfef
KB2 = 0x324e7738926cfbe5
KB3 = 0xf4bf8d8d8c31d763
KS = 0xda06c80abb1185eb4f7c7b5757f5958490cfd47d7c19bb42158d9554f7b46bce


# RT таблица
RT = [0xb7e15162, 0x8aed2a6a, 0xbf715880, 0x9cf4f3c7, 0x62e7160f, 0x38b4da56, 0xa784d904, 0x5190cfef, 0x324e7738, 0x926cfbe5,
      0xf4bf8d8d, 0x8c31d763, 0xda06c80a, 0xbb1185eb, 0x4f7c7b57, 0x57f59594, 0x90cfd47d, 0x7c19bb42, 0x158d9554, 0xf7b46bce,
      0xd55c4d79, 0xfd5f24d6, 0x613c31c3, 0x839a2ddf, 0x8a9a276b, 0xcfbfa1c8, 0x77c56284, 0xdab79cd4, 0xc2d3293d, 0x20e9e5ea,
      0xf02ac60a, 0xcc93ed87, 0x4422a52e, 0xcb238fee, 0xe5ab6add, 0x835fd1a0, 0x753d0a8f, 0x78e537d2, 0xb95bb79d, 0x8dcaec64,
      0x2c1e9f23, 0xb829b5c2, 0x780bf387, 0x37df8bb3, 0x00d01334, 0xa0d0bd86, 0x45cbfa73, 0xa6160ffe, 0x393c48cb, 0xbbca060f,
      0x0ff8ec6d, 0x31beb5cc, 0xeed7f2f0, 0xbb088017, 0x163bc60d, 0xf45a0ecb, 0x1bcd289b, 0x06cbbfea, 0x21ad08e1, 0x847f3f73,
      0x78d56ced, 0x94640d6e, 0xf0d3d37b, 0xe6700831]


# константы 2^64
const_2_64_str = str(10000000000000000000000000000000000000000000000000000000000000000)
const_2_64_int = int(const_2_64_str, 2)


# раунд функции DFC
# входные параметры: раундовый ключ, 64-битный исходный подблок
# выходные параметры: 64-битный зашифрованный подблок
def dfc_round_func(round_key, source_subblock):

    # нарезаем ключ (пункт 1 методы)
    round_key_str = bin(round_key)[2:].zfill(128)
    a_str = round_key_str[0:64]
    b_str = round_key_str[64:128]
    a = int(a_str, 2)
    b = int(b_str, 2)

    # расчет промежуточного значения x (пункт 2 методы)
    x = (((~a * ~source_subblock) + ~b) % (const_2_64_int + 13)) % const_2_64_int

    # нарезаем x на x1 и x2 (пункт 3 методы)
    x_str = bin(x)[2:].zfill(64)
    x1_str = x_str[0:32]
    x2_str = x_str[32:64]
    x1 = int(x1_str, 2)
    x2 = int(x2_str, 2)

    # trunc (усечение битовой строки для пункта 4)
    num_str = x1_str[0:6]
    num = int(num_str, 2)

    # жоска считаем y (пункт 4, формула разделена, а-то она прям огромная)
    part_1_str = bin(x2 ^ RT[~num])[2:].zfill(32)
    part_2_str = bin(x1 ^ KC)[2:].zfill(32)
    concatenacio_str = part_1_str + part_2_str
    concatenacio_int = int(concatenacio_str, 2)
    ciphered_subblock = (~concatenacio_int + ~KD) % const_2_64_int

    return ciphered_subblock


# идем по блок-схеме алгоритма
# входной параметр: 128-битный исходный блок
# выходной параметр: 128-битный блок шифрования
def struct_algo_dfc(source_block_str):

    # разрезаем блок на две части
    left_subblock_str = source_block_str[0:64]
    right_subblock_str = source_block_str[64:128]
    left_subblock = int(left_subblock_str, 2)
    right_subblock = int(right_subblock_str, 2)

    # 8 раундов
    k = 0
    while (k != 8):
        round_calc = dfc_round_func(KS, right_subblock)
        helper = right_subblock
        right_subblock = round_calc ^ left_subblock
        left_subblock = helper
        k += 1

    # формируем зашифрованный блок
    left_subblock_str = bin(left_subblock)[2:].zfill(64)
    rigth_subblock_str = bin(right_subblock)[2:].zfill(64)
    ciphered_block_str = rigth_subblock_str + left_subblock_str

    return ciphered_block_str.zfill(128)


# шифратор
# входной параметр: фрагментированное сообщение
# выходной параметр: зашифрованное сообщение
def cipherer(sliced_message):

    ciphered_message = ''
    i = 0
    while (i != len(sliced_message)):
        ciphered_message += struct_algo_dfc(sliced_message[i])
        i += 1

    return ciphered_message


# демонстрация
# входной параметр: 128-битный ключ шифрования
# выходной параметр: вывести результаты
def main_demo():

    istream = open('source_message.txt')
    source_message = encode_msg(istream.read())
    print("Source message:", decode_msg(source_message), '\n')
    print("Encoded message:", source_message)
    print("KS:", KS)
    print("Random key 0-256b:", random_key)
    print("Key:", PK)
    print("Key:", key)
    print("len key:", key.bit_length())
    print("OK:", OK.bit_length())
    print("Size:", len(source_message), '\n')

    sliced_message = slicer(source_message)
    ciphered_message = cipherer(sliced_message)
    print("Ciphered message:", ciphered_message)
    print("Size:", len(source_message), '\n')

    sliced_message = slicer(ciphered_message)
    deciphered_message = cipherer(sliced_message)
    print("Deciphered message:", deciphered_message)
    print("Size:", len(source_message), '\n')

    print("Decoded message:", decode_msg(deciphered_message))


# Работаем с раундовыми ключами

# Генерируем случайный ключ случайного размера, который мы дополним константой, чтобы получилось 256 бит
random_key = rnd.getrandbits(rnd.randint(0, 256))

# Здесь нужно константу порезать, чтобы дополнить рандомный ключ
new_KS = KS >> (256 - random_key.bit_length())

# А здесь в итоге получаем нужный максимально рандомный ключ в размере 256 бит, ура!
PK = (random_key << 256 - random_key.bit_length()) | KS

# Считаем PK1-8
PK1 = (PK >> 224) & 0xFFFFFFFF
PK2 = (PK >> 192) & 0xFFFFFFFF
PK3 = (PK >> 160) & 0xFFFFFFFF
PK4 = (PK >> 128) & 0xFFFFFFFF
PK5 = (PK >> 96) & 0xFFFFFFFF
PK6 = (PK >> 64) & 0xFFFFFFFF
PK7 = (PK >> 32) & 0xFFFFFFFF
PK8 = PK & 0xFFFFFFFF

# Просто ради проверочки
key = (PK1 << 224) | (PK2 << 192) | (PK3 << 160) | (PK4 << 128) | (PK5 << 96) | (PK6 << 64) | (PK7 << 32) | PK8

# Считаем вспомогательные переменные
OA1 = (PK1 << 32) | PK8
OB1 = (PK5 << 32) | PK4
EA1 = (PK2 << 32) | PK7
EB1 = (PK6 << 32) | PK3

OA2 = ((OA1 & 0xFFFFFFFFFFFFFFFF) + KA1) & 0xFFFFFFFFFFFFFFFF
OB2 = ((OB1 & 0xFFFFFFFFFFFFFFFF) + KB1) & 0xFFFFFFFFFFFFFFFF
EA2 = ((EA1 & 0xFFFFFFFFFFFFFFFF) + KA1) & 0xFFFFFFFFFFFFFFFF
EB2 = ((EB1 & 0xFFFFFFFFFFFFFFFF) + KB1) & 0xFFFFFFFFFFFFFFFF

OA3 = ((OA1 & 0xFFFFFFFFFFFFFFFF) + KA2) & 0xFFFFFFFFFFFFFFFF
OB3 = ((OB1 & 0xFFFFFFFFFFFFFFFF) + KB2) & 0xFFFFFFFFFFFFFFFF
EA3 = ((EA1 & 0xFFFFFFFFFFFFFFFF) + KA2) & 0xFFFFFFFFFFFFFFFF
EB3 = ((EB1 & 0xFFFFFFFFFFFFFFFF) + KB2) & 0xFFFFFFFFFFFFFFFF

OA4 = ((OA1 & 0xFFFFFFFFFFFFFFFF) + KA3) & 0xFFFFFFFFFFFFFFFF
OB4 = ((OB1 & 0xFFFFFFFFFFFFFFFF) + KB3) & 0xFFFFFFFFFFFFFFFF
EA4 = ((EA1 & 0xFFFFFFFFFFFFFFFF) + KA3) & 0xFFFFFFFFFFFFFFFF
EB4 = ((EB1 & 0xFFFFFFFFFFFFFFFF) + KB3) & 0xFFFFFFFFFFFFFFFF

# Считаем OK и EK

OK = (OA1 << 448) | (OB1 << 384) | (OA2 << 320) | (OB2 << 256) | (OA3 << 192) | (OB3 << 128) | (OA4 << 64) | OB4
EK = (EA1 << 448) | (EB1 << 384) | (EA2 << 384) | (EB2 << 256) | (EA3 << 192) | (EB3 << 128) | (EA4 << 64) | EB4

#Ключи для шифровки OK и EK

O1 = (OA1 << 64) + OB1
O2 = (OA2 << 64) + OB2
O3 = (OA3 << 64) + OB3
O4 = (OA4 << 64) + OB4

E1 = (EA1 << 64) + EB1
E2 = (EA2 << 64) + EB2
E3 = (EA3 << 64) + EB3
E4 = (EA4 << 64) + EB4

#Шифруем
# Разбиваем на a и b
a = (O1 >> 64) & 0xFFFFFFFF
b = O1 & 0xFFFFFFFF

# Считаем x



# вызываем
main_demo()
