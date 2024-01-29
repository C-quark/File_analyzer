import struct

BYTE_8 = 8
BYTE_4 = 4
BYTE_2 = 2
BYTE = 1
NUMBER_OF_RVA_AND_SIZES = 16


def analyzer(file):
    with open(file, 'rb') as f:
        dos_header = f.read(64)
        mz = dos_header[0:2]
        if mz != b'MZ':
            print('не запустится')
            return

        e_lfanew = struct.unpack('<I', dos_header[60:64])[0]
        f.seek(e_lfanew)
        pe_signature = f.read(BYTE_4)
        if pe_signature != b'PE\x00\x00':
            print('неверная PE сигнатура')
            return

        point_file_header_start = f.seek(e_lfanew+BYTE_4)
        file_header_machine = f.read(BYTE_2)
        file_header_machine_value = struct.unpack('<H', file_header_machine)[0]

        if file_header_machine_value == 332:
            print('программа может выполняться на x32')
        elif file_header_machine_value == 34404:
            print('программа может выполняться на процессорах AMD64 (x64)')
        elif file_header_machine_value == 512:
            print('программа может выполняться на процессорах Intel Itanium (Intel x64)')
        else:
            print('Нет такой архитектуры')
            return

        file_header_size = BYTE_2 * 4 + BYTE_4 * 3
        point_optional_header_start = f.seek(point_file_header_start + file_header_size)
        optional_header_magic = f.read(BYTE_2)
        optional_header_magic_value = struct.unpack('<H', optional_header_magic)[0]

        data_directory_sizes = BYTE_4 * 2 * NUMBER_OF_RVA_AND_SIZES

        if optional_header_magic_value == 267:
            optional_header_size = BYTE * 2 + BYTE_2 * 9 + BYTE_4 * 19 + data_directory_sizes
            print('x32 (x86) исполняемый образ.')
        elif optional_header_magic_value == 523:
            optional_header_size = BYTE * 2 + BYTE_2 * 9 + BYTE_4 * 13 + BYTE_8 * 5 + data_directory_sizes
            print('x64 исполняемый образ')
        elif optional_header_magic_value == 263:
            print('ROM образ')
        else:
            print('Нет образа')
            return

        data_directory_size = BYTE_4 * 2
        optional_header_without_dt_size = optional_header_size - data_directory_sizes
        import_directory_start = optional_header_without_dt_size + data_directory_size
        point_import_directory_start = f.seek(point_optional_header_start + import_directory_start)

        import_directory = f.read(BYTE_4)
        import_directory_va = struct.unpack('<I', import_directory)[0]
        print(import_directory_va)


if __name__ == "__main__":
    analyzer('notepad++.exe')
