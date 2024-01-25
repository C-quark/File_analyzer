import struct

DWORD = 4
WORD = 2


def analyzer(file):
    with open(file, 'rb') as f:
        dos_header = f.read(64)
        mz = dos_header[0:2]
        if mz != b'MZ':
            print('не запустится')
            return
        e_lfanew = struct.unpack('<I', dos_header[60:64])[0]
        f.seek(e_lfanew)
        pe_signature = f.read(DWORD)
        if pe_signature != b'PE\x00\x00':
            print('неверная PE сигнатура')
            return
        point = f.seek(e_lfanew+DWORD)
        file_header_machine = f.read(WORD)
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

        file_header = WORD * 4 + DWORD * 3
        point = f.seek(point + file_header)
        optional_header_magic = f.read(WORD)
        optional_header_magic_value = struct.unpack('<H', optional_header_magic)[0]
        print(optional_header_magic_value)

        if optional_header_magic_value == 267:
            print('x32 (x86) исполняемый образ.')
        elif optional_header_magic_value == 523:
            print('x64 исполняемый образ')
        elif optional_header_magic_value == 263:
            print('ROM образ')
        else:
            print('Нет образа')
            return


if __name__ == "__main__":
    analyzer('notepad++.exe')
