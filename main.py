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
        file_header_machine_number_of_sections = f.read(BYTE_4)
        file_header_machine_value = struct.unpack('<H', file_header_machine_number_of_sections[0:BYTE_2])[0]
        file_header_number_of_sections_value = struct.unpack('<H', file_header_machine_number_of_sections[BYTE_2:BYTE_4])[0]

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
        f.seek(point_optional_header_start)

        if optional_header_magic_value == 267:
            optional_header_size = BYTE * 2 + BYTE_2 * 9 + BYTE_4 * 19 + data_directory_sizes
            section_alignment_start = BYTE * 2 + BYTE_2 + BYTE_4 * 7
            section_alignment_end = section_alignment_start + BYTE_4
            section_alignment = f.read(section_alignment_start + section_alignment_end)
            section_alignment_value = struct.unpack('<I', section_alignment[section_alignment_start:section_alignment_end])[0]
            print('x32 (x86) исполняемый образ.')
        elif optional_header_magic_value == 523:
            optional_header_size = BYTE * 2 + BYTE_2 * 9 + BYTE_4 * 13 + BYTE_8 * 5 + data_directory_sizes
            section_alignment_start = BYTE * 2 + BYTE_2 + BYTE_4 * 5 + BYTE_8
            section_alignment_end = section_alignment_start + BYTE_4
            section_alignment = f.read(section_alignment_end)
            section_alignment_value = struct.unpack('<I', section_alignment[section_alignment_start:section_alignment_end])[0]
            print('x64 исполняемый образ')
        elif optional_header_magic_value == 263:
            print('ROM образ')
        else:
            print('Нет образа')
            return

        print(file_header_number_of_sections_value)
        print(section_alignment_value)

        data_directory_size = BYTE_4 * 2
        import_directory_start = optional_header_size - data_directory_sizes + data_directory_size
        f.seek(point_optional_header_start + import_directory_start)

        import_directory_va = f.read(BYTE_4)
        import_directory_va_value = struct.unpack('<I', import_directory_va)[0]
        print(import_directory_va_value)

        def align(rva, alignment):
            if rva % alignment == 0:
                return rva
            align_rva = alignment * (rva // alignment) + alignment
            return align_rva

        f.seek(point_optional_header_start + optional_header_size)
        section_header_size = BYTE_8 + BYTE_4 * 7 + BYTE_2 * 2
        for i in range(file_header_number_of_sections_value):
            section_header = f.read(section_header_size)
            section_header_virtual_size_value = struct.unpack('<I', section_header[BYTE_8:BYTE_8+BYTE_4])[0]
            section_header_va_value = struct.unpack('<I', section_header[BYTE_8+BYTE_4:BYTE_8+BYTE_4*2])[0]
            section_header_pointer_to_raw_data_value = struct.unpack('<I', section_header[BYTE_8+BYTE_4*3:BYTE_8+BYTE_4*4])[0]
            start_section = section_header_va_value
            end_section = start_section + align(section_header_virtual_size_value, section_alignment_value)
            if start_section <= import_directory_va_value < end_section:
                print(i, section_header_va_value, section_header_pointer_to_raw_data_value)
                break

        import_directory_table = import_directory_va_value - section_header_va_value + section_header_pointer_to_raw_data_value
        print(import_directory_table)

        f.seek(import_directory_table)
        import_descriptor_size = 5 * BYTE_4

        original_first_thunk_list = []
        name_list = []
        first_thunk_list = []
        for i in range(import_descriptor_size):
            import_descriptor = f.read(import_descriptor_size)
            import_descriptor_original_first_thunk = struct.unpack('<I', import_descriptor[0:BYTE_4])[0]
            original_first_thunk_list.append(import_descriptor_original_first_thunk)
            import_descriptor_name = struct.unpack('<I', import_descriptor[BYTE_4*3:BYTE_4*4])[0]
            name_list.append(import_descriptor_name)
            import_descriptor_first_thunk = struct.unpack('<I', import_descriptor[BYTE_4*4:BYTE_4*5])[0]
            first_thunk_list.append(import_descriptor_first_thunk)

            if import_descriptor_original_first_thunk == 0:
                original_first_thunk_list.remove(import_descriptor_original_first_thunk)
                name_list.remove(import_descriptor_name)
                first_thunk_list.remove(import_descriptor_first_thunk)
                break

        print(original_first_thunk_list)
        print(name_list)
        print(first_thunk_list)

        for i in name_list:
            import_descriptor_name_raw = i - section_header_va_value + section_header_pointer_to_raw_data_value
            f.seek(import_descriptor_name_raw)
            while True:
                name = f.read(BYTE)
                name_value = struct.unpack('<B', name)[0]
                #print(name)
                if name_value == 0:
                    break

        thunk_data_list = []
        for i in original_first_thunk_list:
            original_first_thunk_raw = i - section_header_va_value + section_header_pointer_to_raw_data_value
            f.seek(original_first_thunk_raw)
            while True:
                if optional_header_magic_value == 267:
                    thunk_data_size = BYTE_4
                    thunk_data = f.read(thunk_data_size)
                    thunk_data_value = struct.unpack('<I', thunk_data)[0]
                    thunk_data_list.append(thunk_data_value)
                elif optional_header_magic_value == 523:
                    thunk_data_size = BYTE_8
                    thunk_data = f.read(thunk_data_size)
                    thunk_data_value = struct.unpack('<Q', thunk_data)[0]
                    thunk_data_list.append(thunk_data_value)
                elif thunk_data_value == 0:
                    break

        print(thunk_data_list)

        for i in thunk_data_list:
            thunk_data_raw = i - section_header_va_value + section_header_pointer_to_raw_data_value
            f.seek(thunk_data_raw)
            while True:
                import_by_name_size = BYTE_4 + BYTE
                import_by_name = f.read(import_by_name_size)
                import_by_name_value = struct.unpack('<B', import_by_name[BYTE_4:BYTE_4+BYTE])[0]
                print(import_by_name)
                if import_by_name_value == 0:
                    break


if __name__ == "__main__":
    analyzer('win_app.exe')
