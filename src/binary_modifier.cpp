#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <elf.h>
#include <capstone/capstone.h>

// Trampoline code
static const uint8_t trampoline[] = {
    0x90,       // NOP
    0xC3        // RET
};
constexpr size_t trampoline_size = sizeof(trampoline);

// Function to read the binary file into a vector
std::vector<uint8_t> read_binary(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open file");
    }
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

// Function to write the modified binary back to disk
void write_binary(const std::string& filename, const std::vector<uint8_t>& data) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open file");
    }
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

// Function to insert a call to the trampoline before syscalls
void insert_trampolines(std::vector<uint8_t>& code, uint64_t base_address, uint64_t trampoline_address) {
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        std::cerr << "Failed to initialize Capstone.\n";
        return;
    }

    count = cs_disasm(handle, code.data(), code.size(), base_address, 0, &insn);
    if (count > 0) {
        for (size_t i = 0; i < count; i++) {
            if (insn[i].id == X86_INS_SYSCALL || (insn[i].id == X86_INS_INT && insn[i].detail->x86.operands[0].imm == 0x80)) {
                size_t offset = insn[i].address - base_address; // Calculate offset
                int32_t call_offset = static_cast<int32_t>(trampoline_address - (insn[i].address + 5)); // Relative offset for the call instruction

                code.insert(code.begin() + offset, 0xE8); // Call opcode
                code.insert(code.begin() + offset + 1, reinterpret_cast<uint8_t*>(&call_offset), reinterpret_cast<uint8_t*>(&call_offset) + 4);

                // Adjust for the added call instruction size (5 bytes)
                for (size_t j = 0; j < insn[i].size; ++j) {
                    code.insert(code.begin() + offset + 5, 0x90); // Insert NOPs to maintain alignment
                }
            }
        }
        cs_free(insn, count);
    } else {
        std::cerr << "Failed to disassemble given code!\n";
    }

    cs_close(&handle);
}

// Function to append the trampoline function to the end of the .text section
void append_trampoline_to_text_section(std::vector<uint8_t>& binary, uint64_t& trampoline_address) {
    Elf64_Ehdr *ehdr = reinterpret_cast<Elf64_Ehdr*>(binary.data());
    Elf64_Shdr *shdr = reinterpret_cast<Elf64_Shdr*>(binary.data() + ehdr->e_shoff);

    // Locate the .text section
    Elf64_Shdr *text_shdr = nullptr;
    for (int i = 0; i < ehdr->e_shnum; ++i) {
        if (strcmp(reinterpret_cast<const char*>(binary.data() + shdr[ehdr->e_shstrndx].sh_offset + shdr[i].sh_name), ".text") == 0) {
            text_shdr = &shdr[i];
            break;
        }
    }

    if (!text_shdr) {
        std::cerr << "Failed to locate .text section.\n";
        return;
    }

    // Append the trampoline function to the end of the .text section
    trampoline_address = text_shdr->sh_addr + text_shdr->sh_size;
    size_t text_offset = text_shdr->sh_offset + text_shdr->sh_size;
    binary.insert(binary.begin() + text_offset, std::begin(trampoline), std::end(trampoline));

    // Update the .text section header
    text_shdr->sh_size += trampoline_size;

    // Adjust all section headers and program headers after the .text section
    for (int i = 0; i < ehdr->e_shnum; ++i) {
        if (shdr[i].sh_offset > text_shdr->sh_offset) {
            shdr[i].sh_offset += trampoline_size;
        }
    }

    // Update the program headers
    Elf64_Phdr *phdr = reinterpret_cast<Elf64_Phdr*>(binary.data() + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; ++i) {
        if (phdr[i].p_offset > text_shdr->sh_offset) {
            phdr[i].p_offset += trampoline_size;
        }
    }
}

// Function to process ELF file and modify executable sections
void process_elf(std::vector<uint8_t>& binary) {
    Elf64_Ehdr *ehdr = reinterpret_cast<Elf64_Ehdr*>(binary.data());
    Elf64_Shdr *shdr = reinterpret_cast<Elf64_Shdr*>(binary.data() + ehdr->e_shoff);

    uint64_t trampoline_address;
    append_trampoline_to_text_section(binary, trampoline_address);

    // Modify the code to insert calls to the trampoline
    for (int i = 0; i < ehdr->e_shnum; ++i) {
        if (shdr[i].sh_flags & SHF_EXECINSTR) {
            uint64_t base_address = shdr[i].sh_addr;
            size_t offset = shdr[i].sh_offset;
            size_t size = shdr[i].sh_size;

            std::vector<uint8_t> code(binary.begin() + offset, binary.begin() + offset + size);
            insert_trampolines(code, base_address, trampoline_address);

            // Update binary with modified code
            std::copy(code.begin(), code.end(), binary.begin() + offset);
        }
    }
}

int main(int argc, char **argv) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <input_binary> <output_binary>\n";
        return 1;
    }

    const std::string input_file = argv[1];
    const std::string output_file = argv[2];

    try {
        std::vector<uint8_t> binary = read_binary(input_file);

        process_elf(binary);
        write_binary(output_file, binary);

        std::cout << "Call to trampoline inserted before syscalls.\n";
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\n";
        return 1;
    }

    return 0;
}
