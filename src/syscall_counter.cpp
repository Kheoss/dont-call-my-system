#include <bfd.h>
#include <iostream>
#include <vector>
#include <cstring>

void count_syscalls(bfd *abfd) {
    // Check format
    if (!bfd_check_format(abfd, bfd_object)) {
        std::cerr << "File format not recognized as an object file.\n";
        return;
    }

    // Iterate over sections
    for (asection *section = abfd->sections; section != nullptr; section = section->next) {
        if (!(section->flags & SEC_CODE)) {
            continue; // Skip non-code sections
        }

        bfd_size_type size = section->size;
        std::vector<unsigned char> buffer(size);

        // Read section contents
        if (!bfd_get_section_contents(abfd, section, buffer.data(), 0, size)) {
            std::cerr << "Failed to read section contents.\n";
            continue;
        }

        // Scan for syscalls
        size_t syscall_count = 0;
        for (bfd_size_type i = 0; i < size - 2; ++i) {
            if (buffer[i] == 0xCD && buffer[i + 1] == 0x80) { // int 0x80
                ++syscall_count;
            }
            if (buffer[i] == 0x0F && buffer[i + 1] == 0x05) { // syscall
                ++syscall_count;
            }
        }

        std::cout << "Section: " << section->name << " - Syscall count: " << syscall_count << "\n";
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <binary>\n";
        return 1;
    }

    const char *filename = argv[1];
    bfd_init();

    bfd *abfd = bfd_openr(filename, nullptr);
    if (abfd == nullptr) {
        std::cerr << "Failed to open binary: " << bfd_errmsg(bfd_get_error()) << "\n";
        return 1;
    }

    count_syscalls(abfd);

    bfd_close(abfd);
    return 0;
}
