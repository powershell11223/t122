#define _GNU_SOURCE
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>

// 读取本地文件 a -> 内存加载执行
// 如果 a 是 ELF (7F 45 4C 46) : memfd_create + write + fexecve (无文件执行)
// 如果 a 是 shellcode 原始字节 : mmap(RW) -> memcpy -> mprotect(RX) -> 跳转执行
// 编译(Linux): g++ -O2 -Wall -o loader loader_a.cpp
// 用法:
//   ./loader            // 默认读 ./a
//   ./loader ./a arg1 arg2   // 读指定文件, 后面参数透传给它
//   ./loader ./shell.bin     // 非ELF按shellcode执行

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

static int my_memfd_create(const char *name) {
#ifdef SYS_memfd_create
    return (int)syscall(SYS_memfd_create, name, (unsigned int)MFD_CLOEXEC);
#else
    errno = ENOSYS;
    return -1;
#endif
}

int main(int argc, char *argv[], char *envp[]) {
    std::string path = (argc >= 2) ? argv[1] : "./a";

    // 1. 读取本地 a 文件到内存
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) {
        std::cerr << "[-] 打不开文件: " << path << " : " << strerror(errno) << std::endl;
        return 1;
    }
    std::streamsize size = f.tellg();
    f.seekg(0, std::ios::beg);
    if (size <= 0 || size > 64 * 1024 * 1024) {
        std::cerr << "[-] 文件大小异常: " << size << std::endl;
        return 1;
    }
    std::vector<char> data((size_t)size);
    if (!f.read(data.data(), size)) {
        std::cerr << "[-] 读取失败" << std::endl;
        return 1;
    }
    f.close();
    std::cout << "[*] 已读取 " << path << " " << data.size() << " 字节" << std::endl;

    // 2. 判断是不是 ELF
    bool is_elf = (data.size() > 4 &&
                   (unsigned char)data[0] == 0x7F &&
                   data[1] == 'E' && data[2] == 'L' && data[3] == 'F');

    if (is_elf) {
        // ---- ELF: memfd 内存加载执行 ----
        int mfd = my_memfd_create("mem_exec");
        if (mfd < 0) {
            perror("memfd_create(需Linux>=3.17)");
            return 1;
        }
        size_t off = 0;
        while (off < data.size()) {
            ssize_t w = write(mfd, data.data() + off, data.size() - off);
            if (w < 0) { perror("write memfd"); close(mfd); return 1; }
            off += (size_t)w;
        }
        std::cout << "[*] 已写入 memfd=" << mfd << ", fexecve 执行中..." << std::endl;

        // 构造新 argv: argv[0]=原文件名, 后面跟透传参数
        // ./loader ./a hello  -> 新程序 argv = {"./a", "hello"}
        std::vector<char*> new_argv;
        new_argv.push_back(const_cast<char*>(path.c_str()));
        for (int i = 2; i < argc; i++) new_argv.push_back(argv[i]);
        new_argv.push_back(nullptr);

        if (fexecve(mfd, new_argv.data(), envp) < 0) {
            perror("fexecve");
            close(mfd);
            return 1;
        }
        return 0; // fexecve 成功不会返回
    } else {
        // ---- shellcode: mmap 内存加载执行 ----
        std::cout << "[*] 非ELF, 按 shellcode 加载执行" << std::endl;
        long pagesz = sysconf(_SC_PAGESIZE);
        size_t alloc = ((data.size() + (size_t)pagesz - 1) / (size_t)pagesz) * (size_t)pagesz;

        void *mem = mmap(nullptr, alloc, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mem == MAP_FAILED) { perror("mmap"); return 1; }
        memcpy(mem, data.data(), data.size());

        if (mprotect(mem, alloc, PROT_READ | PROT_EXEC) != 0) {
            perror("mprotect");
            return 1;
        }
#if defined(__aarch64__) || defined(__arm__)
        __builtin___clear_cache((char*)mem, (char*)mem + alloc);
#endif
        std::cout << "[*] shellcode @ " << mem << ", 跳转执行..." << std::endl;
        using fn_t = void(*)();
        fn_t fn = reinterpret_cast<fn_t>(mem);
        fn();
        std::cout << "[+] shellcode 返回" << std::endl;
        munmap(mem, alloc);
        return 0;
    }
}
