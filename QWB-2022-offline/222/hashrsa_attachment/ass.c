#include <unistd.h>
// #include <sys/syscall.h>
// #include <linux/if_alg.h>
#include <fcntl.h>

int main(int argc, char *argv[]){
	unsigned char *data[1 << 16];
	unsigned len = 14472;
	__asm__(//open(argv[0], 0, 0);
		  "mov (%rsi), %rdi;"
          "mov $2, %rsi;"
          "mov $2, %rax;"
          "mov $0, %rdx;"
          "syscall;"
          //read(3, data, 65535)
          "mov %rax, %rdi;"
          "mov data, %rsi;"
          "mov $65535, %rdx;"
          "mov $0, %rax;"
          "syscall;");

	return 0;
}