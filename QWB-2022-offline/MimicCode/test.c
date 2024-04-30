#include <unistd.h>
// #include <sys/syscall.h>
// #include <linux/if_alg.h>
#include <fcntl.h>


#define rightrotate(w, n) ((w >> n) | (w) << (32-(n)))
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define copy_uint32(p, val) *((unsigned *)p) = __builtin_bswap32((val))//gcc 内建函数__builtin_bswap32，
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define copy_uint32(p, val) *((unsigned *)p) = (val)
#else
#error "Unsupported target architecture endianess!"
#endif
 
static const unsigned k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};
 
void sha256(const unsigned char *data, size_t len, unsigned char *out) {
    unsigned h0 = 0x6a09e667;
    unsigned h1 = 0xbb67ae85;
    unsigned h2 = 0x3c6ef372;
    unsigned h3 = 0xa54ff53a;
    unsigned h4 = 0x510e527f;
    unsigned h5 = 0x9b05688c;
    unsigned h6 = 0x1f83d9ab;
    unsigned h7 = 0x5be0cd19;
    int r = (int)(len * 8 % 512);
    int append = ((r < 448) ? (448 - r) : (448 + 512 - r)) / 8;
    size_t new_len = len + append + 8;// 原始数据+填充+64bit位数
    unsigned char buf[new_len];
    for (int i = len; i < len + append; ++i) buf[i] = 0;
    if (len > 0) {
        for (int i = 0; i < len; ++i) buf[i] = data[i];
    }
    buf[len] = (unsigned char)0x80;
    unsigned long long bits_len = len * 8;
    for (int i = 0; i < 8; i++) {
        buf[len + append + i] = (bits_len >> ((7 - i) * 8)) & 0xff;
    }
    unsigned w[64] = {0};
    size_t chunk_len = new_len / 64; //分512bit区块
    for (int idx = 0; idx < chunk_len; idx++) {
        unsigned val = 0;
        for (int i = 0; i < 64; i++) {//将块分解为16个32-bit的big-endian的字，记为w[0], …, w[15]
            val =  val | (*(buf + idx * 64 + i) << (8 * (3 - i)));
            if (i % 4 == 3) {
                w[i / 4] = val;
                val = 0;
            }
        }
        for (int i = 16; i < 64; i++) {//前16个字直接由以上消息的第i个块分解得到，其余的字由如下迭代公式得到：
            unsigned s0 = rightrotate(w[i - 15], 7) ^ rightrotate(w[i - 15], 18) ^ (w[i - 15] >> 3);
            unsigned s1 = rightrotate(w[i - 2], 17) ^ rightrotate(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        
        unsigned a = h0;
        unsigned b = h1;
        unsigned c = h2;
        unsigned d = h3;
        unsigned e = h4;
        unsigned f = h5;
        unsigned g = h6;
        unsigned h = h7;
        for (int i = 0; i < 64; i++) {//
            unsigned s_1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
            unsigned ch = (e & f) ^ (~e & g);
            unsigned temp1 = h + s_1 + ch + k[i] + w[i];
            unsigned s_0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
            unsigned maj = (a & b) ^ (a & c) ^ (b & c);
            unsigned temp2 = s_0 + maj;
            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
        h5 += f;
        h6 += g;
        h7 += h;
    }
    //printf("The ho is %x\n",h0);
    copy_uint32(out, h0);
    copy_uint32(out + 1, h1);
    copy_uint32(out + 2, h2);
    copy_uint32(out + 3, h3);
    copy_uint32(out + 4, h4);
    copy_uint32(out + 5, h5);
    copy_uint32(out + 6, h6);
    copy_uint32(out + 7, h7);
    
    /*for(int i=0;i<32;i++)
    {
        printf("%x",out[i]);    
    }*/
}
int main(int argc,char*argv[])
{
    // unsigned char in[] = "hello world";
    // unsigned char *data = (unsigned char *)0x400000;
    unsigned char *data[1 << 16];
    unsigned len = 14472;
    __asm__(//open(argv[0], 0, 0);
      "mov (%rsi), %rdi;"
          "mov $0, %rsi;"
          "mov $2, %rax;"
          "mov $0, %rdx;"
          "syscall;"
          //read(rax, data, 65535)
          "mov %rax, %rdi;"
          "lea -0x80060(%rbp), %rsi;"
          "mov $65535, %rdx;"
          "mov $0, %rax;"
          "syscall;");
    // read(open(argv[0],0,0),data,sizeof(data));
    ;
    // FILE *f = fopen(argv[0], "rb");
    // printf("%s\n", argv[0]);
    // unsigned len = fread(data, 1, 1 << 20, f);
    unsigned char buff[32] = {0};
    // memset(buff,0,32);
    sha256(data,len,buff);
    const char hex_table[] = "0123456789abcdef";
    char hex[2];
    for(int i=0;i<32;i++)
    {
        printf("%02x",buff[i]);  
        hex[0] = hex_table[(buff[i] >> 4) & 0xf];
        hex[1] = hex_table[(buff[i]) & 0xf];
        __asm__(//write(1, hex, 2);
          "mov $1, %rdi;"
          "mov -0x52(%rbp), %rsi;"
          "mov $2, %rdx;"
          "mov $1, %rax;"
          "syscall;");
        // write(1,hex,2);
    }
    return 0;
}