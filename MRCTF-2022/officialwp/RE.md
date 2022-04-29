# MRCTF Reverse 部分wp
[toc]
## llvmvm
### 1.设计思路
- 该题目使用了llvm进行混淆，首先经过了控制流平坦化，然后是虚拟化pass。虚拟化pass是能够将llvm的ir转化成opcode并运行在专用的虚拟机上。目前项目处于初级阶段，甚至还不支持struct语句。然后还有一点数据流混淆。
- 这题确实出的太过于复杂了，orz，出题人在此谢罪。
### 2.解题
加密的过程如下。首先对密钥进行了扩展，然后与flag进行异或，以及同时将flag字符的bit进行反转，然后是一个小众加密：treyfer，最后则是一个超递增背包问题，可以考虑直接四个字节爆破，得出原来的数据即可。
```cpp=

#include<cstdio>
#include<cstring>
#include<ctime>
#include<cstdlib>
#define uint64_t unsigned long long
#define uint32_t unsigned int
#define uint8_t unsigned char
#define R8(a,b) (((a) >> (b)) | ((a) << (8 - (b))))
#define R32(a,b) (((a) >> (b)) | ((a) << (32 - (b))))
//MRCTF{s@1Sa2O_w1tH_bE5t_1lVmvM!}
void __attribute((__annotate__(("virtualization")))) function1(uint32_t out[16],uint32_t in[16])
{
    int i;
    uint32_t x[16];
    for(i=0;i<16;++i) x[i]=in[i];
    for(i=20;i>0;i-=2) 
    {
        x[4] ^= R32(x[ 0]+x[12], 7);  x[ 8] ^= R32(x[ 4]+x[ 0], 9);
        x[12] ^= R32(x[ 8]+x[ 4],13);  x[ 0] ^= R32(x[12]+x[ 8],18);
        x[ 9] ^= R32(x[ 5]+x[ 1], 7);  x[13] ^= R32(x[ 9]+x[ 5], 9);
        x[ 1] ^= R32(x[13]+x[ 9],13);  x[ 5] ^= R32(x[ 1]+x[13],18);
        x[14] ^= R32(x[10]+x[ 6], 7);  x[ 2] ^= R32(x[14]+x[10], 9);
        x[ 6] ^= R32(x[ 2]+x[14],13);  x[10] ^= R32(x[ 6]+x[ 2],18);
        x[ 3] ^= R32(x[15]+x[11], 7);  x[ 7] ^= R32(x[ 3]+x[15], 9);
        x[11] ^= R32(x[ 7]+x[ 3],13);  x[15] ^= R32(x[11]+x[ 7],18);
        x[ 1] ^= R32(x[ 0]+x[ 3], 7);  x[ 2] ^= R32(x[ 1]+x[ 0], 9);
        x[ 3] ^= R32(x[ 2]+x[ 1],13);  x[ 0] ^= R32(x[ 3]+x[ 2],18);
        x[ 6] ^= R32(x[ 5]+x[ 4], 7);  x[ 7] ^= R32(x[ 6]+x[ 5], 9);
        x[ 4] ^= R32(x[ 7]+x[ 6],13);  x[ 5] ^= R32(x[ 4]+x[ 7],18);
        x[11] ^= R32(x[10]+x[ 9], 7);  x[ 8] ^= R32(x[11]+x[10], 9);
        x[ 9] ^= R32(x[ 8]+x[11],13);  x[10] ^= R32(x[ 9]+x[ 8],18);
        x[12] ^= R32(x[15]+x[14], 7);  x[13] ^= R32(x[12]+x[15], 9);
        x[14] ^= R32(x[13]+x[12],13);  x[15] ^= R32(x[14]+x[13],18);
    }
    for(i=0;i<16;++i) out[i]=x[i]+in[i]; 
}
uint8_t Sbox[256] = { 
  0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 
  0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 
  0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 
  0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75, 
  0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 
  0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 
  0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 
  0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 
  0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73, 
  0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 
  0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 
  0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 
  0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 
  0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 
  0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, 
  0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16 
}; 

uint64_t mod=651381602689;
uint64_t weights[32]={0xff089a41d,0x1980dc39c8,0x3fc2269074,0x75f3fa8b3d,0x576eb22432,0x1a6421561c,0x24d7b9081b,0x533fc4a5e1,0x153661e0b3,0x1a7c3a1d49,0x38288fc1cb,0x6d2103fc5d,0x4c28fc14e4,0x8ec1a5941d,0x15133608e,0x93eb8e2c2b,0x214b1faff,0x42963f5fe,0x966bd3cfd2,0x91fe2d9eea,0x8c52fcc453,0x842cb6965e,0x70b00eb33b,0x53471182a0,0xbb4a90486,0x1a996d9045,0x3202bf9951,0x5414f58e85,0xd50711c50,0x16f3e1f0aa,0x3f97942b2,0x925efe2144};
uint64_t sums[8]={0xa5f92d71d,0x6e6fe0b52d,0x6d46f80380,0x6151bf4384,0x38e637169f,0x92b95b6ea4,0x1a6151e274,0x3d89d4ce37};
bool __attribute((__annotate__(("virtualization")))) function2(uint8_t *key,uint8_t *text)
{
    for(int i=0;i<16;i++)
        key[i]=R8(key[i]^(i+3),i%8);
    uint32_t a=*((uint32_t*)&key[0]),b=*((uint32_t*)&key[4]),c=*((uint32_t*)&key[8]),d=*((uint32_t*)&key[12]);
    uint32_t key_stream[16],tmp[16];
    for(int i=0;i<4;i++)
    {
        a=((b*c)&0xdeadbfef)+(a<<3)+(d>>29);
        b=((c*d)&0xdefdbeef)+(b<<7)+(a>>25);
        c=((d*a)&0xdfadbeef)+(c<<9)+(b>>23);
        d=((a*b)&0xdeadbeff)+(d<<1)+(c>>31);
        key_stream[4*i]=d+0xdeadbeef;
        key_stream[4*i+1]=c+0xaa114514;
        key_stream[4*i+2]=a+0xf1919810;
        key_stream[4*i+3]=b+0x1abcdef1;
    }
    for(int i=0;i<32;i++)
    {
        uint8_t c=text[i]; 
        c=((c&0xaa)>>1)|((c&0x55)<<1);
        c=((c&0xcc)>>2)|((c&0x33)<<2);
        c=((c&0xf0)>>4)|((c&0x0f)<<4);
        text[i]=c;
        for(int j=0;j<32;j++)
            text[j]^=R32(key_stream[j%16],j)&0xff;
        function1(tmp,key_stream);
        for(int j=0;j<16;j++)
            key_stream[j]=tmp[j];
    }
    for(int x=0;x<4;x++)
    {
        uint8_t t=text[8*x];

        for(int y=0;y<100;y++)
        {
            for(int i=0;i<8;i++) 
            {
                t=t+(key[2*i]^key[2*i+1]);
                t=Sbox[t]+text[8*x+(i+1)%8];
                t=(t<<1) | (t>>7);
                text[8*x+(i+1)%8]=t;
            }

        }
    }
    
    uint32_t *ptr=(uint32_t *)text;
    for(int i=0;i<8;i++)
    {
        uint64_t v=0;
        for(int j=0;j<32;j++)
        {
            int b=(ptr[i]>>j)&1;
            v+=weights[j]*b;
            v%=mod;
        }
        if(v!=sums[i])
            return false;
    }
    return true;
	
}

int main()
{
    uint8_t key[]="ezkeyforcipher!!",flag[33];
    printf("Flag: "); 
    scanf("%s",flag);
    if(strlen((char*)flag)!=32)
    {
        printf("Fail!\n");
        return 0;
    }
    if(function2(key,flag))
        printf("Success!\n"); 
    else
        printf("Fail!\n");
    return 0;
}

```
然后可以反向写出解密过程，将密钥流给提起计算出来，然后反向应用到解密的过程中去，即可解出flag。
```cpp=
#include<cstdio>
#include<cstdlib>
#include<ctime>
#define uint64_t unsigned long long
#define uint32_t unsigned int
#define uint8_t unsigned char
#define R8(a,b) (((a) >> (b)) | ((a) << (8 - (b))))
#define R32(a,b) (((a) >> (b)) | ((a) << (32 - (b))))
uint8_t Sbox[256] = { 
  0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 
  0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 
  0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 
  0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75, 
  0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 
  0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 
  0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 
  0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 
  0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73, 
  0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 
  0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 
  0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 
  0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 
  0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 
  0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, 
  0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16 
}; 
void __attribute((__annotate__(("virtualization")))) function1(uint32_t out[16],uint32_t in[16])
{
    int i;
    uint32_t x[16];
    for(i=0;i<16;++i) x[i]=in[i];
    for(i=20;i>0;i-=2) 
    {
        x[4] ^= R32(x[ 0]+x[12], 7);  x[ 8] ^= R32(x[ 4]+x[ 0], 9);
        x[12] ^= R32(x[ 8]+x[ 4],13);  x[ 0] ^= R32(x[12]+x[ 8],18);
        x[ 9] ^= R32(x[ 5]+x[ 1], 7);  x[13] ^= R32(x[ 9]+x[ 5], 9);
        x[ 1] ^= R32(x[13]+x[ 9],13);  x[ 5] ^= R32(x[ 1]+x[13],18);
        x[14] ^= R32(x[10]+x[ 6], 7);  x[ 2] ^= R32(x[14]+x[10], 9);
        x[ 6] ^= R32(x[ 2]+x[14],13);  x[10] ^= R32(x[ 6]+x[ 2],18);
        x[ 3] ^= R32(x[15]+x[11], 7);  x[ 7] ^= R32(x[ 3]+x[15], 9);
        x[11] ^= R32(x[ 7]+x[ 3],13);  x[15] ^= R32(x[11]+x[ 7],18);
        x[ 1] ^= R32(x[ 0]+x[ 3], 7);  x[ 2] ^= R32(x[ 1]+x[ 0], 9);
        x[ 3] ^= R32(x[ 2]+x[ 1],13);  x[ 0] ^= R32(x[ 3]+x[ 2],18);
        x[ 6] ^= R32(x[ 5]+x[ 4], 7);  x[ 7] ^= R32(x[ 6]+x[ 5], 9);
        x[ 4] ^= R32(x[ 7]+x[ 6],13);  x[ 5] ^= R32(x[ 4]+x[ 7],18);
        x[11] ^= R32(x[10]+x[ 9], 7);  x[ 8] ^= R32(x[11]+x[10], 9);
        x[ 9] ^= R32(x[ 8]+x[11],13);  x[10] ^= R32(x[ 9]+x[ 8],18);
        x[12] ^= R32(x[15]+x[14], 7);  x[13] ^= R32(x[12]+x[15], 9);
        x[14] ^= R32(x[13]+x[12],13);  x[15] ^= R32(x[14]+x[13],18);
    }
    for(i=0;i<16;++i) out[i]=x[i]+in[i]; 
}
void decode(uint8_t *key,uint8_t *text)
{
	for(int i=0;i<16;i++)
        key[i]=R8(key[i]^(i+3),i%8);
    uint32_t a=*((uint32_t*)&key[0]),b=*((uint32_t*)&key[4]),c=*((uint32_t*)&key[8]),d=*((uint32_t*)&key[12]);
    uint32_t key_stream[16],tmp[16],history[32][16];
    for(int i=0;i<4;i++)
    {
        a=((b*c)&0xdeadbfef)+(a<<3)+(d>>29);
        b=((c*d)&0xdefdbeef)+(b<<7)+(a>>25);
        c=((d*a)&0xdfadbeef)+(c<<9)+(b>>23);
        d=((a*b)&0xdeadbeff)+(d<<1)+(c>>31);
        key_stream[4*i]=d+0xdeadbeef;
        key_stream[4*i+1]=c+0xaa114514;
        key_stream[4*i+2]=a+0xf1919810;
        key_stream[4*i+3]=b+0x1abcdef1;
    }
    for(int i=0;i<32;i++)
	{
		for(int j=0;j<16;j++)
			history[i][j]=key_stream[j];
		function1(tmp,key_stream);
		for(int j=0;j<16;j++)
			key_stream[j]=tmp[j];
	}
	
    for(int x=0;x<4;x++)
    {
    	uint8_t *data=&(text[8*x]);
    	for(int y=0;y<100;y++)
        {
        	for (int i=7;i>=0;i--)
	        {
	        	uint8_t top,bottom;
	            top=data[i]+(key[2*i]^key[2*i+1]);
	            top=Sbox[top];
	            bottom=data[(i+1)%8];
	            bottom=(bottom>>1) | (bottom<<7);
	            data[(i+1)%8]=bottom-top;
	        }
        }
	}
	for(int i=31;i>=0;i--)
    {
    	for(int j=0;j<32;j++)
			text[j]^=R32(history[i][j%16],j)&0xff;
    	uint8_t c=text[i]; 
		c=((c&0xaa)>>1)|((c&0x55)<<1);
		c=((c&0xcc)>>2)|((c&0x33)<<2);
		c=((c&0xf0)>>4)|((c&0x0f)<<4);
		text[i]=c;
	}
	
}
uint64_t mod=651381602689;
uint64_t weights[32]={0xff089a41d,0x1980dc39c8,0x3fc2269074,0x75f3fa8b3d,0x576eb22432,0x1a6421561c,0x24d7b9081b,0x533fc4a5e1,0x153661e0b3,0x1a7c3a1d49,0x38288fc1cb,0x6d2103fc5d,0x4c28fc14e4,0x8ec1a5941d,0x15133608e,0x93eb8e2c2b,0x214b1faff,0x42963f5fe,0x966bd3cfd2,0x91fe2d9eea,0x8c52fcc453,0x842cb6965e,0x70b00eb33b,0x53471182a0,0xbb4a90486,0x1a996d9045,0x3202bf9951,0x5414f58e85,0xd50711c50,0x16f3e1f0aa,0x3f97942b2,0x925efe2144};
uint64_t sums[8]={0xa5f92d71d,0x6e6fe0b52d,0x6d46f80380,0x6151bf4384,0x38e637169f,0x92b95b6ea4,0x1a6151e274,0x3d89d4ce37};
void find(int idx)                  //用于爆破出原来的flag字节数组。
{   
	printf("\nnow: %d\n",idx);
	int ok=0;
	for(unsigned long long val=0;val<=0xffffffff;val++)
	{
		if(val%0xfffffff==0)
		{
			printf("%x\n",val);
		}
			
		unsigned long long v=0;
		for(int j=0;j<32;j++)
		{
			int b=(val>>j)&1;
			v+=weights[j]*b;
			v%=mod;
		}
		if(v==sums[idx])
		{
			printf("%lld\n",val);
		}
	}
	return;
}
//MRCTF{s@1Sa2O_w1tH_bE5t_1lVmvM!}
int main()
{
    //该处的flag数组由上面的函数爆破而出
	uint8_t key[]="ezkeyforcipher!!",flag[33]={0x8d,0xb3,0x9d,0xdd,0xe5,0xa6,0x44,0xdd,0x16,0x49,0x8f,0xe0,0x57,0xaa,0xb0,0x1c,0x24,0x86,0x6b,0x18,0xb4,0xe0,0xec,0xb0,0x64,0xe,0xac,0xe8,0x68,0x96,0x9c,0x67};
	//generate_bag(flag);
	puts("");
	for(int i=0;i<8;i++)
		find(i);
	decode(key,flag);
	for(int i=0;i<32;i++)
		printf("%c",flag[i]);
	puts("");
	return 0;
}

```
- 后记：关于分析这个最外层的数据流混淆，其实有非常明显的特征，甚至将f5结果抄出来，然后用o2优化编译一遍就能去掉。然后就是关于虚拟机的分析问题，这里放出虚拟机的生成日志文件，相关源码稍后会在github放出。
https://pan.baidu.com/s/1t_PMpfYiPEkH6VJLjYHU8g?pwd=ce93

## weird_vim
生成题目文件的源码https://github.com/veltavid/MRCTF2022/tree/main/weird_calc
题目给的文件重要的地方有两个部分。这部分代表的是VIM图灵机运行结束后纸带的数据，即密文。

![image-20220321112638908](https://s2.loli.net/2022/03/31/jMXE3CZTROyV4eW.png)

第二个重要的地方是加密过程对应的一系列状态转移，头铁的dalao可以强行分析。简单一些的方法是写一个解析状态转移并模拟执行的脚本。

![image-20220321112902330](https://s2.loli.net/2022/03/31/GEAkd46zFaorJ12.png)

通过vim turing machine项目中的vim_machine.py和vim_constant.py两个文件就能明白一条状态转移是如何构造出来的，从而解析出对应的previous state，previous character，next state，next character和direction。然后写一个图灵机模拟器来康康这些状态转移到底干了啥，输入可以随机生成。

![simulator](https://s2.loli.net/2022/03/31/wIgnNyvFmdSEhl2.gif)

多看一会儿可以大概看出加密以4字节为单位，先将4字节明文拷贝到纸带的最后，然后将其左移5位，最后与原本的4字节异或。

simulator（需在linux下运行）

```python
import re
import random
import time
import curses
import sys

def parse_state_trans(state_trans,state_map,context):
	direction=0
	output_fmt="char:{}->{}	cursor:{}->{}\n"
	re_rule='^_(.*)-(.):`k\"_C(.*)\x1b`t"_cw(.)\x1b([`tWmt|`tBmt]*)`ny\\$@\"$'
	(prev_state, prev_char, next_state, next_char, direct_cmd)=[s for s in re.search(re_rule,state_trans).groups()]
	if(direct_cmd=="`tWmt"): # parse tape direction
		direction=1
	elif(direct_cmd=="`tBmt"):
		direction=-1

	if(not state_map.get(prev_state)):
		state_map[prev_state]={}
	state_map[prev_state][prev_char]=(next_state, next_char, direction)
	result=''
	while(True):
		state,cursor,tape=context
		if(state==prev_state and tape[cursor]==prev_char):
			tape[cursor]=next_char
			context[1]=cursor+direction
			context[0]=next_state
			if(cursor+direction==len(tape)):
				tape.append('X')
			result+=output_fmt.format(prev_char,next_char,cursor,cursor+direction)
			if(next_state in state_map):
				next_info=state_map[next_state].get(tape[cursor+direction])
				if(next_info):
					prev_state=next_state
					prev_char=tape[cursor+direction]
					next_state=next_info[0]
					next_char=next_info[1]
					direction=next_info[2]
					continue
		break
	
	return result

def show_tape(win,cursor,tape):
	tape_str="".join(tape)
	win.addstr(0,0,tape_str[:cursor],curses.color_pair(1))
	win.addstr(cursor//32,cursor%32,tape_str[cursor],curses.color_pair(2))
	win.addstr((cursor+1)//32,(cursor+1)%32,tape_str[cursor+1:],curses.color_pair(1))
	time.sleep(0.1)
	win.refresh()

def init_curses():
	stdscr = curses.initscr()
	curses.start_color()
	curses.use_default_colors()
	curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLACK)
	curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)
	curses.noecho()
	win = curses.newwin(10, 32, 0, 0)
	return win,stdscr

def fini_curses(stdscr):
	curses.nocbreak()
	stdscr.keypad(0)
	curses.echo()
	curses.endwin()

def main():
	if_show=False
	if(len(sys.argv)>1 and sys.argv[1]=="show"):
		if_show=True

	win,stdscr=init_curses()
	context=["InitialState",0,[str(random.randint(0,1)) for i in range(160)]]
	state_map={}
	with open("./machine.vim",'r') as fd:
		lines=fd.read().split("# State transitions\n")[-1].split('\n')

	with open("./output.txt",'w') as fd:
		fd.write(" ".join(context[2])+"\n")
		if(if_show):
			show_tape(win,context[1],context[2])
		for line in lines:
			if(line=="# End State transitions"):
				break
			result=parse_state_trans(line,state_map,context)
			if(result):
				fd.write(result)
				fd.write(" ".join(context[2])+"\n")
				if(if_show):
					show_tape(win,context[1],context[2])

	fini_curses(stdscr)

if __name__ == "__main__":
	main()
```

decrypt脚本

```python
def get_bit(x,idx):
	return (x&(1<<idx))>>idx

def leftshift_xor(x,s):
	result=x&((1<<s)-1)
	for i in range(s,32):
		result_i = get_bit(result,i-s) ^ get_bit(x,i);
		result += result_i << i;
	return result

def main():
	cipher="""1 1 0 1 1 0 0 0 1 1 0 0 1 1 1 0 0 1 0 1 1 1 1 0 1 1 0 1 0 1 1 1 1 0 1 1 1 0 0 1
0 0 0 1 1 1 1 1 0 0 0 1 1 0 0 0 1 0 1 1 1 1 1 1 1 1 1 0 1 0 1 0 0 1 1 1 1 1 1 0
0 1 0 1 1 1 1 1 0 0 0 0 0 0 1 1 1 1 0 1 0 0 1 1 1 1 0 1 1 1 1 1 0 1 0 0 1 1 0 0
0 0 1 0 0 0 1 0 1 1 1 0 1 0 1 0 0 1 0 1 0 1 1 0 0 1 1 0 1 1 1 1 0 1 1 0 1 0 1 0"""
	flag=""
	cipher=cipher.replace("\n",'').replace(" ",'')
	for i in range(0,len(cipher),32):
		result=leftshift_xor(int(cipher[i:i+32],2),5)
		for i in range(4):
			flag+=chr((result>>((3-i)*8))&0xff)
	print(flag[:-2]) # remove padding

if __name__ == "__main__":
	main()
```
## Cicada

### 1. 题目设计
- 该题目模仿了反射注入的过程，主动解密并反射加载了位于数据区的dll，所有的逻辑都在这个dll中。
- dll中存在着一个ast执行器，使用antlr将类c语法转化成ast结构，然后动态分配内存构造ast，然后编写了一系列函数执行了ast的语义，从而实现函数的加解密验证。
### 2. 解题
#### 解密dll
- 打开exe可以发现有一个system("titile ")的函数，交叉引用不难找到另一个函数。
![](https://md.buptmerak.cn/uploads/upload_0570db72d937663a1f1083cf9651ef34.png)
- 该函数即是dll的加载函数，首先是decode将数据异或解密，然后通过特征码找到反射dll的入口点，然后如果找到了则直接跳转到dll启动位置，进行dll的自加载。
![](https://md.buptmerak.cn/uploads/upload_68bea29684bd6bf5d2aa6ca0fa54ff66.png)
#### 获取ast树
- 直接定位到dllmain函数即可看到验证逻辑。可以发现程序要求输入了32个字符，并且限定必须是0-9a-f，然后两个字符一组转化成hex数据，即最后是16个byte。
![](https://md.buptmerak.cn/uploads/upload_bcbbdefc41c8035c2a5f532fb0bbc6fb.png)
- 然后发现验证的函数即sub_18000C160，我们甚至点不开他，所以只能看看汇编。
![](https://md.buptmerak.cn/uploads/upload_6897f06a922c51d00a439790c042c895.png)
- 首先是分配一些变量。
![](https://md.buptmerak.cn/uploads/upload_cd3251060e47ceac79ccb62051e1b11b.png)
- 然后将我们的输入写入到flag变量中去。
![](https://md.buptmerak.cn/uploads/upload_9cd44eb25bdd21b5aaecac4912a161fc.png)
- 然后就是一个非常庞大的语法树构造过程。分析一下语法树的结构。他是通过一个函数指针和若干个参数构成的，参数可以是另外一个函数的值也可以是变量也可以是常量，类型取决于type。
![](https://md.buptmerak.cn/uploads/upload_9166aa425459f3c8eca5f3ed8ffc382e.png)
- 然后我们只需要把涉及到的action函数分析一下即可，这里不做赘述，下面是存在的一些函数类型。
![](https://md.buptmerak.cn/uploads/upload_cc635f94229727c96d3f7c6b7c109aff.png)
- 然后我们根据ast树的起始地址，编写idapython脚本将ast树以一种简洁的方式表示出来。
```python=
import idaapi
import ida_funcs
def read_function(addr):
	return idaapi.get_qword(addr)
def read_arg_num(addr):
	return idaapi.get_qword(addr+8)
def get_parameter(addr,idx):
	arr=idaapi.get_qword(addr+16)
	return arr+idx*16
def get_parameter_type(addr):
	return idaapi.get_qword(addr)
def get_parameter_data(addr):
	return idaapi.get_qword(addr+8)

def dump_str(addr):
	str_len=0
	r=b''
	while True:
		c=idaapi.get_bytes(addr+str_len,1)
		if c[0]==0:
			break
		str_len+=1
		r+=int.to_bytes(c[0],1,byteorder='little')
	return r.decode()
    
def dump_ast(node_addr):
	ast=ida_funcs.get_func_name(read_function(node_addr))+'('
	num=read_arg_num(node_addr)
	for i in range(num):
		son=get_parameter(node_addr,i)
		type=get_parameter_type(son)
		if type==1:
			ast+=dump_ast(get_parameter_data(son))
		elif type==2:
			ast+=str(get_parameter_data(son))
		elif type==3:
			ast+='\"'+dump_str(get_parameter_data(son))+'\"'
		else:
			raise Exception("Unknown type")
		if i!=num-1:
			ast+=','
	ast+=')'
	return ast
print(dump_ast(ast_base))
```
- 成功获取到ast树，然后稍微将格式变得好看一点。
![](https://md.buptmerak.cn/uploads/upload_016ba5ffb03f6472b5d81c0f526df2d9.png)
- 大概就是这样一个加密过程。然后最后面一大堆东西是一个验证函数，如果对了就把r变量赋值为114514，否则是1919810。
```C=
unsigned long long i,j,a[4],b[16],flag[16]={0xa3,0xbc,0xdb,0xcb,0x2d,0xce,0x48,0xb4,0x86,0xf9,0xd6,0xce,0xad,0x13,0x7b,0xd1};
i=0;
j=0;
while(i<4)
{
	while(j<4)
	{
		a[i]=((a[i]<<8)|flag[4*i+j]);
		j=j+1;
	}
	j=0;
	i=i+1;
}
i=0;
while(i<4)
{
    a[i]=a[i]^((a[i]<<3)&4294967295)^i;
    i=i+1;
}
i=0;
while(i<4)
{
    b[4*i]=a[i]&255;
    b[4*i+1]=(a[i]>>8)&255;
    b[4*i+2]=(a[i]>>16)&255;
    b[4*i+3]=(a[i]>>24)&255;
    i=i+1;
}
```
#### 分析验证逻辑
- 加密部分已经弄清楚了，接下来分析一下后面那一堆东西是啥，不难发现全是加法和乘法，最后进行比较，可以猜测就是个解方程之类的。直接用z3解一下试试。
```python=
def getVar(a,b):
	return a+'['+b+']'
def getNumber(a):
	return str(a)
def mul(a,b):
	return a+'*'+b
def add(a,b):
	return a+'+'+b
def eq(a,b):
	return a+'=='+b
def ands(a,b):
	ll=[]
	if type(a)==list:
		for s in a:
			ll.append(s)
	else:
		ll.append(a)
	if type(b)==list:
		for s in b:
			ll.append(s)
	else:
		ll.append(b)
	return ll
constraints=ands(eq(add(add(add(add(add(add(add(add(add(add(add(add(add(add(add(mul(getNumber(165),getVar("b",getNumber(0))),mul(getNumber(206),getVar("b",getNumber(1)))),mul(getNumber(184),getVar("b",getNumber(2)))),mul(getNumber(188),getVar("b",getNumber(3)))),mul(getNumber(153),getVar("b",getNumber(4)))),mul(getNumber(183),getVar("b",getNumber(5)))),mul(getNumber(233),getVar("b",getNumber(6)))),mul(getNumber(160),getVar("b",getNumber(7)))),mul(getNumber(193),getVar("b",getNumber(8)))),mul(getNumber(255),getVar("b",getNumber(9)))),mul(getNumber(20),getVar("b",getNumber(10)))),mul(getNumber(92),getVar("b",getNumber(11)))),mul(getNumber(34),getVar("b",getNumber(12)))),mul(getNumber(102),getVar("b",getNumber(13)))),mul(getNumber(133),getVar("b",getNumber(14)))),mul(getNumber(81),getVar("b",getNumber(15)))),getNumber(269764)),ands(eq(add(add(add(add(add(add(add(add(add(add(add(add(add(add(add(mul(getNumber(160),getVar("b",getNumber(0))),mul(getNumber(12),getVar("b",getNumber(1)))),mul(getNumber(112),getVar("b",getNumber(2)))),mul(getNumber(62),getVar("b",getNumber(3)))),mul(getNumber(22),getVar("b",getNumber(4)))),mul(getNumber(52),getVar("b",getNumber(5)))),mul(getNumber(154),getVar("b",getNumber(6)))),mul(getNumber(28),getVar("b",getNumber(7)))),mul(getNumber(166),getVar("b",getNumber(8)))),mul(getNumber(71),getVar("b",getNumber(9)))),mul(getNumber(86),getVar("b",getNumber(10)))),mul(getNumber(70),getVar("b",getNumber(11)))),mul(getNumber(78),getVar("b",getNumber(12)))),mul(getNumber(28),getVar("b",getNumber(13)))),mul(getNumber(179),getVar("b",getNumber(14)))),mul(getNumber(221),getVar("b",getNumber(15)))),getNumber(212071)),ands(eq(add(add(add(add(add(add(add(add(add(add(add(add(add(add(add(mul(getNumber(188),getVar("b",getNumber(0))),mul(getNumber(118),getVar("b",getNumber(1)))),mul(getNumber(244),getVar("b",getNumber(2)))),mul(getNumber(107),getVar("b",getNumber(3)))),mul(getNumber(100),getVar("b",getNumber(4)))),mul(getNumber(206),getVar("b",getNumber(5)))),mul(getNumber(64),getVar("b",getNumber(6)))),mul(getNumber(198),getVar("b",getNumber(7)))),mul(getNumber(207),getVar("b",getNumber(8)))),mul(getNumber(83),getVar("b",getNumber(9)))),mul(getNumber(155),getVar("b",getNumber(10)))),mul(getNumber(56),getVar("b",getNumber(11)))),mul(getNumber(54),getVar("b",getNumber(12)))),mul(getNumber(48),getVar("b",getNumber(13)))),mul(getNumber(21),getVar("b",getNumber(14)))),mul(getNumber(220),getVar("b",getNumber(15)))),getNumber(224889)),ands(eq(add(add(add(add(add(add(add(add(add(add(add(add(add(add(add(mul(getNumber(79),getVar("b",getNumber(0))),mul(getNumber(13),getVar("b",getNumber(1)))),mul(getNumber(65),getVar("b",getNumber(2)))),mul(getNumber(75),getVar("b",getNumber(3)))),mul(getNumber(103),getVar("b",getNumber(4)))),mul(getNumber(216),getVar("b",getNumber(5)))),mul(getNumber(233),getVar("b",getNumber(6)))),mul(getNumber(120),getVar("b",getNumber(7)))),mul(getNumber(177),getVar("b",getNumber(8)))),mul(getNumber(197),getVar("b",getNumber(9)))),mul(getNumber(0),getVar("b",getNumber(10)))),mul(getNumber(217),getVar("b",getNumber(11)))),mul(getNumber(222),getVar("b",getNumber(12)))),mul(getNumber(147),getVar("b",getNumber(13)))),mul(getNumber(216),getVar("b",getNumber(14)))),mul(getNumber(200),getVar("b",getNumber(15)))),getNumber(292201)),ands(eq(add(add(add(add(add(add(add(add(add(add(add(add(add(add(add(mul(getNumber(237),getVar("b",getNumber(0))),mul(getNumber(18),getVar("b",getNumber(1)))),mul(getNumber(150),getVar("b",getNumber(2)))),mul(getNumber(40),getVar("b",getNumber(3)))),mul(getNumber(69),getVar("b",getNumber(4)))),mul(getNumber(226),getVar("b",getNumber(5)))),mul(getNumber(226),getVar("b",getNumber(6)))),mul(getNumber(75),getVar("b",getNumber(7)))),mul(getNumber(1),getVar("b",getNumber(8)))),mul(getNumber(125),getVar("b",getNumber(9)))),mul(getNumber(227),getVar("b",getNumber(10)))),mul(getNumber(19),getVar("b",getNumber(11)))),mul(getNumber(139),getVar("b",getNumber(12)))),mul(getNumber(119),getVar("b",getNumber(13)))),mul(getNumber(106),getVar("b",getNumber(14)))),mul(getNumber(88),getVar("b",getNumber(15)))),getNumber(199862)),ands(eq(add(add(add(add(add(add(add(add(add(add(add(add(add(add(add(mul(getNumber(108),getVar("b",getNumber(0))),mul(getNumber(5),getVar("b",getNumber(1)))),mul(getNumber(109),getVar("b",getNumber(2)))),mul(getNumber(138),getVar("b",getNumber(3)))),mul(getNumber(98),getVar("b",getNumber(4)))),mul(getNumber(189),getVar("b",getNumber(5)))),mul(getNumber(184),getVar("b",getNumber(6)))),mul(getNumber(152),getVar("b",getNumber(7)))),mul(getNumber(179),getVar("b",getNumber(8)))),mul(getNumber(156),getVar("b",getNumber(9)))),mul(getNumber(223),getVar("b",getNumber(10)))),mul(getNumber(16),getVar("b",getNumber(11)))),mul(getNumber(194),getVar("b",getNumber(12)))),mul(getNumber(77),getVar("b",getNumber(13)))),mul(getNumber(119),getVar("b",getNumber(14)))),mul(getNumber(135),getVar("b",getNumber(15)))),getNumber(237891)),ands(eq(add(add(add(add(add(add(add(add(add(add(add(add(add(add(add(mul(getNumber(224),getVar("b",getNumber(0))),mul(getNumber(168),getVar("b",getNumber(1)))),mul(getNumber(133),getVar("b",getNumber(2)))),mul(getNumber(59),getVar("b",getNumber(3)))),mul(getNumber(100),getVar("b",getNumber(4)))),mul(getNumber(122),getVar("b",getNumber(5)))),mul(getNumber(55),getVar("b",getNumber(6)))),mul(getNumber(247),getVar("b",getNumber(7)))),mul(getNumber(254),getVar("b",getNumber(8)))),mul(getNumber(132),getVar("b",getNumber(9)))),mul(getNumber(210),getVar("b",getNumber(10)))),mul(getNumber(55),getVar("b",getNumber(11)))),mul(getNumber(72),getVar("b",getNumber(12)))),mul(getNumber(198),getVar("b",getNumber(13)))),mul(getNumber(236),getVar("b",getNumber(14)))),mul(getNumber(141),getVar("b",getNumber(15)))),getNumber(268255)),ands(eq(add(add(add(add(add(add(add(add(add(add(add(add(add(add(add(mul(getNumber(158),getVar("b",getNumber(0))),mul(getNumber(253),getVar("b",getNumber(1)))),mul(getNumber(219),getVar("b",getNumber(2)))),mul(getNumber(67),getVar("b",getNumber(3)))),mul(getNumber(48),getVar("b",getNumber(4)))),mul(getNumber(106),getVar("b",getNumber(5)))),mul(getNumber(109),getVar("b",getNumber(6)))),mul(getNumber(66),getVar("b",getNumber(7)))),mul(getNumber(85),getVar("b",getNumber(8)))),mul(getNumber(213),getVar("b",getNumber(9)))),mul(getNumber(218),getVar("b",getNumber(10)))),mul(getNumber(50),getVar("b",getNumber(11)))),mul(getNumber(35),getVar("b",getNumber(12)))),mul(getNumber(210),getVar("b",getNumber(13)))),mul(getNumber(246),getVar("b",getNumber(14)))),mul(getNumber(227),getVar("b",getNumber(15)))),getNumber(257474)),ands(eq(add(add(add(add(add(add(add(add(add(add(add(add(add(add(add(mul(getNumber(60),getVar("b",getNumber(0))),mul(getNumber(67),getVar("b",getNumber(1)))),mul(getNumber(171),getVar("b",getNumber(2)))),mul(getNumber(236),getVar("b",getNumber(3)))),mul(getNumber(234),getVar("b",getNumber(4)))),mul(getNumber(30),getVar("b",getNumber(5)))),mul(getNumber(167),getVar("b",getNumber(6)))),mul(getNumber(146),getVar("b",getNumber(7)))),mul(getNumber(111),getVar("b",getNumber(8)))),mul(getNumber(112),getVar("b",getNumber(9)))),mul(getNumber(82),getVar("b",getNumber(10)))),mul(getNumber(235),getVar("b",getNumber(11)))),mul(getNumber(150),getVar("b",getNumber(12)))),mul(getNumber(162),getVar("b",getNumber(13)))),mul(getNumber(3),getVar("b",getNumber(14)))),mul(getNumber(67),getVar("b",getNumber(15)))),getNumber(247429)),ands(eq(add(add(add(add(add(add(add(add(add(add(add(add(add(add(add(mul(getNumber(142),getVar("b",getNumber(0))),mul(getNumber(251),getVar("b",getNumber(1)))),mul(getNumber(115),getVar("b",getNumber(2)))),mul(getNumber(190),getVar("b",getNumber(3)))),mul(getNumber(248),getVar("b",getNumber(4)))),mul(getNumber(103),getVar("b",getNumber(5)))),mul(getNumber(114),getVar("b",getNumber(6)))),mul(getNumber(63),getVar("b",getNumber(7)))),mul(getNumber(63),getVar("b",getNumber(8)))),mul(getNumber(119),getVar("b",getNumber(9)))),mul(getNumber(216),getVar("b",getNumber(10)))),mul(getNumber(137),getVar("b",getNumber(11)))),mul(getNumber(40),getVar("b",getNumber(12)))),mul(getNumber(168),getVar("b",getNumber(13)))),mul(getNumber(191),getVar("b",getNumber(14)))),mul(getNumber(164),getVar("b",getNumber(15)))),getNumber(249780)),ands(eq(add(add(add(add(add(add(add(add(add(add(add(add(add(add(add(mul(getNumber(170),getVar("b",getNumber(0))),mul(getNumber(232),getVar("b",getNumber(1)))),mul(getNumber(239),getVar("b",getNumber(2)))),mul(getNumber(131),getVar("b",getNumber(3)))),mul(getNumber(255),getVar("b",getNumber(4)))),mul(getNumber(86),getVar("b",getNumber(5)))),mul(getNumber(154),getVar("b",getNumber(6)))),mul(getNumber(227),getVar("b",getNumber(7)))),mul(getNumber(251),getVar("b",getNumber(8)))),mul(getNumber(74),getVar("b",getNumber(9)))),mul(getNumber(74),getVar("b",getNumber(10)))),mul(getNumber(118),getVar("b",getNumber(11)))),mul(getNumber(157),getVar("b",getNumber(12)))),mul(getNumber(149),getVar("b",getNumber(13)))),mul(getNumber(23),getVar("b",getNumber(14)))),mul(getNumber(65),getVar("b",getNumber(15)))),getNumber(257080)),ands(eq(add(add(add(add(add(add(add(add(add(add(add(add(add(add(add(mul(getNumber(228),getVar("b",getNumber(0))),mul(getNumber(10),getVar("b",getNumber(1)))),mul(getNumber(29),getVar("b",getNumber(2)))),mul(getNumber(66),getVar("b",getNumber(3)))),mul(getNumber(227),getVar("b",getNumber(4)))),mul(getNumber(61),getVar("b",getNumber(5)))),mul(getNumber(45),getVar("b",getNumber(6)))),mul(getNumber(87),getVar("b",getNumber(7)))),mul(getNumber(24),getVar("b",getNumber(8)))),mul(getNumber(138),getVar("b",getNumber(9)))),mul(getNumber(195),getVar("b",getNumber(10)))),mul(getNumber(91),getVar("b",getNumber(11)))),mul(getNumber(250),getVar("b",getNumber(12)))),mul(getNumber(89),getVar("b",getNumber(13)))),mul(getNumber(56),getVar("b",getNumber(14)))),mul(getNumber(146),getVar("b",getNumber(15)))),getNumber(186720)),ands(eq(add(add(add(add(add(add(add(add(add(add(add(add(add(add(add(mul(getNumber(209),getVar("b",getNumber(0))),mul(getNumber(161),getVar("b",getNumber(1)))),mul(getNumber(57),getVar("b",getNumber(2)))),mul(getNumber(71),getVar("b",getNumber(3)))),mul(getNumber(202),getVar("b",getNumber(4)))),mul(getNumber(171),getVar("b",getNumber(5)))),mul(getNumber(120),getVar("b",getNumber(6)))),mul(getNumber(179),getVar("b",getNumber(7)))),mul(getNumber(75),getVar("b",getNumber(8)))),mul(getNumber(25),getVar("b",getNumber(9)))),mul(getNumber(161),getVar("b",getNumber(10)))),mul(getNumber(33),getVar("b",getNumber(11)))),mul(getNumber(132),getVar("b",getNumber(12)))),mul(getNumber(38),getVar("b",getNumber(13)))),mul(getNumber(144),getVar("b",getNumber(14)))),mul(getNumber(80),getVar("b",getNumber(15)))),getNumber(175856)),ands(eq(add(add(add(add(add(add(add(add(add(add(add(add(add(add(add(mul(getNumber(71),getVar("b",getNumber(0))),mul(getNumber(47),getVar("b",getNumber(1)))),mul(getNumber(193),getVar("b",getNumber(2)))),mul(getNumber(25),getVar("b",getNumber(3)))),mul(getNumber(25),getVar("b",getNumber(4)))),mul(getNumber(115),getVar("b",getNumber(5)))),mul(getNumber(8),getVar("b",getNumber(6)))),mul(getNumber(81),getVar("b",getNumber(7)))),mul(getNumber(137),getVar("b",getNumber(8)))),mul(getNumber(23),getVar("b",getNumber(9)))),mul(getNumber(130),getVar("b",getNumber(10)))),mul(getNumber(241),getVar("b",getNumber(11)))),mul(getNumber(192),getVar("b",getNumber(12)))),mul(getNumber(109),getVar("b",getNumber(13)))),mul(getNumber(203),getVar("b",getNumber(14)))),mul(getNumber(116),getVar("b",getNumber(15)))),getNumber(205239)),ands(eq(add(add(add(add(add(add(add(add(add(add(add(add(add(add(add(mul(getNumber(90),getVar("b",getNumber(0))),mul(getNumber(117),getVar("b",getNumber(1)))),mul(getNumber(113),getVar("b",getNumber(2)))),mul(getNumber(129),getVar("b",getNumber(3)))),mul(getNumber(116),getVar("b",getNumber(4)))),mul(getNumber(164),getVar("b",getNumber(5)))),mul(getNumber(169),getVar("b",getNumber(6)))),mul(getNumber(202),getVar("b",getNumber(7)))),mul(getNumber(6),getVar("b",getNumber(8)))),mul(getNumber(229),getVar("b",getNumber(9)))),mul(getNumber(65),getVar("b",getNumber(10)))),mul(getNumber(52),getVar("b",getNumber(11)))),mul(getNumber(116),getVar("b",getNumber(12)))),mul(getNumber(222),getVar("b",getNumber(13)))),mul(getNumber(214),getVar("b",getNumber(14)))),mul(getNumber(56),getVar("b",getNumber(15)))),getNumber(221466)),eq(add(add(add(add(add(add(add(add(add(add(add(add(add(add(add(mul(getNumber(95),getVar("b",getNumber(0))),mul(getNumber(116),getVar("b",getNumber(1)))),mul(getNumber(71),getVar("b",getNumber(2)))),mul(getNumber(137),getVar("b",getNumber(3)))),mul(getNumber(193),getVar("b",getNumber(4)))),mul(getNumber(145),getVar("b",getNumber(5)))),mul(getNumber(105),getVar("b",getNumber(6)))),mul(getNumber(247),getVar("b",getNumber(7)))),mul(getNumber(57),getVar("b",getNumber(8)))),mul(getNumber(36),getVar("b",getNumber(9)))),mul(getNumber(253),getVar("b",getNumber(10)))),mul(getNumber(147),getVar("b",getNumber(11)))),mul(getNumber(163),getVar("b",getNumber(12)))),mul(getNumber(106),getVar("b",getNumber(13)))),mul(getNumber(223),getVar("b",getNumber(14)))),mul(getNumber(20),getVar("b",getNumber(15)))),getNumber(209726)))))))))))))))))
from z3 import *
b=[Int('b['+str(x)+']') for x in range(16)]
s=Solver()
for c in constraints:
	s.add(eval(c))
s.check()
print(s.model())
```
- 成功接触最终数据，然后解密即可。
#### EXP
```C=
#include<cstdio>
#include<bitset>
using namespace std;
unsigned int rev_l3(unsigned int x)
{
	bitset<32> bit(x);
	for(int i=3;i<32;i++)
	{
		if(bit[i]==bit[i-3])
			bit[i]=0;
		else
			bit[i]=1;
	}
	return bit.to_ulong();
}
int main()
{
	unsigned char b[16];
	b[5] = 13;
	b[11] = 177;
	b[10] = 55;
	b[0] = 147;
	b[14] = 136;
	b[9] = 96;
	b[13] = 165;
	b[3] = 190;
	b[15] = 197;
	b[6] = 188;
	b[12] = 90;
	b[2] = 90;
	b[7] = 67;
	b[4] = 21;
	b[1] = 5;
	b[8] = 188; 
	unsigned int *a=(unsigned int *)b;
	for(int i=0;i<4;i++)
	{
		a[i]^=i;
		a[i]=rev_l3(a[i]);
	}
	for(int i=0;i<4;i++)
		printf("%02x%02x%02x%02x",(a[i]>>24)&255,(a[i]>>16)&255,(a[i]>>8)&255,a[i]&255);		
    return 0;
}


```
## Stuuuuub

开源地址：https://github.com/LLeavesG/MRCTF2022-Stuuuuub

### 1. 题目设计

基本考察点：

* Android一代壳
* Android 10 InMemoryClassLoader实现Dex不落地加载
* 双亲委派机制
* 二代函数抽取壳(ART模式)
* inlineHook
* ollvm
* 字符串加密恢复
* APK签名校验
* JNIFunction

### 2. 解题

#### 分析壳

JEB打开，发现dex已经经过混淆，找到StubApp类
![](https://md.buptmerak.cn/uploads/upload_d3d68f433883b29c0571d1c89cbb2520.png)


在该类中的attachBaseContext方法中，首先通过e.a方法判断，之后调用e.d方法返回一个classloader v0

```java=
if(e.a(arg1)) {
    ClassLoader v0 = e.d();
    StubApp.classLoader = v0;
    if(v0 != null) {
        StubApp.flag = 1;
        return;
    }
}
```

在该类的onCreate方法中，直接使用classLoader加载类MainActivity，而App启动顺序是先调用attachBaseContext，再调用onCreate方法

```java=
 if(StubApp.flag == 1) {
    try {
        Class v4 = StubApp.classLoader.loadClass("com.mrctf.android2022.MainActivity");
        this.startActivity(new Intent(this.getApplicationContext(), v4));
    }
    catch(ClassNotFoundException v3) {
        v3.printStackTrace();
    }

    return;
}
```

查看e.a实际上是进行了一系列架构、API以及ROOT权限的检测
![](https://md.buptmerak.cn/uploads/upload_df2d0d07a258e96c9db9b4e2e5e74298.png)


在e.d中进行了so的解密释放和dex的解密以及使用InMemoryClassLoader装载的过程
其中libnative.so释放时使用decodeSo进行了解密，而libc++_shared.so并未进行解密直接释放，dex直接异或49后加载
![](https://md.buptmerak.cn/uploads/upload_5070dc93099f3cf23f7489211e2ce7d4.png)


在e.d最后调用的e.g实际上是通过替换classloader来使得加载的Activity能被找到并且正常调用，因为ClassLoader加载的是一个Activity而不仅仅是一个类。这里涉及到Android的双亲委派机制，如下图所示，为考虑安全性，当类进行加载时首先向其父类的classloader进行查询这个类是否被加载过，如果加载过就不再加载，如果没加载过则再向上一级查，知道最上层，如果依旧没查到就向下逐级看看能否加载类，直到最底层。

这样做的好处：避免了类重复被加载，其次就是避免系统类被替换从而造成的安全问题。

![](https://md.buptmerak.cn/uploads/upload_1762611c6bf1996c13589932a65b44bf.png)


这里使用InMemoryClassLoader进行加载，向上找肯定没有找到其他的loader已经加载，那么最终还是会交给InMemoryClassLoader进行加载。问题就在这里，因为加载的是Activity，而负责Activity加载的ClassLoader是在程序启动时就已经被赋值的，即图中的mClassLoader（如下图所示），这个mClassLoader其实是PathClassLoader，PathClassLoader是DexClassLoader的父级，BootClassLoader又是PathClassLoader的父级。

![](https://md.buptmerak.cn/uploads/upload_bad6718e69c383ffc2c6343bb895c070.png)


每次加载组件时通过mClassLoader即PathClassLoader来加载，但是因为App在启动时这个类没有被加载进入PathClassLoader，所以后面就无法通过PathClassLoader找到此类，就需要替换mClassLoader为加载自定义类的ClassLoader。

![](https://md.buptmerak.cn/uploads/upload_3593d822d4ed2ac712be7353fce98213.png)


通过反射获取到android.app.LoadedApk类中的mClassLoader字段并进行修改
![](https://md.buptmerak.cn/uploads/upload_37bf008f54e5bcadc1460c36e5254112.png)



到此壳就分析完毕

#### 获取加密后的Dex和so

首先需要解密dex和so，dex很容易解密，直接拿出assets中的build.json逐字节异或49即可
so解密需要分析libstub.so查看decodeSo的实现
发现并没有直接将decodeSo导出，应该是使用动态注册的方式

大量字符串被加密
![](https://md.buptmerak.cn/uploads/upload_bd5d3717843ad295fdcd6267d8f04c04.png)


而这些解密函数都是在.init_array段，也就是会最开始执行
![](https://md.buptmerak.cn/uploads/upload_83497b7899e879836fbcfa95e5da7187.png)
![](https://md.buptmerak.cn/uploads/upload_a9ade2f82d9cb7d077ed556ae9e31a09.png)


此处有多种解法：

* 一种是直接启动APP在内存里找对应的so dump解密后的数据
* 一种是使用unicorn模拟so的执行，使其完成初始化后自动修补so

这里提供第二种做法的脚本,使用AndroidNativeEmu开源框架，或者使用其加强版ExAndroidNativeEmu

```python=
import logging
import sys

from unicorn import *
import struct
from androidemu.emulator import Emulator

# Configure logging
logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)7s %(name)34s | %(message)s"
)


dstr_datas = {}


def hook_mem_write(uc, type, address, size, value, userdata):
    try:
        curdata = struct.pack("I", value)[:size]
        dstr_datas[address] = curdata
    except:
        print(size)
    #print(curdata)


logger = logging.getLogger(__name__)

emulator = Emulator(vfp_inst_set=True, vfs_root="vfs")

# 设置内存的写入监控
emulator.mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)


# 后面的do_init为true就会调用.init_array
lib_module = emulator.load_library("libstub.so", do_init=True)

#emulator.call_symbol(lib_module, "JNI_OnLoad", emulator.java_vm.address_ptr, 0x0)

base_addr = lib_module.base

sofile = open("libstub.so", "rb")

sodata = sofile.read()
for address, v in dstr_datas.items():
    if address > base_addr and address < base_addr+lib_module.size:
        offset = address-base_addr-0x1000
        print("address:0x%x data:%s offset:0x%x" % (address, v, offset))
        sodata = sodata[:offset]+v+sodata[offset+len(v):]

savepath = "./libstub_new.so"
nfile = open(savepath, "wb")
nfile.write(sodata)
nfile.close()
```

解密效果
![](https://md.buptmerak.cn/uploads/upload_cc4b4901a4041521bb8c2b7ba3311a5c.png)


分析JNI_OnLoad
能够根据JNI_OnLoad的固定结构对符号进行部分恢复
![](https://md.buptmerak.cn/uploads/upload_5307d6825be695572ee39373792dbc8b.png)


获取到APP的签名进行异或后与密文比较进行校验
![](https://md.buptmerak.cn/uploads/upload_612edb370fee898749ad506c0e73e170.png)


动态注册decodeSo到该函数，发现其实是是将内容异或0x22后释放到/data/data/com.mrctf.android2022/目录下
![](https://md.buptmerak.cn/uploads/upload_889018e983f05257240da9c7e52f024c.png)
![](https://md.buptmerak.cn/uploads/upload_87263e2f88dfe23c327f5fcbc2d41442.png)

到此为止即可直接恢复 dex 和 libnative.so

但是实际上JNI_OnLoad还没完全分析完，后面会有两个Hook,先把整个JNI_OnLoad流程图放在这
![](https://md.buptmerak.cn/uploads/upload_41c25535d2d2829b396d738d69827acc.png)



* 第一个Hook是用于hook libc.so 导出函数exexve，因为在Android5之后将dalvik虚拟机逐渐改为ART虚拟机用于提示性能，一般在安装APK时就会进行dex2oat的优化，将dex字节码转为直接可以在cpu上执行的机器码，如果是动态加载的dex则无法在安装时进行此操作，但是一旦通过LoadClass加载，在加载过程中会调用相关函数对其进行oat转换，虽然不一定会转换也不一定成功，但是如果一旦转换，对内存中的dex字节码进行修改就会无效，因为系统会执行优化后的机器码，这个时候抽取壳便无效了。
  之所以hook该函数是因为，在dex2oat的过程中最终会通过该函数执行命令进行转换，只要识别到命令中有dex2oat命令就返回null表示失败，其他命令照常执行。（该过程详见参考资料）

* 第二个Hook是Hook libart.so中的LoadMethod函数，该函数是加载流程中走的最底层的函数，能够获取到ArtMethod结构体指针和方法地址偏移，在题目中获取的是其第二个参数==const DexFile& dex_file==,能通过这个地址指向的结构获取内存中的dex的起始位置和size，只需要修改地址空间保护属性对指定方法指令段偏移进行修改即可进行抽取

* 以下是位加载类时执行流程
  `ClassLoader.java::loadClass -> DexPathList.java::findClass -> DexFile.java::defineClass -> class_linker.cc::LoadClass -> class_linker.cc::LoadClassMembers -> class_linker.cc::LoadMethod`
  ![](img/upload_7c7b889dfa21e8000b68c699fd110ade.png)

* 这里不细分析这部分的具体实现了，有兴趣可查阅参考资料和开源项目

#### 分析解密后的libnative. so 和 dex

首先是dex文件，包含两个类，一个MainActivity，另一个Utils
在MainActivity的onCreate开始实例化了一个Utils类，之后便监听按钮截取输入传入nativeCheck
![](https://md.buptmerak.cn/uploads/upload_43437919d1c357aae52916ed86ede507.png)


实例化的时候先load了释放完成的libnative. so，随即进行了删除
![](https://md.buptmerak.cn/uploads/upload_f6c33fa8746c3eee42076792279086c1.png)


查看nativeCheck，也是native层的函数
![](https://md.buptmerak.cn/uploads/upload_94b29e2369bf4b756a5a53f87a79a6b1.png)


分析libnative.so,依旧是字符串经过了加密，用上面的任意一种方法进行解密
![](https://md.buptmerak.cn/uploads/upload_6e7311e73c3f21c31c5d5fcb7c64253c.png)


这次发现好像有nativeCheck的导出函数，但是实际是假的，函数名_Utils前多了一个下划线
函数逻辑是如果调用Java层 test返回结果为1则返回调用Java_com_mrctf_android2022__Utils_check的返回值
![](https://md.buptmerak.cn/uploads/upload_03311b8efb03bf0c922347a46a1338d0.png)


实际上Java_com_mrctf_android2022__Utils_check提示是错误的flag
![](https://md.buptmerak.cn/uploads/upload_3d46c5004a6165d8dbb0b82d273eeddf.png)


JNI_OnLoad查看，依旧是签名校验后注册函数，但是这次注册函数是两个且无法定位到native地址
![](https://md.buptmerak.cn/uploads/upload_1aeb7676e6fcd748f5bffdb4f5c0786d.png)
![](https://md.buptmerak.cn/uploads/upload_57af5245a0e2f4bcae312b391f460f09.png)


在注册上面有一个函数，发现其读取了数据目录的一个shm文件并且将值保存最后调用java层的fs方法将其删除
![](https://md.buptmerak.cn/uploads/upload_a09b7ee421d5c6b6ecdc2dbedd3c5c5c.png)

![](https://md.buptmerak.cn/uploads/upload_f4834b3229dcd61bc360838d01cc8ebb.png)


在JNI_OnLoad末尾有一个函数，目前还不知道是什么功能
![](https://md.buptmerak.cn/uploads/upload_be155f788ff384a3815245f6e3e1ecbf.png)

![](https://md.buptmerak.cn/uploads/upload_435e203b6b7f02a981bd06a326a967e1.png)


分析dword_1837C,发现仅有一个写，是保存了env的地址，
![](https://md.buptmerak.cn/uploads/upload_4dfe8946fbe650b4368cd207b375c0f0.png)

![](https://md.buptmerak.cn/uploads/upload_f2891fa58009cfa1cf121e63cdccb9fb.png)


将jni.h导入IDA，重新定义该结构为_JNIEnv 类型，发现其通过env的function指针获取到了RegisterNatives的地址
![](https://md.buptmerak.cn/uploads/upload_a8c00f3fc61e82199bb6f1fe74fcb05c.png)

![](https://md.buptmerak.cn/uploads/upload_626a52f4914349127fa3aebfdbc931ee.png)


查看sub_5834函数，其实很清晰了，就是将a3，也就是JNINativeMethod结构体指针指向结构体的fnptr - 2022，而该结构体是用于指明动态注册函数的各种信息的，第三个即为注册到的函数地址，那sub_5CE8就可能是Hook函数，Hook到RegisterNatives后对其参数进行修改-2022，之后调用
![](https://md.buptmerak.cn/uploads/upload_aa9a7d9ed4559a7cec39f641b65b3e2d.png)

![](https://md.buptmerak.cn/uploads/upload_13313bd3f0cb9675b5735c96de9babed.png)


对其进行验证，跳转到对应的位置，果然发现逻辑，猜想正确
![](https://md.buptmerak.cn/uploads/upload_f1eda5df4a4ddb7089a904a9f55a6168.png)

![](https://md.buptmerak.cn/uploads/upload_7d4ddc011fde15f55caca823f3db5d5d.png)

![](https://md.buptmerak.cn/uploads/upload_09043b05c407293c6def7e7397f8d456.png)


该nativeCheck函数调用了Java层的test函数并返回了test的返回值，这个时候就有意思了，test明显返回的是1，这里究竟有什么玄机，其实就是抽取壳的实现，之前我们发现一个shm文件到目前为止都没有用到，但是在该函数里出线了shm

* 共三处使用，第一处是赋值操作
![](https://md.buptmerak.cn/uploads/upload_2455a89c079aa12a5c600413ad3d5748.png)


* 第二处使用时仅从156 - 159四个字节进行了修改
  ![](https://md.buptmerak.cn/uploads/upload_91b58e213bdd7be358c304a72fbee8a6.png)


* 第三处是赋0值，而且在大循环里
  ![](https://md.buptmerak.cn/uploads/upload_c2fcb09f7e2534158f5f611d55e5c580.png)


重点关注156 - 159四字节，18 19 15 3 ,其实就是test方法的insn指令的最后四字节==12 13 0F 03==
![](https://md.buptmerak.cn/uploads/upload_5c3762cf6a5d02edffa967bcc101f00b.png)


尝试将赋值数组填回dex,刚好0x80字节

```!
12 17 12 01 6E 10 27 00 08 00 0C 02 12 01 21 24 D8 04 04 FF 35 41 10 00 48 04 02 01 D8 05 01 01 48 05 02 05 B7 54 B7 14 8D 44 4F 04 02 01 D8 01 01 01 28 EE 22 00 1F 00 70 30 31 00 70 02 12 04 1F 04 20 00 22 05 1C 00 70 10 2C 00 05 00 1A 06 00 00 6E 20 2E 00 65 00 0C 05 21 26 DA 06 06 02 6E 20 2D 00 65 00 0C 05 1A 06 8D 00 6E 20 2E 00 65 00 0C 05 6E 10 2F 00 05 00 0C 05 23 76 24 00 12 07 4D 00 06 07 71 30 26 00 54 06 0C 04 6E 10 2B 00 04 00 0C 03 71 10 12 00 03 00 0A 04 0F 04
```

使用JEB解析修改后的dex，果然原形毕露，就是将输入经过简单异或后转为hex调用了check函数
![](https://md.buptmerak.cn/uploads/upload_07af8b7745bee0a13d88dcfecaa5f6d2.png)


跳转到check函数的位置，发现存在大量虚假控制流
![](https://md.buptmerak.cn/uploads/upload_f8bf68fb0fdb54f0eed0c44fbd410bed.png)

![](https://md.buptmerak.cn/uploads/upload_f8c9b54ee044c0fbe90dc964c87542d3.png)


先将.bss和.data段设为只读，之后使用IDA脚本设置x.和y.开头变量值为0

```python=
import ida_bytes
import idautils
for addr,name in idautils.Names():
    if name.startswith('x.') or name.startswith('y.'):
        ida_bytes.patch_dword(addr,0)

```

修改后效果
![](https://md.buptmerak.cn/uploads/upload_538a280baf42ad441f00c0f99aece347.png)

![](https://md.buptmerak.cn/uploads/upload_48d806e3e8e7cfe219fff0f47336149a.png)


逻辑就是对传入的字符串计算长度并进行8位padding，即不足8位补0，如果补完后长度不足80直接返回0，否则传入sub_203c，将其转为伪码就是

```cpp=
    int encryptCount = 0;

    int left;
    int right;
    int key = 0x20222022;
    int sum = 0;
    unsigned int i, j;

    encryptCount = length / 8;

    for (i = 0, j = 0; i < encryptCount; i++, j += 8) {
        sum = 0;

        left = data[j] << 24 | data[j + 1] << 16 | data[j + 2] << 8 | data[j + 3];
        right = data[j + 4] << 24 | data[j + 5] << 16 | data[j + 6] << 8 | data[j + 7];

        left = left ^ key;
        right = right ^ left;

        data[j] = (left >> 24) & 0xff;
        data[j + 1] = (left >> 16) & 0xff;
        data[j + 2] = (left >> 8) & 0xff;
        data[j + 3] = left & 0xff;
        data[j + 4] = (right >> 24) & 0xff;
        data[j + 5] = (right >> 16) & 0xff;
        data[j + 6] = (right >> 8) & 0xff;
        data[j + 7] = right & 0xff;
    }
```

返回check函数，这里的dword_1B384可以根据索引找到发现是sign的值
![](https://md.buptmerak.cn/uploads/upload_2237c28d712b7f0a4fb1be5fd011f5a3.png)


整个逻辑转为伪码便是

```cpp=
    for(i=0;i<80;i++){
        if( (enc[i] ^ sign[i]) != cmp[i]) return 0;
    }
```

那解题思路应该就明确了，先解出sign，然后解出enc，通过enc反推传入check的字符串，得到后就能得到hex编码，之后就可以得到flag

重新梳理抽取流程便是：在libstub中hook LoadMethod获取到dex在内存中的基址，然后在调用libnative 的 nativeCheck时还原函数内容，执行结束后填充回去，防止执行后被dump，而这个地址的传输使用的是shm文件的读写

#### EXP

```cpp=
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned char signByte[1023] = {
    0x33,0x31,0x3a,0x31,0x34,0x36,0x34,0x61,0x3b,0x39,0x32,0x39,0x3c,0x3f,0x3f,0x38,0x71,0x21,0x22,0x20,0x24,0x27,0x26,
0x26,0x28,0x2b,0x2a,0x29,0x2c,0x29,0x29,0x2d,0x44,0x43,0x1b,0x47,0x16,0x15,0x15,0x17,0x18,0x4d,0x1a,0x36,0x31,0x3b,0x31,0x65,0x3d,0x30,0x33,0x30,0x31,0x3c,0x6d,0x3b,0x3d,0x6a,0x3f,0x21,
0x21,0x23,0x23,0x76,0x25,0x23,0x27,0x28,0x2a,0x2a,0x2f,0x24,0x2e,0x2f,0x2f,0x41,0x12,0x12,0x13,0x1c,0x15,0x10,0x17,0x1b,0x1c,0x1f,0x30,0x35,0x32,0x35,0x35,0x36,0x36,0x36,0x3f,0x3a,0x39,0x3a,0x3c,0x6c,0x3d,0x3f,0x20,0x29,0x22,0x25,0x24,0x26,0x23,0x22,0x28,0x2d,0x2a,0x23,0x2d,0x2e,0x2e,0x2e,0x17,0x12,0x11,0x12,0x14,0x44,
0x15,0x17,0x18,0x11,0x1a,0x36,0x31,0x31,0x36,0x31,0x35,0x32,0x37,0x3f,0x38,0x39,0x3b,0x3d,0x3a,0x3d,0x3c,0x21,0x21,0x73,0x20,0x24,0x25,0x2e,0x27,0x2e,0x29,0x29,0x2e,0x29,0x2d,0x2a,0x2f,0x41,0x10,0x11,0x13,0x15,0x12,0x15,0x14,0x19,0x19,0x4b,0x33,0x31,0x32,0x3b,0x34,0x33,0x36,0x34,0x3d,0x3c,0x3a,0x3f,0x3c,0x6f,0x3f,0x3c,0x20,0x20,0x25,0x20,0x27,0x24,0x26,0x76,0x2b,0x29,0x2a,0x23,0x2c,0x2b,
0x2e,0x2c,0x15,0x14,0x12,0x17,0x14,0x16,0x17,0x14,0x18,0x18,0x1d,0x33,0x32,0x32,0x32,0x61,0x34,0x31,0x37,0x6c,0x3a,0x38,0x38,0x3d,0x3e,0x3e,0x3c,0x25,0x22,0x23,0x20,0x27,0x26,0x26,0x24,0x2a,0x2a,0x2b,0x28,0x25,0x2e,0x2d,0x2c,0x10,0x14,0x43,0x12,0x13,0x15,0x42,0x14,0x1c,0x1a,0x1c,0x33,0x31,0x31,0x36,0x37,0x35,0x35,0x30,0x3b,0x39,0x39,0x39,0x3f,0x3c,0x3d,0x36,0x23,0x22,0x21,0x23,0x21,0x74,0x25,0x27,0x2c,0x21,0x29,0x2a,0x2c,0x7c,0x2d,0x2f,0x10,0x19,0x12,
0x15,0x14,0x16,0x13,0x12,0x18,0x1d,0x1a,0x36,0x30,0x31,0x33,0x35,0x32,0x35,0x34,0x39,0x39,0x6b,0x38,0x3c,0x3d,0x36,0x3f,0x26,0x21,0x21,0x26,0x21,0x25,0x22,0x27,0x20,0x28,0x29,0x2b,0x2d,0x2a,0x2d,0x2c,0x11,0x11,0x43,0x10,0x14,0x15,0x1e,0x17,0x1e,0x19,
0x19,0x35,0x34,0x32,0x37,0x34,0x32,0x37,0x34,0x38,0x38,0x3d,0x38,0x3f,0x3c,0x3e,0x6e,0x23,0x21,0x22,0x2b,0x24,0x23,0x26,0x24,0x2d,0x2c,0x2a,0x2f,0x2c,0x7c,0x2f,0x2c,0x10,0x10,0x15,0x10,0x17,0x14,0x16,0x46,0x1b,0x19,0x1a,0x38,0x31,0x34,0x33,0x37,0x30,0x33,0x37,0x3c,0x39,0x68,0x3a,0x3f,0x3d,0x3f,0x38,0x23,0x22,0x23,0x23,0x75,0x26,0x26,0x27,0x20,0x29,0x2c,0x2b,0x2f,0x28,0x2b,0x2f,0x14,0x11,0x11,0x12,0x17,0x15,0x17,0x10,0x1b,0x1a,0x1a,0x38,0x33,0x32,0x32,0x36,0x37,0x35,0x37,0x38,0x6d,0x3a,0x3d,0x3c,0x34,0x3c,0x6e,0x28,0x27,0x26,0x2b,0x2c,0x23,0x70,0x20,0x28,0x7d,0x2a,0x2a,0x2c,0x2c,0x2e,
0x2e,0x10,0x14,0x12,0x13,0x14,0x16,0x1e,0x15,0x18,0x18,0x1a,0x66,0x31,0x32,0x30,0x34,0x3d,0x34,0x37,0x39,0x39,0x6b,0x3b,0x3e,0x35,0x3c,0x3f,0x21,0x21,0x23,0x23,0x24,0x2d,0x27,0x73,0x7b,0x7c,0x2a,0x2e,0x2a,0x2d,0x27,0x7a,0x17,0x44,0x12,0x47,0x14,0x16,0x13,0x1f,0x4b,0x1a,0x18,0x38,0x33,0x31,0x65,0x60,0x67,0x67,0x35,0x38,0x3e,0x39,0x39,0x39,0x3d,0x6f,0x39,0x27,0x77,0x71,0x71,0x2c,0x71,0x74,0x2f,0x21,0x7f,0x2f,0x79,0x28,0x7b,0x2c,0x79,0x41,0x47,0x1b,0x13,
0x42,0x16,0x14,0x13,0x19,0x10,0x48,0x37,0x31,0x3a,0x30,0x62,0x30,0x30,0x36,0x31,0x6c,0x6c,0x39,0x3e,0x39,0x3d,0x69,0x22,0x25,0x2a,0x2a,0x71,0x23,0x2f,0x26,0x21,0x2b,0x2b,0x2c,0x7e,0x25,0x2c,0x7d,0x46,0x10,0x15,0x15,0x10,0x47,0x42,0x1e,0x4c,0x11,0x18,0x39,0x63,0x36,0x36,0x34,0x34,0x31,0x66,0x6a,0x3e,0x32,0x68,0x6a,0x3e,
0x6c,0x3b,0x29,0x23,0x24,0x70,0x23,0x70,0x72,0x75,0x7e,0x2c,0x7e,0x2f,0x2b,0x29,0x29,0x29,0x41,0x13,0x16,0x45,0x15,0x47,0x1e,0x17,0x4b,0x11,0x1c,0x65,0x30,0x37,0x34,0x32,0x37,0x32,0x64,0x6c,0x6f,0x6b,0x39,0x6f,0x3a,0x3b,0x3b,0x23,0x25,0x73,0x22,0x20,0x2d,0x26,0x75,0x2e,0x2d,0x28,0x29,0x2b,0x29,0x2e,0x2a,0x16,0x44,0x43,0x41,0x15,0x41,0x42,0x44,0x19,0x4f,0x13,0x61,0x31,0x31,0x36,0x33,0x34,0x32,0x64,0x6c,0x3d,0x33,0x6e,0x6e,0x3b,0x3e,0x3a,0x27,0x26,0x24,0x25,0x70,0x70,0x72,0x23,0x2b,0x2c,0x7e,0x2d,0x25,0x7f,0x2d,0x7c,0x44,0x16,0x10,0x17,0x47,0x12,0x1f,0x1f,0x1b,0x4c,0x18,0x38,0x38,0x63,
0x32,0x31,0x64,0x35,0x33,0x3c,0x3b,0x39,0x6e,0x6d,0x3f,0x3b,0x69,0x76,0x20,0x2a,0x23,0x75,0x77,0x24,0x23,0x2d,0x7f,0x28,0x7a,0x2a,0x2b,0x2f,0x7d,0x18,0x18,0x41,0x47,0x10,0x11,0x16,0x1e,0x1f,0x4c,0x19,0x64,0x36,0x30,0x61,0x60,0x34,0x60,0x31,0x30,0x6a,0x3a,0x33,0x38,0x6c,0x3d,0x6e,0x26,0x28,0x71,0x21,0x2d,0x76,0x2f,0x73,0x29,0x2b,0x78,0x7d,0x7f,0x7e,0x27,0x79,0x11,0x17,0x12,0x17,0x15,0x43,0x13,0x13,0x18,0x4c,0x18,0x39,0x30,0x61,0x65,0x30,0x30,0x60,0x64,
0x31,0x38,0x3d,0x6f,0x3c,0x6b,0x6b,0x3e,0x21,0x21,0x23,0x22,0x2d,0x73,0x20,0x20,0x7e,0x7d,0x2c,0x79,0x2d,0x2e,0x28,0x2d,0x41,0x19,0x40,0x13,0x45,0x12,0x15,0x17,0x11,0x4d,0x49,0x34,0x32,0x34,0x34,0x3d,0x35,0x63,0x33,0x3e,0x6c,0x3c,0x3c,0x6f,0x3f,0x3d,0x3d,0x27,0x70,0x77,0x20,0x26,0x23,0x72,0x74,0x2c,0x21,0x7b,0x23,0x29,
0x2d,0x7f,0x2e,0x12,0x13,0x16,0x16,0x47,0x43,0x1f,0x1f,0x4a,0x1c,0x1b,0x36,0x32,0x34,0x36,0x34,0x60,0x30,0x64,0x6a,0x31,0x33,0x69,0x38,0x3e,0x3a,0x3e,0x27,0x73,0x25,0x20,0x70,0x23,0x26,0x27,0x2c,0x2d,0x2e,0x2d,0x7f,0x2f,0x26,0x7a,0x18,0x17,0x47,0x47,0x13,0x11,0x47,0x10,0x10,0x1a,0x48,0x64,0x62,0x67,0x66,0x3d,0x64,0x34,0x3e,0x3e,0x39,0x38,0x3f,0x34,0x3e,0x3a,0x39,0x73,0x26,0x20,0x76,0x71,
0x70,0x73,0x74,0x7d,0x2a,0x23,0x2b,0x79,0x7b,0x29,0x26,0x13,0x19,0x46,0x46,0x41,0x1d,0x11,0x17,0x1e,0x4a,0x48,0x34,0x31,0x33,0x60,0x67,0x32,0x33,0x32,0x3a,0x3e,0x3d,0x3d,0x3c,0x39,0x6d,0x39,0x27,0x21,0x20,0x23,0x27,0x25,0x27,0x27,0x28,0x29,0x2b,0x7a,0x2f,0x2f,0x2f,0x2c,0x10,0x10
};

void getSign(){
    int i = 0;
    for(i = 0; i < 1023; i++){
        signByte[i] = signByte[i] ^ (i%43);
    }
}

unsigned char getIndex(unsigned char x){
    int i = 0;
    unsigned char charset[17] = "0123456789abcdef" ;
    for(i = 0; i < 16; i++){
        if(charset[i] == x){
            return i;
        }
    }
    return -1;
}

void dec(unsigned char *data, int length)
{
    int encryptCount = 0;

    int left;
    int right;
    int key = 0x20222022;
    int sum = 0;
    unsigned int i, j;

    encryptCount = length / 8;

    for (i = 0, j = 0; i < encryptCount; i++, j += 8)
    {
        sum = 0;

        left = data[j] << 24 | data[j + 1] << 16 | data[j + 2] << 8 | data[j + 3];
        right = data[j + 4] << 24 | data[j + 5] << 16 | data[j + 6] << 8 | data[j + 7];

        right = right ^ left;
        left = left ^ key;

        data[j] = (left >> 24) & 0xff;
        data[j + 1] = (left >> 16) & 0xff;
        data[j + 2] = (left >> 8) & 0xff;
        data[j + 3] = left & 0xff;
        data[j + 4] = (right >> 24) & 0xff;
        data[j + 5] = (right >> 16) & 0xff;
        data[j + 6] = (right >> 8) & 0xff;
        data[j + 7] = right & 0xff;
    }
}

int main(){
    int i = 0,j = 0,count = 0;
    char res[80] = {0};
    unsigned char tmp;

    unsigned char cmp[80] =
    {
            0x26, 0x2B, 0x2C, 0x73, 0x14, 0x11, 0x16, 0x13, 0x20, 0x77,
            0x2A, 0x29, 0x13, 0x44, 0x13, 0x1A, 0x75, 0x70, 0x26, 0x21,
            0x12, 0x43, 0x13, 0x12, 0x20, 0x26, 0x23, 0x26, 0x13, 0x45,
            0x11, 0x17, 0x75, 0x70, 0x2C, 0x70, 0x13, 0x1B, 0x14, 0x15,
            0x27, 0x20, 0x25, 0x27, 0x17, 0x4C, 0x15, 0x14, 0x2F, 0x20,
            0x20, 0x78, 0x1F, 0x18, 0x43, 0x46, 0x23, 0x27, 0x22, 0x27,
            0x17, 0x4A, 0x17, 0x10, 0x20, 0x73, 0x20, 0x25, 0x15, 0x14,
            0x12, 0x1B, 0x24, 0x26, 0x10, 0x43, 0x24, 0x27, 0x10, 0x1A
    };
    getSign();
    for(i = 0; i < 80; i++){
        cmp[i] = cmp[i] ^ signByte[i];
    }
    dec(cmp, 80);

    for (count = 0; count < 80; count++)
    {
        if(cmp[count] == 0){
            break;
        }
    }

    for(i = 0; i < count - 1; i += 2){
        res[j++] = getIndex(cmp[i]) << 4 | getIndex(cmp[i+1]);
    }

    for(i = j-2; i >= 0; i--){
        res[i] = res[i] ^ res[i + 1] ^ (i);
    }
    printf("%s", res);
    return 0;
}
```

### 3. 参考

https://developer.android.com/reference/dalvik/system/InMemoryDexClassLoader

https://blog.csdn.net/shulianghan/article/details/122017822

https://hanshuliang.blog.csdn.net/article/details/121950834#oat_file_assistantccGenerateOatFileNoChecks__385

https://www.jianshu.com/p/ae66be381e6f

http://aospxref.com/android-8.0.0_r36/xref/art/runtime/oat_file_assistant.cc?fi=MakeUpToDate#GenerateOatFileNoChecks

### 4. 相关开源项目

Allows you to partly emulate an Android native library.
https://github.com/AeonLucid/AndroidNativeEmu

This is a personal improved version of AndroidNativeEmu
https://github.com/maiyao1988/ExAndroidNativeEmu

孤挺花（Armariris） -- 由上海交通大学密码与计算机安全实验室维护的LLVM混淆框架
https://github.com/GoSSIP-SJTU/Armariris

绕过 Android阻止应用动态链接非公开NDK库限制 进行dlopen和dlsym
https://github.com/lizhangqu/dlfcn_compat

thumb16 thumb32 arm32 inlineHook框架
https://github.com/ele7enxxh/Android-Inline-Hook

函数代码抽空解决方案
https://github.com/luoyesiqiu/dpt-shell

ollvm4.0
https://github.com/obfuscator-llvm/obfuscator/tree/llvm-4.0

## old
签到题。每次杀死怪物和拿到钥匙会异或一次密匙，手动过一次后用模拟器保存状态即可重复调试。利用模拟器的调试器和作弊器定位加密函数，逆向即可，其中要注意8位cpu特性。
加密部分汇编代码：
```asm
;
; for(i=0;i<16;i++){
;
	lda     #$00
L00CF:	sta     _i
	cmp     #$10
	bcs     L006D
;
; sum += 0x29;
;
	lda     #$29
	clc
	adc     _sum
	sta     _sum
;
; enc_out[i]=(flagMRCTF[i]^enc_key[i]^sum)+0x10;
;
	lda     #<(_enc_out)
	ldx     #>(_enc_out)
	clc
	adc     _i
	bcc     L0078
	inx
L0078:	sta     sreg
	stx     sreg+1
	ldy     _i
	lda     _flagMRCTF,y
	sta     ptr1
	ldy     _i
	lda     _enc_key,y
	eor     ptr1
	sta     ptr1
	lda     _sum
	eor     ptr1
	clc
	adc     #$10
	ldy     #$00
	sta     (sreg),y
;
; for(i=0;i<16;i++){
;
	lda     _i
	clc
	adc     #$01
	jmp     L00CF
;
; strcpy(textMRCTF,"success");
;
L006D:	ldy     #$FF
L0083:	iny
	lda     L0001+34,y
	sta     _textMRCTF,y
	bne     L0083
;
; for(i=0;i<16;i++){
;
	lda     #$00
L00D0:	sta     _i
	cmp     #$10
	bcs     L0085
;
; enc_out[i] ^= cipher;
;
	lda     #<(_enc_out)
	ldx     #>(_enc_out)
	clc
	adc     _i
	bcc     L008E
	inx
L008E:	sta     sreg
	stx     sreg+1
	sta     ptr1
	stx     ptr1+1
	ldy     #$00
	lda     (ptr1),y
	sta     ptr1
	lda     _cipher
	eor     ptr1
	sta     (sreg),y
;
; if(enc_out[i]!=enc_flag[i]){
;
	ldy     _i
	ldx     #$00
	lda     _enc_out,y
	sta     ptr1
	stx     ptr1+1
	ldy     _i
	lda     _enc_flag,y
	cpx     ptr1+1
	bne     L00CE
	cmp     ptr1
	beq     L0086
;
; strcpy(textMRCTF,"fail   ");
;
L00CE:	ldy     #$FF
L0099:	iny
	lda     L0001+42,y
	sta     _textMRCTF,y
	bne     L0099
;
; break;
;
	jmp     L0085
```
解题脚本
```python
cipher = 0x56
cipher ^= 0x38
for _ in range(44):
    cipher ^= 0x19

print(hex(cipher))
key = [0x6d,0x72,0x63,0x74,0x66,0x5f,0x66,0x61,0x6b,0x65,0x5f,0x66,0x6c,0x61,0x67,0x21]
enflag = [0x5C,0xEB,0xE8,0x9E,0x99,0xB3,0x5F,0x47,0x16,0xB7,0xD7,0xBB,0x35,0x20,0x0D,0x62]
sum = 0

for i in range(16):
    sum = (sum+0x29)&0xFF
    print(chr((((enflag[i]^cipher)-0x10)&0XFF)^key[i]^sum),end="")
```
ida分析nes固件插件



## encfs