#include <stdio.h> 
#include <stdint.h>
#include <string.h>
#include <stdlib.h> 

#define LEFT_ROTATE(a,b)  ( (a << b)  + (a >> ( 32 - b ) ) ) 
#define F(x,y,z)  ( (x & y) | ( ~x & z ) )
#define G(x,y,z)  ( (x & z) | ( y & ~z ) )
#define H(x,y,z)  (x ^ y ^ z)
#define I(x,y,z)  (y ^ (x | ~z ) )

void print_hex_str(const uint8_t *bytes, unsigned int bc, const char *label) {
  int i; 

  if( label != NULL ) 
    printf("%s", label); 

  for( i = 0; i < bc; i++) {
    printf("%02x", bytes[i]);
  }

  printf("\n"); 
}

void print_hex_str32(const uint32_t *words, unsigned int wc, const char *label) {
  int i; 

  if( label != NULL ) 
    printf("%s", label); 

  for( i = 0; i < wc; i++) {
    printf("%08x", words[i]);
  }

  printf("\n"); 
}

void MD5step( uint8_t *ds, uint8_t *ms, unsigned int nb) {

  uint32_t d[4];
  uint32_t m[16];
  uint32_t d0[4];
  unsigned int i,j;
  unsigned int n; 
  uint32_t x; 

  static uint8_t s1[] = { 7, 12, 17, 22}; 
  static uint8_t s2[] = { 5, 9, 14, 20}; 
  static uint8_t s3[] = { 4, 11, 16, 23}; 
  static uint8_t s4[] = { 6, 10, 15, 21}; 
  static uint32_t T[] = { 
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};
  
  
  /* group ds into words */ 
  for( i = 0; i < 4; i++) {
    for( j = 0; j < 4; j++) {
      d[i] = (d[i] >> 8) | ( (uint32_t) ds[j + i*4] << 24);
    }
#ifdef DEBUG 
    printf("d[%d] -> %08x\n",i,d[i]); 
#endif
  }

  /* go through each 64 byte block */
  for( n = 0; n < nb; n++) {

    /* group m into words */ 
    for( i = 0; i < 16; i++) {
      for( j = 0; j < 4; j++) {
        m[i] = (m[i] >> 8) | ( (uint32_t) ms[64*n + 4*i + j] << 24 ); 
      }
#ifdef DEBUG 
      printf("m[%d] -> %08x\n",i,m[i]); 
#endif 
    }
    print_hex_str(ms + 64*n , 64, "block -> ");

    /* save current digest */ 
    memcpy(d0, d, sizeof(d));
    print_hex_str32(d0, 4, "initial ds -> ");

    /* first round */ 
    for( i = 0; i < 16; i++) {
      x = m[i] + T[i] + d[(-i)&3] + F(d[(1-i)&3], d[(2-i)&3],d[(3-i)&3]);
      d[(-i)&3] = d[(1-i)&3] + LEFT_ROTATE(x,s1[i&3]);
    }
    print_hex_str32(d, 4, "1st round ds -> ");
#ifdef DEBUG
    printf("d[%d] -> %08x\n",0,d[0]); 
    printf("d[%d] -> %08x\n",1,d[1]); 
    printf("d[%d] -> %08x\n",2,d[2]); 
    printf("d[%d] -> %08x\n",3,d[3]); 
#endif

    /* second round */ 
    for( i = 0; i < 16; i++) {
      x = m[(5*i+1)&15] + T[i+16] + d[(-i)&3] + G(d[(1-i)&3], d[(2-i)&3],d[(3-i)&3]);
      d[(-i)&3] = d[(1-i)&3] + LEFT_ROTATE(x,s2[i&3]);
    }
    print_hex_str32(d, 4, "2nd round ds -> ");
#ifdef DEBUG
    printf("d[%d] -> %08x\n",0,d[0]); 
    printf("d[%d] -> %08x\n",1,d[1]); 
    printf("d[%d] -> %08x\n",2,d[2]); 
    printf("d[%d] -> %08x\n",3,d[3]); 
#endif
    /* third round */ 
    for( i = 0; i < 16; i++) {
      x = m[(3*i+5)&15] + T[i+32] + d[(-i)&3] + H(d[(1-i)&3], d[(2-i)&3],d[(3-i)&3]);
      d[(-i)&3] = d[(1-i)&3] + LEFT_ROTATE(x,s3[i&3]);
    }
    print_hex_str32(d, 4, "3rd round ds -> ");
#ifdef DEBUG
    printf("d[%d] -> %08x\n",0,d[0]); 
    printf("d[%d] -> %08x\n",1,d[1]); 
    printf("d[%d] -> %08x\n",2,d[2]); 
    printf("d[%d] -> %08x\n",3,d[3]); 
#endif
    /* fourth round */ 
    for( i = 0; i < 16; i++) {
      x = m[(7*i)&15] + T[i+48] + d[(-i)&3] + I(d[(1-i)&3], d[(2-i)&3],d[(3-i)&3]);
      d[(-i)&3] = d[(1-i)&3] + LEFT_ROTATE(x,s4[i&3]);
    }
    print_hex_str32(d, 4, "4th round ds -> ");
#ifdef DEBUG
    printf("d[%d] -> %08x\n",0,d[0]); 
    printf("d[%d] -> %08x\n",1,d[1]); 
    printf("d[%d] -> %08x\n",2,d[2]); 
    printf("d[%d] -> %08x\n",3,d[3]); 
#endif

    /* Add to original digest */ 
    for( i = 0; i < 4; i++ ) { 
      d[i] += d0[i]; 
    }
    print_hex_str32(d, 4, "final stage ds -> ");
#ifdef DEBUG
    printf("d[%d] -> %08x\n",0,d[0]); 
    printf("d[%d] -> %08x\n",1,d[1]); 
    printf("d[%d] -> %08x\n",2,d[2]); 
    printf("d[%d] -> %08x\n",3,d[3]); 
#endif
  }

  /*  split d into bytes */ 
  for( i = 0; i < 4; i++ ) {
    for( j = 0 ; j < 4; j++) {
      ds[i*4+j] = d[i];   
      d[i] >>= 8; 
#ifdef DEBUG 
      printf("ds[%d] -> %02x\n",i*4+j,ds[i*4+j]); 
#endif
    }
  }
}

void MD5sum(uint8_t *ds, uint8_t *ms, unsigned int bc) { 

  uint8_t md0[16] = { 0x01, 0x23, 0x45, 0x67,
                      0x89, 0xab, 0xcd, 0xef,
                      0xfe, 0xdc, 0xba, 0x98, 
                      0x76, 0x54, 0x32, 0x10}; 
  uint8_t *msp; /* message + padding */ 
  unsigned int pb; /* padding bytes */ 
  unsigned int i; 

  pb = ((55 - bc % 64) % 64) + 9; 
  msp = calloc(bc+pb, sizeof(uint8_t)); 

  memcpy(msp, ms, bc); 
  msp[bc] = 0x80; 
  msp[bc+pb-8] = bc << 3; 
  msp[bc+pb-7] = bc >> 5; 
  msp[bc+pb-6] = bc >> 13; 
  msp[bc+pb-5] = bc >> 21; 
  msp[bc+pb-4] = bc >> 29; 

  print_hex_str(msp,bc+pb,"padded msg -> "); 

#ifdef DEBUG 
  for( i = 0; i < bc + pb; i++) {
    printf("msp[%d] -> %02x\n",i, msp[i]);
  }
#endif 

  memcpy(ds, md0, sizeof(md0)); 

  MD5step(ds,msp, (bc+pb)/64);
  free(msp);

}


int main (int argc, char **argv) { 

  uint8_t *msg = argv[1];  
  uint8_t ds[16]; 

  MD5sum(ds,msg, strlen(msg)); 

  print_hex_str(ds,sizeof(ds),"md5 -> ");
}
