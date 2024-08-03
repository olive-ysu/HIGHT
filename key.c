#include <stdio.h>
#include "key.h"

// LFSR
void gen_delta(uint8_t num, uint8_t *del){
    uint8_t del0 = 0b1011010;   // 초기화
    uint8_t del1 = del0;   // 이전 델타 값 저장
    
    for(int i=1; i<=num; i++){
        uint8_t s_1 = del1 & 0b1;
        uint8_t s_2 = (del1 & 0b1000) >> 3;
        uint8_t s_6 = s_1 ^ s_2;

        del1 = (s_6 << 6) | (del1 >> 1);
    }
    *del = del1;
}

void gen_wk(uint8_t mk[16], uint8_t wk[8]){
    for(int i=0; i<=3; i++){
        wk[i] = mk[i+12];
    }
    for(int i=4; i<=7; i++){
        wk[i] = mk[i-4];
    }
}

void gen_sk(uint8_t mk[16], uint8_t sk[128]){    
    for(int i=0; i<8; i++){
        for(int j=0; j<8; j++){        
            sk[16*i+j] = mk[(j-i)&7] + delta[16*i+j];
        }
        for(int j=0; j<8; j++){ 
            sk[16*i+j+8] = mk[((j-i)&7)+8] + delta[16*i+j+8];
        }
    }
}


void gen_dec_sk(uint8_t mk[16], uint8_t sk[128]){
    uint8_t tmp[128] = {0x00,};
    gen_sk(mk, tmp);

    for(int i=0; i<128; i++){
        sk[i] = tmp[127-i];
    }
}


void encrypt(uint8_t ct[8], uint8_t pt[8], uint8_t mk[16]){
    // 서브키, 화이트닝키 생성
    uint8_t wk[8] = { 0x00, };
    uint8_t sk[128] = { 0x00, };
    
    gen_sk(mk, sk);
    gen_wk(mk, wk);
    
    // 암호화 초기 변환
    pt[0] += wk[0];
    pt[2] ^= wk[1];
    pt[4] += wk[2];
    pt[6] ^= wk[3];

    printf("Initial = ");
    for(int i=0; i<8; i++){
        printf("%x", pt[i]);
    }
    printf("\n\n");

    // 라운드 함수
    uint8_t after[8] = { 0x00, };
    for(int i=0; i<31; i++){
        for(int i=0; i<4; i++){
            after[2*i+1] = pt[2*i];
        }
        after[0] = pt[7] ^ (fun0(pt[6]) + sk[4*i + 3]);
        after[2] = pt[1] + (fun1(pt[0]) ^ sk[4*i]);
        after[4] = pt[3] ^ (fun0(pt[2]) + sk[4*i + 1]);
        after[6] = pt[5] + (fun1(pt[4]) ^ sk[4*i + 2]);

        for(int i=0; i<8; i++){
            pt[i] = after[i];
            printf("%x", after[i]);
        }
        printf("\n");
    }

    // Round 32
    for(int i=0; i<8; i++){
        ct[i] = after[i];
    }

    ct[1] += (fun1(after[0]) ^ sk[124]);
    ct[3] ^= (fun0(after[2]) + sk[125]);
    ct[5] += (fun1(after[4]) ^ sk[126]);
    ct[7] ^= (fun0(after[6]) + sk[127]);

    // 최종변환
    ct[0] += wk[4];
    ct[2] ^= wk[5];
    ct[4] += wk[6];
    ct[6] ^= wk[7];
}
 


void decrypt(uint8_t dt[8], uint8_t ct[8], uint8_t mk[16]){
    // 서브키, 화이트닝키 생성
    uint8_t wk[8] = { 0x00, };
    uint8_t sk_p[128] = { 0x00, };
    
    gen_dec_sk(mk, sk_p);
    gen_wk(mk, wk);

    // 초기변환 (Round CT -> 32)
    ct[0] -= wk[4];
    ct[2] ^= wk[5];
    ct[4] -= wk[6];
    ct[6] ^= wk[7];

    // Round 32 -> 31
    ct[1] -= (fun1(ct[0]) ^ sk_p[3]);
    ct[3] ^= (fun0(ct[2]) + sk_p[2]);
    ct[5] -= (fun1(ct[4]) ^ sk_p[1]);
    ct[7] ^= (fun0(ct[6]) + sk_p[0]);

    printf("Round 31 = ");
    for(int i=0; i<8; i++){
        printf("%x", ct[i]);
    }
    printf("\n\n");

    // 복호화 (Round 30 -> 1)
    uint8_t after[8] = { 0x00, };
    for(int i=1; i<32; i++){
        for(int i=0; i<4; i++){
            after[2*i] = ct[2*i+1];
        }

        after[1] = ct[2] - (fun1(ct[1]) ^ sk_p[4*i + 3]);
        after[3] = ct[4] ^ (fun0(ct[3]) + sk_p[4*i + 2]);
        after[5] = ct[6] - (fun1(ct[5]) ^ sk_p[4*i + 1]);
        after[7] = ct[0] ^ (fun0(ct[7]) + sk_p[4*i]);

        for(int i=0; i<8; i++){
            ct[i] = after[i];
            printf("%x", after[i]);
        }
        printf("\n");

        // 최종변환
        for(int i=0; i<8; i++){
            dt[i] = ct[i];
        }
        dt[0] -= wk[0];
        dt[2] ^= wk[1];
        dt[4] -= wk[2];
        dt[6] ^= wk[3];
    }
}

void enc_show(uint8_t ct[8], uint8_t pt[8], uint8_t mk[16]){
    encrypt(ct, pt, mk);
    printf("\nct = ");
    for(int i=0; i<8; i++){
        printf("%02x", ct[i]);
    }
}

void dec_show(uint8_t dt[8], uint8_t ct[8], uint8_t mk[16]){
    decrypt(dt, ct, mk);
    printf("\ndt = ");
    for(int i=0; i<8; i++){
        printf("%02x", dt[i]);
    }
}

int main(){
    /* test vector1 
    uint8_t mk[16] = { 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00 };
    uint8_t pt[8] = { 0x00, };
    uint8_t ct[8] = {  0xf2, 0x03, 0x4f, 0xd9, 0xae, 0x18, 0xf4, 0x00 };
    */

    /* test vector2 
    uint8_t mk[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    uint8_t pt[8] = { 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00 };   // 평문
    uint8_t ct[8] = { 0xd8, 0xe6, 0x43, 0xe5, 0x72, 0x9f, 0xce, 0x23 };   // 암호문
    */

    /* test vector3 
    uint8_t mk[16] = { 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 };
    uint8_t pt[8] = { 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01 };
    uint8_t ct[8] = {  0x66, 0xf4, 0x23, 0x8d, 0xa2, 0xb2, 0x6f, 0x7a };
    */ 

    /* test vector4  
    uint8_t mk[16] = { 0xe7, 0x2b, 0x42, 0x1d, 0xb1, 0x09, 0xa5, 0xcf, 0x7d, 0xd8, 0xff, 0x49, 0xbc, 0xc3, 0xdb, 0x28 };
    uint8_t pt[8] = { 0x14, 0x4a, 0xa8, 0xeb, 0xe2, 0x6b, 0x1e, 0xb4 };
    uint8_t ct[8] = { 0xc6, 0x1f, 0x9c, 0x20, 0x75, 0x7a, 0x04, 0xcc };
    */

    uint8_t ct[8] = { 0x00, };
    uint8_t dt[8] = { 0x00, };

    uint8_t wk[8] = { 0x00, };     // 암호화 화이트닝키
    uint8_t sk[128] = { 0x00, };       // 암호화 서브키
    uint8_t delta;      // LFSR 델타 함수
        
    //gen_wk(mk, wk);
    // for(int i=0; i<8; i++){
    //     printf("%x\n", wk[i]);
    // }

    // gen_sk(mk, sk);
    // for(int i=0; i<128; i++){
    //     printf("sk[%d] = %x ", i, sk[i]);
    //     if(i%4==3){
    //         printf("\n");
    //     }
    // }

    // 암호화
    // enc_show(ct, pt, mk);

    // 복호화
    // dec_show(dt, ct, mk);
}