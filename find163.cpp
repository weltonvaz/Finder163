/*
Develop by Alberto
email: albertobsd@gmail.com
Modified by Trindade
*/

#include <cstddef>
#include <ctime>
#include <openssl/ripemd.h>
#include <cstdint>
#include <cstdio>
#include <stdio.h>
#include <stdlib.h>
#include <sys/random.h>
#include <sys/types.h>

#include "secp256k1/SECP256k1.h"
#include "secp256k1/Point.h"
#include "hash/sha256.h"

#define printhex(a) printf("%lx\n",a); // impressao de numeros hexadecimal facilitada
#define printdec(a) printf("%ld\n",a); // impressao de numeros decimais facilitada

Secp256K1 *secp = new Secp256K1();
Point pubkey;
uint64_t progress = 0x0;

static const uint8_t target[20] = { // ripemd-160 cru da 163
    0x03,0x2d,0xdf,0x76,0xd2,
    0xad,0x15,0x2c,0xb5,0xb3,
    0x91,0xbf,0xba,0x3d,0x24,
    0x25,0x1a,0x65,0x48,0xdc
};

// 15,16,20,22,24,25,26,27,28,29,30,31,32
uint8_t mutables[] = {// esses sao os bytes que ainda nao foram encontrados
    0x40,0xb0,0x60,0x70,0xa0,0x40,0x00,0x80,0x30,0x30,0x30,0x70,0x30
};

static uint8_t pub[33];

void Init(){
    secp->Init();
    printf("%s\n","find 163 by Trindade v1\n Esse codigo é uma modificação do codigo do keyhunt");
    printf("Esse codigo faz a busca da chave privada que gera o rimpad da 163\n que é esse: 032ddf76d2ad152cb5b391bfba3d24251a6548dc ");
    printf("Carteira para doações: bc1qlywys40f6p3njax5txf8lh4qs2hmt58nmsp5j7");
    printf("\nProcurando...\n");
}

bool compare(){
    uint8_t i = 19;
    while (pub[i] == target[i] && i--);
    return i == 0xff;
}

const uint8_t f0 = 0xf0;
void zerate(){
    mutables[0] &= f0;
    mutables[1] &= f0;
    mutables[2] &= f0;
    mutables[3] &= f0;
    mutables[4] &= f0;
    mutables[5] &= f0;
    mutables[6] &= f0;
    mutables[7] &= f0;
    mutables[8] &= f0;
    mutables[9] &= f0;
    mutables[10] &= f0;
    mutables[11] &= f0;
    mutables[12] &= f0;
}

uint8_t *bP = (uint8_t*)&progress;
uint8_t getL4BP(uint8_t index){// pega os 4 bits baixos do progress
    return bP[index] & 0x0f;
}
uint8_t getH4BP(uint8_t index){// pega os 4 bits altos do progress
    return (bP[index] & 0xf0) >> 4;
}

void randomize(){
    zerate();
    getrandom(&progress, 8, GRND_NONBLOCK);
    mutables[12] |= getL4BP(0);
    mutables[11] |= getH4BP(0);
    mutables[10] |= getL4BP(1);
    mutables[9]  |= getH4BP(1);
    mutables[8] |= getL4BP(2);
    mutables[7]  |= getH4BP(2);
    mutables[6] |= getL4BP(3);
    mutables[5]  |= getH4BP(3);
    mutables[4] |= getL4BP(4);
    mutables[3]  |= getH4BP(4);
    mutables[2] |= getL4BP(5);
    mutables[1]  |= getH4BP(5);
    mutables[0] |= getL4BP(6);
}
void increment(){
    zerate();
    progress++;
    mutables[12] |= getL4BP(0);
    mutables[11] |= getH4BP(0);
    mutables[10] |= getL4BP(1);
    mutables[9]  |= getH4BP(1);
    mutables[8] |= getL4BP(2);
    mutables[7]  |= getH4BP(2);
    mutables[6] |= getL4BP(3);
    mutables[5]  |= getH4BP(3);
    mutables[4] |= getL4BP(4);
    mutables[3]  |= getH4BP(4);
    mutables[2] |= getL4BP(5);
    mutables[1]  |= getH4BP(5);
    mutables[0] |= getL4BP(6);
}
void decrement(){
    zerate();
    progress--;
    mutables[0] |= getL4BP(0);
    mutables[1] |= getH4BP(0);
    mutables[2] |= getL4BP(1);
    mutables[3]  |= getH4BP(1);
    mutables[4] |= getL4BP(2);
    mutables[5]  |= getH4BP(2);
    mutables[6] |= getL4BP(3);
    mutables[7]  |= getH4BP(3);
    mutables[8] |= getL4BP(4);
    mutables[9]  |= getH4BP(4);
    mutables[10] |= getL4BP(5);
    mutables[11]  |= getH4BP(5);
    mutables[12] |= getL4BP(6);
}

void printArray(uint8_t *arr, size_t size){
    uint8_t i = 0;
    while (i < size) printf("%02x", arr[i++]);
}

int main(){
    Init();

    while (true) {
        // Esses sao os modos atuais, basta descomentar e testar.
        // Nenhum modo pode ser misturado com o outro ainda, um sobrepoe o outro se tentar.
        // randomize();
        // increment();
        // decrement();
        pubkey = secp->OptimizationPubKeyComp(mutables);
        secp->GetPubKeyHexCompressed(pubkey, pub);
        sha256_33(pub, pub);
        RIPEMD160(pub, 32, pub);
        if (compare()){
            printf("\nEncontrou!!\n");
            printf("Esses sao os bytes que estavam faltando:\n");
            printArray(mutables, 13);
            return 0;
        }
        // para mostrar os bytes mudando no terminal, basta descomentar essa linha de baixo
        printArray(mutables, 13); printf("\r");
    }
    return 0;
}
