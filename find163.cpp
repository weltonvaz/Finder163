/*
Develop by Alberto
email: albertobsd@gmail.com
Modified by Trindade
*/

// {4x,bx,6x,7x,4x,0x,8x,3x,3x,3x,7x,3x}
// {0x40,0xb0,0x60,0x70,0x40,0x00,0x80,0x30,0x30,0x30,0x70,0x30} os bytes para serem encontrados

// 01|02|03|04|05|06|07|08|09|10|11|12|13|14|15|16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31|32 <== indices
// 40|3B|3D|4F|cF|f5|6A|92|f3|35|a0|cF|57|0E|4x|bx|b1|7B|2A|6x|86|7x|86|a8|4x|0x|8x|3x|3-x>8|3x|7x|3x <== valores
// 0x403b3d4fcff56a92f335a0cf570e4xbxb17b2a6x867x86a84x0x8x3x3x3x7x3x
// 0x403b3d4fcff56a92f335a0cf570e40b0b17b2a60867086a84000803030307030
// 01-0
// 02-B
// 03-D
// 04-F
// 05-F
// 06-5
// 07-A
// 08-2
// 09-3
// 10-5
// 11-0
// 12-F
// 13-7
// 14-E
// 17-1
// 18-B
// 19-A
// 21-6
// 23-6
// 24-8
// 29>8 um numero maior que 8
// 31 = [31] - 3
// 32 = [30] + 3

#include <cstddef>
#include <ctime>
#include <openssl/ripemd.h>
#include <cstdint>
#include <cstdio>
#include <stdio.h>
#include <stdlib.h>
#include <sys/random.h>
#include <sys/types.h>
#include <chrono>
#include <ctime>
#include "stdbool.h"

#include "secp256k1/SECP256k1.h"
#include "secp256k1/Point.h"
#include "hash/sha256.h"
#include "secp256k1/Int.h"
// #include <xmath.h>

// #include <math.h>

#define printhex(a) printf("%lx\n",a); // impressao de numeros hexadecimal facilitada
#define printdec(a) printf("%ld\n",a); // impressao de numeros decimais facilitada

Secp256K1 *secp = new Secp256K1();
Point pubkey;

uint64_t progress = 0; // da pra por o progresso aqui
static const uint8_t TARGET[20] = { // ripemd-160 cru da 163
    0x03,0x2d,0xdf,0x76,0xd2,
    0xad,0x15,0x2c,0xb5,0xb3,
    0x91,0xbf,0xba,0x3d,0x24,
    0x25,0x1a,0x65,0x48,0xdc
};

//6eca335d9645307db441656ef4e65b4bfc579b27452bebc19bd870aa1118e5c3
uint8_t PRIVATEKEY[] = {
    0x40,0x3b,0x3d,0x4f,0xcf,0xf5,0x6a,0x92,
    0xf3,0x35,0xa0,0xcf,0x57,0x0e,0x40,0xb0,
    0xb1,0x7b,0x2a,0x60,0x86,0x70,0x86,0xa8,
    0x40,0x00,0x80,0x30,0x38,0x30,0x70,0x30
};

static uint8_t pub[33];
void Init(){
    secp->Init();
    printf("%s\n","find 163 by Trindade v1\n Esse codigo é uma modificação do codigo do keyhunt");
    printf("Esse codigo faz a busca da chave privada que gera o rimpad da 163\n que é esse: 032ddf76d2ad152cb5b391bfba3d24251a6548dc ");
    printf("\nCarteira para doações: bc1qlywys40f6p3njax5txf8lh4qs2hmt58nmsp5j7");
    printf("\nProcurando...\n");
}

bool compare(){
    uint8_t i = 19;
    while (pub[i] == TARGET[i] && i--);
    return i == 0xff;
}

void zerate(){
    const uint8_t f0 = 0xf0;
    PRIVATEKEY[14] &= f0;
    PRIVATEKEY[15] &= f0;
    PRIVATEKEY[19] &= f0;
    PRIVATEKEY[21] &= f0;
    PRIVATEKEY[24] &= f0;
    PRIVATEKEY[25] &= f0;
    PRIVATEKEY[26] &= f0;
    PRIVATEKEY[27] &= f0;
    PRIVATEKEY[28] = 0x38;  // 29 >= 8  maior ou igual por garantia
    PRIVATEKEY[29] &= f0;
    PRIVATEKEY[30] &= f0;
    PRIVATEKEY[31] &= f0;
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
    getrandom(&progress, 6, GRND_NONBLOCK);
    PRIVATEKEY[14] |= getL4BP(5);
    PRIVATEKEY[15] |= getH4BP(4);
    PRIVATEKEY[19] |= getL4BP(4);
    PRIVATEKEY[21] |= getH4BP(3);
    PRIVATEKEY[24] |= getL4BP(3);
    PRIVATEKEY[25] |= getH4BP(2);
    PRIVATEKEY[26] |= getL4BP(2);
    PRIVATEKEY[27] |= getH4BP(1);
    PRIVATEKEY[28] |= getL4BP(1);
    PRIVATEKEY[29] |= getH4BP(0);
    uint8_t b = getL4BP(0);// pega os 4 bits baixos do progress
    PRIVATEKEY[30] |= (b - 3); // [31] = [32] - 3
    PRIVATEKEY[31] |= b;
}
void increment(){
    zerate();
    progress++;
    PRIVATEKEY[14] |= getL4BP(5);
    PRIVATEKEY[15] |= getH4BP(4);
    PRIVATEKEY[19] |= getL4BP(4);
    PRIVATEKEY[21] |= getH4BP(3);
    PRIVATEKEY[24] |= getL4BP(3);
    PRIVATEKEY[25] |= getH4BP(2);
    PRIVATEKEY[26] |= getL4BP(2);
    PRIVATEKEY[27] |= getH4BP(1);
    PRIVATEKEY[28] |= getL4BP(1);
    PRIVATEKEY[29] |= getH4BP(0);
    uint8_t b = getL4BP(0);// pega os 4 bits baixos do progress
    PRIVATEKEY[30] |= (b - 3); // [31] = [32] - 3
    PRIVATEKEY[31] |= b;
}

void decrement(){
    zerate();
    progress--;
    PRIVATEKEY[14] |= getL4BP(0);
    PRIVATEKEY[15] |= getH4BP(0);
    PRIVATEKEY[19] |= getL4BP(1);
    PRIVATEKEY[21] |= getH4BP(1);
    PRIVATEKEY[24] |= getL4BP(2);
    PRIVATEKEY[25] |= getH4BP(2);
    PRIVATEKEY[26] |= getL4BP(3);
    PRIVATEKEY[27] |= getH4BP(3);
    PRIVATEKEY[29] |= getL4BP(4);
    PRIVATEKEY[30] |= getH4BP(4);
    PRIVATEKEY[31] |= getL4BP(5);
}
void normalDec(){
    zerate();
    progress--;
    PRIVATEKEY[14] |= getL4BP(5);
    PRIVATEKEY[15] |= getH4BP(4);
    PRIVATEKEY[19] |= getL4BP(4);
    PRIVATEKEY[21] |= getH4BP(3);
    PRIVATEKEY[24] |= getL4BP(3);
    PRIVATEKEY[25] |= getH4BP(2);
    PRIVATEKEY[26] |= getL4BP(2);
    PRIVATEKEY[27] |= getH4BP(1);
    PRIVATEKEY[28] |= getL4BP(1);
    PRIVATEKEY[29] |= getH4BP(0);
    uint8_t b = getL4BP(0);// pega os 4 bits baixos do progress
    PRIVATEKEY[30] |= (b - 3); // [31] = [32] - 3
    PRIVATEKEY[31] |= b;
}

void printArray(uint8_t *arr, size_t size){
    uint8_t i = 0;
    while (i < size) printf("%02x", arr[i++]);
    printf("\n");
}

int main(){
    Init();
    uint64_t speed = 0;
    uint64_t contagem = 0;

    struct timespec inicio, agora;
    clock_gettime(CLOCK_MONOTONIC_RAW, &inicio); // Marca o início do tempo

    printf("velocidade: \n");
    bool procurando = true;

    while (procurando) {
        // Esses sao os modos atuais, basta descomentar e testar.
        // Nenhum modo pode ser misturado com o outro ainda, um sobrepoe o outro se tentar.
        // randomize();
        // normalDec();
        // decrement();
        // increment();
        // normalDec();
        pubkey = secp->OptimizationPubKeyComp(PRIVATEKEY);
        secp->GetPubKeyHexCompressed(pubkey, pub);
        sha256_33(pub, pub);
        RIPEMD160(pub, 32, pub);
        if (compare()){
            procurando = false; // apenas para garantir a saida do programa.
            printf("\nEncontrou!!\n");
            printArray(pub, 20);// para conferir
            printArray(PRIVATEKEY, 32);
            break;
            // return 0;
        }
        contagem++;
        speed++;

        clock_gettime(CLOCK_MONOTONIC_RAW, &agora); // Marca o tempo atual
                double tempo_decorrido = (agora.tv_sec - inicio.tv_sec) +
                                         (agora.tv_nsec - inicio.tv_nsec) / 1e9; // Converte para segundos

        if (tempo_decorrido >= 10.0){
            printf("velocidade: %lu/s | tentativas: %lu\n", speed / 10, contagem);
            clock_gettime(CLOCK_MONOTONIC_RAW, &inicio);
            speed = 0;
        }
    }
    return 0;
}
