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

#define printhex(a) printf("%lx\n",a); // Impressão de números hexadecimal facilitada
#define printdec(a) printf("%ld\n",a); // Impressão de números decimais facilitada

Secp256K1 *secp = new Secp256K1();
Point pubkey;

uint64_t progress = 0; // Progresso da busca

// Valor inicial da chave privada
uint8_t PRIVATEKEY[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    0x83, 0x2E, 0xD7, 0x4F, 0x2B, 0x5E, 0x35, 0xEE
};

// Limite superior da chave privada
const uint8_t MAX_PRIVATEKEY[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    0x83, 0x2E, 0xD7, 0x4F, 0x2B, 0x5F, 0x35, 0xEE
};

static const uint8_t TARGET[20] = { // RIPEMD-160 alvo
    0x20, 0xd4, 0x5a, 0x6a, 0x76, 0x25, 0x35, 0x70, 0x0c, 0xe9,
    0xe0, 0xb2, 0x16, 0xe3, 0x19, 0x94, 0x33, 0x5d, 0xb8, 0xa5
};

static uint8_t pub[33];

void Init(){
    secp->Init();
    printf("%s\n","find 163 by Trindade v1\n Esse código é uma modificação do código do keyhunt");
    printf("Esse código faz a busca da chave privada que gera o RIPEMD-160: 20d45a6a762535700ce9e0b216e31994335db8a5 \n");
    printf("Carteira para doações: bc1qlywys40f6p3njax5txf8lh4qs2hmt58nmsp5j7\n");
    printf("Procurando...\n");
}

bool compare(){
    uint8_t i = 19;
    while (pub[i] == TARGET[i] && i--);
    return i == 0xff;
}

bool is_within_range(uint8_t *current_key, const uint8_t *max_key) {
    for (int i = 0; i < 32; i++) {
        if (current_key[i] > max_key[i]) return false; // Fora do intervalo
        if (current_key[i] < max_key[i]) return true;  // Ainda dentro do intervalo
    }
    return true; // Igual ao limite superior
}

void increment(){
    for (int i = 31; i >= 0; i--) {
        if (++PRIVATEKEY[i] != 0) break;
    }
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

    printf("Velocidade: \n");
    bool procurando = true;

    while (procurando) {
        if (!is_within_range(PRIVATEKEY, MAX_PRIVATEKEY)) {
            printf("Intervalo de chaves esgotado.\n");
            break;
        }

        pubkey = secp->OptimizationPubKeyComp(PRIVATEKEY);
        secp->GetPubKeyHexCompressed(pubkey, pub);
        sha256_33(pub, pub);
        RIPEMD160(pub, 32, pub);

        if (compare()) {
            procurando = false; // Encontra e sai do loop
            printf("\nEncontrou!!\n");
            printArray(pub, 20); // Exibe o RIPEMD
            printArray(PRIVATEKEY, 32); // Exibe a chave privada
            break;
        }

        increment(); // Incrementa a chave privada
        contagem++;
        speed++;

        clock_gettime(CLOCK_MONOTONIC_RAW, &agora); // Marca o tempo atual
        double tempo_decorrido = (agora.tv_sec - inicio.tv_sec) +
                                 (agora.tv_nsec - inicio.tv_nsec) / 1e9; // Converte para segundos

        if (tempo_decorrido >= 10.0) {
            printf("Velocidade: %lu/s | Tentativas: %lu\n", speed / 10, contagem);
            clock_gettime(CLOCK_MONOTONIC_RAW, &inicio);
            speed = 0;
        }
    }

    return 0;
}
