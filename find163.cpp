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
#include <fstream>
#include <cstring> // Para usar memcmp
#include <sstream> // Para manipulação de strings
#include <iomanip> // Para std::setw e std::setfill

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
    0x83, 0x2e, 0xd7, 0x4f, 0x2b, 0x5e, 0x35, 0xee
};

// Limite superior da chave privada
const uint8_t MAX_PRIVATEKEY[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    0x83, 0x2e, 0xd7, 0x4f, 0x2b, 0x5f, 0x35, 0xff
};

// RIPEMD-160 alvo (em minúsculas)
static const uint8_t TARGET[20] = {
    0xd0, 0xaa, 0x90, 0x17, 0xf7, 0x4d, 0x7a, 0xd6, 0x87, 0x67,
    0x27, 0xf9, 0xec, 0x44, 0xa5, 0x69, 0x6a, 0x3e, 0x41, 0xcc
};

static uint8_t pub[33];

void Init(){
    secp->Init();
    printf("%s\n","find 163 by Trindade v1\n Esse código é uma modificação do código do keyhunt");
    printf("Esse código faz a busca da chave privada que gera o RIPEMD-160: ");
    for (int i = 0; i < 20; i++) {
        printf("%02x", TARGET[i]);
    }
    printf("\nProcurando...\n");
}

bool compare(){
    for (int i = 0; i < 20; i++) {
        if (pub[i] != TARGET[i]) return false;
    }
    return true;
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

std::string toHexString(uint8_t *data, size_t size) {
    std::stringstream ss;
    for (size_t i = 0; i < size; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    return ss.str();
}

void saveToFile(const char* filename, uint8_t* privateKey, uint8_t* rmd160) {
    std::ofstream file(filename);
    if (file.is_open()) {
        file << "Chave Privada: " << toHexString(privateKey, 32) << "\n";
        file << "RIPEMD-160: " << toHexString(rmd160, 20) << "\n";
        file.close();
    } else {
        printf("Erro ao salvar o arquivo.\n");
    }
}

void logActivity(const char* message, uint8_t* privateKey) {
    std::ofstream logFile("activity_log.txt", std::ios::app);
    if (logFile.is_open()) {
        logFile << message << toHexString(privateKey, 32) << "\n";
        logFile.close();
    } else {
        printf("Erro ao salvar o log de atividades.\n");
    }
}

int main(){
    Init();
    uint64_t speed = 0;
    uint64_t contagem = 0;

    struct timespec inicio, agora;
    clock_gettime(CLOCK_MONOTONIC_RAW, &inicio); // Marca o início do tempo

    printf("Velocidade: \n");
    bool procurando = true;

    // Log inicial
    logActivity("Iniciando busca. Chave privada inicial: ", PRIVATEKEY);

    while (procurando) {
        if (!is_within_range(PRIVATEKEY, MAX_PRIVATEKEY)) {
            printf("Intervalo de chaves esgotado.\n");
            logActivity("Intervalo de chaves esgotado. Última chave privada: ", PRIVATEKEY);
            break;
        }

        pubkey = secp->OptimizationPubKeyComp(PRIVATEKEY);
        secp->GetPubKeyHexCompressed(pubkey, pub);
        sha256_33(pub, pub);
        RIPEMD160(pub, 32, pub);

        if (compare()) {
            procurando = false; // Encontra e sai do loop
            printf("\nEncontrou!!\n");
            printf("RIPEMD-160: ");
            printArray(pub, 20); // Exibe o RIPEMD
            printf("Chave Privada: ");
            printArray(PRIVATEKEY, 32); // Exibe a chave privada

            // Salva o resultado no arquivo
            saveToFile("KEYFOUND.txt", PRIVATEKEY, pub);
            logActivity("Chave privada encontrada: ", PRIVATEKEY);
            break;
        }

        increment(); // Incrementa a chave privada
        contagem++;
        speed++;

        // Log da chave privada atual
        if (contagem % 1000 == 0) {
            logActivity("Tentativa atual: ", PRIVATEKEY);
        }

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