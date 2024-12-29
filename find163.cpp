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
#include "secp256k1/Int.h"
#include "hash/sha256.h"

Secp256K1 *secp = new Secp256K1();
Int *priv = new Int();
Point pubkey;

static const uint8_t target[20] = { // ripemd-160 cru da 163
    0x03,0x2d,0xdf,0x76,0xd2,
    0xad,0x15,0x2c,0xb5,0xb3,
    0x91,0xbf,0xba,0x3d,0x24,
    0x25,0x1a,0x65,0x48,0xdc
};


static uint8_t mutables[] = { // encontradas: 18 (letras 15 e 16 nao vao ser reveladas)
    0xf3,0x35,0xa0,0xcf,0x57,0x0e,0x40,0xb0,// essas duas ultimas nao serao reveladas por ele
    0xb1,0x7b,0x2a,0x60,0x86,0x70,0x86,0xa0,
    0x40,0x00,0x80,0x30,0x30,0x30,0x70,0x30,
};
static uint8_t pub[33];

void Init(){
    priv->SetQWord(3, 0x403b3d4fcff56a92);// valor fixo
    printf("%s\n","find 163 by Trindade v1\n Esse codigo é uma modificação do codigo do keyhunt");
    printf("Esse codigo faz a busca da chave privada que gera o rimpad da 163\n que é esse: 032ddf76d2ad152cb5b391bfba3d24251a6548dc ");
    printf("\nProcurando...\n");
    secp->Init();
}

uint8_t proximidade = 0; // conta quantos bytes foram iguais ao target na comparação
bool compare(){
    for (uint8_t i = 0; i < 20; i++) { // primeiro byte sempre igual
        if(pub[i] != target[i]) return false;
        proximidade = i;
    }
    return true;
}

unsigned char buf[14];  // Buffer para armazenar os 14 bytes aleatórios
void randomize(){
    getrandom(buf, sizeof(buf), GRND_NONBLOCK);
    mutables[6] |= buf[0]>>4;
    mutables[7] |= buf[1]>>4;
    mutables[11] |= buf[2]>>4;
    mutables[13] |= buf[3]>>4;
    mutables[15] |= buf[5]>>4;
    mutables[16] |= buf[6]>>4;
    mutables[17] |= buf[7]>>4;
    mutables[18] |= buf[8]>>4;
    mutables[19] |= buf[9]>>4;
    mutables[20] |= buf[10]>>4;
    mutables[21] |= buf[11]>>4;
    mutables[22] |= buf[12]>>4;
    mutables[23] |= buf[13]>>4;
}

void printArray(uint8_t *arr, size_t size){
    for (size_t i = 0; i < size; i++) {
        printf("%02x",arr[i]);
    }
    printf("\n");
}

int main(){
    Init();
    uint8_t maisProximo = 0;
    printf("Mais proximo encontrado:\n");

    inform: printf("\rBytes iguais %d:",maisProximo);
    start: randomize();
    priv->SetLower24Bytes((uint64_t*)mutables);
    pubkey = secp->ComputePublicKey(priv);
    secp->GetPubKeyHexCompressed(pubkey, pub);
    sha256_33(pub, pub);
    RIPEMD160(pub, 32, pub);

    if (compare()){
        printf("\nEncontrou!! %s\n", priv->GetBase16());
        return 0;
    }
    if (maisProximo < proximidade) {
        maisProximo = proximidade;
        goto inform;
    }
    goto start;
    return 0;
}
