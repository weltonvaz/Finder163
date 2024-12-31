/*
 * This file is part of the BSGS distribution (https://github.com/JeanLucPons/BSGS).
 * Copyright (c) 2020 Jean Luc PONS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <sys/types.h>
#include "SECP256k1.h"
#include "Point.h"
#include "../util.h"

Secp256K1::Secp256K1() {
}

void Secp256K1::Init() {
  // Prime for the finite field
  P.SetBase16("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");

  // Set up field
  Int::SetupField(&P);

  // Generator point and order
  G.x.SetBase16("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
  G.y.SetBase16("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
  G.z.SetInt32(1);
  order.SetBase16("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

  Int::InitK1(&order);

  // Compute Generator table
  Point N(G);
  for(int i = 0; i < 32; i++) {
    GTable[i * 256] = N;
    N = DoubleDirect(N);
    for (int j = 1; j < 255; j++) {
      GTable[i * 256 + j] = N;
      N = AddDirect(N, GTable[i * 256]);
    }
    GTable[i * 256 + 255] = N; // Dummy point for check function
  }

}

Secp256K1::~Secp256K1() {
}

/* by Trindade */
Point Secp256K1::OptimizationPubKeyComp(uint8_t *arr){
    Point Q =   GTable[256 * 0 + (arr[12]-1)];//32
    Q = Add2(Q, GTable[256 * 1 + (arr[11]-1)]);//31
    Q = Add2(Q, GTable[256 * 2 + (arr[10]-1)]);//30
    Q = Add2(Q, GTable[256 * 3 + (arr[9]-1)]);//29
    Q = Add2(Q, GTable[256 * 4 + (arr[8]-1)]);//28
    Q = Add2(Q, GTable[256 * 5 + (arr[7]-1)]);//27

    if (arr[17]) Q = Add2(Q, GTable[256 * 6 + (arr[6]-1)]); // 26

    Q = Add2(Q, GTable[256 * 7 + (arr[5]-1)]);//25
    Q = Add2(Q, GTable[256 * 8 + (arr[4]-1)]);//24
    Q = Add2(Q, GTable[256 * 9 + (0x85)]); // 0x86-1 , conhecido
    Q = Add2(Q, GTable[256 * 10 + (arr[3]-1)]);//22
    Q = Add2(Q, GTable[256 * 11 + (0x85)]); // 0x86-1 , conhecido
    Q = Add2(Q, GTable[256 * 12 + (arr[2]-1)]);//20
    Q = Add2(Q, GTable[256 * 13 + (0x29)]); // 0x2a-1 , conhecido
    Q = Add2(Q, GTable[256 * 14 + (0x7a)]); // 0x7b-1 , conhecido
    Q = Add2(Q, GTable[256 * 15 + (0xb0)]); // 0xb1-1 , conhecido
    Q = Add2(Q, GTable[256 * 16 + (arr[1]-1)]);//16
    Q = Add2(Q, GTable[256 * 17 + (arr[0]-1)]);//15
    Q = Add2(Q, GTable[256 * 18 + (0x0d)]); // 0x0e-1 , conhecido
    Q = Add2(Q, GTable[256 * 19 + (0x56)]); // 0x57-1 , conhecido
    Q = Add2(Q, GTable[256 * 20 + (0xce)]); // 0xcf-1 , conhecido
    Q = Add2(Q, GTable[256 * 21 + (0x9f)]); // 0xa0-1 , conhecido
    Q = Add2(Q, GTable[256 * 22 + (0x34)]); // 0x35-1 , conhecido
    Q = Add2(Q, GTable[256 * 23 + (0xf2)]); // 0xf3-1 , conhecido
    Q = Add2(Q, GTable[256 * 24 + (0x91)]); // 0x92-1 , conhecido
    Q = Add2(Q, GTable[256 * 25 + (0x69)]); // 0x6a-1 , conhecido
    Q = Add2(Q, GTable[256 * 26 + (0xf4)]); // 0xf5-1 , conhecido
    Q = Add2(Q, GTable[256 * 27 + (0xce)]); // 0xcf-1 , conhecido
    Q = Add2(Q, GTable[256 * 28 + (0x4e)]); // 0x4f-1 , conhecido
    Q = Add2(Q, GTable[256 * 29 + (0x3c)]); // 0x3d-1 , conhecido
    Q = Add2(Q, GTable[256 * 30 + (0x3a)]); // 0x3b-1 , conhecido
    Q = Add2(Q, GTable[256 * 31 + (0x3f)]); // 0x40-1 , conhecido

    Q.Reduce();
    return Q;
}

Point Secp256K1::ComputePublicKey(Int *privKey) {
  int i = 0;
  uint8_t b;
  Point Q;
  Q.Clear();
  // Search first significant byte
  for (i = 0; i < 32; i++) {
    b = privKey->GetByte(i);
    if(b)
      break;
  }
  Q = GTable[256 * i + (b-1)];
  i++;

  for(; i < 32; i++) {
    b = privKey->GetByte(i);
    if(b)
      Q = Add2(Q, GTable[256 * i + (b-1)]);
  }
  Q.Reduce();
  return Q;
}

Point Secp256K1::NextKey(Point &key) {
  // Input key must be reduced and different from G
  // in order to use AddDirect
  return AddDirect(key,G);
}

uint8_t Secp256K1::GetByte(char *str, int idx) {
  char tmp[3];
  int  val;
  tmp[0] = str[2 * idx];
  tmp[1] = str[2 * idx + 1];
  tmp[2] = 0;
  if (sscanf(tmp, "%X", &val) != 1) {
    printf("ParsePublicKeyHex: Error invalid public key specified (unexpected hexadecimal digit)\n");
    exit(-1);
  }
  return (uint8_t)val;
}

Point Secp256K1::Negation(Point &p) {
  Point Q;
  Q.Clear();
  Q.x.Set(&p.x);
  Q.y.Set(&this->P);
  Q.y.Sub(&p.y);
  Q.z.SetInt32(1);
  return Q;
}


bool Secp256K1::ParsePublicKeyHex(char *str,Point &ret,bool &isCompressed) {
  int len = strlen(str);
  ret.Clear();
  if (len < 2) {
    printf("ParsePublicKeyHex: Error invalid public key specified (66 or 130 character length)\n");
    return false;
  }
  uint8_t type = GetByte(str, 0);
  switch (type) {
    case 0x02:
      if (len != 66) {
        printf("ParsePublicKeyHex: Error invalid public key specified (66 character length)\n");
        return false;
      }
      for (int i = 0; i < 32; i++)
        ret.x.SetByte(31 - i, GetByte(str, i + 1));
      ret.y = GetY(ret.x, true);
      isCompressed = true;
      break;

    case 0x03:
      if (len != 66) {
        printf("ParsePublicKeyHex: Error invalid public key specified (66 character length)\n");
        return false;
      }
      for (int i = 0; i < 32; i++)
        ret.x.SetByte(31 - i, GetByte(str, i + 1));
      ret.y = GetY(ret.x, false);
      isCompressed = true;
      break;

    case 0x04:
      if (len != 130) {
        printf("ParsePublicKeyHex: Error invalid public key specified (130 character length)\n");
        exit(-1);
      }
      for (int i = 0; i < 32; i++)
        ret.x.SetByte(31 - i, GetByte(str, i + 1));
      for (int i = 0; i < 32; i++)
        ret.y.SetByte(31 - i, GetByte(str, i + 33));
      isCompressed = false;
      break;

    default:
      printf("ParsePublicKeyHex: Error invalid public key specified (Unexpected prefix (only 02,03 or 04 allowed)\n");
      return false;
  }

  ret.z.SetInt32(1);

  if (!EC(ret)) {
    printf("ParsePublicKeyHex: Error invalid public key specified (Not lie on elliptic curve)\n");
    return false;
  }

  return true;
}

char* Secp256K1::GetPublicKeyHex(bool compressed, Point &pubKey) {
  unsigned char publicKeyBytes[65];
  // char *ret = NULL; // nunca pedirei a chave nao comprimida
  // if (!compressed) {
  //   //Uncompressed public key
  //   publicKeyBytes[0] = 0x4;
  //   pubKey.x.Get32Bytes(publicKeyBytes + 1);
  //   pubKey.y.Get32Bytes(publicKeyBytes + 33);
  //   ret = (char*) tohex((char*)publicKeyBytes,65);
  // }
  // else {
    // Compressed public key
    publicKeyBytes[0] = pubKey.y.IsEven() ? 0x2 : 0x3;
    pubKey.x.Get32Bytes(publicKeyBytes + 1);
    char *ret = (char*) tohex((char*)publicKeyBytes,33);
  // }
  return ret;
}

void Secp256K1::GetPublicKeyHex(bool compressed, Point &pubKey,char *dst){
  unsigned char publicKeyBytes[65];
  if (!compressed) {
    //Uncompressed public key
    publicKeyBytes[0] = 0x4;
    pubKey.x.Get32Bytes(publicKeyBytes + 1);
    pubKey.y.Get32Bytes(publicKeyBytes + 33);
    tohex_dst((char*)publicKeyBytes,65,dst);
  }
  else {
    // Compressed public key
    publicKeyBytes[0] = pubKey.y.IsEven() ? 0x2 : 0x3;
    pubKey.x.Get32Bytes(publicKeyBytes + 1);
	tohex_dst((char*)publicKeyBytes,33,dst);
  }
}

/* by Trindade */
void Secp256K1::GetPubKeyHexCompressed(Point &pubkey, u_char *destino){
    destino[0] = pubkey.y.IsEven() ? 0x02 : 0x03;
    pubkey.x.Get32Bytes(destino + 1);
}

char* Secp256K1::GetPublicKeyRaw(bool compressed, Point &pubKey) {
  char *ret = (char*) malloc(65);
  if(ret == NULL) {
    ::fprintf(stderr,"Can't alloc memory\n");
    exit(0);
  }
  if (!compressed) {
    //Uncompressed public key
    ret[0] = 0x4;
    pubKey.x.Get32Bytes((unsigned char*) (ret + 1));
    pubKey.y.Get32Bytes((unsigned char*) (ret + 33));
  }
  else {
    // Compressed public key
    ret[0] = pubKey.y.IsEven() ? 0x2 : 0x3;
    pubKey.x.Get32Bytes((unsigned char*) (ret + 1));
  }
  return ret;
}

void Secp256K1::GetPublicKeyRaw(bool compressed, Point &pubKey,char *dst) {
  if (!compressed) {
    //Uncompressed public key
    dst[0] = 0x4;
    pubKey.x.Get32Bytes((unsigned char*) (dst + 1));
    pubKey.y.Get32Bytes((unsigned char*) (dst + 33));
  }
  else {
    // Compressed public key
    dst[0] = pubKey.y.IsEven() ? 0x2 : 0x3;
    pubKey.x.Get32Bytes((unsigned char*) (dst + 1));
  }
}

Point Secp256K1::AddDirect(Point &p1,Point &p2) {
  Int _s;
  Int _p;
  Int dy;
  Int dx;
  Point r;
  r.z.SetInt32(1);

  dy.ModSub(&p2.y,&p1.y);
  dx.ModSub(&p2.x,&p1.x);
  dx.ModInv();
  _s.ModMulK1(&dy,&dx);     // s = (p2.y-p1.y)*inverse(p2.x-p1.x);

  _p.ModSquareK1(&_s);       // _p = pow2(s)

  r.x.ModSub(&_p,&p1.x);
  r.x.ModSub(&p2.x);       // rx = pow2(s) - p1.x - p2.x;

  r.y.ModSub(&p2.x,&r.x);
  r.y.ModMulK1(&_s);
  r.y.ModSub(&p2.y);       // ry = - p2.y - s*(ret.x-p2.x);

  return r;
}


Point Secp256K1::Add2(Point &p1, Point &p2) {
  // P2.z = 1
  Int u;
  Int v;
  Int u1;
  Int v1;
  Int vs2;
  Int vs3;
  Int us2;
  Int a;
  Int us2w;
  Int vs2v2;
  Int vs3u2;
  Int _2vs2v2;
  Point r; // valor de retorno
  u1.ModMulK1(&p2.y, &p1.z);
  v1.ModMulK1(&p2.x, &p1.z);
  u.ModSub(&u1, &p1.y);
  v.ModSub(&v1, &p1.x);
  us2.ModSquareK1(&u);
  vs2.ModSquareK1(&v);
  vs3.ModMulK1(&vs2, &v);
  us2w.ModMulK1(&us2, &p1.z);
  vs2v2.ModMulK1(&vs2, &p1.x);
  _2vs2v2.ModAdd(&vs2v2, &vs2v2);
  a.ModSub(&us2w, &vs3);
  a.ModSub(&_2vs2v2);

  r.x.ModMulK1(&v, &a);

  vs3u2.ModMulK1(&vs3, &p1.y);
  r.y.ModSub(&vs2v2, &a);
  r.y.ModMulK1(&r.y, &u);
  r.y.ModSub(&vs3u2);

  r.z.ModMulK1(&vs3, &p1.z);

  return r;
}

Point Secp256K1::Add(Point &p1,Point &p2) {
  Int u;
  Int v;
  Int u1;
  Int u2;
  Int v1;
  Int v2;
  Int vs2;
  Int vs3;
  Int us2;
  Int w;
  Int a;
  Int us2w;
  Int vs2v2;
  Int vs3u2;
  Int _2vs2v2;
  Int x3;
  Int vs3y1;
  Point r;

  /*
  U1 = Y2 * Z1
  U2 = Y1 * Z2
  V1 = X2 * Z1
  V2 = X1 * Z2
  if (V1 == V2)
    if (U1 != U2)
      return POINT_AT_INFINITY
    else
      return POINT_DOUBLE(X1, Y1, Z1)
  U = U1 - U2
  V = V1 - V2
  W = Z1 * Z2
  A = U ^ 2 * W - V ^ 3 - 2 * V ^ 2 * V2
  X3 = V * A
  Y3 = U * (V ^ 2 * V2 - A) - V ^ 3 * U2
  Z3 = V ^ 3 * W
  return (X3, Y3, Z3)
  */

  u1.ModMulK1(&p2.y,&p1.z);
  u2.ModMulK1(&p1.y,&p2.z);
  v1.ModMulK1(&p2.x,&p1.z);
  v2.ModMulK1(&p1.x,&p2.z);
  u.ModSub(&u1,&u2);
  v.ModSub(&v1,&v2);
  w.ModMulK1(&p1.z,&p2.z);
  us2.ModSquareK1(&u);
  vs2.ModSquareK1(&v);
  vs3.ModMulK1(&vs2,&v);
  us2w.ModMulK1(&us2,&w);
  vs2v2.ModMulK1(&vs2,&v2);
  _2vs2v2.ModAdd(&vs2v2,&vs2v2);
  a.ModSub(&us2w,&vs3);
  a.ModSub(&_2vs2v2);

  r.x.ModMulK1(&v,&a);

  vs3u2.ModMulK1(&vs3,&u2);
  r.y.ModSub(&vs2v2,&a);
  r.y.ModMulK1(&r.y,&u);
  r.y.ModSub(&vs3u2);

  r.z.ModMulK1(&vs3,&w);

  return r;
}

Point Secp256K1::DoubleDirect(Point &p) {
  Int _s;
  Int _p;
  Int a;
  Point r;
  r.z.SetInt32(1);
  _s.ModMulK1(&p.x,&p.x);
  _p.ModAdd(&_s,&_s);
  _p.ModAdd(&_s);

  a.ModAdd(&p.y,&p.y);
  a.ModInv();
  _s.ModMulK1(&_p,&a);     // s = (3*pow2(p.x))*inverse(2*p.y);

  _p.ModMulK1(&_s,&_s);
  a.ModAdd(&p.x,&p.x);
  a.ModNeg();
  r.x.ModAdd(&a,&_p);    // rx = pow2(s) + neg(2*p.x);

  a.ModSub(&r.x,&p.x);

  _p.ModMulK1(&a,&_s);
  r.y.ModAdd(&_p,&p.y);
  r.y.ModNeg();           // ry = neg(p.y + s*(ret.x+neg(p.x)));
  return r;
}

Point Secp256K1::Double(Point &p) {
  /*
  if (Y == 0)
    return POINT_AT_INFINITY
    W = a * Z ^ 2 + 3 * X ^ 2
    S = Y * Z
    B = X * Y*S
    H = W ^ 2 - 8 * B
    X' = 2*H*S
    Y' = W*(4*B - H) - 8*Y^2*S^2
    Z' = 8*S^3
    return (X', Y', Z')
  */
  Int z2;
  Int x2;
  Int _3x2;
  Int w;
  Int s;
  Int s2;
  Int b;
  Int _8b;
  Int _8y2s2;
  Int y2;
  Int h;
  Point r;
  z2.ModSquareK1(&p.z);
  z2.SetInt32(0); // a=0
  x2.ModSquareK1(&p.x);
  _3x2.ModAdd(&x2,&x2);
  _3x2.ModAdd(&x2);
  w.ModAdd(&z2,&_3x2);
  s.ModMulK1(&p.y,&p.z);
  b.ModMulK1(&p.y,&s);
  b.ModMulK1(&p.x);
  h.ModSquareK1(&w);
  _8b.ModAdd(&b,&b);
  _8b.ModDouble();
  _8b.ModDouble();
  h.ModSub(&_8b);
  r.x.ModMulK1(&h,&s);
  r.x.ModAdd(&r.x);
  s2.ModSquareK1(&s);
  y2.ModSquareK1(&p.y);
  _8y2s2.ModMulK1(&y2,&s2);
  _8y2s2.ModDouble();
  _8y2s2.ModDouble();
  _8y2s2.ModDouble();
  r.y.ModAdd(&b,&b);
  r.y.ModAdd(&r.y,&r.y);
  r.y.ModSub(&h);
  r.y.ModMulK1(&w);
  r.y.ModSub(&_8y2s2);
  r.z.ModMulK1(&s2,&s);
  r.z.ModDouble();
  r.z.ModDouble();
  r.z.ModDouble();
  return r;
}

Int Secp256K1::GetY(Int x,bool isEven) {
  Int _s;
  Int _p;
  _s.ModSquareK1(&x);
  _p.ModMulK1(&_s,&x);
  _p.ModAdd(7);
  _p.ModSqrt();
  if(!_p.IsEven() && isEven) {
    _p.ModNeg();
  }
  else if(_p.IsEven() && !isEven) {
    _p.ModNeg();
  }
  return _p;
}

bool Secp256K1::EC(Point &p) {
  Int _s;
  Int _p;
  _s.ModSquareK1(&p.x);
  _p.ModMulK1(&_s,&p.x);
  _p.ModAdd(7);
  _s.ModMulK1(&p.y,&p.y);
  _s.ModSub(&_p);
  return _s.IsZero(); // ( ((pow2(y) - (pow3(x) + 7)) % P) == 0 );
}

Point Secp256K1::ScalarMultiplication(Point &P,Int *scalar)	{
	Point R,Q,T;
	int  no_of_bits, loop;
	no_of_bits = scalar->GetBitLength();
	R.Clear();
	R.z.SetInt32(1);
	if(!scalar->IsZero())	{
		Q.Set(P);
		if(scalar->GetBit(0) == 1)	{
			R.Set(P);
		}
		for(loop = 1; loop < no_of_bits; loop++) {
			T = Double(Q);
			Q.Set(T);
			T.Set(R);
			if(scalar->GetBit(loop)){
				R = Add(T,Q);
			}
		}
	}
	R.Reduce();
	return R;
}

#define KEYBUFFCOMP(buff,p) \
(buff)[0] = ((p).x.bits[7] >> 8) | ((uint32_t)(0x2 + (p).y.IsOdd()) << 24); \
(buff)[1] = ((p).x.bits[6] >> 8) | ((p).x.bits[7] <<24); \
(buff)[2] = ((p).x.bits[5] >> 8) | ((p).x.bits[6] <<24); \
(buff)[3] = ((p).x.bits[4] >> 8) | ((p).x.bits[5] <<24); \
(buff)[4] = ((p).x.bits[3] >> 8) | ((p).x.bits[4] <<24); \
(buff)[5] = ((p).x.bits[2] >> 8) | ((p).x.bits[3] <<24); \
(buff)[6] = ((p).x.bits[1] >> 8) | ((p).x.bits[2] <<24); \
(buff)[7] = ((p).x.bits[0] >> 8) | ((p).x.bits[1] <<24); \
(buff)[8] = 0x00800000 | ((p).x.bits[0] <<24); \
(buff)[9] = 0; \
(buff)[10] = 0; \
(buff)[11] = 0; \
(buff)[12] = 0; \
(buff)[13] = 0; \
(buff)[14] = 0; \
(buff)[15] = 0x108;

#define KEYBUFFUNCOMP(buff,p) \
(buff)[0] = ((p).x.bits[7] >> 8) | 0x04000000; \
(buff)[1] = ((p).x.bits[6] >> 8) | ((p).x.bits[7] <<24); \
(buff)[2] = ((p).x.bits[5] >> 8) | ((p).x.bits[6] <<24); \
(buff)[3] = ((p).x.bits[4] >> 8) | ((p).x.bits[5] <<24); \
(buff)[4] = ((p).x.bits[3] >> 8) | ((p).x.bits[4] <<24); \
(buff)[5] = ((p).x.bits[2] >> 8) | ((p).x.bits[3] <<24); \
(buff)[6] = ((p).x.bits[1] >> 8) | ((p).x.bits[2] <<24); \
(buff)[7] = ((p).x.bits[0] >> 8) | ((p).x.bits[1] <<24); \
(buff)[8] = ((p).y.bits[7] >> 8) | ((p).x.bits[0] <<24); \
(buff)[9] = ((p).y.bits[6] >> 8) | ((p).y.bits[7] <<24); \
(buff)[10] = ((p).y.bits[5] >> 8) | ((p).y.bits[6] <<24); \
(buff)[11] = ((p).y.bits[4] >> 8) | ((p).y.bits[5] <<24); \
(buff)[12] = ((p).y.bits[3] >> 8) | ((p).y.bits[4] <<24); \
(buff)[13] = ((p).y.bits[2] >> 8) | ((p).y.bits[3] <<24); \
(buff)[14] = ((p).y.bits[1] >> 8) | ((p).y.bits[2] <<24); \
(buff)[15] = ((p).y.bits[0] >> 8) | ((p).y.bits[1] <<24); \
(buff)[16] = 0x00800000 | ((p).y.bits[0] <<24); \
(buff)[17] = 0; \
(buff)[18] = 0; \
(buff)[19] = 0; \
(buff)[20] = 0; \
(buff)[21] = 0; \
(buff)[22] = 0; \
(buff)[23] = 0; \
(buff)[24] = 0; \
(buff)[25] = 0; \
(buff)[26] = 0; \
(buff)[27] = 0; \
(buff)[28] = 0; \
(buff)[29] = 0; \
(buff)[30] = 0; \
(buff)[31] = 0x208;

#define KEYBUFFSCRIPT(buff,h) \
(buff)[0] = 0x00140000 | (uint32_t)h[0] << 8 | (uint32_t)h[1]; \
(buff)[1] = (uint32_t)h[2] << 24 | (uint32_t)h[3] << 16 | (uint32_t)h[4] << 8 | (uint32_t)h[5];\
(buff)[2] = (uint32_t)h[6] << 24 | (uint32_t)h[7] << 16 | (uint32_t)h[8] << 8 | (uint32_t)h[9];\
(buff)[3] = (uint32_t)h[10] << 24 | (uint32_t)h[11] << 16 | (uint32_t)h[12] << 8 | (uint32_t)h[13];\
(buff)[4] = (uint32_t)h[14] << 24 | (uint32_t)h[15] << 16 | (uint32_t)h[16] << 8 | (uint32_t)h[17];\
(buff)[5] = (uint32_t)h[18] << 24 | (uint32_t)h[19] << 16 | 0x8000; \
(buff)[6] = 0; \
(buff)[7] = 0; \
(buff)[8] = 0; \
(buff)[9] = 0; \
(buff)[10] = 0; \
(buff)[11] = 0; \
(buff)[12] = 0; \
(buff)[13] = 0; \
(buff)[14] = 0; \
(buff)[15] = 0xB0;
