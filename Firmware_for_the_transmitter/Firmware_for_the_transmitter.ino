/*
The Black Swan Project
Distributed under the MIT License
© Copyright Maxim Bortnikov 2022
For more information please visit
https://github.com/Northstrix/Black_Swan
Required libraries:
https://github.com/zhouyangchao/AES
https://github.com/peterferrie/serpent
https://github.com/ulwanski/sha512
https://github.com/marvinroger/ESP8266TrueRandom
https://github.com/adafruit/Adafruit-ST7735-Library
https://github.com/adafruit/Adafruit-GFX-Library
https://github.com/adafruit/Adafruit_BusIO
https://github.com/platisd/nokia-5110-lcd-library
https://github.com/GyverLibs/GyverBus
https://github.com/PaulStoffregen/PS2Keyboard
https://github.com/fcgdam/DES_Library
*/
#include <SoftwareSerial.h>
#include "aes.h"
#include "serpent.h"
#include <ESP8266TrueRandom.h>
#include <ESP8266WiFi.h>
#include <espnow.h>
#include "GBUS.h"
#include <Adafruit_GFX.h>
#include <Adafruit_ST7735.h>
#include <DES.h>
#include <FS.h>
#define TFT_CS         D2
#define TFT_RST        D3
#define TFT_DC         D4
Adafruit_ST7735 tft = Adafruit_ST7735(TFT_CS, TFT_DC, TFT_RST);
SoftwareSerial mySerial(5, 16); // RX, TX
GBUS bus(&mySerial, 3, 25);
char ch;
int pr_key;
struct myStruct {
  char x;
};
DES des;
int count;
byte tmp_st[8];
char temp_st_for_pp[16];
int m;
bool n;
String keyb_inp;

char *keys[] = {"cc21ef3bc7e2b541dbfeb27d13d091345f84ad39d5ffd2bc030fafecde883c2f"}; // Serpent's key
uint8_t projection_key[32] = {
0xd4,0x7c,0x88,0xf2,
0x77,0x69,0xbf,0x7b,
0x7a,0x7b,0x78,0x46,
0xe3,0x4d,0x1d,0xe2,
0xd4,0xdd,0xbb,0x14,
0x7b,0xc8,0x2c,0x5f,
0x70,0x6d,0x95,0x30,
0x0f,0xf2,0x99,0xce
};
byte TDESkey[] = {
0x4e,0x6e,0xca,0x4b,
0x2b,0xc7,0xe8,0xdc,
0xaa,0x5e,0x7a,0x7c,
0x68,0xe4,0xd7,0x18,
0x39,0x79,0xda,0x62,
0xfa,0x96,0x4d,0x1f
};
byte Setkey[] = {
0x73,0x03,0x4c,0x4e,
0x9a,0xfc,0x6b,0x7e,
0x15,0xf3,0x41,0xca,
0x13,0x99,0x3a,0x95,
0xba,0x5b,0xe4,0x33,
0xec,0x11,0xce,0x86
};

uint8_t broadcastAddress[] = {0x5C, 0xCF, 0x7F, 0xFD, 0x85, 0x1D};

typedef struct struct_message {
  char l_srp[16];
  char r_srp[16];
  bool n;
} struct_message;

struct_message myData;

uint8_t Forward_S_Box[16][16] = {  
    {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},  
    {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},  
    {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},  
    {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},  
    {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},  
    {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},  
    {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},  
    {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},  
    {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},  
    {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},  
    {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},  
    {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},  
    {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},  
    {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},  
    {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},  
    {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}  
};


void OnDataSent(uint8_t *mac_addr, uint8_t sendStatus) {
  Serial.print("Last Packet Send Status: ");
  if (sendStatus == 0){
    Serial.println("Delivery success");
  }
  else{
    Serial.println("Delivery fail");
  }
}

void incr_projection_key(){
  if(projection_key[0] == 255){
    projection_key[0] = 0;
    if(projection_key[1] == 255){
      projection_key[1] = 0;
      if(projection_key[2] == 255){
        projection_key[2] = 0;
        if(projection_key[3] == 255){
          projection_key[3] = 0;

  if(projection_key[4] == 255){
    projection_key[4] = 0;
    if(projection_key[5] == 255){
      projection_key[5] = 0;
      if(projection_key[6] == 255){
        projection_key[6] = 0;
        if(projection_key[7] == 255){
          projection_key[7] = 0;
          
  if(projection_key[8] == 255){
    projection_key[8] = 0;
    if(projection_key[9] == 255){
      projection_key[9] = 0;
      if(projection_key[10] == 255){
        projection_key[10] = 0;
        if(projection_key[11] == 255){
          projection_key[11] = 0;

  if(projection_key[12] == 255){
    projection_key[12] = 0;
    if(projection_key[13] == 255){
      projection_key[13] = 0;
      if(projection_key[14] == 255){
        projection_key[14] = 0;
        if(projection_key[15] == 255){
          projection_key[15] = 0;
        }
        else{
          projection_key[15]++;
        }
        }
      else{
        projection_key[14]++;
      }
    }
    else{
      projection_key[13]++;
    }
  }
  else{
    projection_key[12]++;
  }
          
        }
        else{
          projection_key[11]++;
        }
        }
      else{
        projection_key[10]++;
      }
    }
    else{
      projection_key[9]++;
    }
  }
  else{
    projection_key[8]++;
  }
          
        }
        else{
          projection_key[7]++;
        }
        }
      else{
        projection_key[6]++;
      }
    }
    else{
      projection_key[5]++;
    }
  }
  else{
    projection_key[4]++;
  }
          
        }
        else{
          projection_key[3]++;
        }
        }
      else{
        projection_key[2]++;
      }
    }
    else{
      projection_key[1]++;
    }
  }
  else{
    projection_key[0]++;
  }
}

void incr_TDESkey(){
  if(TDESkey[0] == 255){
    TDESkey[0] = 0;
    if(TDESkey[1] == 255){
      TDESkey[1] = 0;
      if(TDESkey[2] == 255){
        TDESkey[2] = 0;
        if(TDESkey[3] == 255){
          TDESkey[3] = 0;

  if(TDESkey[4] == 255){
    TDESkey[4] = 0;
    if(TDESkey[5] == 255){
      TDESkey[5] = 0;
      if(TDESkey[6] == 255){
        TDESkey[6] = 0;
        if(TDESkey[7] == 255){
          TDESkey[7] = 0;
          
  if(TDESkey[8] == 255){
    TDESkey[8] = 0;
    if(TDESkey[9] == 255){
      TDESkey[9] = 0;
      if(TDESkey[10] == 255){
        TDESkey[10] = 0;
        if(TDESkey[11] == 255){
          TDESkey[11] = 0;

  if(TDESkey[12] == 255){
    TDESkey[12] = 0;
    if(TDESkey[13] == 255){
      TDESkey[13] = 0;
      if(TDESkey[14] == 255){
        TDESkey[14] = 0;
        if(TDESkey[15] == 255){
          TDESkey[15] = 0;
        }
        else{
          TDESkey[15]++;
        }
        }
      else{
        TDESkey[14]++;
      }
    }
    else{
      TDESkey[13]++;
    }
  }
  else{
    TDESkey[12]++;
  }
          
        }
        else{
          TDESkey[11]++;
        }
        }
      else{
        TDESkey[10]++;
      }
    }
    else{
      TDESkey[9]++;
    }
  }
  else{
    TDESkey[8]++;
  }
          
        }
        else{
          TDESkey[7]++;
        }
        }
      else{
        TDESkey[6]++;
      }
    }
    else{
      TDESkey[5]++;
    }
  }
  else{
    TDESkey[4]++;
  }
          
        }
        else{
          TDESkey[3]++;
        }
        }
      else{
        TDESkey[2]++;
      }
    }
    else{
      TDESkey[1]++;
    }
  }
  else{
    TDESkey[0]++;
  }
}

int gen_r_num(){
  int rn = ESP8266TrueRandom.random(0,256);
  return rn;
}

int getNum(char ch)
{
    int num=0;
    if(ch>='0' && ch<='9')
    {
        num=ch-0x30;
    }
    else
    {
        switch(ch)
        {
            case 'A': case 'a': num=10; break;
            case 'B': case 'b': num=11; break;
            case 'C': case 'c': num=12; break;
            case 'D': case 'd': num=13; break;
            case 'E': case 'e': num=14; break;
            case 'F': case 'f': num=15; break;
            default: num=0;
        }
    }
    return num;
}

char getChar(int num){
  char ch;
    if(num>=0 && num<=9)
    {
        ch = char(num+48);
    }
    else
    {
        switch(num)
        {
            case 10: ch='a'; break;
            case 11: ch='b'; break;
            case 12: ch='c'; break;
            case 13: ch='d'; break;
            case 14: ch='e'; break;
            case 15: ch='f'; break;
        }
    }
    return ch;
}

size_t hex2bin (void *bin, char hex[]) {
  size_t len, i;
  int x;
  uint8_t *p=(uint8_t*)bin;
  
  len = strlen (hex);
  
  if ((len & 1) != 0) {
    return 0; 
  }
  
  for (i=0; i<len; i++) {
    if (isxdigit((int)hex[i]) == 0) {
      return 0; 
    }
  }
  
  for (i=0; i<len / 2; i++) {
    sscanf (&hex[i * 2], "%2x", &x);
    p[i] = (uint8_t)x;
  } 
  return len / 2;
}

void split_by_eight_for_pass_proj(char plntxt[], int k, int str_len){
  char res[] = {0, 0, 0, 0, 0, 0, 0, 0};
  for (int i = 0; i < 8; i++){
      if(i+k > str_len - 1)
      break;
      res[i] = plntxt[i+k];
  }
  /*
   for (int i = 0; i < 8; i++){
     Serial.print(res[i]);
  }
  Serial.println();
  */
  Forw_S_Box(res);
}

void Forw_S_Box(char first_eight[8]){
  byte aft_box[8];
  for (int count; count<4; count++){
  String strOne = "";
  String strTwo = "";
  int i = count * 2;
  int j = count * 2 + 1;
  int fir = first_eight[i];
  int sec = first_eight[j];
  if (fir < 16)
  strOne += 0;
  strOne +=  String(fir, HEX);
  if (sec < 16)
  strTwo += 0;
  strTwo +=  String(sec, HEX);  
  /*
  Serial.print(strOne);
  Serial.println("");
  Serial.print(strTwo);
  Serial.println("");
  */
  char chars_f[3];
  char chars_s[3];
  strOne.toCharArray(chars_f, 3);
  strTwo.toCharArray(chars_s, 3);
  chars_f[2] = '\0';
  chars_s[2] = '\0';
  /*
  Serial.print(chars_f[0]);
  Serial.print(chars_f[1]);
  Serial.println("");
  Serial.print(chars_s[0]);
  Serial.print(chars_s[1]);
  Serial.println("");
  */
  int flc = getNum(chars_f[0]);
  int frc = getNum(chars_f[1]);
  int slc = getNum(chars_s[0]);
  int src = getNum(chars_s[1]);
  /*
  Serial.printf("%x",Forward_S_Box[flc][frc]);
  Serial.print(" ");
  Serial.printf("%x",Forward_S_Box[slc][src]);
  Serial.print(" ");
  */
  aft_box[i] = ("%x",Forward_S_Box[flc][frc]);
  aft_box[j] = ("%x",Forward_S_Box[slc][src]);
  }
  /*
  Serial.println("");
  for(int i = 0; i<8; i++){
  Serial.printf("%x",aft_box[i]);
  Serial.print(" ");
  }
  */
  first_xor(aft_box);
}

void first_xor(byte aft_forw_box[8]){
  String stiv1 = readFile(SPIFFS, "/IV1.txt");
  int stiv1_len = stiv1.length() + 1;
  char iv1[stiv1_len];
  stiv1.toCharArray(iv1, stiv1_len);
  byte aft_xor[8];
  for(int i = 0; i<8; i++){
   aft_xor[i] = aft_forw_box[i] ^ iv1[i];
  }
  /*
  Serial.println("");
  for(int i = 0; i<8; i++){
   Serial.printf("%x", aft_xor[i]);
   Serial.print(" ");
  }
  */
  enc_with_3des(aft_xor);
}

void enc_with_3des(byte in[8]){
  byte out[8];
  des.tripleEncrypt(out, in, TDESkey);
  /*
  for(int i = 0; i<8; i++){
   Serial.printf("%x", aft_xor[i]);
   Serial.print(" ");
  }
  */
  Forw_S_Box_two(out);
}

void Forw_S_Box_two(byte first_eight[8]){
  byte aft_box[8];
  for (int count; count<4; count++){
  String strOne = "";
  String strTwo = "";
  int i = count * 2;
  int j = count * 2 + 1;
  int fir = first_eight[i];
  int sec = first_eight[j];
  if (fir < 16)
  strOne += 0;
  strOne +=  String(fir, HEX);
  if (sec < 16)
  strTwo += 0;
  strTwo +=  String(sec, HEX);  
  char chars_f[3];
  char chars_s[3];
  strOne.toCharArray(chars_f, 3);
  strTwo.toCharArray(chars_s, 3);
  chars_f[2] = '\0';
  chars_s[2] = '\0';
  int flc = getNum(chars_f[0]);
  int frc = getNum(chars_f[1]);
  int slc = getNum(chars_s[0]);
  int src = getNum(chars_s[1]);
  aft_box[i] = ("%x",Forward_S_Box[flc][frc]);
  aft_box[j] = ("%x",Forward_S_Box[slc][src]);
  }
  /*
  Serial.println("");
  for(int i = 0; i<8; i++){
  Serial.printf("%x",aft_box[i]);
  Serial.print(" ");
  }
  */
  second_xor(aft_box);
}

void second_xor(byte aft_forw_box[8]){
  String stiv2 = readFile(SPIFFS, "/IV2.txt");
  int stiv2_len = stiv2.length() + 1;
  char iv2[stiv2_len];
  stiv2.toCharArray(iv2, stiv2_len);
  byte aft_xor[16];
  for(int i = 0; i<8; i++){
    aft_xor[i] = aft_forw_box[i] ^ iv2[i];
  }
  /*
  Serial.println("");
  for(int i = 0; i<8; i++){
   Serial.printf("%x",aft_xor[i]);
   Serial.print(" ");
  }
  */
  for (int i = 8; i < 16; i++){
    aft_xor[i] = gen_r_num();
  }
  char t_enc[16];
  for (int i = 0; i < 16; i++){
    int c = aft_xor[i];
    t_enc[i] = c;
  }
  /*
  for (int i = 0; i < 16; i++){
      if(t_enc[i]<16)
        Serial.print("0");
      Serial.print(t_enc[i],HEX);
  }
  */
  encr_AES_for_pp(t_enc);
}

void encr_AES_for_pp(char t_enc[]){
  uint8_t text[16];
  for(int i = 0; i<16; i++){
    int c = int(t_enc[i]);
    text[i] = c;
  }
  uint8_t cipher_text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  uint32_t key_bit[3] = {128, 192, 256};
  aes_context ctx;
  aes_set_key(&ctx, projection_key, key_bit[m]);
  aes_encrypt_block(&ctx, cipher_text, text);
  /*
  for (int i = 0; i < 16; ++i) {
    Serial.printf("%02x", cipher_text[i]);
  }
  */
  String stiv3 = readFile(SPIFFS, "/IV3.txt");
  int stiv3_len = stiv3.length() + 1;
  char iv3[stiv3_len];
  stiv3.toCharArray(iv3, stiv3_len);
  String stiv4 = readFile(SPIFFS, "/IV4.txt");
  int stiv4_len = stiv4.length() + 1;
  char iv4[stiv4_len];
  stiv4.toCharArray(iv4, stiv4_len);
  char L_half[16];
  for(int i = 0; i<8; i++){
    L_half[i] = cipher_text[i] ^ iv3[i];
  }
  char R_half[16];
  for(int i = 0; i<8; i++){
    R_half[i] = cipher_text[i+8] ^ iv4[i];
  }
  for(int i = 8; i<16; i++){
    L_half[i] = gen_r_num();
    R_half[i] = gen_r_num();
  }
  /*
  Serial.println("Left half XORed with IV3");
  for (int i = 0; i < 16; i++){
      if(L_half[i]<16)
        Serial.print("0");
      Serial.print(L_half[i],HEX);
  }
  Serial.println("\nRight half XORed with IV4");
  for (int i = 0; i < 16; i++){
      if(R_half[i]<16)
        Serial.print("0");
      Serial.print(R_half[i],HEX);
  }
  Serial.println();
  */
  serp_for_pp(L_half, false);
  serp_for_pp(R_half, true);
}

void serp_for_pp(char res[], bool snd){
  int tmp_s[16];
  for(int i = 0; i < 16; i++){
      tmp_s[i] = res[i];
  }
  /*
   for (int i = 0; i < 16; i++){
     Serial.print(res[i]);
  }
  Serial.println();
  */
  uint8_t ct1[32], pt1[32], key[64];
  int plen, clen, b, j;
  serpent_key skey;
  serpent_blk ct2;
  uint32_t *p;
  
  for (b=0; b<sizeof(keys)/sizeof(char*); b++) {
    hex2bin (key, keys[b]);
  
    // set key
    memset (&skey, 0, sizeof (skey));
    p=(uint32_t*)&skey.x[0][0];
    
    serpent_setkey (&skey, key);
    //Serial.printf ("\nkey=");
    /*
    for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
      if ((j % 8)==0) putchar('\n');
      Serial.printf ("%08X ", p[j]);
    }
    */
    for(int i = 0; i < 16; i++){
        ct2.b[i] = tmp_s[i];
    }
  serpent_encrypt (ct2.b, &skey, SERPENT_ENCRYPT);
  /*
    for (int i=0; i<16; i++) {
      if(ct2.b[i]<16)
        Serial.print("0");
      Serial.print(ct2.b[i],HEX);
    }
  */
    if (snd == false){
     for(int i = 0; i <16; i++){
      temp_st_for_pp[i] = ct2.b[i];
     }
    }
    if (snd == true){
     for(int i = 0; i <16; i++){
      myData.l_srp[i] = temp_st_for_pp[i];
      myData.r_srp[i] = ct2.b[i];
     }
     myData.n = n;
     esp_now_send(broadcastAddress, (uint8_t *) &myData, sizeof(myData));
     incr_projection_key();
     incr_TDESkey();
     IV_incrementer();
     n = true;
     delayMicroseconds(340);
    }
  }
}

void IV_incrementer(){
  // Read IVs
  String f = readFile(SPIFFS, "/IV1.txt");
  String s = readFile(SPIFFS, "/IV2.txt");
  String t = readFile(SPIFFS, "/IV3.txt");
  String foiv = readFile(SPIFFS, "/IV4.txt");
  String st2 = readFile(SPIFFS, "/st1.txt");
  // Convert IVs to the int
  unsigned int fir = f.toInt();
  unsigned int sec = s.toInt();
  unsigned int thi = t.toInt();
  unsigned int fou = foiv.toInt();
  unsigned int fif = st2.toInt();
  // Increment IVs
  fir++;
  sec++;
  thi++;
  fou++;
  fif++;
  // Convert IVs back to the strings
  f = String(fir);
  s = String(sec);
  t = String(thi);
  foiv = String(fou);
  st2 = String(fif);
  // Save new IVs to the ESP's flash memory
  writeFile(SPIFFS, "/IV1.txt", f);
  writeFile(SPIFFS, "/IV2.txt", s);
  writeFile(SPIFFS, "/IV3.txt", t);
  writeFile(SPIFFS, "/IV4.txt", foiv);
  writeFile(SPIFFS, "/st1.txt", st2);
}

String readFile(fs::FS &fs, String path){
  //Serial.println("Content of the file - " + path);
  File file = fs.open(path, "r");
  if(!file || file.isDirectory()){
    Serial.println("- empty file or failed to open file");
    return String();
  }
  //Serial.println("- read from file:");
  String fileContent;
  while(file.available()){
    fileContent+=String((char)file.read());
  }
  //Serial.println(fileContent);
  return fileContent;
}

void writeFile(fs::FS &fs, String path, String message){
  //Serial.println("Writing file - " + path);
  File file = fs.open(path, "w");
  if(!file){
    Serial.println("- failed to open file for writing");
    return;
  }
  if(file.print(message)){
    //Serial.println("- file written");
  } else {
    //Serial.println("- write failed");
  }
}

void proj_pass_from_Serial(){
 while (pr_key != 27){
  tft.fillScreen(0x2145);
  tft.setTextColor(0xdefb, 0x2145);
  tft.setCursor(0,0);
  tft.println("Paste the password to send into the Serial Monitor:");
  Serial.println("Paste the password to send:");
  String inp_str;
  while (!Serial.available()) {}
  inp_str = Serial.readString();
  int str_len = inp_str.length() + 1;
  char char_array[str_len];
  inp_str.toCharArray(char_array, str_len);
  Serial.println("Ciphertext:");
  int p = 0;
  while(str_len > p+1){
    split_by_eight_for_pass_proj(char_array, p, str_len);
    p+=8;
  }
  return;
 }
}

void send_IV(){
  String st2 = readFile(SPIFFS, "/st1.txt");
  byte in1[8];
  byte in2[8];
  byte in3[8];
  byte in4[8];
  for (int i = 0; i < 8; i++){
    in1[i] = gen_r_num();
    in2[i] = gen_r_num();
    in3[i] = gen_r_num();
    in4[i] = gen_r_num();
  }
  for (int i = 0; i < 2; i++){
    char x = st2[i];
    in1[i] = int(x);
  }
  for (int i = 2; i < 4; i++){
    char x = st2[i];
    in2[i] = int(x);
  }
  for (int i = 4; i < 6; i++){
    char x = st2[i];
    in3[i] = int(x);
  }
  for (int i = 6; i < 8; i++){
    char x = st2[i];
    in4[i] = int(x);
  }
  byte out1[8];
  byte out2[8];
  byte out3[8];
  byte out4[8];
  des.tripleEncrypt(out1, in1, Setkey);
  des.tripleEncrypt(out2, in2, Setkey);
  des.tripleEncrypt(out3, in3, Setkey);
  des.tripleEncrypt(out4, in4, Setkey);
  for(int i = 0; i < 8; i++){
    byte x = out1[i];
    myData.l_srp[i] = int(x);
  }
  for(int i = 0; i < 8; i++){
    byte x = out2[i];
    myData.l_srp[i+8] = int(x);
  }
  for(int i = 0; i < 8; i++){
    byte x = out3[i];
    myData.r_srp[i] = int(x);
  }
  for(int i = 0; i < 8; i++){
    byte x = out4[i];
    myData.r_srp[i+8] = int(x);
  }
  myData.n = true;
  esp_now_send(broadcastAddress, (uint8_t *) &myData, sizeof(myData));
  /*
  for(int i = 0; i < 16; i++){
    Serial.print(int(myData.l_srp[i]));
    Serial.print(" ");
  }
  Serial.println("");
  for(int i = 0; i < 16; i++){
    Serial.print(int(myData.r_srp[i]));
    Serial.print(" ");
  }
  */
}

void set_session_key(){
  String f = readFile(SPIFFS, "/IV1.txt");
  String s = readFile(SPIFFS, "/IV2.txt");
  String t = readFile(SPIFFS, "/IV3.txt");
  String foiv = readFile(SPIFFS, "/IV4.txt");
  String st1 = readFile(SPIFFS, "/st1.txt");
  String nmbr;
  nmbr += s.charAt(4);
  nmbr += f.charAt(3);
  nmbr += t.charAt(6);
  nmbr += s.charAt(7);
  nmbr += foiv.charAt(5);
  nmbr += st1.charAt(7);
  Serial.println(nmbr.toInt());
  unsigned int incr_num = nmbr.toInt();
  for (int i = 0; i < incr_num; i++){
    incr_projection_key();
    incr_TDESkey();
  }
}

void proj_pass(){
  n = false;
  int str_len = keyb_inp.length() + 1;
  char char_array[str_len];
  keyb_inp.toCharArray(char_array, str_len);
  int p = 0;
  while( str_len > p+1){
    split_by_eight_for_pass_proj(char_array, p, str_len);
    p+=8;
  }
  keyb_inp = "";
  ret_to_inp();
  return;
}

void proj_text_from_Serial(){
 while (pr_key != 27){
  tft.fillScreen(0x2145);
  tft.setTextColor(0xdefb, 0x2145);
  tft.setCursor(0,5);
  tft.println("Enter the text you want to");
  tft.setCursor(0,15);
  tft.println("send into the Serial");
  tft.setCursor(0,25);
  tft.println("Monitor.");
  tft.setCursor(0,120);
  tft.println("Press Esc to cancel.");
  Serial.println("Enter the text to send:");
  String inp_str;
  while (!Serial.available()) {
    bus.tick();
   if (bus.gotData()) {
    myStruct data;
    bus.readData(data);
    // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
    ch = data.x;
    pr_key = int(ch);
    if (pr_key == 27){
      keyb_inp = "";
      ret_to_inp();
      return;
    }
   }  
  }
  inp_str = Serial.readString();
  int str_len = inp_str.length() + 1;
  char char_array[str_len];
  inp_str.toCharArray(char_array, str_len);
  int p = 0;
  n = false;
  while(str_len > p+1){
   split_by_eight_for_pass_proj(char_array, p, str_len);
   p+=8;
  }
  ret_to_inp();
  return;
 }
}

void ret_to_inp(){
  keyb_inp = "";
  tft.fillScreen(0x2145);
  tft.setTextColor(0xdefb, 0x2145);
  tft.setTextSize(1);
  tft.setCursor(0, 4);
  tft.print("Enter the text to send:");
  tft.setTextColor(0xffff, 0x2145);
  tft.setTextSize(1);
  tft.setCursor(0, 14);
  tft.fillRect(0, 118, 160, 10, 0xffff);
  tft.setTextSize(1);
  tft.setCursor(5, 119);
  tft.setTextColor(0x2145, 0xffff);
  tft.print("Length:0");
}

void setup() {
  Serial.begin(115200);
  mySerial.begin(9600);
  tft.initR(INITR_BLACKTAB);
  tft.setRotation(1);
  ret_to_inp();
  m = 2;
  if(!SPIFFS.begin()){
    Serial.println("An Error has occurred while mounting SPIFFS");
    return;
  }
  WiFi.mode(WIFI_STA);
  if (esp_now_init() != 0) {
    Serial.println("Error initializing ESP-NOW");
    return;
  }
  esp_now_set_self_role(ESP_NOW_ROLE_CONTROLLER);
  esp_now_register_send_cb(OnDataSent);
  esp_now_add_peer(broadcastAddress, ESP_NOW_ROLE_SLAVE, 1, NULL, 0);
  
  IV_incrementer();
  send_IV();
  IV_incrementer();
  set_session_key();
}

void loop() {
 bus.tick();
 if (bus.gotData()) {
   myStruct data;
   bus.readData(data);
   // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
   ch = data.x;
   pr_key = int(ch);
   if (pr_key != 127 && pr_key != 13 && pr_key != 9 && pr_key != 10 && pr_key != 11) {
     keyb_inp += ch;
   } else if (ch == 127) {
     if (keyb_inp.length() > 0)
       keyb_inp.remove(keyb_inp.length() - 1, 1);
     tft.fillScreen(0x2145);
     tft.setTextColor(0xdefb, 0x2145);
     tft.setTextSize(1);
     tft.setCursor(0, 4);
     tft.print("Enter the text to send:");
     tft.setTextColor(0xffff, 0x2145);
     tft.setTextSize(1);
     tft.setCursor(0, 14);
     tft.fillRect(0, 118, 160, 10, 0xffff);
     tft.setTextSize(1);
     tft.setCursor(5, 119);
     tft.setTextColor(0x2145, 0xffff);
     tft.print("Length:");
   }
   tft.setTextColor(0xffff, 0x2145);
   tft.setTextSize(1);
   tft.setCursor(0, 14);
   tft.print(keyb_inp);
   tft.setTextSize(1);
   tft.setCursor(47, 119);
   tft.setTextColor(0x2145, 0xffff);
   tft.print("    ");
   tft.setCursor(47, 119);
   tft.setTextColor(0x2145, 0xffff);
   tft.print(keyb_inp.length());
   if (pr_key == 13) {
     proj_pass();
   }
   if (pr_key == 9)
    proj_text_from_Serial();
 }
}
