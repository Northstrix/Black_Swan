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
#include <ESP8266WiFi.h>
#include <espnow.h>
#include <FS.h>
#include <DES.h>
#include "aes.h"
#include "serpent.h"
typedef struct struct_message {
  char l_srp[16];
  char r_srp[16];
  bool n;
} struct_message;
DES des;
String pass_f_p = "";
byte tmp_st[8];
struct_message myData;
int tmp_s[8];
int m;
bool key_set;
String plt;

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

uint8_t Inv_S_Box[16][16] = {  
    {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB},  
    {0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB},  
    {0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E},  
    {0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25},  
    {0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92},  
    {0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84},  
    {0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06},  
    {0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B},  
    {0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73},  
    {0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E},  
    {0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B},  
    {0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4},  
    {0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F},  
    {0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF},  
    {0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61},  
    {0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}  
};

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

void IV_incrementer(int n){
  // Read IVs
  String f = readFile(SPIFFS, "/IV1.txt");
  String s = readFile(SPIFFS, "/IV2.txt");
  String t = readFile(SPIFFS, "/IV3.txt");
  String foiv = readFile(SPIFFS, "/IV4.txt");
  String st1 = readFile(SPIFFS, "/st1.txt");
  // Convert IVs to the int
  unsigned int fir = f.toInt();
  unsigned int sec = s.toInt();
  unsigned int thi = t.toInt();
  unsigned int fou = foiv.toInt();
  unsigned int fif = st1.toInt();
  // Increment IVs
  for(int i = 0; i < n; i++){
    fir++;
    sec++;
    thi++;
    fou++;
    fif++;
  }
  // Convert IVs back to the strings
  f = String(fir);
  s = String(sec);
  t = String(thi);
  foiv = String(fou);
  st1 = String(fif);
  // Save new IVs to the ESP's flash memory
  writeFile(SPIFFS, "/IV1.txt", f);
  writeFile(SPIFFS, "/IV2.txt", s);
  writeFile(SPIFFS, "/IV3.txt", t);
  writeFile(SPIFFS, "/IV4.txt", foiv);
  writeFile(SPIFFS, "/st1.txt", st1);
}

void calc_incr(char lh[], char rh[]){
  byte in1[8];
  byte in2[8];
  byte in3[8];
  byte in4[8];
  byte out1[8];
  byte out2[8];
  byte out3[8];
  byte out4[8];
  int i;
  for (i = 0; i < 8; i++){
    char x = lh[i];
    in1[i] = int(x);
  }
  for (i = 0; i < 8; i++){
    char x = lh[i+8];
    in2[i] = int(x);
  }
  for (i = 0; i < 8; i++){
    char x = rh[i];
    in3[i] = int(x);
  }
  for (i = 0; i < 8; i++){
    char x = rh[i+8];
    in4[i] = int(x);
  }
  des.tripleDecrypt(out1, in1, Setkey);
  des.tripleDecrypt(out2, in2, Setkey);
  des.tripleDecrypt(out3, in3, Setkey);
  des.tripleDecrypt(out4, in4, Setkey);
  /*
  for (i = 0; i < 8; i++){
    Serial.print(int(out1[i]));
    Serial.print(" ");
  }
  Serial.println();
  for (i = 0; i < 8; i++){
    Serial.print(int(out2[i]));
    Serial.print(" ");
  }
  Serial.println();
  for (i = 0; i < 8; i++){
    Serial.print(int(out3[i]));
    Serial.print(" ");
  }
  Serial.println();
  for (i = 0; i < 8; i++){
    Serial.print(int(out4[i]));
    Serial.print(" ");
  }
  */
  int tmp_for_rec[8];
  tmp_for_rec[0] = out1[0];
  tmp_for_rec[1] = out1[1];
  tmp_for_rec[2] = out2[2];
  tmp_for_rec[3] = out2[3];
  tmp_for_rec[4] = out3[4];
  tmp_for_rec[5] = out3[5];
  tmp_for_rec[6] = out4[6];
  tmp_for_rec[7] = out4[7];
  String rec_s_key;
  rec_s_key += char(tmp_for_rec[0]);
  rec_s_key += char(tmp_for_rec[1]);
  rec_s_key += char(tmp_for_rec[2]);
  rec_s_key += char(tmp_for_rec[3]);
  rec_s_key += char(tmp_for_rec[4]);
  rec_s_key += char(tmp_for_rec[5]);
  rec_s_key += char(tmp_for_rec[6]);
  rec_s_key += char(tmp_for_rec[7]);
  //Serial.println("\n" + rec_s_key);
  String st1 = readFile(SPIFFS, "/st1.txt");
  unsigned int fir = st1.toInt();
  unsigned int curr = rec_s_key.toInt();
  unsigned int diff = curr - fir;
  if (curr > fir && curr < (fir + 7500)){
    IV_incrementer(diff + 1);
    delayMicroseconds(12);
    set_session_key();
    key_set = true;
    Serial.println("Keys and IVs set up successfully.");
    /*
    Serial.println(readFile(SPIFFS, "/IV1.txt"));
    Serial.println(readFile(SPIFFS, "/IV2.txt"));
    Serial.println(readFile(SPIFFS, "/IV3.txt"));
    Serial.println(readFile(SPIFFS, "/IV4.txt"));
    Serial.println(readFile(SPIFFS, "/st1.txt"));
    Serial.println(projection_key[0]);
    Serial.println(TDESkey[0]);
    */
  }
  else {
    Serial.println("Failed to set up secure communication channel. Reboot the device and try again.");
  }
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
  //Serial.println(nmbr.toInt());
  unsigned int incr_num = nmbr.toInt();
  for (int i = 0; i < incr_num; i++){
    incr_projection_key();
    incr_TDESkey();
  }
}

void OnDataRecv(uint8_t * mac, uint8_t *incomingData, uint8_t len) {
  memcpy(&myData, incomingData, sizeof(myData));
  /*
  Serial.println("");
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
  if (key_set == false){
    calc_incr(myData.l_srp, myData.r_srp);

  }
  else{
    if (key_set == true){
      if (myData.n == false){
        plt = "";
      }
      decr_Serpent(myData.l_srp, false);
      decr_Serpent(myData.r_srp, true);
    }
  }
}

void decr_Serpent(char res[], bool pass){
      uint8_t ct1[32], pt1[32], key[64];
      int plen, clen, i, j;
      serpent_key skey;
      serpent_blk ct2;
      uint32_t *p;
  
  for (i=0; i<sizeof(keys)/sizeof(char*); i++) {
    hex2bin (key, keys[i]);
  
    // set key
    memset (&skey, 0, sizeof (skey));
    p=(uint32_t*)&skey.x[0][0];
    
    serpent_setkey (&skey, key);
    //Serial.printf ("\nkey=");

    for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
      if ((j % 8)==0) putchar('\n');
      //Serial.printf ("%08X ", p[j]);
    }

    for(int i = 0; i <16; i++)
      ct2.b[i] = res[i];
    /*
    Serial.printf ("\n\n");
    for(int i = 0; i<16; i++){
    Serial.printf("%x", ct2.b[i]);
    Serial.printf(" ");
    */
    }
    //Serial.printf("\n");
    serpent_encrypt (ct2.b, &skey, SERPENT_DECRYPT);
    /*
    for (int i=0; i<16; i++) {
      Serial.print(int(ct2.b[i]));
      Serial.print(" ");
    }
    Serial.println();
    */
    if (pass == false){
      for (int i = 0; i<8; i++){
        tmp_s[i] = ct2.b[i];
      }
    }
    if (pass == true){
      String stiv3 = readFile(SPIFFS, "/IV3.txt");
      int stiv3_len = stiv3.length() + 1;
      char iv3[stiv3_len];
      stiv3.toCharArray(iv3, stiv3_len);
      String stiv4 = readFile(SPIFFS, "/IV4.txt");
      int stiv4_len = stiv4.length() + 1;
      char iv4[stiv4_len];
      stiv4.toCharArray(iv4, stiv4_len);
      int t_dec[16];
      for (int i = 0; i<8; i++){
        t_dec[i] = tmp_s[i] ^= iv3[i];
      }
      for (int i = 0; i<8; i++){
        t_dec[i+8] = ct2.b[i] ^= iv4[i];
      }
      decr_AES(t_dec);
    }
}

void decr_AES(int res[]){
      uint8_t ret_text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
      uint8_t cipher_text[16] = {0};
      for(int i = 0; i<16; i++){
        int c = int(res[i]);
        cipher_text[i] = c;
      }
      uint32_t projection_key_bit[3] = {128, 192, 256};
      int i = 0;
      aes_context ctx;
      aes_set_key(&ctx, projection_key, projection_key_bit[m]);
      aes_decrypt_block(&ctx, ret_text, cipher_text);
      /*
      for (i = 0; i < 8; ++i) {
        Serial.print(char(ret_text[i]));
      }
      */
      byte t_xor[8];
      for(int i = 0; i<8; i++){
        t_xor[i] = byte(ret_text[i]);
      }
      second_xor(t_xor);
}

void second_xor(byte aft_forw_box[8]){
  String stiv2 = readFile(SPIFFS, "/IV2.txt");
  int stiv2_len = stiv2.length() + 1;
  char iv2[stiv2_len];
  stiv2.toCharArray(iv2, stiv2_len);
  byte aft_xor[8];
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
  Inverse_S_Box_Two(aft_xor);
}

void Inverse_S_Box_Two(byte aft_forw_box[8]){
  byte aft_inv_box[8];
  for (int count; count<4; count++){
  String strOne = "";
  String strTwo = "";
  int i = count * 2;
  int j = count * 2 + 1;
  int fir = aft_forw_box[i];
  int sec = aft_forw_box[j];
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
  Serial.printf("%x",Inv_S_Box[flc][frc]);
  Serial.print(" ");
  Serial.printf("%x",Inv_S_Box[slc][src]);
  Serial.print(" ");
  */
  aft_inv_box[i] = ("%x",Inv_S_Box[flc][frc]);
  aft_inv_box[j] = ("%x",Inv_S_Box[slc][src]);
  }
  /*
  Serial.println("");
  for(int i = 0; i<8; i++){
   Serial.printf("%x",aft_inv_box[i]);
   Serial.print(" ");
  }
  */
  dec_with_3des(aft_inv_box);
}

void dec_with_3des(byte in[8]){
  byte out[8];
  des.tripleDecrypt(out, in, TDESkey);
  /*
  for(int i = 0; i<8; i++){
   Serial.print(out[i]);
   Serial.print(" ");
  }
  */
  first_xor(out);
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
   Serial.print(aft_xor[i]);
   Serial.print(" ");
  }
  */
  Inverse_S_Box_one(aft_xor);
}

void Inverse_S_Box_one(byte aft_forw_box[8]){
  byte aft_inv_box[8];
  for (int count; count<4; count++){
  String strOne = "";
  String strTwo = "";
  int i = count * 2;
  int j = count * 2 + 1;
  int fir = aft_forw_box[i];
  int sec = aft_forw_box[j];
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
  Serial.printf("%x",Inv_S_Box[flc][frc]);
  Serial.print(" ");
  Serial.printf("%x",Inv_S_Box[slc][src]);
  Serial.print(" ");
  */
  aft_inv_box[i] = ("%x",Inv_S_Box[flc][frc]);
  aft_inv_box[j] = ("%x",Inv_S_Box[slc][src]);
  }
  /*
  Serial.println("");
  for(int i = 0; i<8; i++){
   Serial.printf("%x",aft_inv_box[i]);
   Serial.print(" ");
  }
  */
  for (int i = 0; i < 8; ++i) {
    //Serial.print(char(ret_text[i]));
    //Serial.println(ret_text[i]);
    if (aft_inv_box[i] != 0){
      plt += char(aft_inv_box[i]);
    }
  }
  Serial.print("Received data:");
  Serial.println(plt);
  IV_incrementer(1);
  incr_projection_key();
  incr_TDESkey();
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

void wfip(){
  Serial.println("Waiting for the initialization package to arrive.");
}
 
void setup() {
  Serial.begin(115200);
  m = 2;
  plt = "";
  key_set = false;
  WiFi.mode(WIFI_STA);
  if (esp_now_init() != 0) {
    Serial.println("Error initializing ESP-NOW");
    return;
  }
  if(!SPIFFS.begin()){
    Serial.println("An Error has occurred while mounting SPIFFS");
    return;
  }
  esp_now_set_self_role(ESP_NOW_ROLE_SLAVE);
  esp_now_register_recv_cb(OnDataRecv);
  delay(24);
  wfip();
}
 
void loop() {

}
