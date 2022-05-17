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
#include <FS.h>

String readFile(fs::FS &fs, const char * path){
  Serial.printf("Reading file: %s\r\n", path);
  File file = fs.open(path, "r");
  if(!file || file.isDirectory()){
    Serial.println("- empty file or failed to open file");
    return String();
  }
  String fileContent;
  while(file.available()){
    fileContent+=String((char)file.read());
  }
  return fileContent;
}

void writeFile(fs::FS &fs, const char * path, String IV){
  Serial.printf("Writing file: %s\r\n", path);
  File file = fs.open(path, "w");
  if(!file){
    Serial.println("- failed to open file for writing");
    return;
  }
  if(file.print(IV)){
    Serial.println("- file written");
  } else {
    Serial.println("- write failed");
  }
}
void setup() {
  Serial.begin(115200);
  // Initialize SPIFFS
    if(!SPIFFS.begin()){
      Serial.println("An Error has occurred while mounting SPIFFS");
      return;
    }

  String iv1 = "46201651";
  String iv2 = "60523847";
  String iv3 = "13453694";
  String iv4 = "31216946";
  String st1 = "40282533";
  
  writeFile(SPIFFS, "/IV1.txt", iv1);
  writeFile(SPIFFS, "/IV2.txt", iv2);
  writeFile(SPIFFS, "/IV3.txt", iv3);
  writeFile(SPIFFS, "/IV4.txt", iv4);
  writeFile(SPIFFS, "/st1.txt", st1);

}

void loop() {
  String f = readFile(SPIFFS, "/IV1.txt");
  String s = readFile(SPIFFS, "/IV2.txt");
  String t = readFile(SPIFFS, "/IV3.txt");
  String fourth_iv = readFile(SPIFFS, "/IV4.txt");
  String st1 = readFile(SPIFFS, "/st1.txt");
  unsigned int fir = f.toInt();
  unsigned int sec = s.toInt();
  unsigned int thi = t.toInt();
  unsigned int fou = fourth_iv.toInt();
  unsigned int s1 = st1.toInt();
  Serial.println("IVs:");
  Serial.println(fir);
  Serial.println(sec);
  Serial.println(thi);
  Serial.println(fou);
  Serial.println(s1);
  delay(5000);

}
