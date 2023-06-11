/*
The Black Swan Project
Distributed under the MIT License
© Copyright Maxim Bortnikov 2023
For more information please visit
https://github.com/Northstrix/Black_Swan
Required libraries:
https://github.com/adafruit/Adafruit-GFX-Library
https://github.com/adafruit/Adafruit_BusIO
https://github.com/adafruit/Adafruit_ILI9341
https://github.com/adafruit/Adafruit-ST7735-Library
https://github.com/techpaul/PS2KeyAdvanced
https://github.com/techpaul/PS2KeyMap
*/
// !!! Before uploading this sketch -
// Switch the partition scheme to the
// "Huge APP (3MB No OTA/1MB SPIFFS)" !!!
#include <Adafruit_GFX.h>                                                   // include Adafruit graphics library
#include <Adafruit_ILI9341.h>                                               // include Adafruit ILI9341 TFT library
#define TFT_CS    15                                                        // TFT CS  pin is connected to ESP32 pin D15
#define TFT_RST   4                                                         // TFT RST pin is connected to ESP32 pin D4
#define TFT_DC    2                                                         // TFT DC  pin is connected to ESP32 pin D2
                                                                            // SCK (CLK) ---> ESP32 pin D18
                                                                            // MOSI(DIN) ---> ESP32 pin D23
Adafruit_ILI9341 tft = Adafruit_ILI9341(TFT_CS, TFT_DC, TFT_RST);
#include <SPI.h>
#include <PS2KeyAdvanced.h>
#include <PS2KeyMap.h>
#include <esp_now.h>
#include <WiFi.h>
#include "DES.h"
#include "aes.h"
#include "blowfish.h"
#include "serpent.h"
#include "Crypto.h"
#include "sha512.h"
#include "Lock_screens.h"

PS2KeyAdvanced keyboard;
PS2KeyMap keymap;

uint16_t code;

#define DATAPIN 14
#define IRQPIN 13

int m = 2; // set AES to 256-bit mode
String dec_st;
String dec_tag;
byte tmp_st[8];
int pass_to_serp[16];
int decract;
byte array_for_CBC_mode[10];
bool decrypt_tag;
String string_with_data;
bool packet_one;
bool packet_two;
int curr_key;
bool finish_input;
bool act;
String keyboard_input;

DES des;
Blowfish blowfish;

// Keys (Below)
String kderalgs = "A182rM5oRE4rmXhOv1w913ssdi4DltLIAS747cicFxgrXCK8Dhaw1B1042KKfg5f";
String prefix = "6KH85E";
int numofkincr = 99;
byte hmackey[] = {"x0OucaN4W98Tf0o9TW79QHQ95qz6Zr9dMhxtm2y9fMC1Q0hP08H5a46Wv39cC0C7"};
byte des_key[] = {
0xfe,0x3c,0x36,0x02,0x81,0x36,0xcf,0xc3,
0x12,0xd5,0x44,0xb9,0xfa,0xab,0xc2,0x8e,
0x9b,0x6c,0xc7,0xd1,0xe2,0x88,0x35,0xca
};
uint8_t AES_key[32] = {
0x3a,0xbc,0xf3,0x65,
0x66,0x18,0x8f,0x8b,
0xc1,0x5c,0xf6,0x6b,
0x4b,0x37,0x5c,0x38,
0x85,0x0c,0xdb,0x1a,
0x18,0xd3,0x5d,0x2e,
0xae,0xe7,0x16,0x9f,
0xa2,0xf4,0xfd,0xda
};
unsigned char Blwfsh_key[] = {
0xd5,0xbf,0x5e,0xf5,
0xd1,0x7c,0xd6,0xfb,
0xa4,0xfb,0x72,0xe0,
0x2f,0x11,0xb8,0x95,
0xe4,0xf9,0xbf,0xcb,
0x06,0xfc,0xf8,0x9f
};
uint8_t serp_key[32] = {
0x82,0x5b,0xfa,0x28,
0xdb,0x70,0xca,0xa3,
0xad,0xfa,0xdc,0x01,
0xe4,0x02,0x30,0x53,
0x66,0xad,0x80,0xd8,
0x26,0x73,0xde,0x60,
0xbb,0xe4,0x0c,0x21,
0xb9,0xff,0x05,0x9f
};
uint8_t second_AES_key[32] = {
0xb1,0xfb,0x66,0x7e,
0x39,0x55,0xe9,0xeb,
0xd0,0x78,0xf6,0x47,
0x3d,0x2f,0x2a,0x09,
0x0e,0x16,0x5c,0xef,
0x73,0xb0,0x2e,0xe1,
0x0f,0x53,0x8a,0x24,
0x97,0x7e,0x03,0x6e
};
// Keys (Above)

// REPLACE WITH YOUR RECEIVER MAC Address
uint8_t broadcastAddress[] = {0x94, 0xE6, 0x86, 0x37, 0xFF, 0xD8};

// Structure example to send data
// Must match the receiver structure
typedef struct struct_message {
  char a[112];
  bool b;
} struct_message;

// Create a struct_message called myData
struct_message myData;

esp_now_peer_info_t peerInfo;

// callback when data is sent
void OnDataSent(const uint8_t * mac_addr, esp_now_send_status_t status) {
  Serial.print("\r\nLast Packet Send Status:\t");
  Serial.println(status == ESP_NOW_SEND_SUCCESS ? "Delivery Success" : "Delivery Fail");
}

void OnDataRecv(const uint8_t * mac,
  const uint8_t * incomingData, int len) {
  incr_hmac_key();
  incr_des_key();
  incr_AES_key();
  incr_Blwfsh_key();
  incr_serp_key();
  memcpy( & myData, incomingData, sizeof(myData));
  //Serial.print("Bytes received: ");
  //Serial.println(len);
  //Serial.println("Data: ");
  //for (int i = 0; i < 112; i++)
  //Serial.println(int(myData.a[i]));
  String ciphertext;
  for (int i = 0; i < 112; i++) {
    if (myData.a[i] < 16)
      ciphertext += "0";
    ciphertext += String(myData.a[i], HEX);
  }
  if (packet_one == false) {
    decrypt_string_with_TDES_AES_Blowfish_Serp(ciphertext); // Step 11
    //Serial.println(dec_st);
    //Serial.println(dec_tag);
    if (verify_integrity() == false)
      integrity_verification_failed();
    else
      Serial.println("Integrity verified successfully.");
    string_with_data = dec_st;
    delay(24);
    modify_keys(); // Step 11
    delay(120);
    packet_one = true;
  }
}

void integrity_verification_failed() {
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(0xf800);
  disp_centered_text_b_w("Integrity", 20);
  disp_centered_text_b_w("Verification", 44);
  disp_centered_text_b_w("Failed!!!", 68);
  delay(500);
  while (1);
}

byte back_des_key[24];
uint8_t back_serp_key[32];
unsigned char back_Blwfsh_key[16];
uint8_t back_AES_key[32];
uint8_t back_s_AES_key[32];

void back_serp_k() {
  for (int i = 0; i < 32; i++) {
    back_serp_key[i] = serp_key[i];
  }
}

void rest_serp_k() {
  for (int i = 0; i < 32; i++) {
    serp_key[i] = back_serp_key[i];
  }
}

void back_Bl_k() {
  for (int i = 0; i < 16; i++) {
    back_Blwfsh_key[i] = Blwfsh_key[i];
  }
}

void rest_Bl_k() {
  for (int i = 0; i < 16; i++) {
    Blwfsh_key[i] = back_Blwfsh_key[i];
  }
}

void back_AES_k() {
  for (int i = 0; i < 32; i++) {
    back_AES_key[i] = AES_key[i];
  }
}

void rest_AES_k() {
  for (int i = 0; i < 32; i++) {
    AES_key[i] = back_AES_key[i];
  }
}

void back_3des_k() {
  for (int i = 0; i < 24; i++) {
    back_des_key[i] = des_key[i];
  }
}

void rest_3des_k() {
  for (int i = 0; i < 24; i++) {
    des_key[i] = back_des_key[i];
  }
}

void back_second_AES_key() {
  for (int i = 0; i < 32; i++) {
    back_s_AES_key[i] = second_AES_key[i];
  }
}

void rest_second_AES_key() {
  for (int i = 0; i < 32; i++) {
    second_AES_key[i] = back_s_AES_key[i];
  }
}

void incr_des_key() {
  if (des_key[7] == 255) {
    des_key[7] = 0;
    if (des_key[6] == 255) {
      des_key[6] = 0;
      if (des_key[5] == 255) {
        des_key[5] = 0;
        if (des_key[4] == 255) {
          des_key[4] = 0;
          if (des_key[3] == 255) {
            des_key[3] = 0;
            if (des_key[2] == 255) {
              des_key[2] = 0;
              if (des_key[1] == 255) {
                des_key[1] = 0;
                if (des_key[0] == 255) {
                  des_key[0] = 0;
                } else {
                  des_key[0]++;
                }
              } else {
                des_key[1]++;
              }
            } else {
              des_key[2]++;
            }
          } else {
            des_key[3]++;
          }
        } else {
          des_key[4]++;
        }
      } else {
        des_key[5]++;
      }
    } else {
      des_key[6]++;
    }
  } else {
    des_key[7]++;
  }

  if (des_key[15] == 255) {
    des_key[15] = 0;
    if (des_key[14] == 255) {
      des_key[14] = 0;
      if (des_key[13] == 255) {
        des_key[13] = 0;
        if (des_key[12] == 255) {
          des_key[12] = 0;
          if (des_key[11] == 255) {
            des_key[11] = 0;
            if (des_key[10] == 255) {
              des_key[10] = 0;
              if (des_key[9] == 255) {
                des_key[9] = 0;
                if (des_key[8] == 255) {
                  des_key[8] = 0;
                } else {
                  des_key[8]++;
                }
              } else {
                des_key[9]++;
              }
            } else {
              des_key[10]++;
            }
          } else {
            des_key[11]++;
          }
        } else {
          des_key[12]++;
        }
      } else {
        des_key[13]++;
      }
    } else {
      des_key[14]++;
    }
  } else {
    des_key[15]++;
  }

  if (des_key[23] == 255) {
    des_key[23] = 0;
    if (des_key[22] == 255) {
      des_key[22] = 0;
      if (des_key[21] == 255) {
        des_key[21] = 0;
        if (des_key[20] == 255) {
          des_key[20] = 0;
          if (des_key[19] == 255) {
            des_key[19] = 0;
            if (des_key[18] == 255) {
              des_key[18] = 0;
              if (des_key[17] == 255) {
                des_key[17] = 0;
                if (des_key[16] == 255) {
                  des_key[16] = 0;
                } else {
                  des_key[16]++;
                }
              } else {
                des_key[17]++;
              }
            } else {
              des_key[18]++;
            }
          } else {
            des_key[19]++;
          }
        } else {
          des_key[20]++;
        }
      } else {
        des_key[21]++;
      }
    } else {
      des_key[22]++;
    }
  } else {
    des_key[23]++;
  }
}

void incr_AES_key() {
  if (AES_key[0] == 255) {
    AES_key[0] = 0;
    if (AES_key[1] == 255) {
      AES_key[1] = 0;
      if (AES_key[2] == 255) {
        AES_key[2] = 0;
        if (AES_key[3] == 255) {
          AES_key[3] = 0;
          if (AES_key[4] == 255) {
            AES_key[4] = 0;
            if (AES_key[5] == 255) {
              AES_key[5] = 0;
              if (AES_key[6] == 255) {
                AES_key[6] = 0;
                if (AES_key[7] == 255) {
                  AES_key[7] = 0;
                  if (AES_key[8] == 255) {
                    AES_key[8] = 0;
                    if (AES_key[9] == 255) {
                      AES_key[9] = 0;
                      if (AES_key[10] == 255) {
                        AES_key[10] = 0;
                        if (AES_key[11] == 255) {
                          AES_key[11] = 0;
                          if (AES_key[12] == 255) {
                            AES_key[12] = 0;
                            if (AES_key[13] == 255) {
                              AES_key[13] = 0;
                              if (AES_key[14] == 255) {
                                AES_key[14] = 0;
                                if (AES_key[15] == 255) {
                                  AES_key[15] = 0;
                                } else {
                                  AES_key[15]++;
                                }
                              } else {
                                AES_key[14]++;
                              }
                            } else {
                              AES_key[13]++;
                            }
                          } else {
                            AES_key[12]++;
                          }
                        } else {
                          AES_key[11]++;
                        }
                      } else {
                        AES_key[10]++;
                      }
                    } else {
                      AES_key[9]++;
                    }
                  } else {
                    AES_key[8]++;
                  }
                } else {
                  AES_key[7]++;
                }
              } else {
                AES_key[6]++;
              }
            } else {
              AES_key[5]++;
            }
          } else {
            AES_key[4]++;
          }
        } else {
          AES_key[3]++;
        }
      } else {
        AES_key[2]++;
      }
    } else {
      AES_key[1]++;
    }
  } else {
    AES_key[0]++;
  }
}

void incr_Blwfsh_key() {
  if (Blwfsh_key[0] == 255) {
    Blwfsh_key[0] = 0;
    if (Blwfsh_key[1] == 255) {
      Blwfsh_key[1] = 0;
      if (Blwfsh_key[2] == 255) {
        Blwfsh_key[2] = 0;
        if (Blwfsh_key[3] == 255) {
          Blwfsh_key[3] = 0;
          if (Blwfsh_key[4] == 255) {
            Blwfsh_key[4] = 0;
            if (Blwfsh_key[5] == 255) {
              Blwfsh_key[5] = 0;
              if (Blwfsh_key[6] == 255) {
                Blwfsh_key[6] = 0;
                if (Blwfsh_key[7] == 255) {
                  Blwfsh_key[7] = 0;
                  if (Blwfsh_key[8] == 255) {
                    Blwfsh_key[8] = 0;
                    if (Blwfsh_key[9] == 255) {
                      Blwfsh_key[9] = 0;
                      if (Blwfsh_key[10] == 255) {
                        Blwfsh_key[10] = 0;
                        if (Blwfsh_key[11] == 255) {
                          Blwfsh_key[11] = 0;
                          if (Blwfsh_key[12] == 255) {
                            Blwfsh_key[12] = 0;
                            if (Blwfsh_key[13] == 255) {
                              Blwfsh_key[13] = 0;
                              if (Blwfsh_key[14] == 255) {
                                Blwfsh_key[14] = 0;
                                if (Blwfsh_key[15] == 255) {
                                  Blwfsh_key[15] = 0;
                                } else {
                                  Blwfsh_key[15]++;
                                }
                              } else {
                                Blwfsh_key[14]++;
                              }
                            } else {
                              Blwfsh_key[13]++;
                            }
                          } else {
                            Blwfsh_key[12]++;
                          }
                        } else {
                          Blwfsh_key[11]++;
                        }
                      } else {
                        Blwfsh_key[10]++;
                      }
                    } else {
                      Blwfsh_key[9]++;
                    }
                  } else {
                    Blwfsh_key[8]++;
                  }
                } else {
                  Blwfsh_key[7]++;
                }
              } else {
                Blwfsh_key[6]++;
              }
            } else {
              Blwfsh_key[5]++;
            }
          } else {
            Blwfsh_key[4]++;
          }
        } else {
          Blwfsh_key[3]++;
        }
      } else {
        Blwfsh_key[2]++;
      }
    } else {
      Blwfsh_key[1]++;
    }
  } else {
    Blwfsh_key[0]++;
  }
}

void incr_serp_key() {
  if (serp_key[15] == 255) {
    serp_key[15] = 0;
    if (serp_key[14] == 255) {
      serp_key[14] = 0;
      if (serp_key[13] == 255) {
        serp_key[13] = 0;
        if (serp_key[12] == 255) {
          serp_key[12] = 0;
          if (serp_key[11] == 255) {
            serp_key[11] = 0;
            if (serp_key[10] == 255) {
              serp_key[10] = 0;
              if (serp_key[9] == 255) {
                serp_key[9] = 0;
                if (serp_key[8] == 255) {
                  serp_key[8] = 0;
                  if (serp_key[7] == 255) {
                    serp_key[7] = 0;
                    if (serp_key[6] == 255) {
                      serp_key[6] = 0;
                      if (serp_key[5] == 255) {
                        serp_key[5] = 0;
                        if (serp_key[4] == 255) {
                          serp_key[4] = 0;
                          if (serp_key[3] == 255) {
                            serp_key[3] = 0;
                            if (serp_key[2] == 255) {
                              serp_key[2] = 0;
                              if (serp_key[1] == 255) {
                                serp_key[1] = 0;
                                if (serp_key[0] == 255) {
                                  serp_key[0] = 0;
                                } else {
                                  serp_key[0]++;
                                }
                              } else {
                                serp_key[1]++;
                              }
                            } else {
                              serp_key[2]++;
                            }
                          } else {
                            serp_key[3]++;
                          }
                        } else {
                          serp_key[4]++;
                        }
                      } else {
                        serp_key[5]++;
                      }
                    } else {
                      serp_key[6]++;
                    }
                  } else {
                    serp_key[7]++;
                  }
                } else {
                  serp_key[8]++;
                }
              } else {
                serp_key[9]++;
              }
            } else {
              serp_key[10]++;
            }
          } else {
            serp_key[11]++;
          }
        } else {
          serp_key[12]++;
        }
      } else {
        serp_key[13]++;
      }
    } else {
      serp_key[14]++;
    }
  } else {
    serp_key[15]++;
  }
}

void incr_second_AES_key() {
  if (second_AES_key[0] == 255) {
    second_AES_key[0] = 0;
    if (second_AES_key[1] == 255) {
      second_AES_key[1] = 0;
      if (second_AES_key[2] == 255) {
        second_AES_key[2] = 0;
        if (second_AES_key[3] == 255) {
          second_AES_key[3] = 0;
          if (second_AES_key[4] == 255) {
            second_AES_key[4] = 0;
            if (second_AES_key[5] == 255) {
              second_AES_key[5] = 0;
              if (second_AES_key[6] == 255) {
                second_AES_key[6] = 0;
                if (second_AES_key[7] == 255) {
                  second_AES_key[7] = 0;
                  if (second_AES_key[8] == 255) {
                    second_AES_key[8] = 0;
                    if (second_AES_key[9] == 255) {
                      second_AES_key[9] = 0;
                      if (second_AES_key[10] == 255) {
                        second_AES_key[10] = 0;
                        if (second_AES_key[11] == 255) {
                          second_AES_key[11] = 0;
                          if (second_AES_key[12] == 255) {
                            second_AES_key[12] = 0;
                            if (second_AES_key[13] == 255) {
                              second_AES_key[13] = 0;
                              if (second_AES_key[14] == 255) {
                                second_AES_key[14] = 0;
                                if (second_AES_key[15] == 255) {
                                  second_AES_key[15] = 0;
                                } else {
                                  second_AES_key[15]++;
                                }
                              } else {
                                second_AES_key[14]++;
                              }
                            } else {
                              second_AES_key[13]++;
                            }
                          } else {
                            second_AES_key[12]++;
                          }
                        } else {
                          second_AES_key[11]++;
                        }
                      } else {
                        second_AES_key[10]++;
                      }
                    } else {
                      second_AES_key[9]++;
                    }
                  } else {
                    second_AES_key[8]++;
                  }
                } else {
                  second_AES_key[7]++;
                }
              } else {
                second_AES_key[6]++;
              }
            } else {
              second_AES_key[5]++;
            }
          } else {
            second_AES_key[4]++;
          }
        } else {
          second_AES_key[3]++;
        }
      } else {
        second_AES_key[2]++;
      }
    } else {
      second_AES_key[1]++;
    }
  } else {
    second_AES_key[0]++;
  }
}

void incr_hmac_key() {
  if (hmackey[42] == 255) {
    hmackey[42] = 0;
    if (hmackey[41] == 255) {
      hmackey[41] = 0;
      if (hmackey[40] == 255) {
        hmackey[40] = 0;
        if (hmackey[39] == 255) {
          hmackey[39] = 0;
          if (hmackey[38] == 255) {
            hmackey[38] = 0;
            if (hmackey[37] == 255) {
              hmackey[37] = 0;
              if (hmackey[36] == 255) {
                hmackey[36] = 0;
                if (hmackey[35] == 255) {
                  hmackey[35] = 0;
                } else {
                  hmackey[35]++;
                }
              } else {
                hmackey[36]++;
              }
            } else {
              hmackey[37]++;
            }
          } else {
            hmackey[38]++;
          }
        } else {
          hmackey[39]++;
        }
      } else {
        hmackey[40]++;
      }
    } else {
      hmackey[41]++;
    }
  } else {
    hmackey[42]++;
  }

  if (hmackey[15] == 255) {
    hmackey[15] = 0;
    if (hmackey[14] == 255) {
      hmackey[14] = 0;
      if (hmackey[13] == 255) {
        hmackey[13] = 0;
        if (hmackey[12] == 255) {
          hmackey[12] = 0;
          if (hmackey[11] == 255) {
            hmackey[11] = 0;
            if (hmackey[10] == 255) {
              hmackey[10] = 0;
              if (hmackey[9] == 255) {
                hmackey[9] = 0;
                if (hmackey[8] == 255) {
                  hmackey[8] = 0;
                } else {
                  hmackey[8]++;
                }
              } else {
                hmackey[9]++;
              }
            } else {
              hmackey[10]++;
            }
          } else {
            hmackey[11]++;
          }
        } else {
          hmackey[12]++;
        }
      } else {
        hmackey[13]++;
      }
    } else {
      hmackey[14]++;
    }
  } else {
    hmackey[15]++;
  }

  if (hmackey[23] == 255) {
    hmackey[23] = 0;
    if (hmackey[22] == 255) {
      hmackey[22] = 0;
      if (hmackey[21] == 255) {
        hmackey[21] = 0;
        if (hmackey[20] == 255) {
          hmackey[20] = 0;
          if (hmackey[19] == 255) {
            hmackey[19] = 0;
            if (hmackey[18] == 255) {
              hmackey[18] = 0;
              if (hmackey[17] == 255) {
                hmackey[17] = 0;
                if (hmackey[16] == 255) {
                  hmackey[16] = 0;
                } else {
                  hmackey[16]++;
                }
              } else {
                hmackey[17]++;
              }
            } else {
              hmackey[18]++;
            }
          } else {
            hmackey[19]++;
          }
        } else {
          hmackey[20]++;
        }
      } else {
        hmackey[21]++;
      }
    } else {
      hmackey[22]++;
    }
  } else {
    hmackey[23]++;
  }
}

size_t hex2bin(void * bin) {
  size_t len, i;
  int x;
  uint8_t * p = (uint8_t * ) bin;
  for (i = 0; i < 32; i++) {
    p[i] = (uint8_t) serp_key[i];
  }
  return 32;
}

int getNum(char ch) {
  int num = 0;
  if (ch >= '0' && ch <= '9') {
    num = ch - 0x30;
  } else {
    switch (ch) {
    case 'A':
    case 'a':
      num = 10;
      break;
    case 'B':
    case 'b':
      num = 11;
      break;
    case 'C':
    case 'c':
      num = 12;
      break;
    case 'D':
    case 'd':
      num = 13;
      break;
    case 'E':
    case 'e':
      num = 14;
      break;
    case 'F':
    case 'f':
      num = 15;
      break;
    default:
      num = 0;
    }
  }
  return num;
}

char getChar(int num) {
  char ch;
  if (num >= 0 && num <= 9) {
    ch = char(num + 48);
  } else {
    switch (num) {
    case 10:
      ch = 'a';
      break;
    case 11:
      ch = 'b';
      break;
    case 12:
      ch = 'c';
      break;
    case 13:
      ch = 'd';
      break;
    case 14:
      ch = 'e';
      break;
    case 15:
      ch = 'f';
      break;
    }
  }
  return ch;
}

void back_keys() {
  back_3des_k();
  back_AES_k();
  back_Bl_k();
  back_serp_k();
  back_second_AES_key();
}

void rest_keys() {
  rest_3des_k();
  rest_AES_k();
  rest_Bl_k();
  rest_serp_k();
  rest_second_AES_key();
}

bool verify_integrity() {
  int str_lentg = dec_st.length() + 1;
  char char_arraytg[str_lentg];
  dec_st.toCharArray(char_arraytg, str_lentg);
  SHA256HMAC hmac(hmackey, sizeof(hmackey));
  hmac.doUpdate(char_arraytg);
  byte authCode[SHA256HMAC_SIZE];
  hmac.doFinal(authCode);
  String res_hash;

  for (byte i = 0; i < SHA256HMAC_SIZE - 2; i++) {
    if (authCode[i] < 0x10) {
      res_hash += 0;
    } {
      res_hash += String(authCode[i], HEX);
    }
  }
  /*
  Serial.println(dec_st);
  Serial.println(dec_tag);
  Serial.println(res_hash);
  */
  return dec_tag.equals(res_hash);
}

// 3DES + AES + Blowfish + Serpent in CBC Mode(Below)

void split_by_ten(char plntxt[], int k, int str_len) {
  byte res[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  byte res2[8] = {
    0,
    0
  };

  for (int i = 0; i < 8; i++) {
    if (i + k > str_len - 1)
      break;
    res[i] = byte(plntxt[i + k]);
  }

  for (int i = 0; i < 2; i++) {
    if (i + 8 + k > str_len - 1)
      break;
    res2[i] = byte(plntxt[i + 8 + k]);
  }

  for (int i = 0; i < 8; i++) {
    res[i] ^= array_for_CBC_mode[i];
  }

  for (int i = 0; i < 2; i++) {
    res2[i] ^= array_for_CBC_mode[i + 8];
  }

  encrypt_with_tdes(res, res2);
}

void encrypt_iv_for_tdes_aes_blwfsh_serp() {
  byte res[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  byte res2[8] = {
    0,
    0
  };

  for (int i = 0; i < 10; i++) {
    array_for_CBC_mode[i] = esp_random() % 256;
  }

  for (int i = 0; i < 8; i++) {
    res[i] = array_for_CBC_mode[i];
  }

  for (int i = 0; i < 2; i++) {
    res2[i] = array_for_CBC_mode[i + 8];
  }

  encrypt_with_tdes(res, res2);
}

void encrypt_with_tdes(byte res[], byte res2[]) {

  for (int i = 2; i < 8; i++) {
    res2[i] = esp_random() % 256;
  }

  byte out[8];
  byte out2[8];
  des.tripleEncrypt(out, res, des_key);
  incr_des_key();
  des.tripleEncrypt(out2, res2, des_key);
  incr_des_key();

  char t_aes[16];

  for (int i = 0; i < 8; i++) {
    int b = out[i];
    t_aes[i] = char(b);
  }

  for (int i = 0; i < 8; i++) {
    int b = out2[i];
    t_aes[i + 8] = char(b);
  }

  encrypt_with_AES(t_aes);
}

void encrypt_with_AES(char t_enc[]) {
  uint8_t text[16] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  for (int i = 0; i < 16; i++) {
    int c = int(t_enc[i]);
    text[i] = c;
  }
  uint8_t cipher_text[16] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  uint32_t AES_key_bit[3] = {
    128,
    192,
    256
  };
  int i = 0;
  aes_context ctx;
  aes_set_key( & ctx, AES_key, AES_key_bit[m]);
  aes_encrypt_block( & ctx, cipher_text, text);
  /*
  for (int i=0; i<16; i++) {
    if(cipher_text[i]<16)
      Serial.print("0");
    Serial.print(cipher_text[i],HEX);
  }
  Serial.println();
  */
  incr_AES_key();
  unsigned char first_eight[8];
  unsigned char second_eight[8];
  for (int i = 0; i < 8; i++) {
    first_eight[i] = (unsigned char) cipher_text[i];
    second_eight[i] = (unsigned char) cipher_text[i + 8];
  }
  encrypt_with_Blowfish(first_eight, false);
  encrypt_with_Blowfish(second_eight, true);
  encrypt_with_serpent();
}

void encrypt_with_Blowfish(unsigned char inp[], bool lrside) {
  unsigned char plt[8];
  for (int i = 0; i < 8; i++)
    plt[i] = inp[i];
  blowfish.SetKey(Blwfsh_key, sizeof(Blwfsh_key));
  blowfish.Encrypt(plt, plt, sizeof(plt));
  String encrypted_with_blowfish;
  for (int i = 0; i < 8; i++) {
    if (lrside == false)
      pass_to_serp[i] = int(plt[i]);
    if (lrside == true)
      pass_to_serp[i + 8] = int(plt[i]);
  }
  incr_Blwfsh_key();
}

void encrypt_with_serpent() {
  uint8_t ct1[32], pt1[32], key[64];
  int plen, clen, b, j;
  serpent_key skey;
  serpent_blk ct2;
  uint32_t * p;

  for (b = 0; b < 1; b++) {
    hex2bin(key);

    // set key
    memset( & skey, 0, sizeof(skey));
    p = (uint32_t * ) & skey.x[0][0];

    serpent_setkey( & skey, key);

    for (int i = 0; i < 16; i++) {
      ct2.b[i] = pass_to_serp[i];
    }
    serpent_encrypt(ct2.b, & skey, SERPENT_ENCRYPT);
    incr_serp_key();
    /*
    for (int i = 0; i < 16; i++) {
      if (ct2.b[i] < 16)
        Serial.print("0");
      Serial.print(ct2.b[i], HEX);
    }
    */
    for (int i = 0; i < 16; i++) {
      if (decract > 0) {
        if (i < 10) {
          array_for_CBC_mode[i] = byte(int(ct2.b[i]));
        }
      }
      if (ct2.b[i] < 16)
        dec_st += "0";
      dec_st += String(ct2.b[i], HEX);
    }
    decract++;
  }
}

void split_for_decryption(char ct[], int ct_len, int p) {
  int br = false;
  byte res[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  byte prev_res[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  for (int i = 0; i < 32; i += 2) {
    if (i + p > ct_len - 1) {
      br = true;
      break;
    }
    if (i == 0) {
      if (ct[i + p] != 0 && ct[i + p + 1] != 0)
        res[i] = 16 * getNum(ct[i + p]) + getNum(ct[i + p + 1]);
      if (ct[i + p] != 0 && ct[i + p + 1] == 0)
        res[i] = 16 * getNum(ct[i + p]);
      if (ct[i + p] == 0 && ct[i + p + 1] != 0)
        res[i] = getNum(ct[i + p + 1]);
      if (ct[i + p] == 0 && ct[i + p + 1] == 0)
        res[i] = 0;
    } else {
      if (ct[i + p] != 0 && ct[i + p + 1] != 0)
        res[i / 2] = 16 * getNum(ct[i + p]) + getNum(ct[i + p + 1]);
      if (ct[i + p] != 0 && ct[i + p + 1] == 0)
        res[i / 2] = 16 * getNum(ct[i + p]);
      if (ct[i + p] == 0 && ct[i + p + 1] != 0)
        res[i / 2] = getNum(ct[i + p + 1]);
      if (ct[i + p] == 0 && ct[i + p + 1] == 0)
        res[i / 2] = 0;
    }
  }

  for (int i = 0; i < 32; i += 2) {
    if (i + p - 32 > ct_len - 1) {
      br = true;
      break;
    }
    if (i == 0) {
      if (ct[i + p - 32] != 0 && ct[i + p - 32 + 1] != 0)
        prev_res[i] = 16 * getNum(ct[i + p - 32]) + getNum(ct[i + p - 32 + 1]);
      if (ct[i + p - 32] != 0 && ct[i + p - 32 + 1] == 0)
        prev_res[i] = 16 * getNum(ct[i + p - 32]);
      if (ct[i + p - 32] == 0 && ct[i + p - 32 + 1] != 0)
        prev_res[i] = getNum(ct[i + p - 32 + 1]);
      if (ct[i + p - 32] == 0 && ct[i + p - 32 + 1] == 0)
        prev_res[i] = 0;
    } else {
      if (ct[i + p - 32] != 0 && ct[i + p - 32 + 1] != 0)
        prev_res[i / 2] = 16 * getNum(ct[i + p - 32]) + getNum(ct[i + p - 32 + 1]);
      if (ct[i + p - 32] != 0 && ct[i + p - 32 + 1] == 0)
        prev_res[i / 2] = 16 * getNum(ct[i + p - 32]);
      if (ct[i + p - 32] == 0 && ct[i + p - 32 + 1] != 0)
        prev_res[i / 2] = getNum(ct[i + p - 32 + 1]);
      if (ct[i + p - 32] == 0 && ct[i + p - 32 + 1] == 0)
        prev_res[i / 2] = 0;
    }
  }

  if (br == false) {
    if (decract > 10) {
      for (int i = 0; i < 10; i++) {
        array_for_CBC_mode[i] = prev_res[i];
      }
    }
    uint8_t ct1[32], pt1[32], key[64];
    int plen, clen, i, j;
    serpent_key skey;
    serpent_blk ct2;
    uint32_t * p;

    for (i = 0; i < 1; i++) {
      hex2bin(key);

      // set key
      memset( & skey, 0, sizeof(skey));
      p = (uint32_t * ) & skey.x[0][0];

      serpent_setkey( & skey, key);

      for (int i = 0; i < 16; i++)
        ct2.b[i] = res[i];
      /*
      Serial.printf ("\n\n");
      for(int i = 0; i<16; i++){
      Serial.printf("%x", ct2.b[i]);
      Serial.printf(" ");
      */
    }
    //Serial.printf("\n");
    serpent_encrypt(ct2.b, & skey, SERPENT_DECRYPT);
    incr_serp_key();
    unsigned char lh[8];
    unsigned char rh[8];
    for (int i = 0; i < 8; i++) {
      lh[i] = (unsigned char) int(ct2.b[i]);
      rh[i] = (unsigned char) int(ct2.b[i + 8]);
    }
    blowfish.SetKey(Blwfsh_key, sizeof(Blwfsh_key));
    blowfish.Decrypt(lh, lh, sizeof(lh));
    incr_Blwfsh_key();
    blowfish.SetKey(Blwfsh_key, sizeof(Blwfsh_key));
    blowfish.Decrypt(rh, rh, sizeof(rh));
    incr_Blwfsh_key();
    uint8_t ret_text[16] = {
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0
    };
    uint8_t cipher_text[16] = {
      0
    };
    for (int i = 0; i < 8; i++) {
      int c = int(lh[i]);
      cipher_text[i] = c;
    }
    for (int i = 0; i < 8; i++) {
      int c = int(rh[i]);
      cipher_text[i + 8] = c;
    }
    /*
    for (int i=0; i<16; i++) {
      if(cipher_text[i]<16)
        Serial.print("0");
      Serial.print(cipher_text[i],HEX);
    }
    Serial.println();
    */
    uint32_t AES_key_bit[3] = {
      128,
      192,
      256
    };
    aes_context ctx;
    aes_set_key( & ctx, AES_key, AES_key_bit[m]);
    aes_decrypt_block( & ctx, ret_text, cipher_text);
    incr_AES_key();

    byte res[8];
    byte res2[8];

    for (int i = 0; i < 8; i++) {
      res[i] = int(ret_text[i]);
      res2[i] = int(ret_text[i + 8]);
    }

    byte out[8];
    byte out2[8];
    des.tripleDecrypt(out, res, des_key);
    incr_des_key();
    des.tripleDecrypt(out2, res2, des_key);
    incr_des_key();
    /*
        Serial.println();
        for (int i=0; i<8; i++) {
          if(out[i]<8)
            Serial.print("0");
          Serial.print(out[i],HEX);
        }

        for (int i=0; i<8; i++) {
          if(out2[i]<8)
            Serial.print("0");
          Serial.print(out[i],HEX);
        }
        Serial.println();
    */

    if (decract > 2) {
      for (int i = 0; i < 8; i++) {
        out[i] ^= array_for_CBC_mode[i];
      }

      for (int i = 0; i < 2; i++) {
        out2[i] ^= array_for_CBC_mode[i + 8];
      }

      if (decrypt_tag == false) {

        for (i = 0; i < 8; ++i) {
          if (out[i] > 0)
            dec_st += char(out[i]);
        }

        for (i = 0; i < 2; ++i) {
          if (out2[i] > 0)
            dec_st += char(out2[i]);
        }

      } else {
        for (i = 0; i < 8; ++i) {
          if (out[i] < 0x10)
            dec_tag += "0";
          dec_tag += String(out[i], HEX);
        }

        for (i = 0; i < 2; ++i) {
          if (out2[i] < 0x10)
            dec_tag += "0";
          dec_tag += String(out2[i], HEX);
        }
      }
    }

    if (decract == -1) {
      for (i = 0; i < 8; ++i) {
        array_for_CBC_mode[i] = out[i];
      }

      for (i = 0; i < 2; ++i) {
        array_for_CBC_mode[i + 8] = out2[i];;
      }
    }
    decract++;
  }
}

void encr_hash_for_tdes_aes_blf_srp(String input) {
  back_keys();
  clear_variables();
  encrypt_iv_for_tdes_aes_blwfsh_serp();
  SHA256HMAC hmac(hmackey, sizeof(hmackey));
  int str_len = input.length() + 1;
  char input_arr[str_len];
  input.toCharArray(input_arr, str_len);
  hmac.doUpdate(input_arr);
  byte authCode[SHA256HMAC_SIZE];
  hmac.doFinal(authCode);
  int p = 0;
  char hmacchar[30];
  for (int i = 0; i < 30; i++) {
    hmacchar[i] = char(authCode[i]);
  }

  for (int i = 0; i < 3; i++) {
    split_by_ten(hmacchar, p, 100);
    p += 10;
  }
  rest_keys();
}

void encrypt_with_TDES_AES_Blowfish_Serp(String input) {
  back_keys();
  clear_variables();
  encrypt_iv_for_tdes_aes_blwfsh_serp();
  int str_len = input.length() + 1;
  char input_arr[str_len];
  input.toCharArray(input_arr, str_len);
  int p = 0;
  while (str_len > p + 1) {
    split_by_ten(input_arr, p, str_len);
    p += 10;
  }
  rest_keys();
}

void decrypt_with_TDES_AES_Blowfish_Serp(String ct) {
  back_keys();
  clear_variables();
  decrypt_tag = false;
  int ct_len = ct.length() + 1;
  char ct_array[ct_len];
  ct.toCharArray(ct_array, ct_len);
  int ext = 0;
  decract = -1;
  while (ct_len > ext) {
    split_for_decryption(ct_array, ct_len, 0 + ext);
    ext += 32;
    decract += 10;
  }
  rest_keys();
}

void decrypt_tag_with_TDES_AES_Blowfish_Serp(String ct) {
  back_keys();
  clear_variables();
  decrypt_tag = true;
  int ct_len = ct.length() + 1;
  char ct_array[ct_len];
  ct.toCharArray(ct_array, ct_len);
  int ext = 0;
  decract = -1;
  while (ct_len > ext) {
    split_for_decryption(ct_array, ct_len, 0 + ext);
    ext += 32;
    decract += 10;
  }
  rest_keys();
}

void encrypt_string_with_tdes_aes_blf_srp(String input) {
  encrypt_with_TDES_AES_Blowfish_Serp(input);
  String td_aes_bl_srp_ciphertext = dec_st;
  encr_hash_for_tdes_aes_blf_srp(input);
  dec_st += td_aes_bl_srp_ciphertext;
}

void decrypt_string_with_TDES_AES_Blowfish_Serp(String ct) {
  back_keys();
  clear_variables();
  decrypt_tag = true;
  int ct_len = ct.length() + 1;
  char ct_array[ct_len];
  ct.toCharArray(ct_array, ct_len);
  int ext = 0;
  decract = -1;
  for (int i = 0; i < 128; i += 32) {
    split_for_decryption(ct_array, ct_len, 0 + ext);
    ext += 32;
    decract += 10;
  }
  rest_keys();

  back_keys();
  dec_st = "";
  decrypt_tag = false;
  int ct_len1 = ct.length() + 1;
  char ct_array1[ct_len1];
  ct.toCharArray(ct_array1, ct_len1);
  ext = 128;
  decract = -1;
  while (ct_len1 > ext) {
    split_for_decryption(ct_array1, ct_len1, 0 + ext);
    ext += 32;
    decract += 10;
  }
  rest_keys();
}

// 3DES + AES + Blowfish + Serpent in CBC Mode (Above)

void clear_variables() {
  dec_st = "";
  dec_tag = "";
  decract = 0;
  return;
}

void modify_keys() {
  string_with_data += kderalgs;
  int str_len = string_with_data.length() + 1;
  char input_arr[str_len];
  string_with_data.toCharArray(input_arr, str_len);
  std::string str = "";
  if (str_len > 1) {
    for (int i = 0; i < str_len - 1; i++) {
      str += input_arr[i];
    }
  }
  String h = sha512(str).c_str();
  for (int i = 0; i < numofkincr; i++) {
    int str_len1 = h.length() + 1;
    char input_arr1[str_len1];
    h.toCharArray(input_arr1, str_len1);
    std::string str1 = "";
    if (str_len1 > 1) {
      for (int i = 0; i < str_len1 - 1; i++) {
        str1 += input_arr1[i];
      }
    }
    h = sha512(str1).c_str();
    delay(1);
  }
  //Serial.println(h);
  int h_len = h.length() + 1;
  char h_array[h_len];
  h.toCharArray(h_array, h_len);
  byte res[64];
  for (int i = 0; i < 128; i += 2) {
    if (i == 0) {
      if (h_array[i] != 0 && h_array[i + 1] != 0)
        res[i] = 16 * getNum(h_array[i]) + getNum(h_array[i + 1]);
      if (h_array[i] != 0 && h_array[i + 1] == 0)
        res[i] = 16 * getNum(h_array[i]);
      if (h_array[i] == 0 && h_array[i + 1] != 0)
        res[i] = getNum(h_array[i + 1]);
      if (h_array[i] == 0 && h_array[i + 1] == 0)
        res[i] = 0;
    } else {
      if (h_array[i] != 0 && h_array[i + 1] != 0)
        res[i / 2] = 16 * getNum(h_array[i]) + getNum(h_array[i + 1]);
      if (h_array[i] != 0 && h_array[i + 1] == 0)
        res[i / 2] = 16 * getNum(h_array[i]);
      if (h_array[i] == 0 && h_array[i + 1] != 0)
        res[i / 2] = getNum(h_array[i + 1]);
      if (h_array[i] == 0 && h_array[i + 1] == 0)
        res[i / 2] = 0;
    }
  }
  for (int i = 0; i < 13; i++) {
    hmackey[i] ^= res[i];
  }
  des_key[9] ^= res[13];
  des_key[16] ^= (unsigned char) res[31];
  des_key[17] = (unsigned char) res[32];
  des_key[18] = (unsigned char) res[33];
  serp_key[12] = int(res[34]);
  serp_key[14] ^= int(res[35]);
  for (int i = 0; i < 9; i++) {
    Blwfsh_key[i] ^= (unsigned char) res[i + 14];
  }
  for (int i = 0; i < 3; i++) {
    des_key[i] = (unsigned char) res[i + 23];
  }
  for (int i = 0; i < 5; i++) {
    hmackey[i + 13] = int(res[i + 26]);
  }
  for (int i = 0; i < 10; i++) {
    AES_key[i] ^= int(res[i + 36]);
  }
  for (int i = 0; i < 9; i++) {
    serp_key[i] ^= int(res[i + 46]);
  }
  for (int i = 0; i < 4; i++) {
    hmackey[i + 18] = res[i + 55];
    des_key[i + 3] ^= (unsigned char) res[i + 59];
  }
  for (int i = 0; i < 5; i++) {
    second_AES_key[i] ^= ((int(res[i + 31]) * int(res[i + 11])) + int(res[50])) % 256;
  }
}

void set_up_keys() {
  generate_first_random_value(); // Step 1
  encrypt_and_send_packet(); // Steps 2, 3
  modify_keys(); // Step 4
  Serial.println("Done");
}

void generate_first_random_value() {
  string_with_data = "";
  for (int i = 0; i < 20; i++) {
    string_with_data += char(32 + esp_random() % 95);
  }
  //Serial.println(string_with_data);
}

void encrypt_and_send_packet() {
  incr_hmac_key();
  incr_des_key();
  incr_AES_key();
  incr_Blwfsh_key();
  incr_serp_key();
  String data_to_send;
  encr_hash_for_tdes_aes_blf_srp(string_with_data);
  data_to_send += dec_st;
  encrypt_with_TDES_AES_Blowfish_Serp(string_with_data);
  data_to_send += dec_st;

  byte res[112];
  for (int i = 0; i < 224; i += 2) {
    if (i == 0) {
      if (data_to_send[i] != 0 && data_to_send[i + 1] != 0)
        res[i] = 16 * getNum(data_to_send[i]) + getNum(data_to_send[i + 1]);
      if (data_to_send[i] != 0 && data_to_send[i + 1] == 0)
        res[i] = 16 * getNum(data_to_send[i]);
      if (data_to_send[i] == 0 && data_to_send[i + 1] != 0)
        res[i] = getNum(data_to_send[i + 1]);
      if (data_to_send[i] == 0 && data_to_send[i + 1] == 0)
        res[i] = 0;
    } else {
      if (data_to_send[i] != 0 && data_to_send[i + 1] != 0)
        res[i / 2] = 16 * getNum(data_to_send[i]) + getNum(data_to_send[i + 1]);
      if (data_to_send[i] != 0 && data_to_send[i + 1] == 0)
        res[i / 2] = 16 * getNum(data_to_send[i]);
      if (data_to_send[i] == 0 && data_to_send[i + 1] != 0)
        res[i / 2] = getNum(data_to_send[i + 1]);
      if (data_to_send[i] == 0 && data_to_send[i + 1] == 0)
        res[i / 2] = 0;
    }
  }

  for (int i = 0; i < 112; i++) {
    myData.a[i] = res[i];
  }

  // Send message via ESP-NOW
  esp_err_t result = esp_now_send(broadcastAddress, (uint8_t * ) & myData, sizeof(myData));

  if (result == ESP_OK) {
    Serial.println("Sent with success");
  } else {
    Serial.println("Error sending the data");
  }
}

void generate_second_random_value() {
  string_with_data = prefix;
  for (int i = 0; i < 14; i++) {
    string_with_data += char(32 + esp_random() % 95);
  }
  //Serial.println(string_with_data);
}

void disp_centered_text_b_w(String text, int h) {
  int16_t x1;
  int16_t y1;
  uint16_t width;
  uint16_t height;

  tft.getTextBounds(text, 0, 0, & x1, & y1, & width, & height);
  tft.setTextColor(0x0882);
  tft.setCursor((320 - width) / 2, h - 1);
  tft.print(text);
  tft.setCursor((320 - width) / 2, h + 1);
  tft.print(text);
  tft.setCursor(((320 - width) / 2) - 1, h);
  tft.print(text);
  tft.setCursor(((320 - width) / 2) + 1, h);
  tft.print(text);
  tft.setTextColor(0xf7de);
  tft.setCursor((320 - width) / 2, h);
  tft.print(text);
}

void disp_centered_text(String text, int h) {
  int16_t x1;
  int16_t y1;
  uint16_t width;
  uint16_t height;

  tft.getTextBounds(text, 0, 0, & x1, & y1, & width, & height);
  tft.setCursor((320 - width) / 2, h);
  tft.print(text);
}

int chosen_lock_screen;

void press_any_key_to_continue() {
  bool break_the_loop = false;
  int c, v;
  while (break_the_loop == false) {
    c = esp_random() % 312;
    v = esp_random() % 41;
    if (Inscription[c][v] == 0) {
      if (esp_random() % 2 == 1)
        tft.drawPixel(c + 4, v + 10, Colorado_Springs[(esp_random() % 320)][esp_random() % 240]);
      else
        tft.drawPixel(c + 4, v + 10, Tel_Aviv[(esp_random() % 320)][esp_random() % 240]);
    }
    if (keyboard.available()) {
      c = keyboard.read();
      break_the_loop = true;
    }
  }
}

void set_stuff_for_input(String blue_inscr) {
  curr_key = 65;
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(0xffff);
  tft.setCursor(2, 0);
  tft.print("Char'");
  tft.setCursor(74, 0);
  tft.print("'");
  disp();
  tft.setCursor(0, 24);
  tft.setTextSize(2);
  tft.setTextColor(0x051b);
  tft.print(blue_inscr);
  tft.fillRect(312, 0, 8, 240, 0x051b);
  tft.setTextColor(0x07e0);
  tft.setCursor(216, 0);
  tft.print("ASCII:");
}

void keyb_input() {
  finish_input = false;
  while (finish_input == false) {

    code = keyboard.available();
    if (code > 0) {
      code = keyboard.read();
      code = keymap.remapKey(code);
      if (code > 0) {
        if ((code & 0xFF)) {

          if ((code & 0xFF) == 27) { // Esc
            act = false;
            finish_input = true;
          } else if ((code & 0xFF) == 13) { // Enter
            finish_input = true;
          } else if ((code & 0xFF) == 8) { // Backspace
            if (keyboard_input.length() > 0)
              keyboard_input.remove(keyboard_input.length() - 1, 1);
            //Serial.println(keyboard_input);
            tft.fillRect(0, 48, 312, 192, 0x0000);
            //Serial.println(keyboard_input);
            check_bounds_and_change_char();
            disp();
          } else {
            keyboard_input += char(code & 0xFF);
            check_bounds_and_change_char();
            disp();
          }
        }

      }
    }

    delayMicroseconds(400);
  }
}

void check_bounds_and_change_char() {
  if (curr_key < 32)
    curr_key = 126;

  if (curr_key > 126)
    curr_key = 32;

  if (keyboard_input.length() > 0)
    curr_key = keyboard_input.charAt(keyboard_input.length() - 1);
}

void disp() {
  //gfx->fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(0xffff);
  tft.fillRect(62, 0, 10, 16, 0x0000);
  tft.setCursor(62, 0);
  tft.print(char(curr_key));
  tft.fillRect(288, 0, 22, 14, 0x0000);
  tft.setCursor(288, 0);
  String hexstr;
  if (curr_key < 16)
    hexstr += 0;
  hexstr += String(curr_key, HEX);
  hexstr.toUpperCase();
  tft.setTextColor(0x07e0);
  tft.print(hexstr);
  tft.setTextColor(0xffff);
  tft.setTextSize(2);
  tft.setCursor(0, 48);
  tft.print(keyboard_input);
}

void send_string(char plntxt[], int k, int str_len) {
  char plt_data[20];
  int scnt = 0;

  for (int i = 0; i < 20; i++)
    plt_data[i] = 127 + (esp_random() % 129);

  for (int i = 0; i < 14; i++) {
    if (i + k > str_len - 1)
      break;
    plt_data[i] = plntxt[i + k];
    scnt++;
  }

  //Serial.println(scnt);
  string_with_data = "";

  for (int i = 0; i < 20; i++)
    string_with_data += plt_data[i];

  encrypt_and_send_packet();
  delay(80 + (k / 2));
}

void setup() {
  myData.b = true;
  tft.begin();
  tft.fillScreen(0x0000);
  tft.setRotation(1);
  keyboard.begin(DATAPIN, IRQPIN);
  keyboard.setNoBreak(1);
  keyboard.setNoRepeat(1);
  keymap.selectMap((char * )
    "US");
  chosen_lock_screen = esp_random() % 12;

  if (chosen_lock_screen == 0) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 240; j++) {
        tft.drawPixel(i, j, Colorado_Springs[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 1) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 240; j++) {
        tft.drawPixel(i, j, Dallas[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 2) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 240; j++) {
        tft.drawPixel(i, j, Denver[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 3) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 240; j++) {
        tft.drawPixel(i, j, Field[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 4) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 240; j++) {
        tft.drawPixel(i, j, Houston[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 5) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 240; j++) {
        tft.drawPixel(i, j, Kansas_City[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 6) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 240; j++) {
        tft.drawPixel(i, j, Mexico_City[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 7) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 240; j++) {
        tft.drawPixel(i, j, Milan[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 8) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 240; j++) {
        tft.drawPixel(i, j, Minneapolis[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 9) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 240; j++) {
        tft.drawPixel(i, j, Montreal[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 10) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 240; j++) {
        tft.drawPixel(i, j, Tel_Aviv[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 11) {
    for (int i = 0; i < 320; i++) {
      for (int j = 0; j < 240; j++) {
        tft.drawPixel(i, j, Vancouver[i][j]);
      }
    }
  }

  tft.setTextSize(2);
  tft.setTextColor(0xf7de);
  disp_centered_text_b_w("Turn The Receiver On", 201);
  disp_centered_text_b_w("And Press Any Key", 223);
  press_any_key_to_continue();
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(0xf7de);
  disp_centered_text_b_w("Setting Up Keys", 20);
  disp_centered_text_b_w("Please Wait", 44);
  disp_centered_text_b_w("For A While", 68);
  packet_one = false;
  packet_two = false;
  // Init Serial Monitor
  //Serial.begin(115200);

  // Set device as a Wi-Fi Station
  WiFi.mode(WIFI_STA);

  // Init ESP-NOW
  if (esp_now_init() != ESP_OK) {
    Serial.println("Error initializing ESP-NOW");
    return;
  }

  // Once ESPNow is successfully Init, we will register for Send CB to
  // get the status of Trasnmitted packet
  esp_now_register_send_cb(OnDataSent);

  // Register peer
  memcpy(peerInfo.peer_addr, broadcastAddress, 6);
  peerInfo.channel = 0;
  peerInfo.encrypt = false;

  // Add peer        
  if (esp_now_add_peer( & peerInfo) != ESP_OK) {
    Serial.println("Failed to add peer");
    return;
  }

  esp_now_register_recv_cb(OnDataRecv);

  delay(100);
  set_up_keys();
}

void loop() {
  if (packet_one == true && packet_two == false) {
    delay(240);
    generate_second_random_value(); // Step 12
    encrypt_and_send_packet(); // Steps 13, 14
    modify_keys(); // Step 15
    packet_two = true;
  }
  if (packet_one == true && packet_two == true) {
    delay(240);
    set_stuff_for_input("Enter the string to send");
    keyboard_input = "";
    act = true;
    keyb_input();
    if (act == true) {
      myData.b = false;
      int str_len = keyboard_input.length() + 1;
      char char_array[str_len];
      keyboard_input.toCharArray(char_array, str_len);
      int p = 0;
      while (str_len > p + 1) {
        send_string(char_array, p, str_len);
        p += 14;
        myData.b = true;
      }
      //Serial.println(keyboard_input);
    }
    keyboard_input = "";
  }
}
