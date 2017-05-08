#include <AddicoreRFID.h>
#include <SPI.h>


AddicoreRFID myRFID;

//pin selection for rc522 chip
const int chipSelectRFID = 7;
const int resetRFID = 3;

//keyB from lockbox
byte keyB[] = {0x01, 0x02, 0x05, 0x06, 0x09, 0x10};

//standard sector trailor
byte std_sector_trailer[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,0x07 ,0x80 ,0x69 ,0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

//the block adress for the sector trailer
const byte key_addr = 7;

void setup() {
  // put your setup code here, to run once:
  Serial.begin(9600);


  //initialize SPI communications used 
  myRFID.Advanced_Setup_AddicoreRFID(chipSelectRFID, resetRFID);
  myRFID.AddicoreRFID_Init();//for SD and RFID
  SPI.begin();
  
}

void loop() {
  // put your main code here, to run repeatedly:
  byte serNum[5];
  unsigned char i, tmp, checksum, stat;
  unsigned char str[MAX_LEN];
  unsigned char ret[18];
  stat = myRFID.AddicoreRFID_Request(PICC_REQIDL , str);//search area for cards
  stat = myRFID.AddicoreRFID_Anticoll(serNum);//read selected card with anticollision detection

  unsigned int val;

  if (stat == MI_OK)
  {
    val = myRFID.AddicoreRFID_SelectTag(serNum); //select card
    stat = myRFID.AddicoreRFID_Auth(PICC_AUTHENT1B, key_addr, keyB, serNum);//attempt to authoirze with keyB
    if(stat == MI_OK){//if authporization works reset key_addr to to standard sector trailor so that it is recognized as a new card
      myRFID.AddicoreRFID_Write(key_addr, std_sector_trailer);
      Serial.println("now not a user");
    }else{//if authorization does not work then the card does not have the keyB of a user
      Serial.println("Already not a user");
    }
    
    stat = myRFID.AddicoreRFID_Read(7, ret);
    Serial.println(hexArray(ret,16));
    delay(500);
  }
  //reset the rfid card and RC522 to be used again
  myRFID.ClearBitMask(Status2Reg, 0x08);
  myRFID.AddicoreRFID_Halt();   

    
    
}

//take a byte array and convert it to a char array of hex values
char* hexArray(byte *data, byte len) {
  char* temp = (char*)malloc(3 * sizeof(char));
  char* hex = (char*)malloc(((3 * len)) * sizeof(char));
  sprintf(hex, "%02X", data[0]);
  for (int i = 1; i < len; i++) {
    sprintf(temp, " %02X", data[i]);
    strcat(hex, temp);
  }
  free(temp);
  return (hex);
}


