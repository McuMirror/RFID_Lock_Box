#include <AddicoreRFID.h>
#include <Wire.h>
#include <RTClib.h>
#include <SPI.h>
#include <SD.h>
#include <AESLib.h>
#include <Servo.h>

AddicoreRFID myRFID;
RTC_DS1307 rtc;
Servo myservo;

enum states {init_s, make_new_user, find_user, unlock, wait_1, lock} state;

//pin selection for all external chips
const int servoPin = 9;
const int buttonPin = 8;
const int chipSelectSD = 10;
const int chipSelectRFID = 7;
const int resetRFID = 3;

//files for saving log data and user data
const char* saveFile = "dl.txt";
const char* userFile = "ul.txt";

//key for AES 128 encryption
const byte crypt_key[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

//standard keyA for RFID communication with Mifare 1K cards
const byte std_keyA[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

//Keys that are set to make the sectorof a card secure
//these can be changed but must be kept secret
const byte keyA[] = {0x00, 0x03, 0x04, 0x07, 0x08, 0x11};
const byte keyB[] = {0x01, 0x02, 0x05, 0x06, 0x09, 0x10};

//the access bit determine what each key\ can do 
//For this example key B is needed to change sector trailer and neither key can be read.
//Both key A&B have unlimited access to blocks 0-2 of the sector. Last byte can be anything.
const byte access_bits[] = {0x7F, 0x07, 0x88, 0x69};

//the block adress for the sector trailer
const byte key_addr = 7;
//the block adress for the 16 byte ID number
const byte ID_addr = 4;

byte sector_trailer[16];

void setup()
{

  //initialize the servo and set it to open the box incase something goes wrong with initialization
  myservo.attach(servoPin);
  myservo.write(0);

  //set the butttonPin to be an input
  pinMode(buttonPin, INPUT);

  //seed rng with an analog read to a pin that is not connected to anything which is effectivly random
  randomSeed(analogRead(0));
  
  // Open serial communications
  Serial.begin(9600);

  //initialize SPI communications used for SD and RFID
  SPI.begin();

  //initialize real time clock pins 4 and 5
  rtc.begin();

  Serial.print("Initializing SD card...");
  // see if the card is present and can be initialized and wait 1 second and try again if not present
  while (!SD.begin(chipSelectSD)) {
    Serial.println("Card failed, or not present");
    delay(1000);
  }
  Serial.println("card initialized.");

  //set the values for RFID SPI communication and initialize
  myRFID.Advanced_Setup_AddicoreRFID(chipSelectRFID, resetRFID);
  myRFID.AddicoreRFID_Init();

  //complies both keys with the access bits to create the sector_trailer to be writen to each cards key_addr
  memcpy(sector_trailer, keyA, 6);
  memcpy(sector_trailer + 6, access_bits, 4);
  memcpy(sector_trailer + 10, keyB, 6);

  
  
  //set the initial state and previous state
  state = init_s;
  char p_state = 0;
  while(1){

    //if states change print out the new state
    if(p_state!=state){
      Serial.println(state);
    }
    p_state = state;

    //reun the state machine
    stateMachine();
  }
}


void stateMachine() {
  byte stat;
  byte serNum[5];
  unsigned char ret[18];
  
  switch (state) { //state actions
    case init_s: //in the initial state the 
      myservo.write(0);
      break;
    case make_new_user:
      //must first find a nearby card and its serial number then select it
      myRFID.AddicoreRFID_Request(PICC_REQIDL , ret);
      myRFID.AddicoreRFID_Anticoll(serNum);
      myRFID.AddicoreRFID_SelectTag(serNum);

      //attempt to authoize the card with the standard key A
      stat = myRFID.AddicoreRFID_Auth(PICC_AUTHENT1A, key_addr, std_keyA, serNum);
      
      if (stat == MI_OK) {//if it works create a new id and write it to the card
        byte* cardID = getNewID();
        myRFID.AddicoreRFID_Write(ID_addr, cardID);

        //encrypt the id use it to make a new user on the sd card
        aes128_enc_single(crypt_key, cardID);
        makeUser(cardID);

        free(cardID);

        myRFID.AddicoreRFID_Write(key_addr, sector_trailer);
      }
      //reset the RFID reader and RFID card so that they can reconnect or connect to different things
      myRFID.ClearBitMask(Status2Reg, 0x08);
      myRFID.AddicoreRFID_Halt();      
      break;

    case find_user:
      //must first find a nearby card and its serial number then select it
      myRFID.AddicoreRFID_Request(PICC_REQIDL , ret);
      myRFID.AddicoreRFID_Anticoll(serNum);
      myRFID.AddicoreRFID_SelectTag(serNum);

      //attempt to authoize the card with the key A
      stat = myRFID.AddicoreRFID_Auth(PICC_AUTHENT1A, key_addr, keyA, serNum);
      if (stat == MI_OK) {//if it works read the id off of the card
        myRFID.AddicoreRFID_Read(ID_addr, ret);

        //encrypt the id
        aes128_enc_single(crypt_key, ret);
        char* uname=(char*)malloc(26*sizeof(char));
        if(findUser(ret, uname)){//check the encrypted id against the file of users
          //if the user exsits print their name, save it to the data log, and set the flag stat to MI_OK
          stat = MI_OK;
          Serial.println(uname);
          saveMessage(uname, (char*)saveFile, 25);//save out to SD card with date and time to file savefile
        }else{//if no user set stat to MI_ERR to indicate it
          stat = MI_ERR;
        }
        free(uname);
      }
      //reset the RFID reader and RFID card so that they can reconnect or connect to different things
      myRFID.ClearBitMask(Status2Reg, 0x08);
      myRFID.AddicoreRFID_Halt();      
      break;
    case unlock://unlock the system
      myservo.write(0);
      break;
    case wait_1://waiting for button press so no action
      break;
    case lock://lock the system
      myservo.write(85);
      break;
    default://default to locking the system
      myservo.write(85);
  }

  switch (state) { //state transitions
    case init_s://if there is a user in the system lock otherwise add a new user
      if (numUsers() > 0) {
        state = lock;
      } else {
        state = make_new_user;
      }
      break;
    case make_new_user://if there is at least one user and the button is not being pressed go to wait for button press
      if (!digitalRead(buttonPin) && numUsers() > 0) {
        state = wait_1;
      } else {
        state = make_new_user;
      }
      break;
    case find_user: //if stat == MI_OK then user is found and go to unlock
      if (stat == MI_OK) {
        state = unlock;
      } else {
        state = find_user;
      }
      break;
    case unlock: //if button is being pressed make_new_user otherwise wait for button press
      if (digitalRead(buttonPin)) {
        state = make_new_user;
      } else {
        state = wait_1;
      }
      break;
    case wait_1://if button press lock the system
      if (digitalRead(buttonPin)) {
        state = lock;
      } else {
        state = wait_1;
      }
      break;
    case lock://go to waiting for user to unlock the system
      state = find_user;
      break;
    default:
      state = init_s;
  }
}


void loop(){
  
}

//make a new user in the userFile with the userid
void makeUser(byte* userid) {

  int userIndex = numUsers();
  //Serial.println(userIndex);
  File dataFile = SD.open(userFile, FILE_WRITE);
  // if the file is available, write to it:
  if (dataFile) {
    char* dataString = (char*)malloc((60) * sizeof(char));
    char* temp = (char*)malloc((12) * sizeof(char));

    //if there are no users in the system add in the first line telling where the name should end
    if (userIndex < 1) {
      userIndex = 0;
      sprintf(dataString, "Replace user# with your name. Your name should end here->|");
      dataFile.println(dataString);
    }

    //increment number of users by 1
    userIndex++;

    //turn the user id into a char array of the hexvalues
    sprintf(dataString, "");
    for (int i = 0; i < 16; i++) {
      sprintf(dataString, "%s%02X", dataString, userid[i]);
    }

    //create the filler user name
    sprintf(temp, "user%d", userIndex);

    //compile the string to be printed to the userFile
    sprintf(dataString, "%s %25s", dataString, temp);
    
    dataFile.println(dataString);
    dataFile.close();

    //print the current state of the userFile
    dataFile = SD.open(userFile);
    while (dataFile.available()) {
      Serial.write(dataFile.read());
    }
    
    dataFile.close();
    free(temp);
    free(dataString);
  }
  // if the file isn't open, pop up an error:
  // some times an error will not come up even if there actually is an error
  else {
    Serial.println("error");
  }
}

//attempt to find a user asociated with the entered userid, if found return a 1 and put the user name in userName
//otherwise return a 0
boolean findUser(byte* userid, char* userName) {
  int numUser = numUsers();
  char* userhex = (char*)malloc((33) * sizeof(char));
  sprintf(userhex, "");

  //convert the userid to hex which is how it is stored in the file
  for (int i = 0; i < 16; i++) {
    sprintf(userhex, "%s%02X", userhex, userid[i]);
  }
  File dataFile = SD.open(userFile);
  if (dataFile) {
    boolean isUser;
    for (int user = 1; user <= numUser; user++) {
      //each user is 60 char long + the first 60 char line so the begining cahr of the user id is at position user# * 60
      dataFile.seek(user * 60);
      isUser = 1;
      //read the user id hex by hex to compare it to userhex
      for (int i = 0; i < 32; i++) {
        if (dataFile.read() != userhex[i]) {
          isUser = 0;
          break;
        }
      }
      if (isUser) {
        free(userhex);
        //there is one space between the userid and the userName so call read() function to advance by one character skippinng the space
        dataFile.read();
        dataFile.read(userName, 25);
        dataFile.close();
        //make sure the last character is a 0 so that it is a proper string
        userName[25] = 0;
        Serial.println(userName);
        return 1;
      }
    }
    dataFile.close();
    free(userhex);
    return 0;
  }
  else {
    free(userhex);
    Serial.println("error");
    setup();
    return findUser(userid, userName);
  }
}

//determine the number of users
int numUsers() {
  File dataFile = SD.open(userFile);
  if (dataFile) {
    //each user uses 60 characters of space in the file in addition to the 60 characters at the begining of the file
    int num = (dataFile.size() / 60) - 1;
    dataFile.close();
    return num;
  }
  else {
    return -1;
  }
}

//save str and current date and time to and SD card file specified by fileName
void saveMessage(char* data, char* fileName, byte len) {
  // make a string for assembling the data to log:
  char *dataString = (char*)malloc((len + 20 + 2) * sizeof(char));
  char *dateTime = date();
  sprintf(dataString, "%s\t%s", data, dateTime);
  Serial.println(dataString);


  // open the file. note that only one file can be open at a time,
  // so you have to close this one before opening another.
  File dataFile = SD.open(fileName, FILE_WRITE);
  // if the file is available, write to it:
  if (dataFile) {
    dataFile.println(dataString);
    dataFile.close();
  }
  // if the file isn't open, pop up an error:
  else {
    Serial.println("error");
  }

  free(dataString);
  free(dateTime);
}

//return the current date and time
char* date() {
  DateTime t_now = rtc.now();//retrieves the current date and time from the real time clock
  char* date = (char*)malloc(20 * sizeof(char));
  //compile the date and time into a usable string
  sprintf(date, "%d/%d/%d %d:%d:%d", t_now.month(), t_now.day(), t_now.year(), t_now.hour(), t_now.minute(), t_now.second());
  return date;
}

//take a byte array and convert it to a chararray of hex values
//not used in the code but is useful for printing byte arrays when debugging
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

//Generate a new ID which is returned as a 16 Byte array.
byte* getNewID() {
  byte* ID = (byte*)malloc(16 * sizeof(byte));;
  for (int i = 0; i < 16; i++) {
    ID[i] = random(256);
  }
  return ID;
}










