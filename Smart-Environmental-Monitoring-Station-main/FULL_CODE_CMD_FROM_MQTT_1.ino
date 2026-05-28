#include <WiFi.h>
#include <EEPROM.h>
#include <PubSubClient.h>
#include <Wire.h>
#include <Adafruit_SSD1306.h>
#include <Adafruit_GFX.h>
#include <Adafruit_Sensor.h>
#include <DHT.h>
#include <BH1750.h>

// WiFi and MQTT
const char* ssid = "Redmi Note 13 Pro";     
const char* password = "12345678";  
const char* mqtt_server = "broker.hivemq.com";

WiFiClient espClient;
PubSubClient client(espClient);

// OLED Display
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, -1);

// Sensors
#define DHTPIN 4
#define DHTTYPE DHT22
DHT dht(DHTPIN, DHTTYPE);

BH1750 lightMeter;
#define MQ135_PIN 34
#define SOIL_PIN 35


// Thresholds
struct Thresholds{
  double tempMax, tempMin;
  double humMax, humMin;
  double lightMax, lightMin;
  int airMax, airMin;
  int soilMax, soilMin;
  unsigned long msgInterval;
};

Thresholds th = {38, 15, 80, 40, 1000, 100, 2000, 200, 2500, 1000, 5000}; // {C, C, %, %, lx, lx, air, air, soil, soil, ms}

// EEPROM config
#define EEPROM_SIZE sizeof(Thresholds)

void saveThresholds() {
  EEPROM.put(0,th);
  EEPROM.commit();
  Serial.println("Saved");
}

void loadThresholds() {
  EEPROM.get(0,th);
  Serial.println("Loaded");
}
// Timing
unsigned long lastMsg = 0;

// 64-bit rotates
static inline uint64_t ROL64(uint64_t x,int r){
  return (x<<r)|(x>>(64-r));
}
static inline uint64_t ROR64(uint64_t x,int r){
  return (x>>r)|(x<<(64-r));
}

// SIMON f-function
static inline uint64_t f64(uint64_t x){
  return ((ROL64(x,1)&ROL64(x,8))^ROL64(x,2));
}

// your 128-bit key
uint64_t SIMON_KEY[2] = {
  0x656b696c20646e75ULL,
  0x656b696c20646e75ULL
};

// Key schedule produces 68 round keys
void simon128_key_schedule(const uint64_t key[2],uint64_t rk[68]){

  uint64_t A = key[0];
  uint64_t B = key[1];
  const uint64_t c = 0xfffffffffffffffcULL;
  uint64_t z = 0x7369f885192c0ef5ULL;  // z0 LSB-first

  int i = 0;
  for (i=0;i<64;){
    rk[i++] = A;
    A ^= c^(z&1ULL)^ROR64(B,3)^ROR64(B,4);
    z >>= 1;

    rk[i++] = B;
    B ^= c^(z&1ULL)^ROR64(A,3)^ROR64(A,4);
    z >>= 1;
  }

  rk[64] = A;
  A ^= c^1ULL^ROR64(B,3)^ROR64(B,4);

  rk[65] = B;
  B ^= c^0ULL^ROR64(A,3)^ROR64(A,4);

  rk[66] = A;
  rk[67] = B;
}

// Encryption
void simon128_encrypt(const uint64_t pt[2],uint64_t ct[2],const uint64_t rk[68]){

  uint64_t x = pt[0];
  uint64_t y = pt[1];

  for(int i=0;i<68;i++){
    uint64_t new_x = y^f64(x)^rk[i];
    uint64_t new_y = x;
    x = new_x;
    y = new_y;
  }

  ct[0] = x;
  ct[1] = y;
}

// Decryption
void simon128_decrypt(const uint64_t ct[2],uint64_t pt[2],const uint64_t rk[68]){

  uint64_t x = ct[0];
  uint64_t y = ct[1];

  for(int i=67;i>=0;i--){
    uint64_t old_x = y;
    uint64_t old_y = x^f64(y)^rk[i];
    x = old_x;
    y = old_y;
  }

  pt[0] = x;
  pt[1] = y;
}
// Byte helpers(big-endian)
uint64_t bytes_to_u64_be(const uint8_t *b){
  return ((uint64_t)b[0]<<56)|((uint64_t)b[1]<<48)|
         ((uint64_t)b[2]<<40)|((uint64_t)b[3]<<32)|
         ((uint64_t)b[4]<<24)|((uint64_t)b[5]<<16)|
         ((uint64_t)b[6]<<8)|(uint64_t)b[7];
}

void u64_to_bytes_be(uint64_t v, uint8_t *b){
  b[0] = (v>>56)&0xFF;
  b[1] = (v>>48)&0xFF;
  b[2] = (v>>40)&0xFF;
  b[3] = (v>>32)&0xFF;
  b[4] = (v>>24)&0xFF;
  b[5] = (v>>16)&0xFF;
  b[6] = (v>>8)&0xFF;
  b[7] =  v&0xFF;
}

// Encrypt string 32 hex chars
String simon128EncryptString(String plain){

  while(plain.length()<16) plain += ' ';
  if(plain.length()>16) plain = plain.substring(0,16);

  uint8_t buf[16];
  for (int i=0;i<16;i++) buf[i]=plain[i];

  uint64_t pt[2] = {
    bytes_to_u64_be(&buf[0]),
    bytes_to_u64_be(&buf[8])
  };

  uint64_t rk[68];
  simon128_key_schedule(SIMON_KEY,rk);

  uint64_t ct[2];
  simon128_encrypt(pt,ct,rk);

  char out[33];
  sprintf(out,"%016llX%016llX",
          (unsigned long long)ct[0],
          (unsigned long long)ct[1]);

  return String(out);
}
// Decrypt 32-hex-char plaintext
String simon128DecryptString(String hexCipher){

  if(hexCipher.length()!=32) return "";

  uint64_t ct[2] = {
    strtoull(hexCipher.substring(0,16).c_str(),NULL,16),
    strtoull(hexCipher.substring(16).c_str(),NULL,16)
  };

  uint64_t rk[68];
  simon128_key_schedule(SIMON_KEY,rk);

  uint64_t pt[2];
  simon128_decrypt(ct,pt,rk);

  uint8_t buf[16];
  u64_to_bytes_be(pt[0], &buf[0]);
  u64_to_bytes_be(pt[1], &buf[8]);

  String result = "";
  for(int i=0;i<16;i++) result+=(char)buf[i];

  while(result.endsWith(" ")) result.remove(result.length()-1);

  return result;
}

// WiFi Connect
void setup_wifi(){
  Serial.print("Connecting to ");
  Serial.println(ssid);
  WiFi.begin(ssid,password);
  while(WiFi.status()!=WL_CONNECTED){
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nWiFi connected");
  Serial.println(WiFi.localIP());
}

void reconnect(){
  while(!client.connected()){
    Serial.print("Attempting MQTT connection...");
    if (client.connect("ESP32ClientGroup5")){
      Serial.println("connected");
      client.subscribe("esp32/commands_enc");   
    } 
    else{
      Serial.print("failed");
      Serial.println(" retrying in 5s");
      delay(5000);
    }
  }
}

 // Command help
void printHelp(){
  Serial.println("\nCommands:");
  Serial.println("interval=<ms>");
  Serial.println("temp_min=<v>, temp_max=<v>");
  Serial.println("hum_min=<v>, hum_max=<v>");
  Serial.println("light_min=<v>, light_max=<v>");
  Serial.println("air_min=<v>, air_max=<v>");
  Serial.println("soil_min=<v>, soil_max=<v>");
  Serial.println("show: display all thresholds");
  Serial.println("reset: reset to default values");
}

// Handle command
void handleCommand(String cmd){
  cmd.trim();
  bool changed = false;
  if(cmd.equalsIgnoreCase("show")){
      Serial.printf("\nInterval: %lu ms\n",th.msgInterval);
      Serial.printf("Temp: %.2f - %.2f C\n",th.tempMin,th.tempMax);
      Serial.printf("Hum: %.2f - %.2f %%\n",th.humMin,th.humMax);
      Serial.printf("Light: %.2f - %.2f lx\n",th.lightMin,th.lightMax);
      Serial.printf("Air: %d - %d\n",th.airMin,th.airMax);
      Serial.printf("Soil: %d - %d\n",th.soilMin,th.soilMax);
    }
  else if(cmd.equalsIgnoreCase("reset")){
  th = {38, 15, 80, 40, 1000, 100, 2000, 200, 2500, 1000, 5000}; // {C, C, %, %, lx, lx, air, air, soil, soil, ms}
  saveThresholds();
  String enmsg= simon128EncryptString(cmd);
  String msg = simon128DecryptString(enmsg);
  Serial.print("Encrypted: ");    //test encrypted and decrypted string
  Serial.println(enmsg);
  Serial.print("Decrypted: ");
  Serial.println(msg);
  Serial.println("Reseted to default values");
  }
  else if(cmd.startsWith("temp_max=")){ 
    th.tempMax = (cmd.substring(9)).toDouble(); 
    changed = true; 
    String enmsg= simon128EncryptString(cmd);
    String msg = simon128DecryptString(enmsg);
    Serial.print("Encrypted: ");    //test encrypted and decrypted string
    Serial.println(enmsg);
    Serial.print("Decrypted: ");
    Serial.println(msg);
    }
  else if(cmd.startsWith("temp_min=")){ 
    th.tempMin = (cmd.substring(9)).toDouble(); 
    changed = true; 
    }
  else if(cmd.startsWith("hum_max=")){ 
    th.humMax = (cmd.substring(8)).toDouble(); 
    changed = true; 
    }
  else if(cmd.startsWith("hum_min=")){ 
    th.humMin = (cmd.substring(8)).toDouble(); 
    changed = true; 
    }
  else if(cmd.startsWith("light_max=")){ 
    th.lightMax = (cmd.substring(10)).toDouble(); 
    changed = true; 
    }
  else if(cmd.startsWith("light_min=")){ 
    th.lightMin = (cmd.substring(10)).toDouble(); 
    changed = true; 
    }
  else if(cmd.startsWith("air_max=")){ 
    th.airMax = cmd.substring(8).toInt(); 
    changed = true; 
    }
  else if(cmd.startsWith("air_min=")){ 
    th.airMin = cmd.substring(8).toInt(); 
    changed = true; 
    }
  else if(cmd.startsWith("soil_max=")){ 
    th.soilMax = cmd.substring(9).toInt(); 
    changed = true; 
    }
  else if(cmd.startsWith("soil_min=")){ 
    th.soilMin = cmd.substring(9).toInt(); 
    changed = true; 
    }
  else if(cmd.startsWith("interval=")){ 
    th.msgInterval = cmd.substring(9).toInt(); 
    changed = true; 
    }
  else printHelp();

  if (changed){
    saveThresholds();
    String msg = "Updated: " + cmd;
    Serial.println(msg);
    client.publish("esp32/alerts",msg.c_str());
  }
}
//float
//topic
// emperature data	    esp32/temperature	
// Humidity data	      esp32/humidity	
// Light data	          esp32/light	
// Air quality data	    esp32/air	
// Soil moisture data	  esp32/soil	
// Threshold alerts	    esp32/alertst - temp , esp32/alertsh - humi, esp32/alertsl - light, esp32/alertsa - air, esp32/alertss - soil
// Encrypted commands	  esp32/commands_enc      

void callback(char* topic,byte* message,unsigned int length){
  String encMsg;
  for(int i = 0;i < length;i++) encMsg += (char)message[i];

  Serial.print("Encrypted incoming: ");
  Serial.println(encMsg);

  if(String(topic) == "esp32/commands_enc"){
      String cmd = simon128DecryptString(encMsg);
      Serial.print("Decrypted: ");
      Serial.println(cmd);

      handleCommand(cmd);
  }
}

// Setup
void setup() {
  Serial.begin(115200);
  Wire.begin();
  EEPROM.begin(EEPROM_SIZE);

  setup_wifi();
  client.setServer(mqtt_server, 1883);
  client.setCallback(callback);

  loadThresholds();

  dht.begin();
  lightMeter.begin();

  display.begin(SSD1306_SWITCHCAPVCC,0x3C);

  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0,0);
  display.println("Smart Plant Station");
  display.display();

  delay(2000);

  printHelp();
}

// Loop
void loop() {
  if(!client.connected()) reconnect();
  client.loop();

  if(Serial.available()){
    String cmd = Serial.readStringUntil('\n');
    handleCommand(cmd);
  }

  unsigned long now = millis();
  if(now - lastMsg > th.msgInterval){
    lastMsg = now;

    float temperature = dht.readTemperature();
    float humidity = dht.readHumidity();
    float lux = lightMeter.readLightLevel();
    int airValue = analogRead(MQ135_PIN);
    int soilValue = analogRead(SOIL_PIN);

    // Encrypt
    String encTemp = simon128EncryptString(String(temperature,2));
    String encHumi = simon128EncryptString(String(humidity,2));
    String encLight = simon128EncryptString(String(lux,2));
    String encAir = simon128EncryptString(String(airValue));
    String encSoil = simon128EncryptString(String(soilValue));

    //Decrypt
    float decTemp = simon128DecryptString(encTemp).toDouble();
    float decHumi = simon128DecryptString(encHumi).toDouble();
    float decLight = simon128DecryptString(encLight).toDouble();
    int decAir = simon128DecryptString(encAir).toInt();
    int decSoil = simon128DecryptString(encSoil).toInt();

    // Serial monitor
    Serial.println(" Sensor Data");
    Serial.printf("Temp: %.2f C | Hum: %.2f %% | Light: %.2f lx | Air: %d | Soil: %d\n",
                   temperature,humidity,lux,airValue,soilValue);
    Serial.printf("Temp: %s C | Hum: %s %% | Light: %s lx | Air: %s | Soil: %s\n",
                  encTemp.c_str(),encHumi.c_str(),encLight.c_str(),encAir.c_str(),encSoil.c_str());
    Serial.printf("Temp: %.2f C | Hum: %.2f %% | Light: %.2f lx | Air: %d | Soil: %d\n",
                   decTemp,decHumi,decLight,decAir,decSoil);

    // OLED display
    display.clearDisplay();
    display.setCursor(0, 0);
    display.print("Temp: "); display.print(temperature); display.println(" C");
    display.print("Humi: "); display.print(humidity); display.println(" %");
    display.print("Light: "); display.print(lux); display.println(" lx");
    display.print("Air: "); display.println(airValue);
    display.print("Soil: "); display.println(soilValue);
    

    // Publish
    client.publish("esp32/temperature", encTemp.c_str());
    client.publish("esp32/humidity", encHumi.c_str());
    client.publish("esp32/light", encLight.c_str());
    client.publish("esp32/air", encAir.c_str());
    client.publish("esp32/soil", encSoil.c_str());

    // Threshold checks
    char alert[16];
    if(th.tempMin>=th.tempMax){
      sprintf(alert,"Set Sai");
      Serial.println(alert);
      display.print(alert);
      String enalert=simon128EncryptString(String(alert));
      client.publish("esp32/alertst",enalert.c_str());
    }
    else if(th.humMin>=th.humMax){
      sprintf(alert,"Set Sai");
      Serial.println(alert);
      display.print(alert);
      String enalert=simon128EncryptString(String(alert));
      client.publish("esp32/alertsh",enalert.c_str());
    }
    else if(th.lightMin>=th.lightMax){
      sprintf(alert,"Set Sai");
      Serial.println(alert);
      display.print(alert);
      String enalert=simon128EncryptString(String(alert));
      client.publish("esp32/alertsl",enalert.c_str());
    }
    else if(th.airMin>=th.airMax){
      sprintf(alert,"Set Sai");
      Serial.println(alert);
      display.print(alert);
      String enalert=simon128EncryptString(String(alert));
      client.publish("esp32/alertsa",enalert.c_str());
    }
    else if(th.soilMin>=th.soilMax){
      sprintf(alert,"Set Sai");
      Serial.println(alert);
      display.print(alert);
      String enalert=simon128EncryptString(String(alert));
      client.publish("esp32/alertss",enalert.c_str());
    }
    else{
    if(temperature < th.tempMin){
      sprintf(alert,"Too Cold");
      Serial.println(alert);
      display.print(alert);
      String enalert=simon128EncryptString(String(alert));
      client.publish("esp32/alertst",enalert.c_str());
    }

    if(temperature > th.tempMax){
     sprintf(alert,"Too Hot");
      Serial.println(alert);
      display.print(alert);
      String enalert=simon128EncryptString(String(alert));
      client.publish("esp32/alertst",enalert.c_str());
    }

    if(humidity < th.humMin){
     sprintf(alert,"Too Dried");
     Serial.println(alert);
     display.print(alert);
     String enalert=simon128EncryptString(String(alert));
     client.publish("esp32/alertsh",enalert.c_str());
    }

    if(humidity > th.humMax){
     sprintf(alert,"Too Humid");
     Serial.println(alert);
     display.print(alert);
     String enalert=simon128EncryptString(String(alert));
     client.publish("esp32/alertsh",enalert.c_str());
    }

    if(lux < th.lightMin){
      sprintf(alert,"Too Dark");
      Serial.println(alert);
      display.print(alert);
      String enalert=simon128EncryptString(String(alert));
      client.publish("esp32/alertsl",enalert.c_str());
    }
    if(lux > th.lightMax){
      sprintf(alert,"Too Bright");
      Serial.println(alert);
      display.print(alert);
      String enalert=simon128EncryptString(String(alert));
      client.publish("esp32/alertsl",enalert.c_str());
    }

    if(airValue < th.airMin){
      sprintf(alert,"Too Clean");
      Serial.println(alert);
      display.print(alert);
      String enalert=simon128EncryptString(String(alert));
      client.publish("esp32/alertsa",enalert.c_str());
    }
    if(airValue > th.airMax){
      sprintf(alert,"Too Poor");
      Serial.println(alert);
      display.print(alert);
      String enalert=simon128EncryptString(String(alert));
      client.publish("esp32/alertsa",enalert.c_str());
    }

    if(soilValue < th.soilMin){
      sprintf(alert,"Too Wet");
      Serial.println(alert);
      display.print(alert);
      String enalert=simon128EncryptString(String(alert));
      client.publish("esp32/alertss",enalert.c_str());
    }
    if(soilValue > th.soilMax){
      sprintf(alert,"Too Dry");
      Serial.println(alert);
      display.print(alert);
      String enalert=simon128EncryptString(String(alert));
      client.publish("esp32/alertss",enalert.c_str());
    }
    }

    // Serial.printf("Sent data at %lu ms\n", now);
    display.display();
  }
}
