# Secure Smart Plant Monitoring System (IoT)

An end-to-end, secure Internet of Things (IoT) ecosystem designed to monitor environmental plant conditions in real-time. The system integrates an **ESP32 microcontroller** edge node with a **Python desktop application**, establishing encrypted telemetry data streaming and remote configuration pipelines over the MQTT protocol.

## 🚀 Key Features
- **Multi-Sensor Edge Node:** Collects real-time environmental data including temperature, humidity, ambient light intensity, air quality, and soil moisture.
- **Lightweight Cryptography:** Implements the **SIMON 128/128 Lightweight Block Cipher** from scratch on both ESP32 (C/C++) and PC Client (Python) to secure wireless data pipelines.
- **Dynamic Graphical Dashboard:** Built with Python (Tkinter) featuring real-time sensor cards, color-coded threshold statuses, and an automated warning notification feed.
- **Remote Configuration:** Allows secure updates to environmental safe-zone thresholds and data collection intervals from the PC client back to the edge node via encrypted MQTT command topics.
- **Non-Volatile Storage:** Hardware thresholds persist through reboots utilizing the ESP32 emulated EEPROM.

---

## 🏗️ System Architecture & Data Flow

The system operates on a lightweight, secure telemetry architecture structured around the following framework:

1. **Edge Node Topology (ESP32):** Reads hardware peripherals sequentially (DHT22, BH1750, MQ135, and Analog Soil Sensor) at user-defined intervals (Default: 5000ms).
2. **Data Encapsulation & Encryption:** Formats raw metrics into strings, applies the SIMON-128 cryptographic cipher block, and publishes hex-encoded ciphertext to individual MQTT topics.
3. **Broker Transit (HiveMQ):** Acts as the asynchronous routing layer for encrypted packets (`esp32/temperature`, `esp32/light`, `esp32/commands_enc`, etc.).
4. **PC Client Processing (Python):** Handles network callbacks via `paho-mqtt`, executes SIMON decryption, updates the Tkinter GUI thread, and maintains status states using localized JSON storage (`thresholds.json`).

---

## 🛠️ Tech Stack & Components

### Software & Protocols
- **Languages:** Python (3.x), C/C++ (Arduino / ESP-IDF Framework)
- **Giao thức Mạng:** MQTT (Message Queuing Telemetry Transport)
- **Mã hóa:** SIMON 128-bit block cipher / 128-bit key
- **Libraries (Python):** `paho-mqtt`, `tkinter`, `json`
- **Libraries (ESP32):** `WiFi.h`, `PubSubClient.h`, `Wire.h`, `Adafruit_SSD1306.h`, `DHT.h`, `BH1750.h`, `EEPROM.h`

### Hardware Components
- ESP32 Development Board (ESP32-WROOM-32)
- DHT22 Temperature & Humidity Sensor
- BH1750 Ambient Light Intensity Sensor
- MQ135 Air Quality Sensor
- Analog Soil Moisture Sensor
- SSD1306 OLED Display (128x64 pixels)

---

## 👥 My Personal Contributions
As the **Network & Python Application Developer** for this project, I engineered the end-to-end network communication and control application layer:
- Developed the Python Desktop Dashboard application using **Tkinter** with automated UI state updates based on live sensor ranges.
- Implemented the full **SIMON 128/128 encryption/decryption engine** in Python, ensuring perfect mathematical alignment with the ESP32 C++ implementation.
- Established asynchronous network socket connection handlers and topic subscriptions using **paho-mqtt**.
- Designed the remote command-handling interface and localized parameter persistence using structured **JSON tracking**.
- Partnered with firmware developers to rigorously debug, capture, and verify network payload alignment across the public broker.

---

## 🔮 Future Enhancements
- **Multi-Node Scalability:** Transitioning to an ESP-MESH or Zigbee network topology to aggregate telemetry from multiple plant nodes into a single edge gateway.
- **Power Optimization:** Incorporating hardware solar harvesting circuits paired with active ESP32 Deep-Sleep cyclic interval scheduling.
- **Autonomous Actuators:** Adding relay hardware switches to control automated water pumps and ventilation systems directly derived from threshold breaches.
