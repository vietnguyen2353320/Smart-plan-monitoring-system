import tkinter as tk
from tkinter import messagebox
import threading
import paho.mqtt.client as mqtt
import json
import os
import re


# ============================================================
#   SIMON 128/128 — Python Implementation (matches Arduino)
# ============================================================

# -------- 64-bit rotates --------
def rol64(x, r):
    return ((x << r) | (x >> (64 - r))) & 0xFFFFFFFFFFFFFFFF

def ror64(x, r):
    return ((x >> r) | (x << (64 - r))) & 0xFFFFFFFFFFFFFFFF

# -------- SIMON f-function --------
def f64(x):
    return (rol64(x, 1) & rol64(x, 8)) ^ rol64(x, 2)

# -------- Your 128-bit key (same as Arduino) --------
SIMON_KEY = [
    0x656b696c20646e75,
    0x656b696c20646e75
]

# ============================================================
# Key schedule — produces 68 round keys
# ============================================================
def simon128_key_schedule(key):
    rk = [0] * 68

    A = key[0]
    B = key[1]
    c = 0xfffffffffffffffc
    z = 0x7369f885192c0ef5  # z0 sequence, LSB-first

    i = 0
    while i < 64:
        rk[i] = A
        A ^= c ^ (z & 1) ^ ror64(B, 3) ^ ror64(B, 4)
        z >>= 1
        i += 1

        rk[i] = B
        B ^= c ^ (z & 1) ^ ror64(A, 3) ^ ror64(A, 4)
        z >>= 1
        i += 1

    rk[64] = A
    A ^= c ^ 1 ^ ror64(B, 3) ^ ror64(B, 4)

    rk[65] = B
    B ^= c ^ 0 ^ ror64(A, 3) ^ ror64(A, 4)

    rk[66] = A
    rk[67] = B

    return rk

# ============================================================
# Encryption — correct SIMON round
# ============================================================
def simon128_encrypt_block(pt, rk):
    x, y = pt

    for i in range(68):
        new_x = y ^ f64(x) ^ rk[i]
        new_y = x
        x = new_x & 0xFFFFFFFFFFFFFFFF
        y = new_y & 0xFFFFFFFFFFFFFFFF

    return (x, y)

# ============================================================
# Decryption — inverse of encryption
# ============================================================
def simon128_decrypt_block(ct, rk):
    x, y = ct

    for i in reversed(range(68)):
        old_x = y
        old_y = x ^ f64(y) ^ rk[i]
        x = old_x & 0xFFFFFFFFFFFFFFFF
        y = old_y & 0xFFFFFFFFFFFFFFFF

    return (x, y)

# ============================================================
# Byte helpers (big-endian)
# ============================================================
def bytes_to_u64_be(b):
    return int.from_bytes(b, "big")

def u64_to_bytes_be(v):
    return v.to_bytes(8, "big")

# ============================================================
# Encrypt string → 32 hex chars
# ============================================================
def simon128_encrypt_string(plain):
    # pad/truncate to 16 bytes
    plain = plain[:16].ljust(16, " ")

    buf = plain.encode("utf-8")

    pt = (
        bytes_to_u64_be(buf[:8]),
        bytes_to_u64_be(buf[8:])
    )

    rk = simon128_key_schedule(SIMON_KEY)
    ct = simon128_encrypt_block(pt, rk)

    return f"{ct[0]:016X}{ct[1]:016X}"

# ============================================================
# Decrypt 32-hex → plaintext string
# ============================================================
def simon128_decrypt_string(hex_cipher):
    if len(hex_cipher) != 32:
        return ""

    ct0 = int(hex_cipher[:16], 16)
    ct1 = int(hex_cipher[16:], 16)

    rk = simon128_key_schedule(SIMON_KEY)
    pt = simon128_decrypt_block((ct0, ct1), rk)

    buf = u64_to_bytes_be(pt[0]) + u64_to_bytes_be(pt[1])
    text = buf.decode("utf-8", errors="ignore")

    return text.rstrip(" ")

# ====================================================
#  Send encrypted command
# ====================================================

def send_encrypted_to_mqtt(client, plain_cmd):
    try:
        encrypted = simon128_encrypt_string(plain_cmd)
        decrypted = simon128_decrypt_string(encrypted)
        print(f"SEND -> plain: '{plain_cmd}', encrypted: {encrypted}, decrypted: {decrypted}")
        client.publish("esp32/commands_enc", encrypted)
    except Exception as e:
        print("Error sending command:", e)

# ====================================================
#  GUI SENSOR CARD
# ====================================================

def round_rect(canvas, x1, y1, x2, y2, radius=20, **kwargs):
    points = [
        x1 + radius, y1,
        x2 - radius, y1,
        x2, y1,
        x2, y1 + radius,
        x2, y2 - radius,
        x2, y2,
        x2 - radius, y2,
        x1 + radius, y2,
        x1, y2,
        x1, y2 - radius,
        x1, y1 + radius,
        x1, y1
    ]
    return canvas.create_polygon(points, smooth=True, **kwargs)

class SensorCard:
    def __init__(self, canvas, x, y, label, emoji, color, app):
        self.canvas = canvas
        self.app = app
        self.label = label
        self.value = 0
        self.min_value = 20
        self.max_value = 80
        self.was_bad = False
        self.card = round_rect(canvas, x, y, x + 220, y + 160, radius=25,
                               fill=color, outline="white", width=2)
        self.label_text = canvas.create_text(x + 110, y + 30, text=label,
                                             font=("Arial", 18, "bold"))
        self.value_text = canvas.create_text(x + 110, y + 80,
                                             text=str(self.value),
                                             font=("Arial", 32, "bold"),
                                             fill="#1B7F6B")
        self.emoji_text = canvas.create_text(x + 180, y + 30,
                                             text=emoji,
                                             font=("Arial", 22))
        self.status_text = canvas.create_text(x + 110, y + 130,
                                              text="Good",
                                              font=("Arial", 16),
                                              fill="green")
    def update_value(self, v):
        self.value = v
        self.canvas.itemconfig(self.value_text, text=str(v))
        out = v < self.min_value or v > self.max_value
        if out:
            self.canvas.itemconfig(self.status_text, text="Bad", fill="red")
            self.canvas.itemconfig(self.emoji_text, text="😟")
        else:
            self.canvas.itemconfig(self.status_text, text="Good", fill="green")
            self.canvas.itemconfig(self.emoji_text, text="😊")
    def update_thresholds(self, mn, mx):
        self.min_value = mn
        self.max_value = mx

# ====================================================
#  MAIN APP
# ====================================================
class App:

    THRESHOLD_FILE = "thresholds.json"

    VALID_COMMANDS = [
    r"temp_min=\d+", r"temp_max=\d+",
    r"hum_min=\d+",  r"hum_max=\d+",
    r"light_min=\d+", r"light_max=\d+",
    r"air_min=\d+",   r"air_max=\d+",
    r"soil_min=\d+",  r"soil_max=\d+",
    r"reset", r"show"
]
    #Save and load threshold
    def save_thresholds(self):
        data = {
            "temperature": [self.temp.min_value, self.temp.max_value],
            "humidity": [self.hum.min_value, self.hum.max_value],
            "light": [self.light.min_value, self.light.max_value],
            "air": [self.air.min_value, self.air.max_value],
            "soil": [self.soil.min_value, self.soil.max_value],
        }

        with open(self.THRESHOLD_FILE, "w") as f:
            json.dump(data, f, indent=4)

    def load_thresholds(self):
        if not os.path.exists(self.THRESHOLD_FILE):
            return  # No file → use defaults

        try:
            with open(self.THRESHOLD_FILE, "r") as f:
                data = json.load(f)

            self.temp.update_thresholds(*data["temperature"])
            self.hum.update_thresholds(*data["humidity"])
            self.light.update_thresholds(*data["light"])
            self.air.update_thresholds(*data["air"])
            self.soil.update_thresholds(*data["soil"])

        except Exception as e:
            print("Failed to load thresholds:", e)

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Smart Plant Monitor")
        self.root.geometry("900x700")
        self.root.config(bg="white")
        self.canvas = tk.Canvas(self.root, width=900, height=600,
                                bg="white", highlightthickness=0)
        self.canvas.pack()
        self.canvas.create_text(400, 40,
                                text="🌿 Smart Plant Monitor",
                                font=("Arial", 30, "bold"))

        # Sensor Cards
        self.temp = SensorCard(self.canvas, 50, 100, "Temperature", "🌡️", "#FFE5E5", self)
        self.hum = SensorCard(self.canvas, 300, 100, "Humidity", "💧", "#E6F3FF", self)
        self.light = SensorCard(self.canvas, 550, 100, "Light", "🔆", "#FFF8D5", self)
        self.air = SensorCard(self.canvas, 200, 300, "Air Quality", "🍃", "#E9FFF1", self)
        self.soil = SensorCard(self.canvas, 450, 300, "Soil Moisture", "🌱", "#F7EEDB", self)

        self.temp.update_thresholds(15, 38)
        self.hum.update_thresholds(40, 80)
        self.light.update_thresholds(100, 1000)
        self.air.update_thresholds(200, 2000)
        self.soil.update_thresholds(1000, 2500)
        
        self.load_thresholds()

        self.sensors = {
            "temperature": self.temp,
            "humidity": self.hum,
            "light": self.light,
            "air": self.air,
            "soil": self.soil
        }

        # Menu Panel
        self.create_menu()
        self.create_warning_chat()
        self.start_mqtt()


    # WARNING CHAT
    def create_warning_chat(self):
        frame = tk.Frame(self.root, bg="#F0F0F0", height=120)
        frame.pack(fill="x", side="bottom")
        tk.Label(frame, text="Warnings", bg="#F0F0F0",
                 font=("Arial", 14, "bold")).pack(anchor="w", padx=10)
        self.chat_box = tk.Text(frame, height=6, bg="white",
                                fg="black", font=("Arial", 12))
        self.chat_box.pack(fill="both", padx=10, pady=5)
        self.chat_box.config(state="disabled")

    def send_warning(self, msg):
        self.chat_box.config(state="normal")
        self.chat_box.insert("end", msg + "\n")
        self.chat_box.see("end")
        self.chat_box.config(state="disabled")


    # MENU PANEL
    def create_menu(self):
        self.menu = tk.Frame(self.root, bg="#E6FFF5", relief="ridge", bd=2)
        tk.Label(self.menu, text="Enter Command / Threshold",
                 font=("Arial", 12, "bold"), bg="#E6FFF5").pack(pady=(5, 0))
        self.entry = tk.Entry(self.menu, width=40)
        self.entry.pack(pady=5)
        tk.Button(self.menu, text="Apply", command=self.apply_command).pack(pady=5)
        self.menu_visible = False
        self.menu_button = tk.Button(self.root, text="☰ Menu",
                                     command=self.toggle_menu)
        self.menu_button.place(x=10, y=10)

    def toggle_menu(self):
        if self.menu_visible:
            self.menu.place_forget()
        else:
            self.menu.place(x=10, y=50)
        self.menu_visible = not self.menu_visible

    # APPLY COMMAND
    def is_valid_command(self, cmd):
        cmd = cmd.lower().strip()
        for pattern in self.VALID_COMMANDS:
            if re.fullmatch(pattern, cmd):
                return True
        return False
    def apply_command(self):
        cmd = self.entry.get().strip()

        if not self.is_valid_command(cmd):
            help_msg = (
                "❌ Invalid command!\n\n"
                "Valid commands:\n"
                "temp_min=<v>,  temp_max=<v>\n"
                "hum_min=<v>,   hum_max=<v>\n"
                "light_min=<v>, light_max=<v>\n"
                "air_min=<v>,   air_max=<v>\n"
                "soil_min=<v>,  soil_max=<v>\n\n"
                "show  - display all thresholds\n"
                "reset - reset to default values"
            )
            messagebox.showerror("Invalid Command", help_msg)
            return

        # Local effects for thresholds
        try:
            if "=" in cmd:
                name, raw = cmd.split("=", 1)
                value = int(raw)
                sensor_name, bound = name.split("_")
                sensor_map = {
                    "temp": "temperature", "temperature": "temperature",
                    "hum": "humidity", "humidity": "humidity",
                    "light": "light",
                    "air": "air",
                    "soil": "soil"
                }
                sensor_key = sensor_map.get(sensor_name)
                if sensor_key and sensor_key in self.sensors:
                    sensor = self.sensors[sensor_key]
                    # --- NEW CHECK HERE ---
                    if bound == "min":
                        if value > sensor.max_value:
                            messagebox.showerror(
                                "Invalid Threshold",
                                f"Min value cannot be greater than current max ({sensor.max_value})"
                            )
                            return
                        sensor.update_thresholds(value, sensor.max_value)
                        self.save_thresholds()

                    elif bound == "max":
                        if value < sensor.min_value:
                            messagebox.showerror(
                                "Invalid Threshold",
                                f"Max value cannot be lower than current min ({sensor.min_value})"
                            )
                            return
                        sensor.update_thresholds(sensor.min_value, value)
                        self.save_thresholds()

        except:
            pass

        # Local effect for reset/show
        if cmd.lower() == "reset":
            for s in self.sensors.values():
                self.temp.update_thresholds(15, 38)
                self.hum.update_thresholds(40, 80)
                self.light.update_thresholds(100, 1000)
                self.air.update_thresholds(200, 2000)
                self.soil.update_thresholds(1000, 2500)
            self.save_thresholds()
            messagebox.showinfo("Reset", "All thresholds reset")
        elif cmd.lower() == "show":
            all_vals = "\n".join([
                f"temperature: {self.temp.min_value} - {self.temp.max_value}",
                f"humidity: {self.hum.min_value} - {self.hum.max_value}",
                f"light: {self.light.min_value} - {self.light.max_value}",
                f"air: {self.air.min_value} - {self.air.max_value}",
                f"soil: {self.soil.min_value} - {self.soil.max_value}",
            ])
            messagebox.showinfo("Thresholds", all_vals)

        # Send encrypted command
        try:
            send_encrypted_to_mqtt(self.client, cmd)
        except Exception as e:
            messagebox.showerror("MQTT Error", f"Failed to send command: {e}")
            return

        messagebox.showinfo("OK", f"Command sent: {cmd}")

    # MQTT
    def start_mqtt(self):
        self.client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message
        self.client.connect("broker.hivemq.com", 1883, 60)
        threading.Thread(target=self.client.loop_forever, daemon=True).start()

    def on_connect(self, client, userdata, flags, rc, properties):
        client.subscribe("esp32/temperature")
        client.subscribe("esp32/humidity")
        client.subscribe("esp32/light")
        client.subscribe("esp32/air")
        client.subscribe("esp32/soil")
        client.subscribe("esp32/alertst")
        client.subscribe("esp32/alertsh")
        client.subscribe("esp32/alertsl")
        client.subscribe("esp32/alertsa")
        client.subscribe("esp32/alertss")

    def on_message(self, client, userdata, msg):
        raw = msg.payload.decode()

        # Handle ALERTS first
        if msg.topic.startswith("esp32/alerts"):
            try:
                decrypted = simon128_decrypt_string(raw)
            except Exception as e:
                decrypted = f"Decryption error: {e}"

            self.root.after(0, lambda: self.send_warning(f"⚠️ {decrypted}"))
            return

        # Otherwise normal sensor data
        decrypted = simon128_decrypt_string(raw)
        num = re.findall(r"-?\d+\.?\d*", decrypted)
        if not num:
            return

        value = float(num[-1])
        if value.is_integer():
            value = int(value)

        topic = msg.topic.split("/")[-1]
        if topic in self.sensors:
            self.root.after(0, lambda: self.sensors[topic].update_value(value))


    def start(self):
        self.root.mainloop()

if __name__ == "__main__":
    App().start()
