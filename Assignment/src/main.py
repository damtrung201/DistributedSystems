# main_app.py
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
import socket
import threading
import json
import uuid
import time
from datetime import datetime
import os
import random
from identity import UserIdentity  # <<< BỔ SUNG QUAN TRỌNG

# --- Cấu hình ---
BROADCAST_PORT = 37020
PEER_TIMEOUT = 10
HEARTBEAT_INTERVAL = 3
MAX_HISTORY_SIZE = 100
# USERS_FILE đã bị loại bỏ
GOSSIP_FANOUT = 3


# --- Cửa sổ Thiết lập Định danh (THAY THẾ LoginWindow) ---
class IdentitySetupWindow:
    def __init__(self, on_success_callback):
        self.on_success = on_success_callback
        self.root = tk.Toplevel()
        self.root.title("Setup Identity")
        self.root.geometry("400x250")
        self.root.configure(bg="#2c3e50")

        tk.Label(self.root, text="Display Name", bg="#2c3e50", fg="#ecf0f1").pack(pady=(10, 0))
        self.username_entry = tk.Entry(self.root, bg="#34495e", fg="#ecf0f1", insertbackground="white")
        self.username_entry.pack(pady=5, padx=20, fill=tk.X)

        tk.Label(self.root, text="Private Key File (optional)", bg="#2c3e50", fg="#ecf0f1").pack(pady=(10, 0))
        key_frame = tk.Frame(self.root, bg="#2c3e50")
        key_frame.pack(pady=5, padx=20, fill=tk.X)
        self.key_file_entry = tk.Entry(key_frame, bg="#34495e", fg="#ecf0f1", insertbackground="white")
        self.key_file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Button(key_frame, text="Browse...", command=self.browse_file, bg="#3498db", fg="white").pack(side=tk.RIGHT,
                                                                                                        padx=(5, 0))

        tk.Button(self.root, text="Start Chatting", command=self.start, bg="#1abc9c", fg="white",
                  font=("Helvetica", 12, "bold")).pack(pady=20, ipady=8, ipadx=10)

        self.root.protocol("WM_DELETE_WINDOW", lambda: os._exit(0))
        self.root.transient()
        self.root.grab_set()
        self.root.focus_set()

    def browse_file(self):
        filename = filedialog.askopenfilename(
            title="Select your private key",
            filetypes=(("PEM files", "*.pem"), ("All files", "*.*"))
        )
        if filename:
            self.key_file_entry.delete(0, tk.END)
            self.key_file_entry.insert(0, filename)

    def start(self):
        username = self.username_entry.get().strip()
        if not username:
            messagebox.showerror("Error", "Display Name cannot be empty.")
            return

        key_file = self.key_file_entry.get().strip()
        identity = None
        try:
            if key_file and os.path.exists(key_file):
                identity = UserIdentity(private_key_path=key_file)
                messagebox.showinfo("Success", f"Identity loaded successfully from {key_file}")
            else:
                identity = UserIdentity()
                default_key_file = "my_private_key.pem"
                identity.save_private_key(default_key_file)
                messagebox.showinfo("Welcome!",
                                    f"A new identity has been created for you and saved to '{default_key_file}'. Keep this file safe!")

            self.root.destroy()
            self.on_success(identity, username)

        except Exception as e:
            messagebox.showerror("Error", f"Failed to load or create identity: {e}")


# --- Ứng dụng Chat chính (Đã cập nhật) ---
class P2pChatApp:
    def __init__(self, root, user_identity, username):
        self.root = root
        self.identity = user_identity  # <<< THAY ĐỔI
        self.username = username  # <<< THAY ĐỔI
        self.peer_id = self.identity.user_id  # <<< ID là Khóa Public
        self.root.title(f"P2P Secure Chat (Gossip) - Logged in as {self.username}")

        self.peers = {}
        self.chat_history = []
        self.tcp_port = None
        self.is_running = True
        self.seen_message_ids = set()

        self.setup_ui()
        self.tcp_server_thread = threading.Thread(target=self.start_tcp_server, daemon=True)
        self.tcp_server_thread.start()
        self.root.after(100, self.start_dependent_network_services)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    # --- Các hàm setup_ui, update_peer_list, check_peers, v.v. giữ nguyên ---
    def start_dependent_network_services(self):
        if self.tcp_port is None:
            self.root.after(100, self.start_dependent_network_services)
            return
        self.udp_listener_thread = threading.Thread(target=self.listen_for_peers, daemon=True)
        self.udp_listener_thread.start()
        self.heartbeat_thread = threading.Thread(target=self.send_heartbeat, daemon=True)
        self.heartbeat_thread.start()
        self.peer_checker_thread = threading.Thread(target=self.check_peers, daemon=True)
        self.peer_checker_thread.start()
        self.announce_presence_and_request_history()

    def setup_ui(self):
        main_frame = tk.Frame(self.root, bg="#2c3e50")
        main_frame.pack(fill=tk.BOTH, expand=True)
        left_frame = tk.Frame(main_frame, width=200, bg="#34495e", padx=10, pady=10)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, expand=False)
        my_id_label = tk.Label(left_frame, text="Logged in as:", bg="#34495e", fg="#ecf0f1",
                               font=("Helvetica", 10, "bold"))
        my_id_label.pack(anchor="w")
        my_id_value = tk.Label(left_frame, text=self.username, bg="#34495e", fg="#1abc9c",
                               font=("Helvetica", 12, "bold"), wraplength=180, justify="left")
        my_id_value.pack(anchor="w", pady=(0, 10))
        peers_label = tk.Label(left_frame, text="Peers Online:", bg="#34495e", fg="#ecf0f1",
                               font=("Helvetica", 10, "bold"))
        peers_label.pack(anchor="w")
        self.peer_listbox = tk.Listbox(left_frame, bg="#2c3e50", fg="#ecf0f1", selectbackground="#1abc9c",
                                       borderwidth=0, highlightthickness=0)
        self.peer_listbox.pack(fill=tk.BOTH, expand=True)
        right_frame = tk.Frame(main_frame, bg="#2c3e50", padx=10, pady=10)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        self.chat_display = scrolledtext.ScrolledText(right_frame, state='disabled', bg="#34495e", fg="#ecf0f1",
                                                      wrap=tk.WORD, font=("Helvetica", 11))
        self.chat_display.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        input_frame = tk.Frame(right_frame, bg="#2c3e50")
        input_frame.pack(fill=tk.X)
        self.message_entry = tk.Entry(input_frame, bg="#34495e", fg="#ecf0f1", insertbackground="white",
                                      font=("Helvetica", 11))
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=8, padx=(0, 10))
        self.message_entry.bind("<Return>", self.send_group_message_event)
        send_button = tk.Button(input_frame, text="Send", command=self.send_group_message_event, bg="#1abc9c",
                                fg="white", font=("Helvetica", 10, "bold"), borderwidth=0)
        send_button.pack(side=tk.RIGHT, ipady=5, ipadx=10)

    def display_message(self, sender_id, sender_username, text, timestamp_val=None, is_verified=True):
        # Kiểm tra nếu là tin nhắn của chính mình
        if sender_id == self.peer_id:
            sender_display = "You"
        else:
            # Lấy 10 ký tự đầu của khóa công khai để làm "dấu vân tay"
            key_preview = f"({sender_id[:10]}...)"
            # Kết hợp tên người dùng và dấu vân tay khóa
            sender_display = f"{sender_username}"

        dt_object = datetime.fromtimestamp(timestamp_val) if timestamp_val else datetime.now()
        timestamp_str = dt_object.strftime('%H:%M:%S')
        verification_tag = "✅" if is_verified else "❌"

        self.chat_display.config(state='normal')
        # Chèn định dạng hiển thị mới vào khung chat
        self.chat_display.insert(tk.END, f"[{timestamp_str}] {sender_display} {verification_tag}: {text}\n")
        self.chat_display.config(state='disabled')
        self.chat_display.yview(tk.END)

    def update_peer_list(self):
        self.peer_listbox.delete(0, tk.END)
        for pid, data in self.peers.items():
            self.peer_listbox.insert(tk.END, data['username'])

    def send_broadcast(self, message):
        # ID giờ là khóa public
        message.update({'id': self.peer_id, 'username': self.username, 'tcp_port': self.tcp_port})
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            sock.sendto(json.dumps(message).encode('utf-8'), ('255.255.255.255', BROADCAST_PORT))
        except Exception as e:
            print(f"Error sending broadcast: {e}")
        finally:
            sock.close()

    def listen_for_peers(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', BROADCAST_PORT))
        while self.is_running:
            try:
                data, addr = sock.recvfrom(1024)
                message = json.loads(data.decode('utf-8'))
                sender_id, sender_username, sender_tcp_port = message.get('id'), message.get('username'), message.get(
                    'tcp_port')
                if not all([sender_id, sender_username, sender_tcp_port]) or sender_id == self.peer_id:
                    continue
                if sender_id not in self.peers:
                    print(f"Discovered new peer: {sender_username} ({sender_id[:15]}...)")
                    self.send_broadcast({'type': 'heartbeat'})
                self.peers[sender_id] = {'addr': (addr[0], sender_tcp_port), 'last_seen': time.time(),
                                         'username': sender_username}
                if message.get('type') == 'req_history':
                    print(f"Received history request from {sender_username}. Sending history.")
                    self.send_history_to_peer(self.peers[sender_id]['addr'])
                self.root.after(0, self.update_peer_list)
            except Exception as e:
                if self.is_running: print(f"Error in UDP listener: {e}")

    def send_heartbeat(self):
        while self.is_running:
            self.send_broadcast({'type': 'heartbeat'})
            time.sleep(HEARTBEAT_INTERVAL)

    def check_peers(self):
        while self.is_running:
            now = time.time()
            offline_peers = [pid for pid, data in self.peers.items() if now - data['last_seen'] > PEER_TIMEOUT]
            if offline_peers:
                for pid in offline_peers:
                    print(f"Peer {self.peers[pid]['username']} timed out.")
                    del self.peers[pid]
                self.root.after(0, self.update_peer_list)
            time.sleep(PEER_TIMEOUT / 2)

    def announce_presence_and_request_history(self):
        print("Announcing presence and requesting history...")
        self.send_broadcast({'type': 'heartbeat'})
        self.send_broadcast({'type': 'req_history'})

    def start_tcp_server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('', 0))
        self.tcp_port = server_socket.getsockname()[1]
        print(f"TCP Server started, listening on port {self.tcp_port}")
        server_socket.listen(5)
        while self.is_running:
            try:
                client_socket, addr = server_socket.accept()
                threading.Thread(target=self.handle_tcp_client, args=(client_socket,), daemon=True).start()
            except Exception as e:
                if self.is_running: print(f"Error in TCP server: {e}")
        server_socket.close()

    def handle_tcp_client(self, client_socket):
        try:
            full_data = b""
            while True:
                chunk = client_socket.recv(1024)
                if not chunk: break
                full_data += chunk
            if full_data:
                message = json.loads(full_data.decode('utf-8'))
                if message.get('type') == 'group_message':
                    self.handle_incoming_message(message['data'], message.get('gossiped_from'))
                elif message.get('type') == 'history':
                    self.handle_incoming_history(message['data'])
        except Exception as e:
            print(f"Error handling TCP client: {e}")
        finally:
            client_socket.close()

    def send_tcp_message(self, target_addr, message):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect(target_addr)
                sock.sendall(json.dumps(message).encode('utf-8'))
        except Exception as e:
            print(f"Error sending TCP message to {target_addr}: {e}")

    # --- CÁC HÀM GỬI/NHẬN TIN NHẮN ĐÃ ĐƯỢC NÂNG CẤP BẢO MẬT ---
    def send_group_message_event(self, event=None):
        text = self.message_entry.get()
        if not text.strip(): return
        self.message_entry.delete(0, tk.END)

        timestamp = time.time()
        # Nội dung cần ký: kết hợp các thông tin bất biến của tin nhắn
        content_to_sign = f"{timestamp}:{text}"
        signature = self.identity.sign_message(content_to_sign)

        message_data = {
            'msg_id': str(uuid.uuid4()),
            'sender_id': self.peer_id,  # Khóa public của người gửi
            'sender_username': self.username,
            'text': text,
            'timestamp': timestamp,
            'signature': signature  # <<< Chữ ký số
        }

        self.add_to_history(message_data)
        self.display_message(self.peer_id, self.username, text, timestamp, is_verified=True)
        self.gossip_message(message_data)

    def gossip_message(self, message_data, gossiped_from=None):
        potential_targets = list(self.peers.keys())
        if self.peer_id in potential_targets: potential_targets.remove(self.peer_id)
        if gossiped_from in potential_targets: potential_targets.remove(gossiped_from)
        if not potential_targets: return

        k = min(GOSSIP_FANOUT, len(potential_targets))
        gossip_targets = random.sample(potential_targets, k)
        print(f"Gossiping message {message_data['msg_id'][:8]} to {len(gossip_targets)} peers.")
        tcp_message = {'type': 'group_message', 'data': message_data, 'gossiped_from': self.peer_id}
        for peer_id in gossip_targets:
            target_addr = self.peers[peer_id]['addr']
            threading.Thread(target=self.send_tcp_message, args=(target_addr, tcp_message), daemon=True).start()

    def handle_incoming_message(self, msg_data, gossiped_from=None):
        if msg_data['msg_id'] in self.seen_message_ids:
            return

        # <<< BƯỚC XÁC THỰC QUAN TRỌNG NHẤT >>>
        content_to_verify = f"{msg_data['timestamp']}:{msg_data['text']}"
        is_valid = UserIdentity.verify_signature(
            public_key_b64=msg_data['sender_id'],
            signature_b64=msg_data['signature'],
            message=content_to_verify
        )

        if not is_valid:
            print(f"!!! WARNING: Invalid signature for message {msg_data['msg_id'][:8]}. Discarding. !!!")
            # Tùy chọn: hiển thị tin nhắn không hợp lệ trên UI
            self.root.after(0, lambda: self.display_message(
                msg_data['sender_id'], msg_data['sender_username'],
                f"[INVALID SIGNATURE] {msg_data['text']}", msg_data['timestamp'], is_verified=False
            ))
            return  # Dừng xử lý ngay lập tức

        # Nếu chữ ký hợp lệ, tiếp tục xử lý
        self.seen_message_ids.add(msg_data['msg_id'])
        if self.add_to_history(msg_data):
            self.root.after(0, lambda: self.display_message(
                msg_data['sender_id'], msg_data['sender_username'],
                msg_data['text'], msg_data['timestamp'], is_verified=True
            ))
            self.gossip_message(msg_data, gossiped_from=gossiped_from)

    # --- Các hàm quản lý lịch sử giữ nguyên ---
    def add_to_history(self, msg_data):
        if msg_data['msg_id'] not in [m['msg_id'] for m in self.chat_history]:
            self.chat_history.append(msg_data)
            self.chat_history.sort(key=lambda x: x['timestamp'])
            while len(self.chat_history) > MAX_HISTORY_SIZE: self.chat_history.pop(0)
            return True
        return False

    def send_history_to_peer(self, target_addr):
        if self.chat_history:
            message = {'type': 'history', 'data': self.chat_history}
            threading.Thread(target=self.send_tcp_message, args=(target_addr, message), daemon=True).start()

    def handle_incoming_history(self, history_data):
        print("Received chat history. Synchronizing...")
        current_msg_ids = {msg['msg_id'] for msg in self.chat_history}
        new_messages_added = False
        for msg in history_data:
            # Xác thực từng tin nhắn trong lịch sử trước khi thêm vào
            content_to_verify = f"{msg.get('timestamp', 0)}:{msg.get('text', '')}"
            if msg.get('signature') and UserIdentity.verify_signature(msg['sender_id'], msg['signature'],
                                                                      content_to_verify):
                if msg['msg_id'] not in current_msg_ids:
                    self.chat_history.append(msg)
                    current_msg_ids.add(msg['msg_id'])
                    self.seen_message_ids.add(msg['msg_id'])
                    new_messages_added = True
            else:
                print(f"Skipping unverified message from history: {msg['msg_id'][:8]}")

        if new_messages_added:
            self.chat_history.sort(key=lambda x: x['timestamp'])
            while len(self.chat_history) > MAX_HISTORY_SIZE: self.chat_history.pop(0)
            self.root.after(0, self.redisplay_history)

    def redisplay_history(self):
        self.chat_display.config(state='normal')
        self.chat_display.delete('1.0', tk.END)
        self.chat_display.config(state='disabled')
        for msg in self.chat_history:
            self.display_message(msg['sender_id'], msg['sender_username'], msg['text'], msg['timestamp'],
                                 is_verified=True)

    def on_closing(self):
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.is_running = False
            self.root.destroy()


# --- Luồng chính đã cập nhật ---
if __name__ == "__main__":
    main_root = tk.Tk()
    main_root.withdraw()


    def on_identity_setup_success(identity_obj, username_str):
        main_root.deiconify()
        app = P2pChatApp(main_root, identity_obj, username_str)
        main_root.geometry("800x600")


    setup_app = IdentitySetupWindow(on_identity_setup_success)
    setup_app.root.mainloop()