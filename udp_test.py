import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
import time
import ipaddress

class UDPTester:
    def __init__(self, root):
        self.root = root
        self.root.title("UDP 통신 테스트")
        self.root.geometry("600x500")
        self.root.resizable(True, True)
        
        self.udp_socket = None
        self.is_listening = False
        self.listen_thread = None
        
        self.create_widgets()
        self.update_ip_addresses()
        
    def create_widgets(self):
        # IP 주소 표시 및 선택
        ip_frame = tk.Frame(self.root)
        ip_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(ip_frame, text="IP 주소:").pack(side=tk.LEFT)
        self.ip_var = tk.StringVar()
        self.ip_dropdown = tk.OptionMenu(ip_frame, self.ip_var, "")
        self.ip_dropdown.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # 포트 입력
        port_frame = tk.Frame(self.root)
        port_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(port_frame, text="포트:").pack(side=tk.LEFT)
        self.port_var = tk.StringVar(value="5000")
        tk.Entry(port_frame, textvariable=self.port_var, width=10).pack(side=tk.LEFT, padx=5)
        
        # 제어 버튼
        control_frame = tk.Frame(self.root)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.listen_button = tk.Button(control_frame, text="수신 시작", command=self.toggle_listening)
        self.listen_button.pack(side=tk.LEFT, padx=5)
        
        tk.Button(control_frame, text="로그 지우기", command=self.clear_log).pack(side=tk.LEFT, padx=5)
        
        # 로그 영역
        log_frame = tk.Frame(self.root)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        tk.Label(log_frame, text="수신 로그:").pack(anchor=tk.W)
        self.log_area = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=20)
        self.log_area.pack(fill=tk.BOTH, expand=True)
        self.log_area.config(state=tk.DISABLED)
        
        # 상태 표시줄
        self.status_var = tk.StringVar(value="준비")
        status_bar = tk.Label(self.root, textvariable=self.status_var, bd=1, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def update_ip_addresses(self):
        # 시스템의 모든 IP 주소 가져오기
        ip_addresses = self.get_ip_addresses()
        
        # 드롭다운 메뉴 업데이트
        menu = self.ip_dropdown["menu"]
        menu.delete(0, "end")
        
        for ip in ip_addresses:
            menu.add_command(label=ip, command=lambda value=ip: self.ip_var.set(value))
        
        # 첫 번째 IP 주소 선택
        if ip_addresses:
            self.ip_var.set(ip_addresses[0])
        else:
            self.ip_var.set("127.0.0.1")
    
    def get_ip_addresses(self):
        ip_list = []
        
        # 모든 네트워크 인터페이스의 IP 주소 가져오기
        try:
            hostname = socket.gethostname()
            # IPv4 주소만 가져오기
            ip_list = [addr for addr in socket.getaddrinfo(hostname, None) 
                      if addr[0] == socket.AF_INET and not addr[4][0].startswith('127.')]
            ip_list = [addr[4][0] for addr in ip_list]
            
            # 중복 제거
            ip_list = list(dict.fromkeys(ip_list))
            
            # 로컬호스트 추가
            ip_list.append('127.0.0.1')
        except Exception as e:
            self.log_message(f"IP 주소 가져오기 오류: {e}")
            ip_list = ['127.0.0.1']
        
        return ip_list
    
    def toggle_listening(self):
        if not self.is_listening:
            self.start_listening()
        else:
            self.stop_listening()
    
    def start_listening(self):
        try:
            ip = self.ip_var.get()
            
            try:
                port = int(self.port_var.get())
                if port < 0 or port > 65535:
                    raise ValueError("포트 범위 오류")
            except ValueError:
                messagebox.showerror("오류", "유효한 포트 번호를 입력하세요 (0-65535)")
                return
            
            # 이미 열려있는 소켓 닫기
            if self.udp_socket:
                self.udp_socket.close()
            
            # 새 UDP 소켓 생성
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_socket.bind((ip, port))
            self.udp_socket.settimeout(0.5)  # 타임아웃 설정
            
            self.is_listening = True
            self.listen_button.config(text="수신 중지")
            self.status_var.set(f"수신 중: {ip}:{port}")
            
            # 로그에 메시지 추가
            self.log_message(f"UDP 소켓 열림 - {ip}:{port}")
            
            # 수신 스레드 시작
            self.listen_thread = threading.Thread(target=self.listen_for_data)
            self.listen_thread.daemon = True
            self.listen_thread.start()
            
        except Exception as e:
            messagebox.showerror("오류", f"수신 시작 실패: {e}")
            self.log_message(f"오류: {e}")
    
    def stop_listening(self):
        if self.is_listening:
            self.is_listening = False
            self.listen_button.config(text="수신 시작")
            self.status_var.set("준비")
            
            # 소켓 닫기
            if self.udp_socket:
                self.udp_socket.close()
                self.udp_socket = None
            
            # 로그에 메시지 추가
            self.log_message("UDP 소켓 닫힘")
    
    def listen_for_data(self):
        while self.is_listening:
            try:
                data, addr = self.udp_socket.recvfrom(4096)
                self.log_message(f"수신 ({addr[0]}:{addr[1]}):")
                
                # 데이터 표시 (16진수 및 ASCII)
                self.log_hexdump(data)
                
            except socket.timeout:
                # 타임아웃은 정상 - 계속 진행
                pass
            except Exception as e:
                if self.is_listening:  # 정상 종료가 아닌 경우만 오류 표시
                    self.log_message(f"수신 오류: {e}")
                break
    
    def log_message(self, message):
        def update_log():
            self.log_area.config(state=tk.NORMAL)
            self.log_area.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {message}\n")
            self.log_area.see(tk.END)
            self.log_area.config(state=tk.DISABLED)
        
        # GUI 업데이트는 메인 스레드에서 실행
        self.root.after(0, update_log)
    
    def log_hexdump(self, data):
        def update_log():
            self.log_area.config(state=tk.NORMAL)
            
            # 16진수 덤프 형식으로 데이터 표시
            hex_dump = ""
            ascii_dump = ""
            
            for i, byte in enumerate(data):
                # 16진수 값 추가
                hex_dump += f"{byte:02X} "
                
                # ASCII 문자 추가 (출력 가능한 문자만)
                if 32 <= byte <= 126:
                    ascii_dump += chr(byte)
                else:
                    ascii_dump += "."
                
                # 16바이트마다 줄바꿈
                if (i + 1) % 16 == 0 or i == len(data) - 1:
                    # 마지막 라인의 정렬을 위한 패딩
                    padding = "   " * (15 - (i % 16))
                    if i % 16 != 15:
                        hex_dump += padding
                    
                    line = f"  {hex_dump} |{ascii_dump}|\n"
                    self.log_area.insert(tk.END, line)
                    
                    hex_dump = ""
                    ascii_dump = ""
            
            self.log_area.insert(tk.END, "\n")
            self.log_area.see(tk.END)
            self.log_area.config(state=tk.DISABLED)
        
        # GUI 업데이트는 메인 스레드에서 실행
        self.root.after(0, update_log)
    
    def clear_log(self):
        self.log_area.config(state=tk.NORMAL)
        self.log_area.delete(1.0, tk.END)
        self.log_area.config(state=tk.DISABLED)

def main():
    root = tk.Tk()
    app = UDPTester(root)
    root.mainloop()

if __name__ == "__main__":
    main() 