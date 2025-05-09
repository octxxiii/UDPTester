import socket
import tkinter as tk
from tkinter import messagebox

class UDPSender:
    def __init__(self, root):
        self.root = root
        self.root.title("UDP 데이터 전송")
        self.root.geometry("500x300")
        self.root.resizable(True, True)
        
        self.create_widgets()
    
    def create_widgets(self):
        # 목적지 IP 입력
        ip_frame = tk.Frame(self.root)
        ip_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(ip_frame, text="목적지 IP:").pack(side=tk.LEFT)
        self.ip_var = tk.StringVar(value="127.0.0.1")
        tk.Entry(ip_frame, textvariable=self.ip_var, width=15).pack(side=tk.LEFT, padx=5)
        
        # 목적지 포트 입력
        port_frame = tk.Frame(self.root)
        port_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(port_frame, text="목적지 포트:").pack(side=tk.LEFT)
        self.port_var = tk.StringVar(value="5000")
        tk.Entry(port_frame, textvariable=self.port_var, width=10).pack(side=tk.LEFT, padx=5)
        
        # 전송할 데이터 입력
        data_frame = tk.Frame(self.root)
        data_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        tk.Label(data_frame, text="전송할 데이터 (텍스트):").pack(anchor=tk.W)
        self.data_text = tk.Text(data_frame, height=8)
        self.data_text.pack(fill=tk.BOTH, expand=True)
        self.data_text.insert(tk.END, "테스트 메시지")
        
        # 전송 버튼
        button_frame = tk.Frame(self.root)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Button(button_frame, text="전송", command=self.send_data).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="16진수 전송", command=self.send_hex_data).pack(side=tk.LEFT, padx=5)
    
    def send_data(self):
        try:
            ip = self.ip_var.get()
            
            try:
                port = int(self.port_var.get())
                if port < 0 or port > 65535:
                    raise ValueError("포트 범위 오류")
            except ValueError:
                messagebox.showerror("오류", "유효한 포트 번호를 입력하세요 (0-65535)")
                return
            
            data = self.data_text.get(1.0, tk.END)
            
            # UDP 소켓 생성 및 데이터 전송
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(data.encode('utf-8'), (ip, port))
            sock.close()
            
            messagebox.showinfo("성공", "데이터 전송 완료")
            
        except Exception as e:
            messagebox.showerror("오류", f"전송 실패: {e}")
    
    def send_hex_data(self):
        try:
            ip = self.ip_var.get()
            
            try:
                port = int(self.port_var.get())
                if port < 0 or port > 65535:
                    raise ValueError("포트 범위 오류")
            except ValueError:
                messagebox.showerror("오류", "유효한 포트 번호를 입력하세요 (0-65535)")
                return
            
            hex_text = self.data_text.get(1.0, tk.END).strip()
            
            # 공백 제거 및 16진수 문자열 정리
            hex_text = hex_text.replace(" ", "").replace("\n", "")
            
            # 유효한 16진수 문자열인지 확인
            try:
                # 홀수 길이인 경우 오류 처리
                if len(hex_text) % 2 != 0:
                    raise ValueError("16진수 문자열은 짝수 길이여야 합니다.")
                
                # 16진수 문자열을 바이트로 변환
                data = bytes.fromhex(hex_text)
                
                # UDP 소켓 생성 및 데이터 전송
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(data, (ip, port))
                sock.close()
                
                messagebox.showinfo("성공", "데이터 전송 완료")
                
            except ValueError as e:
                messagebox.showerror("오류", f"16진수 변환 실패: {e}")
            
        except Exception as e:
            messagebox.showerror("오류", f"전송 실패: {e}")

def main():
    root = tk.Tk()
    app = UDPSender(root)
    root.mainloop()

if __name__ == "__main__":
    main() 