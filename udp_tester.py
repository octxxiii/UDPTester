import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk, filedialog, Canvas
import time
import ipaddress
import binascii
import os
from datetime import datetime

# 포트 프리셋 정의
PORT_PRESETS = {
    "KAMD 외부 입력": 17001,
    "KAMD 내부 연결": 10021,
    "KAMD 수신기": 9904,
    "기본 포트": 5000
}

class UDPTester:
    def __init__(self, root):
        self.root = root
        self.root.title("UDP 통신 통합 테스트")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        # UDP 통신 관련 변수
        self.udp_socket = None
        self.is_listening = False
        self.listen_thread = None
        
        # 로그 자동 스크롤 기능 변수
        self.auto_scroll = True
        
        # UI 생성
        self.create_widgets()
        self.update_ip_addresses()
        
    def create_widgets(self):
        # 상단 탭 생성
        self.tab_control = ttk.Notebook(self.root)
        
        # 수신 탭
        self.receiver_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.receiver_tab, text="UDP 수신")
        
        # 송신 탭
        self.sender_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.sender_tab, text="UDP 송신")
        
        # 네트워크 흐름도 탭
        self.flowchart_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.flowchart_tab, text="네트워크 흐름도")
        
        self.tab_control.pack(expand=1, fill=tk.BOTH, padx=5, pady=5)
        
        # 수신 탭 UI 구성
        self.setup_receiver_tab()
        
        # 송신 탭 UI 구성
        self.setup_sender_tab()
        
        # 흐름도 탭 UI 구성
        self.setup_flowchart_tab()
        
        # 공통 로그 영역
        self.setup_common_log()
        
    def setup_receiver_tab(self):
        # IP 주소 표시 및 선택
        ip_frame = ttk.Frame(self.receiver_tab)
        ip_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(ip_frame, text="수신 IP 주소:").pack(side=tk.LEFT)
        self.receive_ip_var = tk.StringVar()
        self.receive_ip_dropdown = ttk.Combobox(ip_frame, textvariable=self.receive_ip_var, state="readonly")
        self.receive_ip_dropdown.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # 모든 인터페이스 수신 옵션
        self.all_interfaces_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(ip_frame, text="모든 인터페이스 수신(0.0.0.0)", 
                        variable=self.all_interfaces_var).pack(side=tk.LEFT, padx=5)
        
        # IP 새로고침 버튼
        ttk.Button(ip_frame, text="새로고침", command=self.update_ip_addresses).pack(side=tk.RIGHT, padx=5)
        
        # 포트 입력
        port_frame = ttk.Frame(self.receiver_tab)
        port_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(port_frame, text="수신 포트:").pack(side=tk.LEFT)
        self.receive_port_var = tk.StringVar(value="9904")  # KAMD 수신기 포트로 기본값 변경
        self.receive_port_entry = ttk.Entry(port_frame, textvariable=self.receive_port_var, width=10)
        self.receive_port_entry.pack(side=tk.LEFT, padx=5)
        
        # 포트 프리셋 드롭다운
        ttk.Label(port_frame, text="프리셋:").pack(side=tk.LEFT, padx=(10, 0))
        self.receive_port_preset = ttk.Combobox(port_frame, values=list(PORT_PRESETS.keys()), width=15, state="readonly")
        self.receive_port_preset.pack(side=tk.LEFT, padx=5)
        self.receive_port_preset.bind("<<ComboboxSelected>>", lambda e: self.apply_port_preset(self.receive_port_preset, self.receive_port_var))
        
        # 에코 옵션
        self.echo_mode_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(port_frame, text="에코 모드 (받은 데이터 자동 응답)", 
                        variable=self.echo_mode_var).pack(side=tk.LEFT, padx=(20, 5))
        
        # 제어 버튼
        control_frame = ttk.Frame(self.receiver_tab)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.listen_button = ttk.Button(control_frame, text="수신 시작", command=self.toggle_listening)
        self.listen_button.pack(side=tk.LEFT, padx=5)
    
    def setup_sender_tab(self):
        # 목적지 IP 입력
        ip_frame = ttk.Frame(self.sender_tab)
        ip_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(ip_frame, text="목적지 IP:").pack(side=tk.LEFT)
        self.send_ip_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(ip_frame, textvariable=self.send_ip_var, width=15).pack(side=tk.LEFT, padx=5)
        
        # 목적지 포트 입력
        port_frame = ttk.Frame(self.sender_tab)
        port_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(port_frame, text="목적지 포트:").pack(side=tk.LEFT)
        self.send_port_var = tk.StringVar(value="17001")  # KAMD 외부 입력 포트로 기본값 변경
        self.send_port_entry = ttk.Entry(port_frame, textvariable=self.send_port_var, width=10)
        self.send_port_entry.pack(side=tk.LEFT, padx=5)
        
        # 포트 프리셋 드롭다운
        ttk.Label(port_frame, text="프리셋:").pack(side=tk.LEFT, padx=(10, 0))
        self.send_port_preset = ttk.Combobox(port_frame, values=list(PORT_PRESETS.keys()), width=15, state="readonly")
        self.send_port_preset.pack(side=tk.LEFT, padx=5)
        self.send_port_preset.bind("<<ComboboxSelected>>", lambda e: self.apply_port_preset(self.send_port_preset, self.send_port_var))
        
        # 전송할 데이터 입력
        data_frame = ttk.Frame(self.sender_tab)
        data_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        ttk.Label(data_frame, text="전송할 데이터:").pack(anchor=tk.W)
        
        format_frame = ttk.Frame(data_frame)
        format_frame.pack(fill=tk.X, pady=2)
        
        self.data_format = tk.StringVar(value="text")
        ttk.Radiobutton(format_frame, text="텍스트", variable=self.data_format, value="text").pack(side=tk.LEFT)
        ttk.Radiobutton(format_frame, text="16진수", variable=self.data_format, value="hex").pack(side=tk.LEFT, padx=10)
        
        self.data_text = scrolledtext.ScrolledText(data_frame, height=8)
        self.data_text.pack(fill=tk.BOTH, expand=True)
        self.data_text.insert(tk.END, "테스트 메시지")
        
        # 전송 버튼
        button_frame = ttk.Frame(self.sender_tab)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(button_frame, text="전송", command=self.send_data).pack(side=tk.LEFT, padx=5)
        
        # 반복 전송 옵션
        repeat_frame = ttk.Frame(self.sender_tab)
        repeat_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.repeat_enabled = tk.BooleanVar(value=False)
        ttk.Checkbutton(repeat_frame, text="반복 전송", variable=self.repeat_enabled, 
                        command=self.toggle_repeat_options).pack(side=tk.LEFT)
        
        self.repeat_interval_var = tk.StringVar(value="1")
        ttk.Label(repeat_frame, text="간격(초):").pack(side=tk.LEFT, padx=(10, 0))
        self.repeat_interval_entry = ttk.Entry(repeat_frame, textvariable=self.repeat_interval_var, width=5, state="disabled")
        self.repeat_interval_entry.pack(side=tk.LEFT, padx=2)
        
        self.repeat_count_var = tk.StringVar(value="10")
        ttk.Label(repeat_frame, text="반복 횟수:").pack(side=tk.LEFT, padx=(10, 0))
        self.repeat_count_entry = ttk.Entry(repeat_frame, textvariable=self.repeat_count_var, width=5, state="disabled")
        self.repeat_count_entry.pack(side=tk.LEFT, padx=2)
        
        self.infinite_repeat = tk.BooleanVar(value=False)
        self.infinite_repeat_btn = ttk.Checkbutton(repeat_frame, text="무제한", variable=self.infinite_repeat, state="disabled")
        self.infinite_repeat_btn.pack(side=tk.LEFT, padx=(10, 0))
        
        self.is_repeating = False
        self.repeat_thread = None
        self.repeat_control_btn = ttk.Button(repeat_frame, text="반복 시작", state="disabled", command=self.toggle_repeat_sending)
        self.repeat_control_btn.pack(side=tk.LEFT, padx=(10, 0))
        
    def setup_flowchart_tab(self):
        # 흐름도 설명
        info_frame = ttk.Frame(self.flowchart_tab)
        info_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(info_frame, text="KAMD UDP 데이터 흐름도", font=("Helvetica", 12, "bold")).pack(pady=5)
        
        desc_text = (
            "이 다이어그램은 UDP 통신 흐름을 시각화합니다.\n"
            "- 외부 테스터는 KAMD 시뮬레이터의,17001 포트로 데이터를 전송합니다.\n"
            "- KAMD 내부에서 데이터는 10021 포트로 전달됩니다(내부 처리).\n"
            "- 최종적으로 처리된 데이터는 9904 포트로 출력되어 수신 애플리케이션에서 확인됩니다."
        )
        ttk.Label(info_frame, text=desc_text, justify=tk.LEFT).pack(anchor=tk.W, pady=5)
        
        # 캔버스 생성
        self.flow_canvas = Canvas(self.flowchart_tab, bg="white")
        self.flow_canvas.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 캔버스에 흐름도 그리기
        self.draw_network_flow()
        
        # 흐름도 재그리기 버튼
        ttk.Button(self.flowchart_tab, text="흐름도 새로고침", 
                   command=self.draw_network_flow).pack(side=tk.BOTTOM, pady=10)
    
    def draw_network_flow(self):
        # 캔버스 초기화
        self.flow_canvas.delete("all")
        
        # 캔버스 크기 구하기
        canvas_width = self.flow_canvas.winfo_width() or 700
        canvas_height = self.flow_canvas.winfo_height() or 400
        
        # 상자 크기와 위치 계산
        box_width = 160
        box_height = 60
        margin = 20
        arrow_length = 120
        
        # 시작 위치
        start_x = margin * 2
        center_y = canvas_height // 2
        
        # 시작점 (외부 테스터)
        tester_x = start_x
        tester_y = center_y
        
        # KAMD 시뮬레이터 (17001 포트)
        kamd_x = tester_x + box_width + arrow_length
        kamd_y = center_y
        
        # 내부 연결 (10021 포트)
        internal_x = kamd_x + box_width + arrow_length
        internal_y = center_y
        
        # 수신기 (9904 포트)
        receiver_x = internal_x + box_width + arrow_length
        receiver_y = center_y
        
        # 박스 색상 정의
        colors = {
            "tester": "#FFC107",
            "kamd": "#2196F3",
            "internal": "#9C27B0",
            "receiver": "#4CAF50"
        }
        
        # UDP 테스터 (외부) 박스
        self.draw_component(tester_x, tester_y, box_width, box_height, "UDP 테스터", 
                            "외부 송신 포트", colors["tester"])
        
        # KAMD 시뮬레이터 박스
        self.draw_component(kamd_x, kamd_y, box_width, box_height, "KAMD 시뮬레이터", 
                            "포트: 17001", colors["kamd"])
        
        # 내부 연결 박스
        self.draw_component(internal_x, internal_y, box_width, box_height, "내부 처리", 
                            "포트: 10021", colors["internal"])
        
        # 수신기 박스
        self.draw_component(receiver_x, receiver_y, box_width, box_height, "UDP 수신기", 
                            "포트: 9904", colors["receiver"])
        
        # 연결 화살표
        self.draw_arrow(tester_x + box_width, tester_y, kamd_x, kamd_y, "UDP")
        self.draw_arrow(kamd_x + box_width, kamd_y, internal_x, internal_y, "내부 전달")
        self.draw_arrow(internal_x + box_width, internal_y, receiver_x, receiver_y, "UDP")
        
        # 캔버스 크기 재조정 후 다시 그리기 
        self.flow_canvas.after(100, self.draw_network_flow_delayed)
    
    def draw_network_flow_delayed(self):
        if self.flow_canvas.winfo_width() > 10:  # 제대로 된 크기가 할당되었다면
            self.draw_network_flow()
    
    def draw_component(self, x, y, width, height, title, subtitle, color):
        """네트워크 컴포넌트(박스) 그리기"""
        # 박스 그리기
        self.flow_canvas.create_rectangle(x, y - height//2, x + width, y + height//2, 
                                          fill=color, outline="black", width=2)
        
        # 제목 그리기
        self.flow_canvas.create_text(x + width//2, y - 10, text=title, 
                                    font=("Helvetica", 10, "bold"), fill="black")
        
        # 부제목 그리기
        self.flow_canvas.create_text(x + width//2, y + 15, text=subtitle, 
                                    font=("Helvetica", 9), fill="black")
    
    def draw_arrow(self, x1, y1, x2, y2, label):
        """화살표 그리기"""
        # 시작점과 끝점 조정 (박스 경계에 맞추기)
        start_x = x1
        start_y = y1
        end_x = x2
        end_y = y2
        
        # 화살표 그리기
        self.flow_canvas.create_line(start_x, start_y, end_x, end_y, 
                                    arrow=tk.LAST, width=2, arrowshape=(16, 20, 6))
        
        # 화살표 위에 레이블 그리기
        label_x = (start_x + end_x) // 2
        label_y = (start_y + end_y) // 2 - 10
        self.flow_canvas.create_text(label_x, label_y, text=label, 
                                    font=("Helvetica", 9), fill="black")
    
    def setup_common_log(self):
        # 로그 영역
        log_frame = ttk.LabelFrame(self.root, text="통신 로그")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # 로그 툴바
        log_toolbar = ttk.Frame(log_frame)
        log_toolbar.pack(fill=tk.X)
        
        # 로그 자동 스크롤 체크박스
        self.auto_scroll_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(log_toolbar, text="자동 스크롤", variable=self.auto_scroll_var,
                        command=lambda: self.set_auto_scroll(self.auto_scroll_var.get())).pack(side=tk.LEFT)
        
        # 로그 지우기 버튼
        ttk.Button(log_toolbar, text="로그 지우기", command=self.clear_log).pack(side=tk.RIGHT, padx=5)
        
        # 로그 저장 버튼
        ttk.Button(log_toolbar, text="로그 저장", command=self.save_log).pack(side=tk.RIGHT, padx=5)
        
        # 로그 영역
        self.log_area = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD)
        self.log_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.log_area.config(state=tk.DISABLED)
        
        # 상태 표시줄
        self.status_var = tk.StringVar(value="준비")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def set_auto_scroll(self, enabled):
        self.auto_scroll = enabled
    
    def toggle_repeat_options(self):
        state = "normal" if self.repeat_enabled.get() else "disabled"
        self.repeat_interval_entry.config(state=state)
        self.repeat_count_entry.config(state=state)
        self.infinite_repeat_btn.config(state=state)
        self.repeat_control_btn.config(state=state)
    
    def toggle_repeat_sending(self):
        if self.is_repeating:
            self.is_repeating = False
            self.repeat_control_btn.config(text="반복 시작")
        else:
            try:
                interval = float(self.repeat_interval_var.get())
                if interval <= 0:
                    raise ValueError("간격은 0보다 커야 합니다")
                
                if not self.infinite_repeat.get():
                    count = int(self.repeat_count_var.get())
                    if count <= 0:
                        raise ValueError("반복 횟수는 0보다 커야 합니다")
                
                self.is_repeating = True
                self.repeat_control_btn.config(text="반복 중지")
                
                # 반복 전송 시작
                self.repeat_thread = threading.Thread(target=self.repeat_send, daemon=True)
                self.repeat_thread.start()
                
            except ValueError as e:
                messagebox.showerror("입력 오류", str(e))
    
    def repeat_send(self):
        count = int(self.repeat_count_var.get()) if not self.infinite_repeat.get() else float('inf')
        interval = float(self.repeat_interval_var.get())
        
        i = 0
        while self.is_repeating and (self.infinite_repeat.get() or i < count):
            self.send_data(show_message=False)
            i += 1
            
            # 상태 업데이트
            self.status_var.set(f"반복 전송 중... ({i}/{count if not self.infinite_repeat.get() else '무제한'})")
            
            # 반복 간격 대기
            for _ in range(int(interval * 10)):  # 0.1초 단위로 나누어 중간 취소 가능하게
                if not self.is_repeating:
                    break
                time.sleep(0.1)
        
        self.is_repeating = False
        self.repeat_control_btn.config(text="반복 시작")
        self.status_var.set("준비")
    
    def send_data(self, show_message=True):
        try:
            ip = self.send_ip_var.get()
            
            try:
                port = int(self.send_port_var.get())
                if port < 0 or port > 65535:
                    raise ValueError("포트 범위 오류")
            except ValueError:
                if show_message:
                    messagebox.showerror("오류", "유효한 포트 번호를 입력하세요 (0-65535)")
                return
            
            # 수신 포트와 동일한지 체크
            if self.is_listening and port == int(self.receive_port_var.get()):
                if show_message:
                    response = messagebox.askquestion("포트 중복", 
                                                   "송신 포트가 현재 수신 중인 포트와 동일합니다.\n"
                                                   "계속 진행하시겠습니까?")
                    if response != 'yes':
                        return
            
            # 데이터 형식에 따라 처리
            data_str = self.data_text.get(1.0, tk.END).strip()
            if self.data_format.get() == "hex":
                # 공백 제거
                data_str = data_str.replace(" ", "").replace("\n", "")
                
                # 유효한 16진수 확인
                try:
                    if len(data_str) % 2 != 0:
                        raise ValueError("16진수 문자열은 짝수 길이여야 합니다.")
                    data = bytes.fromhex(data_str)
                except ValueError as e:
                    if show_message:
                        messagebox.showerror("오류", f"16진수 변환 실패: {e}")
                    return
            else:
                # 텍스트 데이터
                data = data_str.encode('utf-8')
            
            # UDP 소켓 생성 및 데이터 전송
            send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            send_sock.sendto(data, (ip, port))
            
            # 로그 출력
            send_time = time.strftime('%H:%M:%S.%f')[:-3]
            self.log_message(f"[전송] {send_time} → {ip}:{port} (크기: {len(data)}바이트)")
            self.log_hexdump(data, is_outgoing=True)
            
            send_sock.close()
            
            if show_message and not self.is_repeating:
                self.status_var.set(f"전송 완료: {ip}:{port}")
            
        except Exception as e:
            self.log_message(f"전송 오류: {e}")
            if show_message:
                messagebox.showerror("오류", f"전송 실패: {e}")
    
    def update_ip_addresses(self):
        # 시스템의 모든 IP 주소 가져오기
        ip_addresses = self.get_ip_addresses()
        
        # 드롭다운 메뉴 업데이트
        self.receive_ip_dropdown['values'] = ip_addresses
        
        # 첫 번째 IP 주소 선택
        if ip_addresses:
            self.receive_ip_var.set(ip_addresses[0])
        else:
            self.receive_ip_var.set("127.0.0.1")
    
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
            # 모든 인터페이스 수신이 체크되었는지 확인
            ip = "0.0.0.0" if self.all_interfaces_var.get() else self.receive_ip_var.get()
            
            try:
                port = int(self.receive_port_var.get())
                if port < 0 or port > 65535:
                    raise ValueError("포트 범위 오류")
            except ValueError:
                messagebox.showerror("오류", "유효한 포트 번호를 입력하세요 (0-65535)")
                return
            
            # 이미 열려있는 소켓 닫기
            if self.udp_socket:
                self.udp_socket.close()
            
            # 에코 모드 상태 확인
            echo_mode = self.echo_mode_var.get()
            
            # 새 UDP 소켓 생성
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # SO_REUSEADDR 옵션 설정 (다른 프로세스에서 바인딩한 포트를 재사용 가능)
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            try:
                self.udp_socket.bind((ip, port))
            except socket.error as e:
                if "Only one usage of each socket address" in str(e):
                    messagebox.showerror("포트 오류", f"포트 {port}가 이미 사용 중입니다.\n다른 포트를 사용하세요.")
                    return
                raise  # 다른 소켓 에러는 상위로 전달
                
            self.udp_socket.settimeout(0.5)  # 타임아웃 설정
            
            self.is_listening = True
            self.listen_button.config(text="수신 중지")
            
            # 상태 메시지에 에코 모드 표시 추가
            status_msg = f"수신 중: {ip}:{port}"
            if echo_mode:
                status_msg += " (에코 모드)"
            self.status_var.set(status_msg)
            
            # 로그에 메시지 추가
            self.log_message(f"UDP 소켓 열림 - {ip}:{port}" + (" (에코 모드)" if echo_mode else ""))
            
            # 수신 스레드 시작
            self.listen_thread = threading.Thread(target=self.listen_for_data, daemon=True)
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
        echo_mode = self.echo_mode_var.get()
        
        while self.is_listening:
            try:
                data, addr = self.udp_socket.recvfrom(4096)
                recv_time = time.strftime('%H:%M:%S.%f')[:-3]
                
                # 상세 로그 메시지 추가
                src_ip = addr[0]
                src_port = addr[1]
                data_size = len(data)
                
                self.log_message(f"[수신] {recv_time} ← {src_ip}:{src_port} (크기: {data_size}바이트)")
                
                # 데이터 표시 (16진수 및 ASCII)
                self.log_hexdump(data, is_outgoing=False)
                
                # 에코 모드가 활성화된 경우 데이터 그대로 응답
                if echo_mode and self.is_listening:
                    try:
                        self.udp_socket.sendto(data, addr)
                        self.log_message(f"[에코] {time.strftime('%H:%M:%S.%f')[:-3]} → {src_ip}:{src_port} (크기: {data_size}바이트)")
                        self.log_hexdump(data, is_outgoing=True)
                    except Exception as e:
                        self.log_message(f"에코 응답 실패: {e}")
                
                # 상태 표시줄 업데이트
                self.status_var.set(f"데이터 수신: {src_ip}:{src_port} - {data_size}바이트")
                
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
            if self.auto_scroll:
                self.log_area.see(tk.END)
            self.log_area.config(state=tk.DISABLED)
        
        # GUI 업데이트는 메인 스레드에서 실행
        self.root.after(0, update_log)
    
    def log_hexdump(self, data, is_outgoing=False):
        def update_log():
            self.log_area.config(state=tk.NORMAL)
            
            # 방향 표시 추가
            direction = "→" if is_outgoing else "←"
            prefix = "  [보낸 데이터]" if is_outgoing else "  [받은 데이터]"
            
            # 데이터 요약 정보 추가
            self.log_area.insert(tk.END, f"{prefix} 크기: {len(data)}바이트\n")
            
            # 16진수 덤프 형식으로 데이터 표시
            offset = 0
            
            while offset < len(data):
                # 라인 시작 부분에 오프셋 표시
                line = f"  {offset:04X}: "
                
                # 16진수 값
                hex_values = ""
                # ASCII 문자
                ascii_values = ""
                
                # 16바이트씩 처리
                chunk = data[offset:offset+16]
                
                for byte in chunk:
                    # 16진수 값 추가
                    hex_values += f"{byte:02X} "
                    
                    # ASCII 문자 추가 (출력 가능한 문자만)
                    if 32 <= byte <= 126:
                        ascii_values += chr(byte)
                    else:
                        ascii_values += "."
                
                # 마지막 라인 정렬을 위한 패딩
                padding = "   " * (16 - len(chunk))
                
                self.log_area.insert(tk.END, f"{line}{hex_values}{padding} |{ascii_values}|\n")
                offset += 16
            
            self.log_area.insert(tk.END, "\n")
            if self.auto_scroll:
                self.log_area.see(tk.END)
            self.log_area.config(state=tk.DISABLED)
        
        # GUI 업데이트는 메인 스레드에서 실행
        self.root.after(0, update_log)
    
    def clear_log(self):
        self.log_area.config(state=tk.NORMAL)
        self.log_area.delete(1.0, tk.END)
        self.log_area.config(state=tk.DISABLED)
    
    def save_log(self):
        """로그 파일로 저장"""
        if not self.log_area.get(1.0, tk.END).strip():
            messagebox.showinfo("알림", "저장할 로그 내용이 없습니다.")
            return
            
        # 현재 날짜/시간으로 기본 파일명 생성
        default_filename = f"UDP_Log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        # 파일 저장 대화상자
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("텍스트 파일", "*.txt"), ("모든 파일", "*.*")],
            initialfile=default_filename
        )
        
        if not file_path:  # 사용자가 취소한 경우
            return
            
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                # 로그 헤더 추가
                f.write(f"============= UDP 통신 테스트 로그 =============\n")
                f.write(f"생성 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"========================================\n\n")
                
                # 로그 내용 저장
                f.write(self.log_area.get(1.0, tk.END))
                
            self.status_var.set(f"로그 저장 완료: {os.path.basename(file_path)}")
            messagebox.showinfo("저장 완료", f"로그가 다음 위치에 저장되었습니다:\n{file_path}")
            
        except Exception as e:
            messagebox.showerror("저장 오류", f"로그 저장 중 오류가 발생했습니다:\n{e}")

    def apply_port_preset(self, preset_combobox, port_var):
        """포트 프리셋을 적용"""
        selected = preset_combobox.get()
        if selected in PORT_PRESETS:
            port_var.set(str(PORT_PRESETS[selected]))

def main():
    root = tk.Tk()
    app = UDPTester(root)
    root.mainloop()

if __name__ == "__main__":
    main() 