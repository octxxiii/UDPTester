# UDP 통신 테스트 프로그램

이 프로그램은 UDP 통신을 테스트하기 위한 도구입니다. 로컬 시스템의 IP 주소와 포트를 사용하여 UDP 패킷을 수신하고, 수신된 데이터를 로그 창에 표시합니다.

## 기능

### UDP 수신기 (udp_test.py)
- 시스템의 모든 IP 주소 자동 탐지 및 표시
- 사용자가 지정한 포트에서 UDP 데이터 수신
- 수신된 데이터를 16진수 및 ASCII 형식으로 표시
- 로그 내용 저장 및 지우기 기능

### UDP 송신기 (udp_sender.py)
- 지정된 IP 주소와 포트로 UDP 데이터 전송
- 일반 텍스트 또는 16진수 형식으로 데이터 전송
- 간단한 사용자 인터페이스

### UDP 통합 테스터 (udp_tester.py) - 신규!
- 송신 및 수신 기능을 하나의 애플리케이션으로 통합
- 탭 인터페이스로 송신/수신 모드 전환 가능
- 단일 로그 창에서 송수신 데이터 모두 확인
- 반복 전송 기능 지원
  - 일정 간격으로 데이터 반복 전송
  - 횟수 지정 또는 무제한 반복 가능
- 자동 스크롤 및 로그 관리 기능
- **추가된 기능 (v3)**:
  - 포트 프리셋 기능 (외부 입력, 내부 연결, 수신기 포트 등)
  - 포트 충돌 체크 및 알림
  - 모든 네트워크 인터페이스(0.0.0.0) 수신 옵션
  - 에코(Echo) 모드 지원 - 수신된 데이터 자동 응답
  - 상세한 로그 출력 (데이터 크기, 시간 등)
  - 로그 저장 기능 (파일로 저장)

## 요구 사항

- Python 3.x
- tkinter (Python 기본 라이브러리)

## 사용 방법

### UDP 수신기 실행
```
python udp_test.py
```

1. 드롭다운 메뉴에서 원하는 IP 주소를 선택합니다.
2. 포트 번호를 입력합니다 (기본값: 5000).
3. "수신 시작" 버튼을 클릭하여 패킷 수신을 시작합니다.
4. 수신된 데이터는 로그 창에 표시됩니다.
5. "수신 중지" 버튼을 클릭하여 수신을 중지할 수 있습니다.

### UDP 송신기 실행
```
python udp_sender.py
```

1. 목적지 IP 주소와 포트를 입력합니다.
2. 전송할 데이터를 텍스트 영역에 입력합니다.
3. "전송" 버튼을 클릭하여 텍스트 데이터를 전송합니다.
4. 또는 "16진수 전송" 버튼을 클릭하여 16진수 형식의 데이터를 전송합니다.
   (16진수 데이터는 공백 없이 짝수 길이여야 합니다. 예: "48656C6C6F")

### UDP 통합 테스터 실행
```
python udp_tester.py
```

1. 상단 탭에서 "UDP 수신" 또는 "UDP 송신" 모드를 선택합니다.
2. 수신 모드:
   - IP 주소와 포트를 설정하고 "수신 시작" 버튼을 클릭합니다.
   - 프리셋 드롭다운에서 미리 정의된 포트 (KAMD 외부 입력: 17001, 내부 연결: 10021, 수신기: 9904)를 선택할 수 있습니다.
   - 에코 모드를 활성화하면 수신된 데이터를 자동으로 응답합니다.
   - "모든 인터페이스 수신" 옵션을 사용하여 0.0.0.0에서 수신할 수 있습니다.
3. 송신 모드:
   - 목적지 IP와 포트를 설정합니다.
   - 프리셋 드롭다운에서 미리 정의된 포트를 선택할 수 있습니다.
   - 전송할 데이터를 텍스트 또는 16진수 형식으로 입력합니다.
   - "전송" 버튼을 클릭하여 데이터를 전송합니다.
   - 필요 시 "반복 전송" 옵션을 활성화하여 주기적인 전송을 설정할 수 있습니다.
4. 네트워크 흐름도 탭:
   - UDP 데이터 흐름의 시각적 다이어그램을 제공합니다.
5. 하단의 통합 로그 창에서 송수신 데이터를 모두 확인할 수 있습니다.
   - "로그 저장" 버튼을 클릭하여 로그를 파일로 저장할 수 있습니다.

## 실행 파일 생성 방법

PyInstaller를 사용하여 실행 파일을 생성할 수 있습니다:

```
pip install pyinstaller
pyinstaller --onefile --windowed --name "UDP_수신기" udp_test.py
pyinstaller --onefile --windowed --name "UDP_송신기" udp_sender.py
pyinstaller --onefile --windowed --name "UDP_통합테스터" udp_tester.py
```

## 테스트 방법

1. 먼저 UDP 수신기를 실행하여 수신을 시작합니다.
2. 다른 창에서 UDP 송신기를 실행하여 데이터를 전송합니다.
3. 수신기 로그 창에서 수신된 데이터를 확인합니다.

또는 외부 장치에서 프로그램이 실행 중인 컴퓨터의 IP 주소와 지정된 포트로 UDP 패킷을 전송하여 테스트할 수 있습니다.
