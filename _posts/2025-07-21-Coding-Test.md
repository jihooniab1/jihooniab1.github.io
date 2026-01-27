---
title: "코딩 테스트 준비"
date: 2025-07-21 00:00:00 +0900
categories: [Study]
tags: [algorithm]
permalink: /posts/Coding-Test/
---
## 파이썬 기초 문법
### 자료형
정수형: 양의 정수, 음의 정수, 0이 포함됨
```
a = 1000
print(a)

a = -7
print(a)
```

실수형: 소수점 아래의 데이터를 포함하는 수 자료형 (0 생략 가능)
```
a = 157.93
print(a)

a = 5.
print(a)

a = -.7
print(a)
```

컴퓨터 시스템 특성상 실수 정보를 정확하게 표현하는데 한계가 있음 => **round()** 함수를 써보자(소수 n째자리까지 반올림림)
```
a = 0.3 + 0.6
print(round(a,4)) #0.9가 나옴
```

리스트: 여러 데이터를 연속적으로 담아 처리 (STL vector와 유사), 배열과 연결 리스트의 기능 지원. 비어있는 리스트를 선언하려면
`list()`나 `[]` 형태로 선언 가능. 원소에 접근할 때는 **Index** 값을 괄호에 넣어 사용하고, 0부터 시작함 
```
a = [1,2,3,4,5]
print(a[3])

n = 10
a = [0] * 10 #크기 10의 모든 값이 0인 1차원 리스트 초기화
```

**인덱싱(Indexing)**: 인덱스 값을 통해 특정 원소에 접근. 음의 정수를 넣으면 원소를 거꾸로 탐색함
```
a = [1,2,3,4,5]
print(a[1]) # 1
print(a[-1]) # 5
```

**슬라이싱(Slicing)**: 리스트에서 연속적인 위치를 갖는 원소들을 가져옴, 대괄호 안에 콜론`:`을 넣어서 시작, 끝 인덱스 설정. 끝 인덱스는 시작 인덱스보다 1 더 크게 설정
```
a = [1,2,3,4,5]
print(a[1:4]) # [2,3,4]
```

**list comprehension**: 리스트를 초기화하는 방법 중 하나. **대괄호 안에 조건문과 반목문** 을 적용하여 리스트를 초기화 할 수 있음
```
array = [i for i in range(5)]
print(array) # [0, 1, 2, 3, 4]

array = [i for i in range(10) if i % 2 == 1]
print(array) # [1, 3, 5, 7, 9]

array =[[0] * m for _ in range(n)] # 이 방식으로 N X M 크기의 2차원 리스트 쉽게 초기화 가능능
```

| 함수명 | 사용법 | 설명 | 시간 복잡도 |
| :--- | :--- | :--- | :--- |
| `append()` | `변수명.append()` | 리스트에 원소를 하나 삽입할 때 사용한다. | $O(1)$ |
| `sort()` | `변수명.sort()`<br>`변수명.sort(reverse = True)` | 기본 정렬 기능으로 오름차순으로 정렬한다.<br>내림차순으로 정렬한다. | $O(N \log N)$ |
| `reverse()` | `변수명.reverse()` | 리스트의 원소의 순서를 모두 뒤집어 놓는다. | $O(N)$ |
| `insert()` | `insert(삽입할 위치 인덱스, 삽입할 값)` | 특정한 인덱스 위치에 원소를 삽입할 때 사용한다. | $O(N)$ |
| `count()` | `변수명.count(특정 값)` | 리스트에서 특정한 값을 가지는 데이터의 개수를 셀 때 사용한다. | $O(N)$ |
| `remove()` | `변수명.remove(특정 값)` | 특정한 값을 갖는 원소를 제거하는데, 값을 가진 원소가 여러 개면 하나만 제거한다. | $O(N)$ |

문자열: 초기화할 때 큰 따옴표나 작은 따옴표를 이용. 
```
data = "don't you know \"Python\"?
print(data)
```

문자열 연산: 덧셈(+)을 이용하면 **연결(Concatenate)**, 인덱싱과 슬라이싱이 가능하지만 값은 못 바꿈

튜플 자료형: 리스트와 비슷하지만 차이가 존재. 한 번 선언된 값을 바꾸지 못하고, 소괄호를 이용함. **서로 다른 성질의 데이터** 를 묶어서 관리할 때 유용함.  데이터의 나열의 **해싱의 키 값** 으로 사용해랴 할 때도 사용 
```
a = (1,2,3,4,5)
print(a[1:4]) # (2, 3, 4)
```

사전 자료형: **키와 값의 쌍** 을 데이터로 가지는 자료형. 순차적으로 저장하는게 아님. **임의의 변경 불가능한 자료형** 을 키로 사용할 수 있음.
해시 테이블을 사용하기에 데이터의 조회와 수정이 ** O(1)** 시간내에 처리 가능
```
data = dict()
data['사과'] = 'Apple'
data['바나나'] = 'Banana'
data['코코넛'] = 'Coconut'

if '사과' in data:
    print("사과 데이터 존재")
```

키 데이터만 뽑아서 리스트로 이용: **keys()** 함수. 값은 **values()** 함수

집합 자료형: 중복 허용 X, 순서 X. 리스트나 문자열을 이용해서 초기화할 수 있고, 이때 **set() 함수** 를 이용함. 혹은 중괄호와 콤마로 원소 표현
```
data = set([1,1,2,3,4,4])
print(data) # [1,2,3,4]
```

집합 연산: 합집합, 교집합, 차집합 
```
a = set([1,2,3,4,5])
b = set([3,4,5,6,7])

print(a | b) # 합집합
print(a & b) # 교집합
print(a - b) # 차집합합
```

set에 대한 추가 연산은 다음과 같다. 사전의 키나 집합의 원소를 이용해 **O(1)** 의 시간 복잡도로 조회함 
```
data = set([1,2,3])

data.add(4)
data.update([5,6]) # 원소 여러개 추가가
data.remove(3)
```

### 기본 입출력
- input(): **한 줄의 문자열** 을 입력 받는 함수
- map(): 리스트의 모든 원소에 각각 특정한 함수를 적용할 때 사용 

아래와 같이 활용할 수 있음
```
n = int(input()) # 데이터 개수
data = list(map(int, input().split())) # 각 데이터를 공백을 기준으로 구분하여 입력

data.sort(reverse=True)
print(data)
```

입력을 최대한 빨리받아야 하는 경우 => `sys.stdin.readline()` 메서드를 쓸 수 있음. 다만 엔터가 줄 바꿈 기호로 입력되기에 **rstip()** 메서드도 같이 쓴다. 
```
import sys

data = sys.stdin.readline().rstrip()
print(data)
```

기본 출력: **print() 함수**. 기본적으로 출력 후 줄바꿈을 하기에 `end` 속성으로 이를 바꿀 수 있음
```
a = 1
b = 2
print(a, b)
print(7, end=" ")

print("test " + str(a) + "test")
```

f-string: 문자열 앞에 **접두사 f** 를 붙여 중괄호 안에 변수명을 기입하여 간단히 문자열과 정수를 함께 넣을 수 있음
```
answer = 7
print(f"정답은 {answer}.")
```

### 조건문과 반복문
조건문 예제. 파이썬에서는 **코드의 블록을 들여쓰기로 지정** 함.
```
x = 15
if x >= 10:
    print("1")
if x >= 0:
    print("2")
```

if ~ elif ~ else는 다음과 같이 사용
```
a = 5

if a >= 0:
    print("1")
elif a >= 10:
    print("2")
else
    print("3")
```

논리 연산자는 **논리 값(True/False)** 사이의 연산을 수행할 때 사용
- X and Y
- X or Y
- not X

다수의 데이터를 담는 자료형을 위해 **in, not in** 연산자가 제공됨
- x in 리스트 : 리스트 안에 x 들어가있으면 True
- x not in 문자열 : 문자열 안에 x 포함되어 있지 않으면 True

반복문 => for 문이 더 간결하다. 특정한 변수를 이용하여  `in` 뒤에 오는 데이터(리스트, 튜플 등)에 포함된 원소를
첫 번째 인덱스부터 차례대로 하나씩 방문. 연속적인 값을 차례대로 순회할 때는 `range()`를 주로 사용. (시작, 끝 + 1). 인자를 하나만 넣으면 자동으로 시작 값은 0.
```
array = [9,8,7,6,5]
for x in array:
    print(x)

result = 0
for i in range(1, 10):
    result += i
```

### 함수
- 내장 함수: 기본적으로 제공
- 사용자 정의: 개발자가 직접 정의

매개변수: 함수 내부에서 사용할 변수. 반환값: 함수에서 처리 된 결과 반환, 여러 개의 반환 값도 가질 수 있음음
```
def add(a, b):
    return a + b
```

**global** 키워드로 변수를 지정하면 함수 바깥에 선언된 변수를 바로 참조하게 됨
```
a = 0

def func():
    global a
    a += 1
```

람다 표현식: 함수를 간단하게 작성 가능. 이름 없는 함수라고 봐도 됨 
```
array = [('홍길동', 50),('이순신',32),('아무개',74)]

def my_key(x):
    return x[1]

print(sorted(array, key=my_key))
print(sorted(array, key=lambda x: x[1]))
```

```
list1 = [1, 2, 3, 4, 5]
list2 = [6, 7, 8, 9, 10]

result = map(lambda a,b: a + b, list1, list2) # 두 리스트의 각 원소를 함수에 적용
```

### 유용한 표준 라이브러리
- itertools: 반복되는 형태의 데이터를 처리하기 위한 유용한 기능 제공(순열, 조합...)
- heapq: 힙 자료구조를 제공
- bisect: 이진 탐색 기능을 제공
- collections: 덱(deque), 카운터(Counter) 등의 유용한 자료구조 포함
- math: 팩토리얼, 제곱근, 최대공약수 등 다양한 수학 기능 포함 

```
result = sum([1,2,3,4,5])

min_result = min(7, 3, 5, 2)

result = eval("(3+5)*7") # 수식을 실제로 계산
```

**sorted**: 반복가능한 객체가 들어왔을 때, 정렬한 결과를 반환 

- 순열: 서로 다른 n개에서 r개를 선택해서 일렬로 나열 (순서 고려)
- 조합: 서로 다른 n개에서 순서 상관없이 r개를 선택 

```
from itertools import permutations

data = ['A', 'B', 'C']

result = list(permutations(data, 3)) # 3개를 골라서 나열
```

```
from itertools import combinations

data = ['A', 'B', 'C']

result = list(combinations(data, 2)) # 2개를 뽑는 모든 조합
```

중복 순열(product 라이브러리), 중복 조합(combinations_with_replacement 라이브러리)도 가능

**카운터**: 반복 가능한 객체가 주어질 때 내부의 원소가 몇번 씩 등장했는지 알려줌
```
from collections import Counter

counter = Counter(['red','blue','green','red'])
print(counter['green']) # 1
```

## 백준
### 배열
#### 3273 두 수의 합
https://www.acmicpc.net/problem/3273

제한시간이 1초라 단순하게 반복문을 탐색하는 방법으로는 힙들다. 이때는 **투포인터** 기법을 활용할 수 있다. 배열이 정렬되어 있을 때, 왼쪽 끝과 오른쪽 끝에 포인터를 배치해두고 조건에 따라 각 포인터를 이동시킨다.

어차피 두 수의 합은 정해져 있으고, 배열의 각 원소는 서로 다른 양의 정수니 
- arr[left] + arr[right] == x: left, right를 각각 1씩 증감
- arr[left] + arr[right] < x: left만 1 증가
- arr[left] + arr[right] > x: right만 1 감소

**left < right** 조건이 유지되는 동안 반복문을 돌면서 위 연산을 반복하고, 카운트를 측정하면 된다.

```
import bisect

n = int(input())
arr = list(map(int,input().split()))
x = int(input())

arr.sort()

cnt = 0
left = 0
right = n - 1

while left < right:
    cur = arr[left] + arr[right]

    if cur == x:
        cnt = cnt + 1
        left = left + 1
        right = right - 1
    elif cur < x:
        left = left + 1
    else:
        right = right - 1
print(cnt)
```

### 연결 리스트
#### 1406 에디터
https://www.acmicpc.net/problem/1406

전형적인 **에디터 시뮬레이터** 문제이다. 명령어가 최대 50만개까지 주어지는데, 직접 풀어보면 **insert** 메서드를 썼을 때 시간 초과가 나는 것을 알 수 있다. 파이썬의 리스트 구조 상 맨 끝과 앞에 빼고 넣는 `append`, `pop()`은 연산 속도가 빠르지만, 중간에 빼고 넣는 작업은 시간이 굉장히 오래 걸린다. 

접근은 다음과 같다. 커서를 기준으로 왼쪽, 오른쪽 배열을 나누는 것이다. 커서가 왼쪽으로 움직이는 것은 왼쪽 배열의 끝 원소가 오른쪽 원소로 간다는 뜻이고, 뭘 쓰고 지울 때마다 왼쪽 배열에서 더하고 빼면 된다. 

```
from sys import stdin

left = list(input())
right = []

for _ in range(int(input())):
    command = list(stdin.readline().split())
    if command[0] == 'L' and left:
        right.append(left.pop())
    elif command[0] == 'D' and right:
        left.append(right.pop())
    elif command[0] == 'B' and left:
        left.pop()
    elif command[0] == 'P':
        left.append(command[1])

answer = left + right[::-1]
print(''.join(answer))
```

### 스택
#### 2493 탑
https://www.acmicpc.net/problem/2493

탑의 수가 많아 반복문 같은 구조로 일일이 세고 있으면 무조건 시간 초과가 발생한다. **단조 감소 스택** 을 사용해서 풀어야 한다. 각 탑들은 신호를 왼쪽으로 보내기 때문에, 오른쪽에 있는 탑보다 작은 탑들은 영원히 신호를 받을 수 없다. 즉 **스택에서 바로 제거** 해도 상관이 없다. 이 원리를 바탕으로 탑이 입력되자마자 처리하고 출력을 해줄 수 있다.

```
n = int(input())
height = list(map(int, input().split()))
tower = list()

for i in range(n):
    h = height[i]
    while True:
        if len(tower) == 0:
            tower.append((h, i))
            break
        top = tower[len(tower) - 1]
        if top[0] < h:
            tower.pop()
        else:
            tower.append((h, i))
            break
    if len(tower) == 1:
        print(0, end=' ')
    else:
        top = tower[len(tower) - 2]
        print(f"{top[1] + 1}",end=' ')
```

#### 6198 옥상 정원 꾸미기
https://www.acmicpc.net/problem/6198

이 문제도 탑 문제와 비슷하다. 결국 방향만 다를 뿐 작은 원소가 더 큰 원소에 의해 가려진다는 공통점이 있기 때문이다. 
본인은 더 큰 빌딩이 작은 빌딩을 제거할 때 카운팅을 해주었다. 

```
import sys

n = int(input())

building = list()
stack = list()

for i in range(n):
    building.append(int(sys.stdin.readline().rstrip()))

count = 0

for i in range(len(building)-1,-1,-1):
    stack.append([building[i],0])
    while True:
        if len(stack) == 1: break
        front = stack[len(stack) - 2]
        if building[i] > front[0]:
            stack[len(stack) - 1][1] = stack[len(stack) - 1][1] + 1 + front[1]
            count = count + front[1]
            stack.pop(len(stack) - 2)
        else:
            break

for s in stack:
    count = count + s[1]
print(count)
```

#### 3015 오아시스 재결합
https://www.acmicpc.net/problem/3015

이 문제 역시 단조 스택을 활용 하지만, **키가 같은 사람** 을 처리하는 것이 까다로운 문제이다. 키가 같은 사람들이 나란히 입력되는 경우 그룹을 구성해서 
- 키가 같은 사람들끼리의 pair
- 기존의 키가 큰 사람과의 pair

을 고려해서 계산해주어야 한다.

```
import sys

n = int(input())
count = 0
stack = []

for _ in range(n):
    h = int(sys.stdin.readline().rstrip())
    
    while stack and stack[-1][0] < h:
        count += stack.pop()[1]
    
    if not stack:
        stack.append((h, 1))
        continue
    
    if stack[-1][0] == h:
        group_size = stack.pop()[1]
        count += group_size
        
        if stack:
            count += 1
        
        stack.append((h, group_size + 1))
    
    else:
        count += 1
        stack.append((h, 1))
```

### 큐
#### 10845 큐
https://www.acmicpc.net/problem/10845

전형적인 선입선출의 큐 자료구조 문제이다. 문제는 파이썬에서 이를 리스트로 구현하면 시간 초과의 가능성이 생긴다. **pop(), append()** 와 같이 끝에 뭘 더하고 빼는건 빠르지만, 맨앞에서 제거하는 연산은 `O(n)`이 걸리기 때문이다. 

이럴 때 쓸 수 있는게 파이썬의 **deque, double-ended queue** 자료구조이다. 양쪽 끝에서 삽입/삭제가 빈번하게 발생할 때 쓰기 좋다. `popleft, appendleft`가 전부 O(1)이다. 

```
from collections import deque
import sys

n = int(input())

q = deque()

for _ in range(n):
    command = sys.stdin.readline().split()
    
    if command[0] == 'push':
        num = int(command[1])
        q.append(num)
    elif command[0] == 'pop':
        if len(q) == 0: print(-1)
        else:
            left = q.popleft()
            print(left)
    elif command[0] == 'size':
        print(len(q))
    elif command[0] == 'empty':
        if len(q) == 0: print(1)
        else: print(0)
    elif command[0] == 'front':
        if len(q) == 0: print(-1)
        else:
            print(q[0])
    else:
        if len(q) == 0: print(-1)
        else:
            print(q[-1])
```

### 덱
#### 5430 AC
https://www.acmicpc.net/problem/5430

문제 자체는 어렵지 않으나 **파싱** 방법을 기억할만 한 거 같았다. 전형적인 deque을 사용하는 문제이다. R로 방향을 기록하고, D를 쓰기 전에 비어있는지만 확인하면 되는데, **파싱과 빈 덱 처리** 를 못해서 틀렸었다. 

문제 입력 자체가 `[1,2,3,4]` 상태로 들어오는데 처음에는 `read(1)` 를 이용해서 일일이 입력 받았으나, 더 좋은 방법이 있었다. 
```
arr_str = arr[1:-1]  # 이렇게 하면 1,2,3,4 나 빈 배열이 남는다.
...
numbers = arr_str.split(',')
```
이런 식으로 하면 숫자 배열을 깔끔하게 얻을 수 있고, 빈 배열 처리도 쉽게 가능하다. 출력할 때도 빈 배열 처리에 신경을 써주어야 한다. 
```
import sys
from collections import deque

t = int(input())

for _ in range(t):
    dir = 0
    error = 0
    arr = deque()
    p = list(sys.stdin.readline().rstrip())
    l = int(input())

    arr_input = input().strip()
    arr_str = arr_input[1:-1]
    if arr_str:
        numbers = arr_str.split(',')
        for num in numbers:
            arr.append(num.strip())
    for c in p:
        if c == 'R':
            dir = not dir
        else:
            if len(arr) == 0:
                    error = 1
                    break
            if dir == 0:
                arr.popleft()
            else:
                arr.pop()
    if error == 1:
        print('error')
        continue
    print('[', end='')
    if len(arr) == 0:
        print(']')
    elif dir == 0:
        for i in range(len(arr)):
            print(arr[i], end='')
            if i == len(arr) - 1: 
                print(']')
            else: 
                print(',', end='')
    else:
        for i in range(len(arr)-1, -1, -1):
            print(arr[i], end='')
            if i == 0: 
                print(']')
            else: 
                print(',', end='')
```

#### 11003 최솟값 찾기
https://www.acmicpc.net/problem/11003

**슬라이딩 윈도우의 최솟값** 을 찾는 문제이다. 이 문제의 경우 deque을 사용하여 최솟값을 구할 수 있고, **단조 덱** 을 이용하여 덱의 원소들을 특정 우선순위에 맞게 유지시킬 수 있다. 이 문제도 스택 문제처럼 최솟값이 될 수 없는 값들을 없애버리는 방법을 사용할 수 있다.

1. 덱에는 입력 배열의 인덱스를 저장하고, 값은 항상 오름차순을 유지해야 한다.
2. 윈도우의 크기가 l을 넘으면 덱의 맨 앞을 제거한다.
3. 그리고 새로 들어온 값이 덱의 마지막보다 크다면 그대로 넣고, 작으면 오름차순 유지를 위해 계속 pop을 한다. 

이런 알고리즘을 반복하면 결국 덱의 맨 앞은 항상 그 윈도우의 최솟값 인덱스를 가리키게 된다. 

```
from collections import deque
import sys

n, l = map(int, input().split())
arr = list(map(int, sys.stdin.readline().split()))
q = deque()

q.append(0)
print(arr[0],end=' ')

for i in range(1, len(arr)):
    cur = arr[i]
    if q[0] < i - l + 1:
        q.popleft()
    while True:
        if not q: break
        if arr[q[-1]] > cur:
            q.pop()
        else:
            break
    q.append(i)
    print(arr[q[0]],end=' ')
```

### BFS
#### 5427 불
https://www.acmicpc.net/problem/5427

그래프 탐색 자체는 복잡하지 않다. 이런 불 문제의 경우 먼저 불의 이동경로를 bfs로 계산해둔 다음, 사람이 움직일 수 있는 경우의 수를 탐색하면 해결 가능하다. 문제는 입력 방식에 있었다. 자꾸 시간 초과가 발생하길래 뭐가 문제였나 싶었는데 입력 방식에 문제가 있었다.

원래는 `sys.stdin.read(1)` 방식으로 띄어쓰기 없는 입력을 받았는데, 이 방식이 생각보다 굉장히 느린 듯 하다. 대신 다음과 같은 방법을 쓸 수 있다.

```
board = [list(map(int,input())) for _ in range(n)]
```

이렇게 입력을 받으면 배열을 생성하면서 동시에 입력을 받을 수 있어서 속도 측면에서 장점이 있는 듯 하다.

```
from collections import deque
import sys

test = int(input())

dx = [1,0,-1,0]
dy = [0,1,0,-1]

for _ in range(test):
    w, h = map(int, input().split())
    
    board = [list(sys.stdin.readline().strip()) for _ in range(h)]
    
    check = [[0] * w for _ in range(h)]
    fire_q = deque()
    sang_q = deque()
    sx = sy = 0

    for i in range(h):
        for j in range(w):
            if board[i][j] == '*':
                check[i][j] = -1
                fire_q.append((i,j))
            elif board[i][j] == '@':
                sx, sy = i, j

    while fire_q:
        cur = fire_q.popleft()
        for dir in range(4):
            x = cur[0] + dx[dir]
            y = cur[1] + dy[dir]
            if x < 0 or y < 0 or x >= h or y >= w: continue
            if check[x][y] != 0 or board[x][y] == '#': continue
            check[x][y] = check[cur[0]][cur[1]] - 1
            fire_q.append((x,y))

    check[sx][sy] = 1
    sang_q.append((sx,sy))
    escaped = False

    while sang_q:
        if escaped: break
        cur = sang_q.popleft()
        for dir in range(4):
            x = cur[0] + dx[dir]
            y = cur[1] + dy[dir]
            if x < 0 or y < 0 or x >= h or y >= w:
                escaped = True
                print(check[cur[0]][cur[1]])
                break
            if board[x][y] == '#': continue  # ord() 제거
            if check[x][y] > 0: continue
            if check[x][y] < 0 and check[cur[0]][cur[1]] + 1 >= -check[x][y]: 
                continue
            check[x][y] = check[cur[0]][cur[1]] + 1
            sang_q.append((x,y))
    
    if not escaped:
        print("IMPOSSIBLE")
```

## 프로그래머스
### 합승 택시 요금 (Lv 3, 다익스트라)
https://school.programmers.co.kr/learn/courses/30/lessons/72413

어떻게 풀지 아이디어도 떠올리지 못했고, 떠올렸어도 다익스트라도 몰라 못 푸는 문제였다.

먼저 다익스트라 알고리즘을 자세하게 알아보자
#### Dijkstra
다익스트라 알고리즘의 목적은 **하나의 시작점에서 모든 노드까지의 최단 거리를 구하는 것** 이다. 현재까지 가장 가까운 노드부터 처리하면 그 노드의 최단 거리는 확정된다는 원리를 갖고 작동한다. 이 가정이 계속 통하려면 음수 간선이 있어서는 안된다. 그래프는 인접 행렬, 인접 리스트 둘다 상관없지만 공간 복잡도 측면에서 인접 리스트를 다루는 것이 유리하다. 다익스트라 알고리즘 코드는 다음과 같다.

```
import heapq

def dijkstra(start, n, graph):
    distance = [INF] * (n + 1)
    distance[start] = 0
    pq = [(0, start)]  
    
    while pq:
        dist, now = heapq.heappop(pq)
        
        if dist > distance[now]:
            continue
            
        for next_node, cost in graph[now]:
            new_cost = dist + cost
            if new_cost < distance[next_node]:
                distance[next_node] = new_cost
                heapq.heappush(pq, (new_cost, next_node))
    
    return distance
```

코드를 분석해보자. 

```
INF = int(1e9)

distance = [INF] * (n + 1)
distance[start] = 0
pq = [(0, start)]
```
먼저 모든 거리를 `무한대`로 초기화한다. 시작점 거리는 0으로 설정한다. 힙에 **(거리, 노드)** 형태로 시작점을 추가한다. 

```
while pq:
    dist, now = heapq.heappop(pq)
```
메인 루프는 힙에서 가장 거리가 짧은 노드를 꺼내는데, 우선순위 큐를 사용하니 힙이 알아서 최솟값을 관리한다.

```
if dist > distance[now]:
    continue
```
이미 그 노드가 더 짧은 거리로 처리가 되어 있다면 무시한다.

```
for next_node, cost in graph[now]:
    new_cost = dist + cost
    if new_cost < distance[next_node]:
        distance[next_node] = new_cost
        heapq.heappush(pq, (new_cost, next_node))
```
현재 노드와 연결된 모든 노드를 확인하여 더 짧은 경로를 찾으면 **거리를 갱신하고 힙에 추가** 한다. 

### 전력망을 둘로 나누기 (Lv 2, BFS)
https://school.programmers.co.kr/learn/courses/30/lessons/86971

몇 가지 실수한 점이 있는 문제였다. 나는 인접 행렬을 만들어서, 간선 하나를 제외하면서 반복하며 트리 크기를 계산했는데, 

1. 인접 행렬 대신 가급적이면 인접 리스트를 쓰는 것이 좋은 것 같다. 미리미리 습관을 들여 놓아야 좋을 것 같다. 제외하는 간선의 경우, 헷갈리게 테이블에서 일일이 지우고 다시 그리지 말고 그냥 bfs 루트에서 처리할 수 있는 좋은 방법이 있었다.
2. 그리고 문제를 풀 때 그 트리의 크기를 모두 계산했는데, 사실 전체 트리 크기에서 하나만 구하면 다른 하나는 저절로 나온다는 사실 또한 떠올리지 못하였다.(효율의 문제)

### 프로세스 (Lv 2, deque)
https://school.programmers.co.kr/learn/courses/30/lessons/42587

**deque** 를 쓰는 생각을 잘 못해서, 이상하게 풀고 이상하게 틀린 문제이다. 최댓값을 찾는다는 점에서는 heapq가 생각날 수도 있지만, **순서를 유지** 해야한다는 점에서 적합하지 않다. 대신 deque를 사용하여 일단 arr[0]에서 뽑고 대상이 아니면 뒤로 붙여서 순환시키는 방법을 사용할 수 있다. 

```
from collections import deque

def solution(priorities, location):
    queue = deque((p, i) for i, p in enumerate(priorities))
    order = 0
    
    while queue:
        cur = queue.popleft()  
        
        if any(cur[0] < q[0] for q in queue):
            queue.append(cur) 
        else:
            order += 1
            if cur[1] == location:
                return order
```

클로드의 코드를 참고한 코드이다. `enumerate`는 인자로 들어온 리스트의 원소들을 (인덱스, 원소) 쌍으로 반환하는 함수이다. 인덱스도 location과 비교를 하기 위해 필요하기 때문에 이렇게 초기화를 한다. 

**any** 는 안에 있는게 하나라도 조건을 만족하면 True를 반환하는데, 위의 코드는 queue에 있는 원소 중 하나라도 우선순위가 더 큰 요소가 있는지 찾는 코드이다. 풀어쓰면 다음과 같다.
```
for q in queue:
    if cur[0] < q[0]:
        return True
return False
```

deque을 사용하여 리스트를 순환시킨다는 아이디어가 제일 중요했던 것 같다. 

### 길 찾기 게임 (Lv 3, 재귀, 트리)
https://school.programmers.co.kr/learn/courses/30/lessons/42892

문제를 너무 어렵게 생각해서 풀지 못하였다. y 좌표를 기준으로 정렬하여 루트부터 시작한다는 발상까지는 도달하였는데, 그 후로 진행을 매끄럽게 못하였다. 정렬부터 깔끔하게 하는 방법을 보자
```
def solution(nodeinfo):
    global node
    for i in range(len(nodeinfo)):
        node.append( ( nodeinfo[i][1],nodeinfo[i][0], i+1 ) )
    node.sort(key=lambda n: (-n[0],n[1]))
```

이런 식으로 진행하면 문제 풀이에 맞게 깔끔하게 정렬할 수 있다. **lambda** 는 이름 없는 간단한 함수를 뜻하는데, 아래 두 표현은 동치라고 할 수 있다.
```
def get_key(n):
    return (-n[0], n[1])

lambda n: (-n[0], n[1])
```

sort의 **key 파라미터** 는 `이 기준으로 정렬해라`라는 뜻으로, (-n[0],n[1]) 꼴의 비교 함수를 넣어주면 
1. 첫번째 인자는 내림차순
2. 두번째 인자는 오름차순

으로 저절로 정렬이 된다. -n[0]은 뒤집었을 때 가장 작은 값 순서대로 오름차순이니 내림차순.. 이라고 생각하면 될 거 같다.

이제 재귀 함수를 돌면서 트리를 구성해주면 되는데, 본인은 백트래킹을 통해 트리를 구성해야 한다고 생각했으나, 사실 y, x 순으로 정렬된 노드들을 순서대로 처리하면 결정적으로 트리를 만들어낼 수 있다. 트리 문제가 낯설어서 생각이 부족했던 것 같다. 어떤 노드가 들어올 때 루트부터 오른쪽, 왼쪽을 타고 내려간다고 생각하면 편하다. 트리를 만들어준 다음 순회를 구현하면 된다.

```
import sys
sys.setrecursionlimit(10**6)

node = list()
left = list()
right = list()

def front(indx):
    global node
    global left
    global right
    
    answer = list()
    answer.append(node[indx][2])
    
    l = left[indx]
    r = right[indx]
    
    if l != 0:
        answer += front(l)
    if r != 0:
        answer += front(r)
    return answer

def back(indx):
    global node
    global left
    global right
    
    answer = list()
    
    l = left[indx]
    r = right[indx]
    
    if l != 0:
        answer += back(l)
    if r != 0:
        answer += back(r)
    answer.append(node[indx][2])
    return answer

def build_tree(indx, cur):
    global node
    global left
    global right
    
    x = node[indx][1]
    x_cur = node[cur][1]
    
    if x < x_cur:
        if left[cur] == 0:
            left[cur] = indx
            return
        else:
            build_tree(indx, left[cur])
            return
    else:
        if right[cur] == 0:
            right[cur] = indx
            return
        else:
            build_tree(indx, right[cur])
            return
            
def solution(nodeinfo):
    global node
    global left
    global right
    for i in range(len(nodeinfo)):
        node.append((nodeinfo[i][1], nodeinfo[i][0], i + 1 ))
    node.sort(key=(lambda n: (-n[0],n[1])))
    
    root = node[0][2]
    
    for i in range(len(nodeinfo)):
        left.append(0)
        right.append(0)
        
    for i in range(1, len(node)):
        build_tree(i, 0)
                       
    ans1 = front(0)
    ans2 = back(0)
    
    return [ans1, ans2]
```
- 전위: Root -> Left -> Right
- 중위: Left -> Root -> Right
- 후위: Left -> Right -> Root

이 순서를 기억하자.. 

그리고 재귀 깊이가 부족할 수 있으니 재귀 함수를 사용할 때 **깊이를 늘려주는 것** 을 항상 기억하자
```
import sys
sys.setrecursionlimit(10**6)
```