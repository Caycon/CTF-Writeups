- Mất khá nhiều thời gian để mình có thể hiểu hết code đang làm gì.
- Cụ thể thì `flag` sẽ bị mã hóa từng bit qua hàm `gen_w()` và sẽ trả giá trị khác nhau tùy theo bit bằng `0` hoặc `1`.
- Nếu `bit= 0` thì $w= r^2\ mod\ x$, còn nếu `bit= 1` thì $w= r^2y\ mod\ x$.
- Thì để decrypt mình có hướng là ta sẽ xét `w` xem liệu với $w\ mod\ x$ có tồn tại $r$ sao cho $r^2= w\ mod\ x$ hay không. Nếu tồn tại thì ta trả về 0 ngược lại ta trả về 1.
```python
 from Crypto.Util.number import long_to_bytes
import os
from ast import literal_eval

def read_file_content(file_path):
    with open(file_path, 'r') as f:
        lines = f.readlines()
    return lines

def parse_content(lines):
    w = int(lines[1].split('=')[1].strip()) 
    pairs = [literal_eval(lines[3 + i].strip()) for i in range(407)] 
    list_i = literal_eval(lines[410].split('=')[1].strip()) 
    responses = [literal_eval(line.strip()) for line in lines[412:]]  
    return w, pairs, list_i, responses

def find_flag(num_rounds, x):
    flag_bits = ''
    for i in range(num_rounds):
        file_path = os.path.join( f"output_{i}.txt")
        lines = read_file_content(file_path)
        w, pairs, list_i, responses = parse_content(lines)
        
        for idx, response in enumerate(responses):
            if isinstance(response, int): 
                a = pairs[idx][0]
                if pow(response, 2, x) == (w * a) % x:
                    flag_bits += '0'
                else:
                    flag_bits += '1'
                break
    flag_bytes = long_to_bytes(int(flag_bits[::-1], 2))
    return flag_bytes

num_rounds = 407
x = 106276637345585586395178695555113419125706596151484787339368729136766801222943

flag = find_flag(num_rounds, x)
print(flag)
```
