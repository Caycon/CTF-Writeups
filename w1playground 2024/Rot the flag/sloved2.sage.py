

# This file was *autogenerated* from the file sloved2.sage
from sage.all_cmdline import *   # import sage library

_sage_const_0 = Integer(0); _sage_const_1 = Integer(1); _sage_const_2 = Integer(2); _sage_const_4 = Integer(4)
from sage.all import *

with open("output.txt", 'r') as out:
    data = out.read().split('\n')
    p = int(data[_sage_const_0 ].split("=")[_sage_const_1 ])
    rot_matrix = matrix(GF(p), eval(data[_sage_const_1 ].split("=")[_sage_const_1 ]))
    flag_out = matrix(GF(p), eval(data[_sage_const_2 ].split("=")[_sage_const_1 ]))
    
# flag_out = rot_matrix * flag.T*flag * rot_matrix.T
# Đặt A = flag.T*flag
# find A

A = rot_matrix.inverse() * flag_out * rot_matrix.T.inverse()
l = len(list(A))
D = [A[i][i] for i in range(l)]
# print(D)

F = matrix([pow(x, -(p+_sage_const_1 )//_sage_const_4 , p) for x in D])
F = F.LLL()
print(F)

