
- Chall này mình có tìm được hướng làm trong lúc thi tuy nhiên mình không biết nó cụ thể là phương pháp nào:)
- Sau thi thì mình có tham khảo wu thì biết đây là `nonce reuse attack`.
- Đầu tiên ta cần tính toán và gửi 2 ct vào sao cho `nouce` của chúng giống nhau để làm được điều này thì ta phải tính toán dựa trên y đã cho.

```python
def polynomial_evaluation(coefficients, x):
	at_x = 0
	for i in range(len(coefficients)):
		at_x += coefficients[i] * (x ** i)
		at_x = at_x % p
	return at_x
```
- Giải phương trình $f(x)= \sum{cof_i*x^i}_{0}^{15}$
