import random
import string

generate_otp = lambda: ''.join(random.choice(string.digits) for _ in range(6))
message = generate_otp()
print(message())