from pwn import *

def otp_encrypt(plaintext, key):
    return ''.join(chr(((ord(p) - ord('a') + ord(k) - ord('a')) % 26) + ord('a')) for p, k in zip(plaintext, key))

host = '172.26.201.17'
port = 2131

conn = remote(host, port)

conn.sendline(b'2') 

question_lines = []
while True:
    line = conn.recvline().decode()
    question_lines.append(line)
    if 'Now encrypt the following plaintext:' in line:
        break

question = ''.join(question_lines)
print("Received Question:", repr(question))

plaintext_start = question.find('plaintext: "') + len('plaintext: "')
plaintext_end = question.find('"', plaintext_start)
plaintext = question[plaintext_start:plaintext_end]

key_start = question.find('with key="') + len('with key="')
key_end = question.find('"', key_start)
key = question[key_start:key_end]

print(f"Plaintext: {plaintext}")
print(f"Key: {key}")

ciphertext = otp_encrypt(plaintext, key)
print(f"Ciphertext: {ciphertext}")

print("Expected Ciphertext:", repr(ciphertext))

conn.sendline(ciphertext.encode())

result = conn.recvall(timeout=5).decode()
print("Received Result:", repr(result))

conn.close()
