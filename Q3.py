from pwn import *

def shift_decrypt(ciphertext, shift):
    return ''.join([chr((ord(char) - shift - 65) % 26 + 65) if char.isalpha() else char for char in ciphertext.upper()])

io = remote('172.26.201.17', 2131)

io.recvline()
io.sendline(b"3")

cypher_text = io.recvline().decode("utf-8").split(': ', 1)[1][:-1]

hint = 'easy'
shift = next(shift for shift in range(1, 26) if hint in shift_decrypt(cypher_text, shift).lower())

io.sendline(shift_decrypt(cypher_text, shift).lower().encode())

io.recvline()
flag_line = io.recvline().decode("utf-8")
print("Flag:", flag_line)

io.close()
