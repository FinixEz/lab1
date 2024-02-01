from pwn import *

def main():
    io = remote('172.26.201.17', 2131)

    io.sendline(b"4")

    otp_line = ''
    while 'OTP' not in otp_line:
        otp_line = io.recvline().decode("utf-8")

    otp = bytes.fromhex(otp_line.split(": ")[1].strip())

    ciphertext_line = ''
    while 'ciphertext' not in ciphertext_line:
        ciphertext_line = io.recvline().decode("utf-8")

    ciphertext = bytes.fromhex(ciphertext_line.split(": ")[1].strip())

    decrypted = bytes([a ^ b for a, b in zip(ciphertext, otp)])
    print(decrypted)

    io.sendline(decrypted)

    flag_line = io.recvline().decode("utf-8")
    print("Flag:", flag_line)

    io.close()

main()
