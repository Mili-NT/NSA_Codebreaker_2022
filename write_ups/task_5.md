# Task 5
## Category: Reverse Engineering/Cryptography
### Prompt:
The FBI knew who that was, and got a warrant to seize their laptop. It looks like they had an encrypted file, which may be of use to your investigation.

We believe that the attacker may have been clever and used the same RSA key that they use for SSH to encrypt the file. We asked the FBI to take a core dump of ssh-agent that was running on the attacker's computer.

Extract the attacker's private key from the core dump, and use it to decrypt the file.

Hint: if you have the private key in PEM format, you should be able to decrypt the file with the command openssl pkeyutl -decrypt -inkey privatekey.pem -in data.enc
### Provided Materials:
- Core dump of ssh-agent (core)
- SSH-Agent binary (ssh-agent)
- Encrypted file (data.enc)
### Task Goal:
- Decrypted Token Value
### Preface:
Task 5 was probably the biggest hurdle for me during the 2022 NSA Codebreaker apart from 9. I started it with little to no reverse engineering knowledege, and I learned a lot during the three weeks it took me to solve it. Unlike the first 4 writeups which were quick and to the point, I'll try to include my entire trial and error process including my notes and diagrams I made during the process.
### Steps:
