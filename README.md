# OTP
In cryptography, the one-time pad (OTP) is an encryption technique that cannot be cracked, but requires the use of a single-use pre-shared key that is not smaller than the message being sent. In this technique, a plaintext is paired with a random secret key (also referred to as a one-time pad). Then, each bit or character of the plaintext is encrypted by combining it with the corresponding bit or character from the pad using modular addition.

The `compileall` shell script creates 5 executable programs from files. These 5 programs must be created in the same directory as `compileall`.

To run the script, open a terminal and execute the following command:
```bash compileall```


## Executable programs
Once `compileall` has been executed, you can run the following executable programs:

- `enc_server`: runs the encryption server. It takes one argument, the `listening_port`.
  ```./enc_server listening_port```

- `dec_server`: runs the decryption server. It takes one argument, the `listening_port`.
  ```./dec_server listening_port```

- `enc_client`: runs the encryption client. It takes three arguments, the `plaintext`, the `key`, and the `port`.
  ```./enc_client plaintext key port```

- `dec_client`: runs the decryption client. It takes three arguments, the `plaintext`, the `key`, and the `port`.
  ```./dec_client plaintext key port```
