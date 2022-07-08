# Baby-Ransomware
## _Encryption & Decryption._

The baby-ransomware, this programe make for encryption and decryption. Build from python language with cryptography library([pyca/cryptography](https://cryptography.io/en/latest/)). 
**Project of Cyber Security @ SUT.**

- Have encryption and decryption mode.
- Use symmetric and asymmetric key cryptography.

## Features

##### _:: 2 Mode ::_
1. Encryption
    - Use AES (symmetric) 
    - Use IV (Initialization vector) 16 bytes for AES with Random
    - Create 'LocalKey' file for store a AES key and IV
    - Encrypt 'LocalKey' file with RSA Public key (asymmetric)
2. Decryption
    - Use RSA Private key (asymmetric) to decrypt 'LocalKey' file. then get AES key and IV

## Installation

The baby-ransomware requires [Python](https://www.python.org/) v3.9.7+ to run.

Install the dependencies and devDependencies and run the `src/main.py`

#### git clone
```sh
git clone https://github.com/miracleexotic/baby-ransomware.git
cd baby-ransomware
```

### install dependencies
```sh
pip install -r requirements.txt
```

### run
```sh
python src/main.py
```

![Image baby-ransomware gui](/assets/images/gui.png "GUI")

## License

MIT

**Free Software, Thank you!**