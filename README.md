# RSA Encryption and Decryption in Python

This project demonstrates the use of RSA encryption and decryption with Python's `cryptography` library. It generates an RSA key pair, saves the keys in PEM format, and provides functions to encrypt and decrypt messages.

## Table of Contents
1. [Introduction](#introduction)
2. [Features](#features)
3. [Requirements](#requirements)
4. [Setup](#setup)
5. [Usage](#usage)
6. [License](#license)

## Introduction
This code is intended as an introductory project for learning about RSA encryption, a widely used method in cybersecurity to secure communications. RSA encryption uses a public-private key pair to ensure confidentiality and authenticity in digital communications. The code includes functionality for generating RSA keys, saving them to files, loading them, and encrypting/decrypting messages.

## Features
- Generate an RSA key pair (public and private keys).
- Save keys in PEM format.
- Load keys from PEM files.
- Encrypt a message using the public key.
- Decrypt a message using the private key.

## Requirements
- **Python 3.6+**
- **Cryptography Library**

Install the required library with:
```bash
pip install cryptography
