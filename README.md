# CrytoLab2AES
Cryptographic Analysis &amp; Enhancement of AES Block Cipher Modes  Implemented AES encryption in both ECB and OFB modes from scratch in Python to analyze their security properties and vulnerabilities firsthand.

 Project Overview

This project implements and analyzes various Advanced Encryption Standard (AES) block cipher modes, with a focus on comparing the insecure ECB mode against more secure alternatives like OFB mode. The project includes practical cryptanalysis, image encryption demonstrations, and a security-enhanced modification to the OFB mode.

Key Features

1. AES Mode Implementations

AES-ECB Mode: Basic implementation showing pattern vulnerabilities
AES-OFB Mode: Secure stream cipher implementation with IV
Enhanced OFB Mode: Custom improvement combining counter mode and KDF
2. Security Analysis

Pattern detection in ECB ciphertexts
Visual cryptanalysis using image encryption
Comparative analysis of mode security properties
3. Enhanced OFB Implementation

Key Derivation Function (KDF): HMAC-SHA256 for session keys
Counter-based Keystream: Enables parallel processing
Security Improvements: Prevents key reuse and reduces error propagation

#Author: Joori Eihab Alhindi

#Course: Understanding Cryptography by Christof Paar , Jan Pelzl

#Technologies: Python, PyCryptodome, AES, HMAC-SHA256
