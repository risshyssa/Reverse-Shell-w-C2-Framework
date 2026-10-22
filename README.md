# ⚠️ DISCLAIMER

This is strictly for **educational purposes only** and is only intended to be used on a **VM** that you own or have explicit permission to test. 

- Do NOT use this on systems that you don't own.
- Do NOT use without unauthorized access

## Overview

A Python based C2 framework that demonstrates:
- *RSA-2048* key exchange for session initialization
- *AES-256-GCM* command and control channel
- Reverse shell functionality (only built for VM's)

# SYSTEM

Keychain -> can generate the RSA key to pair with the implant 

|___ private_key.pem (on C2 server) 

|___ public_key.pem (on the Host server) 

Implant -> runs on the target 

|___ Will perform the RSA handshake with C2 

|___ Encrypts the AES encrypted with RSA 

|___ Sends/receives the encrypted terminal 

C2 Beacon -> runs on the host machine 

|___ Listens for incoming connections from the implant 

|___ Provides the command shell 
