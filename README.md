# LRDP Server Logic & Architecture

This document outlines the design for the **Lightweight Registration and Data Protocol (LRDP)** server.

## 1. High-Level Overview

The server's purpose is to autonomously register new devices, manage data exchanges, and ensure secure communication between clients and the server. The architecture is modular, allowing for scalability and easy maintenance.


## 2. Main Flows

### A. **Device Registration**: 

    - Client use a tcp port to connect to the server.
    - First client will receive a public key
    - Client sends a registration request encrypted with the public key. (Includes mac, deviceID and public key of the client)
    - Server decrypts the request, validates the information, and stores the device details in the database.

### B. **Data Dump**:
    
    - Two main flows: High QoS and Low QoS ( same port)
    - Each client on a boot up first will connect to High QoS flow to check for playbook updates.
   #### i. High QoS Flow:
        - Client establishes a secure connection using TCP
        - Client receive a nonce from the server.
        - Client sends nonce hashed and signed ( with the client private key) and deviceId encrypted with the server public key.
        - If authentication is successful, server sends an playbook.json file to the client.
        - The playbook represents a list of commands the client must execute and report back so the server can process that data.
        - Client will send data only in this format
        - data FORMAT : {"device": 1234, "type": "DATA", "payload": {...}}
        - Server process the data accordingly.
   #### ii. Low QoS Flow:
        - Client sends data packets to the server over UDP.
        - Each packet includes a timestamp and a signature for verification.
        - FORMAT : [timestamp][data_length][data][signature]
        - data FORMAT : {"device": 1234, "type": "CONNECTED", "payload": {...}}
        - Server verifies the signature and processes the data if valid.
  