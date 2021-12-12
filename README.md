# Cryptography Project 2
Applied Cryptography - Fall 2021

Team Name(s): Leo Ho, Matteo Mastrogiovanni, Nathan Cantu

Project Type: Project type 1

1. Data processing application: Party1 e-mails a message to Party2
 
2. End-to-end security impact:
Normally all email messages (including userids and passwords) are transmitted between computer and E-mail servers as plain text. 
This is not secure and anyone who can intercept this can read your email and obtain your userids, passwords and sensitive emaill content (data eavesdropping)
Man-in-the-middle can intercept and make modification to email content. If this can be done, it can be used for phishing attack using another user identity (data modification, data originator spoofing and data replay)
 
3. Design Method to protect data: encrypt content/data using AES-GCM
AES-GCM is IND-CCA2 , which protects against data eavesdropping, data modification, data originator spoofing and data replay
Create a sender socket and receiver socket with python to represent sending emails

-----------------------------------------------------------------------------------
Running the application:

Run server first in one terminal: python server.py

Run client on another terminal: python client.py
