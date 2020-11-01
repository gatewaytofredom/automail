import os
import socket
import platform

# Read config file here

# Identify Hostname and Platform

HOSTNAME = socket.gethostname()

print(HOSTNAME)

PLATFORM = platform.system()

print(PLATFORM)

if "windows" in PLATFORM.lower():
    print("Automail is inteded to run on Ubuntu. \n Sorry!")
