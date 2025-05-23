#!/bin/sh

# Create user and home directory
adduser --disabled-password --gecos '' user
mkdir -p /home/user
chown -R user:user /home/user

# Place the flag
FLAG="FLAG{LFI_2_Local_File_Pwned}"
echo "$FLAG" > /home/user/flag.txt
chmod 644 /home/user/flag.txt

# Set ownership so Flask can read it
chown -R user:user /home/user

# Start the Flask app
python3 app.py