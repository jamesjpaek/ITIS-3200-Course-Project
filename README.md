# ITIS-3200-Couse-Project
ITIS-3200-Couse-Project

-----------------------------------------------------------------
do "pip install cryptography"
-----------------------------------------------------------------

to use regularly do:

"python server.py" in a terminal
"python client.py Username" in another terminal
"python client.py Username2" in another terminal

send messages between the two clients

-----------------------------------------------------------------

to defend against intercepting messages do:

"python server.py" in a terminal
"python attacker.py --mitm --sniff" in another terminal
"python client.py Username --port 8888" in another terminal

-----------------------------------------------------------------

to successfully intercept messages do:

"python server.py" in a terminal
"python attacker.py --mitm --sniff" in another terminal
"python client.py Username --port 8888 --skip-sig-verify" in another terminal

send and intercept messages

-----------------------------------------------------------------

to defend against tampering do:

"python server.py" in a terminal
"python attacker.py --mitm --tamper" in another terminal
"python client.py Username --port 8888" in another terminal

send messages and they will not go through

-----------------------------------------------------------------

to successfully tamper messages do:

"python server.py --skip-hmac" in a terminal
"python attacker.py --mitm --tamper" in another terminal
"python client.py Username --port 8888 --skip-sig-verify --skip-hmac" in another terminal

send messages and they will be tampered

-----------------------------------------------------------------

to defend against replay do:

"python server.py" in a terminal
"python attacker.py --replay" in another terminal
"python client.py Username --port 8888" in another terminal

replay messages are blocked

-----------------------------------------------------------------

to successfully replay messages do:

"python server.py --skip-seq" in a terminal
"python attacker.py --replay" in another terminal
"python client.py Username --port 8888 --skip-seq" in another terminal

send messages and they will be replayed

-----------------------------------------------------------------
