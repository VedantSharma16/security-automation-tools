I just used AI to make an automation tool that scans the port using the `socket` library in python. I spent around half an hour to understand what is happening and this is what I understand from this code.
The code: ![[port_scanner.py]]
The working:
1. First, we import a library called `socket` which enables python to make a connection from our PC to any other PC, like a phone call. 
2. Then we initialise a variable called `target` which takes input from user, which can either be the IP address or the domain of the website. 
3. The other variable is `port` where we mention the ports we are scanning, like FTP, HTTP/HTTPS etc.
4. Then we create a `for` loop with `port in ports` meaning that each port number will go through the loop until all the ports in the `ports` list are run through.
5. For each port, we run a few commands of our imported library. **This part was really tough for me to understand**. We create a variable `s` and give it a value which goes like `socket.socket(...)`. This is basically python creating a phone to initiate a communication.
6. Inside the brackets is `socket.AF_INET` which means we are using IPv4 address to connect to the target and then we use a comma, followed with `socket.SOCK_STREAM` which is used for TCP connections. We can use something else for UDP or Raw packets.
7. The next line is the core of our code, which is `result = s.connect_ex((target,port))` where we initiate a variable called result, where `connect_ex` is the function that tries to connect to the IP for that particular port which is in the `for` loop. 
8. In the end, if the result value returns 0, the port is open. For any other value, means the port is closed. 

Easy analogy: 🔁 Real-Life Analogy (thank you ChatGPT)

|Concept|Real-Life Example|
|---|---|
|`socket.socket()`|You bought a new phone|
|`s.connect_ex(...)`|You call someone’s number (IP + port)|
|`0`|They pick up (port is open)|
|Non-zero result|They reject your call or phone’s off (closed)|
|`s.close()`|You hang up the phone|
