Onix
====

Small tool that creates an RSA tunnel from client to server and vice-versa. At the moment, the client sends the server an encrypted message, to which the server returns an answer equal to message.UPPERCASE.

##Usage
#####Compile
On first usage, compile the code with 
```
    javac Client.java
```
and 
```
    javac Server.java
```

###Server
To start the server, simply run the command
```
    java Server
```
from the terminal. 
#####Optional arguments
To specify an other port (instead of the default port 4444), add 
```
    -p <port-number>
```
to the command.

For verbose output, add
```
    -v
```
to the command.

###Client
Run the client with the command
```
    java Client
```
#####Optional arguments
To specify a message (rather than the default message "test"), add
```
    -m <message> 
```
to the command. Use ' before and after the message if the message consists of more than one word.

To specify an other port (instead of the default port 4444), add 
```
-p <port-number>
```
to the command.
To specify an other host (instead of the default host 'localhost'), add 
```    
-h <host>
```
to the command.

For verbose output, add
    -v
to the command.
