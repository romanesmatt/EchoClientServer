# Echo-Client-And-Server
A secure communication channel application that can send messages between the client and server. The security of the channel is ensured by using the RSA asymmetric encryption algorithm, as well as SHA256withRSA for signage and verification of the message. Data is encrypted prior to sending, using the cipher RSA/PKCS1Padding. Data is decrypted in the same manner to be read by either the client or server as plaintext. 
## Running The Application
The server will wait for a message from the client, decrypt it into plaintext and re-encrypt the message into ciphertext to be sent back to the client. So make sure to run the server side first before running the client side, as an error will be thrown when the server cannot find something to connect to. This applies in particular to the *part1* directory
### Part One: Prompting For A Public Key
The directory *part1* is designed to run programmatically. To run this part of the project, press the Play button in your IDE. The program will print a public key encoded in Base64 as a String. The program will prompt you to input the key, so copy and paste the given String. Both the client and server sides of the channel will prompt for a key, so use the same key for both.
### Part Two: Keystore
The directory *part2* is designed to run via the command line. To run this part of the project, compile both server (**compile this first**)and client sides using the following command: ```javac <projectName>``` <br>

If no errors are found, input the following command: ```java <projectName>```

### Part Three: Secure Channel Principles
Incomplete.
