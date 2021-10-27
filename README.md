# Echo Client & Server
CYBR 372, Assignment 2 <br>

### External Links

## Part One
### Running The Code
Run the server and client sides of the program by pressing the Play button on your IDE. 
This part of the assignment is designed to run programmatically and not from the command line.

When specifying the public key, simply copy and paste the public key string defined as the constant PUBLIC_KEY_STRING 
in the console for both Server and Client. The program will do the rest.
###Design Decisions
In regards to design choices, I made very little deviation from the example code given in the 
assignment brief. That said, however, instead of combining the key generation, encryption, decryption,
signing and verification of signature in the pre-written methods, I decided to segregate these into their
own respective methods in order to organize the code and more importantly, allow for easier debugging.

If there is a design choice I would like to explain and justify, it is in regard to the constant
PRIVATE_KEY_STRING, which houses the this.PrivateKey's bytes encoded in Base64 in the form of a 
string (for both Server and Client). I have decided to implement this design choice on the basis that
without creating the String Base64 encoded bytes of the private key, the program throws a NullPointerException
due to the this.PrivateKey being null when it is used for its respective purpose (
decryption and signing of message).


## Part Two
### Running The Code
Run the program from the command line. To specify the password for the KeyStore, type 
'badpassword' on the command line; the program will accept it as an argument. 

### Design Decisions
The requirements for this part of the assignment differed from the first part; instead of 
prompting the user for the public key (encoded as a Base64 string), we use the KeyStore instance
to not only store the public and private keys, but also the certificate for both the client and server
(stored in cybr372.jks).

When generating the key pair, rather than needing the Base64 encoded string values of the public and
private key, as per assignment requirements I opted to generate it from the KeyStore. Doing so generated
its own certificate which would be useful for both the Client and Server side of the program.

And just like in the first part of this assignment, once again
I made little deviation from the example code, but instead separated each functionality by their own
respective methods for easier debugging and general organisation of the code.
