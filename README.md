# TUPW

Safely store credentials in config files

## Command Line Program

This program serves as an example of how to safely store credentials in config files. It works as a command line tool to encrypt and decrypt credentials. The decryption part can be incorporated into an application.

The idea is to store credentials in a config file in an encrypted form like this:

    <credentials>
      <user name="dbuser" user="3$OX6llWMaTw04aM27M8ie0g==$wxINKIoVSPue9AWTtFCETM0AFIeTTRWi+u1sUyX0RAE=$xGIUOaz+OYCBv5Qg9zgD6v4AgFZtg2qgHnurNWnf+G0=" password="3$1JoZeUaYLWtxJ0lxriBVww==$a0J6qe2RC2kiYAO+l04G1lihqNPNyUCAT21gsJzhDEE=$y5xX+gBa1QRs4PwS7Ut+AXk9NDCnAd86R6MCAOXkX5s="/>
    </credentials>

If one uses OpenShift an encrypted secret can be used as an environment variable, a file, or an imagePullSecret. If one does not store the secret itself, but an encrypted secret this can be used like following. E.g. if there is a secret named "`oc-userid-secret`" that is mapped as an evironment variable one can use it like this:

    someStartupCmd --userid=$(java -jar tupw.jar decrypt d:\keyfile.bin userid ${oc-userid-secret})

This is especially useful as environment variables show up in logs and memory dumps. If the secret is stored unencrypted it can be read in clear by anyone who has access to the logs and the memory dumps. Also, everbody who has some kind of access to a pod can echo the environment variable or cat the file. TUPW helps here in that the secret is nowhere stored in clear text format.

The encrypted data is stored as four parts separated by '$' characters:

1. The format code:
    * 1 =`{IV}{AES-128-CFB-ABytPadding}{HMAC}`
    * 2 =`{IV}{AES-128-CTR-ABytPadding}{HMAC}`
    * 3 =`{IV}{AES-128-CTR-Blinded-Data-and-RandomPadding}{HMAC}`
    * 4 =`{IV}{AES-128-CBC-Blinded-Data-and-RandomPadding}{HMAC}`
2. The IV
3. The data encrypted with the method specified in the format code
3. The HMAC of the format code, the IV and the encrypted data

This format uses the following fields:

* The initialization vector used for encryption
* The type of encryption ([AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard "AES") 128 bit)
* The encryption mode
    * [CBC](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CBC "CBC")
    * [CFB](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CFB "CFB")
	* [CTR](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CTR "CTR")
* The padding or blinding
    * Padding with [arbitrary tail byte ("ABytPadding") padding](https://eprint.iacr.org/2003/098.pdf "AByt-Pad")
	* Blinding of data and padding to the cipher block length with random bytes (RandomPadding)
* Integrity protection by [HMAC](https://en.wikipedia.org/wiki/Hash-based_message_authentication_code "HMAC")

All parts except the format code are [BASE64](https://en.wikipedia.org/wiki/Base64 "BASE64") encoded. Beginning with format 4 these BASE64 values are no longer padded with "=" characters.

The encryption key is generated by calculating the [HMAC](https://en.wikipedia.org/wiki/Hash-based_message_authentication_code "HMAC")-[SHA-256](https://en.wikipedia.org/wiki/SHA-2 "SHA-256") value of a file that is filled with random bytes. This file should be stored in a directory that is only accessible by the user that runs the application and nobody else.

The HMAC needs a key that is hard-coded in the program. So the key is calculated from something that is "known" (the HMAC key), something that is in "posession" of the program (the file) and an optional "subject" string.

The above data can only be decrypted with the same file, the same HMAC key and the same subject string.

The program is used like this ('d:\keyfile.bin' is the name of the key file):

    java -jar tupw.jar encrypt d:\keyfile.bin userid dbUser

This generates (for example) the following output:

    4$mmAq871mld4AgTUDvkQkvA$XbIxT7soZ07Rm0rGsoic1059aghAai2mG5QYl25j/84jHwELMIVeeVrzZgal2UvR$KAR9QlLreFfCmFRJIIn7ZyZZUldeq5czY5aDgLhxQUc
	
Note that the "iv" part (the one after '3$') of the encryption will change with each invocation of the program as it is derived from a secure random number generator and hence the result of the encryption (which uses the random iv) and also the HMAC will be different, as well, even if the same key file is used in all of these invocations.

Of course, one would need the keyfile to decrypt this like so:

    java -jar tupw.jar decrypt d:\keyfile.bin userid "4$mmAq871mld4AgTUDvkQkvA$XbIxT7soZ07Rm0rGsoic1059aghAai2mG5QYl25j/84jHwELMIVeeVrzZgal2UvR$KAR9QlLreFfCmFRJIIn7ZyZZUldeq5czY5aDgLhxQUc"

which yields (with the correct key file):

    dbUser

This way one can store the credentials and the key file in configuration management systems without storing them in the clear.

Note that "userid" is the optional "subject" parameter. It can have any value you like and is used to modify the encryption key. It may also be not present, at all.

The decryption part of the program would typically be copied and used in an application to decrypt the credentials in the configuration file.

The program can also be used in a pipe to decode a file like this:

    java -jar tupw.jar decrypt d:\keyfile.bin - < cat encrypted-secret.config > plain.config
	
The trailing "-" tells the program that the input comes from stdin and not from the command line. This makes it possible to decrypt a secret configuration file, use it to start a server and then remove it after the sever has been started.

Of course, this is not perfectly safe, as an attacker can get access to the machine and extract the key file and the program classes and reverse engineer the way the key is calculated.

This program just makes it harder to get at the credentials, as both the file and the program code are needed to reconstruct the encryption key.

## Library

The command line program uses a library that can be found in the `dbscryptolib` source path. This library is the interface to the encryption and decryption methods. It is used like this:

    // This is the static HMAC key which is only known to the program
    // TODO: Do not use this constant byte array. Roll your own!!!!
    final byte[] HMAC_KEY = {(byte) 0xB4, (byte) 0xDC, (byte) 0x1C, (byte) 0x05,
       (byte) 0xCD, (byte) 0x1C, (byte) 0x30, (byte) 0xB8,
       (byte) 0x59, (byte) 0x80, (byte) 0x90, (byte) 0xC7,
       (byte) 0xFA, (byte) 0x4D, (byte) 0x07, (byte) 0x12,
       (byte) 0xD2, (byte) 0xA0, (byte) 0x67, (byte) 0xF5,
       (byte) 0x4C, (byte) 0x17, (byte) 0x11, (byte) 0xD0,
       (byte) 0x90, (byte) 0xF6, (byte) 0x53, (byte) 0x8A,
       (byte) 0x0B, (byte) 0xDF, (byte) 0xA4, (byte) 0x17};
    
	...
	
	try (FileAndKeyEncryption MyEncryptor = new FileAndKeyEncryption(HMAC_KEY, pathToKeyFile)) {
	   ...
       String decryptedData = MyEncryptor.decryptData(dataToDecrypt, subject);
	   ...
	   // TODO: Do whatever you need to do with the decrypted string
    } catch (Exception e) {
       System.err.print(e.toString());
    }

I.e. the class `FileAndKeyEncryption` is instantiated with an HMAC key that is encoded in the program's source code and a key file whose path can be supplied as a parameter, or be read from a configuration file.

The class instance then generates a key from the HMAC of the key file and stores this key safely in the program's memory. When data have to be encrypted, or decrypted the calculated key is optionally modfied with the supplied "subject" string and then used for the requested cryptographic operation. Both operations expect a `String` as input data and return a `String` as output data. So you can not encrypt binary data with it, which makes kind of sense as it is designed to store readable data.

The class is meant to be instantiated once and then used throughout the lifetime of the program as needed. It should not be instantiated every time it is used as reading the key file and calculating the HMAC of it is quite expensive. The class stores the calculated key in a secure manner in an instance of the `SecureSecretKeySpec` class which can be found in the `dbscryptolib` source path.

The size of the key file should be at least 100,000 bytes to have enough entropy.

## Blinding

"Blinding" means that the data to be encrypted is prepended and appended with random bytes of varying lengths. These blinders are chosen so that the resulting "blinded" data has a least a length of the AES block size plus 1 byte which results in two AES blocks padded with random bytes. This effectively "blinds" the true length of the source data, if it is shorter than 29 bytes.

Blinded data has the following data structure:

| Field | Length (in bytes) |
| --- | :---: |
|Length of prepended data | 1 |
|Length of appended data | 1 |
|Length of source text as compressed integer | 1-4 |
|Prepended data | Variable |
|Source text | Variable |
|Appended data | Variable |

A "compressed integer" encodes an unsigned integer in a variable length format. The first two bits of the first byte determine the length of the compressed integer:

| First bits  | Length (in bytes) | Valuation |
| :---: | :---: | ---: |
|00 | 1 | 0 - 63 |
|01 | 2 | 64 - 16447 |
|10 | 3 | 16448 - 4210687 |
|11 | 4 | 4210688 - 1077936127 |

## Contributing

Feel free to submit a pull request with new features, improvements on tests or documentation and bug fixes.

## Contact

Frank Schwab ([Mail](mailto:frank.schwab@deutschebahn.com "Mail"))

## License

TUPW is released under the 3-clause BSD license. See "LICENSE" for details.
