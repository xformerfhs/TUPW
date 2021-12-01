# TUPW

Safely store secrets in config files, environment variables, and files

## Introduction

In almost every project, secrets need to be stored: passwords, tokens, user names, you name it.
Developers are faced with the question of how to store these secrets securely?
Too often they are simply stored in plain text in configuration files where an attacker can easily find them.
If not, often some kind of home-brewn obfuscation is used.
This is a very bad idea as it can easily be broken.
Sometimes these secrets are encrypted.
Most of the time this encryption is done wrong, so that it is not secure.
Encryption is hard to do correctly.
Even if it is done correctly, the question arises how to store the key for the encrypted secret and once again one is faced with the problem of how to securely store this key?

This project helps to solve the above problem in two ways:

   1. It uses a secure encryption
   2. It divides the key in different parts, so there is not one single place where it is stored

This alleviates the usability problem described above.

Of course, if one can use key management systems like [Azure Key Vault](https://azure.microsoft.com/en-us/services/key-vault/), [AWS KMS](https://aws.amazon.com/kms/), [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/), [Google Cloud KMS](https://cloud.google.com/kms/), or [Hashicorp Vault](https://www.vaultproject.io/) these should be used.
They offer better security and have more features.
TUPW should only be used if a key management system is not available.

The idea of TUPW is to store secrets in an encrypted form and to distribute the elements the key is derived from, so it is not found in a single place.

Because of the encryption an attacker that breaks the application and is able to access it's files and environment variables will see something like

    61p2nc5NgP9XGXZk9V6n7DZ8964J1pK2nh2nZpjcjxJ5zN9HxHVDVJ3hDp6Nd6JdhC8pX2hx74Pd88J45PZ38XpxtdPc79x5x65kxVdN6cv5k35VnKVPNc8K92vxhN4HnG8T1tkTXNtKNJhP3Gk8Cg4JP88x85vcx529vxGGNdNVNnHNjXgZgK7tT

instead of

    Very1Very2Very3SécurePasswôrd?!

One can store this encrypted form in config files.
If one use OpenShift, Kubernetes, GitLab or any other software that puts secrets in environment variables, files or imagePullSecrets, these secrets can also be encrypted with TUPW.

This is especially useful as environment variables show up in logs and memory dumps.
If the secret is stored unencrypted it can be read in clear by anyone who has access to the logs and the memory dumps.
Also, everbody who has some kind of access to a pod can echo the environment variable or cat the file.
TUPW helps here in that the secret is nowhere stored in clear text format.

To encrypt the data two keys are needed:

   1. An encryption key
   2. An HMAC key
   
Both keys are generated by calculating the [HMAC](https://en.wikipedia.org/wiki/Hash-based_message_authentication_code "HMAC")-[SHA-256](https://en.wikipedia.org/wiki/SHA-2 "SHA-256") value of some bytes that are supplied from outside the program, like e.g. the contents of a file, of environment variables, or some other values.
The above mentioned keys are derived from this HMAC of the data that is supplied to the classes used by TUPW.

The HMAC to generate both the keys needs itself a key that is provided by the application.
So both keys are calculated from something that is "known" to the program only (the HMAC key) and something that is in "posession" of the program (the source bytes or the file) and an optional "subject" string.
It is not possible to specify a key directly.
The key is always calculated from the different parts, so that an attacker would need to get hold of all the components the key is derived from.

One of the interfaces expects a file which should be stored in a directory that is only accessible by the user that runs the application and nobody else. 

**Attention**: The key sources or any other part the key is derived from *must not* be stored in the repository.

So the keys are generated from the following parts:

1. The content of a file or the contents of some other bytes from outside the program 
2. The key that the program uses
3. The subject string (optional)

By distributing the elements that both keys are derived from between the application and several external entities an attacker needs to have access to all of these elements.
Most attackers will not be able to do so and so will not be able to get at the keys.

In a docker environment one can place a file in the docker image and delete it in the running container after it has been used for the instantiation of the class that implements the encryption.
This way an attacker will not be able to access a part the keys are generated from and will have a harder time getting at them.

BTW, Java's [SecretKeySpec](https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/spec/SecretKeySpec.html) class is *not* secure, so TUPW uses a drop-in replacement called [SecureSecretKeySpec](https://github.com/dbsystel/SecureSecretKeySpec) to securely store the keys it uses.

The minimum JRE version needed for this library is Java 8.

## Format

The encrypted data is stored as four parts separated by a special character:

1. The format code:
    * 1 =`{IV}{AES-128-CFB-ABytPadding}{HMAC}` (Encoded as Base64 with `$` as the field separator)
    * 2 =`{IV}{AES-128-CTR-ABytPadding}{HMAC}` (Encoded as Base64 with `$` as the field separator)
    * 3 =`{IV}{AES-128-CTR-Blinded-Data-and-RandomPadding}{HMAC}` (Encoded as Base64 with `$` as the field separator)
    * 4 =`{IV}{AES-128/256-CBC-Blinded-Data-and-RandomPadding}{HMAC (wrong when subject present)}` (Encoded as Base64 with `$` as the field separator)
    * 5 =`{IV}{AES-128/256-CBC-Blinded-Data-and-RandomPadding}{HMAC}` (Encoded as Base64 with `$` as the field separator)
    * 6 =`{IV}{AES-128/256-CBC-Blinded-Data-and-RandomPadding}{HMAC}` (Encoded in custom Base32 with `1` as the field separator)
2. The IV
3. The data encrypted with the method specified in the format code
3. The HMAC of the format code, the IV and the encrypted data

This format uses the following fields:

* The initialization vector used for encryption
* The type of encryption ([AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard "AES") 128 bits or 256 bits)
* The encryption mode
    * [CBC](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CBC "CBC")
    * [CFB](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CFB "CFB")
	* [CTR](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CTR "CTR")
* The padding or blinding
    * Padding with [arbitrary tail byte ("ABytPadding") padding](https://eprint.iacr.org/2003/098.pdf "AByt-Pad")
	* Blinding of data and padding to the cipher block length with random bytes (RandomPadding)
* Integrity protection by [HMAC](https://en.wikipedia.org/wiki/Hash-based_message_authentication_code "HMAC")

All parts except the format code are encoded in a custom version of [Base32](https://en.wikipedia.org/wiki/Base32 "BASE32").
Former versions used [Base64](https://en.wikipedia.org/wiki/Base64 "BASE64").
However, Base64 uses special characters `+` and `/` which make it difficult to copy a resulting encrypted string in an editor.

The custom version of Base32 uses a subset of characters that does not contain any vowels, so there will be no words formed accidentely by the encryption. 
Also there are no characters that can be easily confused with other characters like e.g. `l`, `1` and `I` or `O` and `0`.
The `1` character is only used as the separator.

The only drawback of the Base32 encoding is that is about 40% longer than the Base64 encoding.
But it is still shorter than using the hexadecimal representation of the encrypted values.

The encrypted data can only be decrypted with the same key sources and the same subject string.

## Command Line Program

The command line program is used like this ('d:\someimage.jpg' is the name of the key file):

    java -jar tupw.jar encrypt d:\someimage.jpg strangeness "Very1Very2Very3SécurePasswôrd?!"

This generates (for example) the following output:

    61p2nc5NgP9XGXZk9V6n7DZ8964J1pK2nh2nZpjcjxJ5zN9HxHVDVJ3hDp6Nd6JdhC8pX2hx74Pd88J45PZ38XpxtdPc79x5x65kxVdN6cv5k35VnKVPNc8K92vxhN4HnG8T1tkTXNtKNJhP3Gk8Cg4JP88x85vcx529vxGGNdNVNnHNjXgZgK7tT
	
Note that the "iv" part (the one after the first separator character) of the encryption will change with each invocation of the program as it is derived from a secure random number generator and hence the result of the encryption (which uses the random iv) and also the HMAC will be different, as well, even if the same key file is used in all of these invocations.

Of course, one would need the keyfile and the corresponding program to decrypt this like so:

    java -jar tupw.jar decrypt d:\keyfile.bin strangeness 61p2nc5NgP9XGXZk9V6n7DZ8964J1pK2nh2nZpjcjxJ5zN9HxHVDVJ3hDp6Nd6JdhC8pX2hx74Pd88J45PZ38XpxtdPc79x5x65kxVdN6cv5k35VnKVPNc8K92vxhN4HnG8T1tkTXNtKNJhP3Gk8Cg4JP88x85vcx529vxGGNdNVNnHNjXgZgK7tT

which yields (with the correct key file):

    Very1Very2Very3SécurePasswôrd?!

This way one can store the credentials and the key file in configuration management systems without storing them in the clear.

Note that "strangeness" is the optional "subject" parameter.
It can have any value you like and is used to modify the encryption key.
It may also be not present, at all.

The decryption part of the program would typically be copied and used in an application to decrypt the credentials in the configuration file.

The program can also be used in a shell script to decode a file like this:

    $(java -jar tupw.jar decrypt d:\keyfile.bin - < encrypted-secret.config)

The trailing '-' tells the program that the input comes from stdin and not from the command line.
This makes it possible to decrypt a secret configuration file, use it to start a server and then remove it after the sever has been started.

Of course, this is not perfectly safe, as an attacker can get access to the machine and extract the key sources and the program classes and reverse engineer the way the key is calculated.

This program just makes it harder to get at the credentials, as the key sources, the program code and the subject are needed to reconstruct the encryption key.
If an attacker manages to take over the server or container, he will be able to reconstruct the key.
It is just a matter of time and effort.
But in this case even a key management system will not help, at all.

**Important**

It is the responsibility of the user of the program or the library that the same initialization vector (iv) is **never** used twice or more.
The iv is the second part of the string after the first separator character.
In practice the pseudo random number generator is very unlikely to emit the same iv more than once.
But it is possible!
So check the iv and if that one has been used before, run the program once again to get a unique value.

### The special case of (double) quotes

If the data that is to be encrypted contains special characters it is always a wise idea to put them in quotes (\*nix) or double quotes (Windows).

If the data contains quotes or double quotes (") things get really messy as what the encryptor sees depends on the operating system.

Here are some examples:

| OS        | Argument  | Data the program "sees" |
| --------- | --------- | ----------------------- |
| Windows   | Bla"Bli   | BlaBli                  |
| Windows   | 'Bla"Bli' | 'Bla"Bli'               |
| \*nix     | Bla""Bli  | BlaBli                  |
| \*nix     | 'Bla"Bli' | Bla"Bli                 |
| \*nix     | "Bla$Bli" | Bla                     |

Under Windows just always enclose the data in double quotes.
The above example will work correctly if one specifies `"Bla""Bli"`.
*Attention*: Do *not* use single quotes under Windows as `'Bla"Bli'` will be transferred to the command line program as `'Bla"Bli'`, i.e. the quotes are preserved.

Under \*nix always enclose the data in single quotes or use an escape character (\\) before the special character.
The above example will work correctly if one uses `"Bla\"Bli"`.
*Attention*: Do *not* use double quotes if the data contains '$' characters.
The shell will consider everything after the '$' sign to be the name of an environment variable which very likely will not exist and therefore be empty.

So, enclosing the data in quotes is a good idea under \*nix but a bad idea under Windows.
Enclosing the data in double quotes is a good idea under Windows but a bad idea under \*nix.

## Classes

There are two different classes that are used as interfaces, both of whoch are located in the `Crypto` source directory:

1. SplitKeyEncryption
2. FileAndKeyEncryption

Class `SplitKeyEncryption` is the base class and uses a HMAC key and a number of bytes arrays as the sources for key calculation.

Class `FileAndKeyEncryption` uses a HMAC key and the contents of a file for key calculation.
It is implemented as a wrapper around `SplitKeyEncryption` that reads the contents of the file and passes them on to `SplitKeyEncryption`.
This class is provided as a convenience as it was the first (and then only) method to call the encryption used by TUPW.

The "SplitKeyEncryption" class is used like in the following example:

```java
   /**
    * Implements a method that creates a deterministic HMAC key from
    * a pseudo-random number generator with a fixed key
    *
    * @return The deterministic HMAC key
    */
   private static byte[] createHMACKey() {
      final byte[] result = new byte[32];  // This has to be at least 14 bytes long
      // TODO: Do not use this seed constant. Roll your own!!!!
      final Xoroshiro128plusplus xs128 = new Xoroshiro128plusplus(0x5A7F93DDD402915AL);

      for(int i=0; i<result.length; i++ )
         result[i] = xs128.nextByte();

      return result;
   }

   ...

   // Calculate the HMAC_KEY in a deterministic way
   final byte[] CALCULATED_HMAC_KEY = createHMACKey();    

   ...

   Get some reproducible content from outside the program, like environment variables, configuration variables, file contents, data from RPC calls, etc.
   Examples are
      System.getenv("SOME_ENV_VARIABLE").getbytes("UTF-8")
      some_byte_array_from_an_external_source
	  some_bytes_from_a_file
      some_configuration_string.getbytes("UTF-8")
      some_data_from_an_rpc

   ...

   try (SplitKeyEncryption MyEncryptor = new SplitKeyEncryption(CALCULATED_HMAC_KEY, some_bytes_1, some_bytes_2, some_bytes_3)) {
      // Clear all bytes that have been used for the instantiation
      Arrays.fill(some_bytes_1, (byte) 0);
      Arrays.fill(some_bytes_2, (byte) 0);
      Arrays.fill(some_bytes_3, (byte) 0);
      ...
      // Never store a password or a secret as a string as strings are immutable and can be gathered from a memory dump!
      char[] decryptedData = MyEncryptor.decryptDataAsCharacterArray(dataToDecrypt, subject);
      ...
      // TODO: Do whatever you need to do with the decrypted data
      ...
      // Now delete the decrypted data from memory if you no longer need it. That can not be done with a string.
      Arrays.fill(decryptedData, '\0');
   } catch (Exception e) {
      System.err.print(e.toString());
   }
```

One can also use a constant HMAC key and take the external bytes the key is calculated from from a file:

```java
// This is the static HMAC key which is only known to the program
//
// Please note that one does not have to use a constant byte array. This is used here just for simplicity.
// It would also be possible to store the HMAC key in a (e.g.) Kubernetes secret or some other place
// and read it from there.
//
// TODO: Do not use this constant byte array. Roll your own!!!!
// Minimum HMAC key length is 14 bytes, maximum length is 32 bytes
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
      // Never store a password or a secret as a string as strings are immutable and can be gathered from a memory dump!
      char[] decryptedData = MyEncryptor.decryptDataAsCharacterArray(dataToDecrypt, subject);
      ...
      // TODO: Do whatever you need to do with the decrypted data
      ...
      // Now delete the decrypted data from memory if you no longer need it. That can not be done with a string.
      Arrays.fill(decryptedData, '\0');
   } catch (Exception e) {
      System.err.print(e.toString());
   }
```

The class instances then generate the keys from the HMAC and the supplied bytes and store these keys safely in the program's memory.

The classes are meant to be instantiated once and then used throughout the lifetime of the program as needed.
They should not be instantiated every time they are used as checking the supplied bytes and calculating the keys is quite expensive.
The class stores the calculated key in a secure manner in an instance of the `SecureSecretKeySpec` class which can be found in the `Crypto` source directory.

The supplied bytes and the key sources may have any name and any old content.
There is no special format.
They should not be empty.

As mentioned above, it is not necessary that the HMAC key is stored in the program as a byte array.
It can be generated in any form that seems fit.
The only requirement is, that it should be something that is generated in or supplied by the program binary.
E.g., one could also use a number generator or some kind of calculation that may be controlled by some configuration parameter.

## Blinding

"Blinding" means that the data to be encrypted is prepended and appended with random bytes of varying lengths.
These blinders are chosen so that the resulting "blinded" data has a least a length of the AES block size plus 1 byte which results in two AES blocks padded with random bytes.
This effectively "blinds" the true length of the source data, if it is shorter than 29 bytes.

Blinded data has the following data structure:

| Field | Length (in bytes) |
| --- | :---: |
|Length of prepended data | 1 |
|Length of appended data | 1 |
|Length of source text as compressed integer | 1-4 |
|Prepended data | Variable |
|Source text | Variable |
|Appended data | Variable |

A "compressed integer" encodes an unsigned integer in a variable length format.
The first two bits of the first byte determine the length of the compressed integer:

| First bits  | Length (in bytes) | Valuation |
| :---: | :---: | ---: |
|00 | 1 | 0 - 63 |
|01 | 2 | 64 - 16,447 |
|10 | 3 | 16,448 - 4,210,751 |
|11 | 4 | 4,210,752 - 1,077,952,575 |

## Contributing

Feel free to submit a pull request with new features, improvements on tests or documentation and bug fixes.

## Contact

Frank Schwab ([Mail](mailto:frank.schwab@deutschebahn.com "Mail"))

## License

TUPW is released under the Apache license, V2.0. See "LICENSE" for details.
