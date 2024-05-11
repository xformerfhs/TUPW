# Programming Interface

This repository contains a library and a command line program (`TUPW.java`) as an example.
The command line program is **not** part of the library.

In this document the programming interface is described.
The complete programming interface is described in the files in the `javadoc` directory.
This file gives a simplified description.

## Introduction

There are two interfaces:

- Class `SplitKeyEncrytion`
- Class `FileAndKeyEncryption`

Both of them are located in the `crypto` directory.

The main interface is the `SplitKeyEncryption` class.
As its name suggests it works with split keys.
The class `FileAndKeyEncryption` is a wrapper around the `SplitKeyEncryption` class when one wants to work with files.
If one writes a new program against this library `SplitKeyEncryption` should be used.

### SplitKeyEncryption

One starts with an instance of `SplitKeyEncryption`.
This instance needs to be created only once.
There is no need create an instance more than one time.

#### Constructor

`SplitKeyEncryption` has one constructor:

```java
public SplitKeyEncryption(final byte[] hmacKey, final byte[]... sourceBytes) throws InvalidKeyException, NoSuchAlgorithmException
```

The parameters have the following meanings:

| Parameter     | Meaning                                                                                                         |
|---------------|-----------------------------------------------------------------------------------------------------------------|
| `hmacKey`     | A byte array with a key for calculating the encryption key. This key can have a length between 14 and 32 bytes. |
| `sourceBytes` | One or more byte arrays containing data from which the key is calculated.                                       | 

After the instance has been created a key has been calculated from the `sourceBytes` data that is stored in the `SplitKeyEncryption` instance in a secure way.
The key is not visible in a memory dump.
It is used in the methods of the instance to encrypt and decrypt data.
The key itself is not given as a parameter, only the parts from which it is calculated.

#### Interface

The `SplitKeyEncryption` class implements the [`AutoClosable`](https://docs.oracle.com/en%2Fjava%2Fjavase%2F21%2Fdocs%2Fapi%2F%2F/java.base/java/lang/AutoCloseable.html) interface.
This enables it to be used in a [try-with-resources](https://docs.oracle.com/javase/tutorial/essential/exceptions/tryResourceClose.html) statement like so:

```java
   try (SplitKeyEncryption myDecryptor = new SplitKeyEncryption(HMAC_KEY, source1, source2, source3, source4)){
      // ...
      final char[] secret = myDecryptor.decryptDataAsCharacterArray(encryptedSecret, subject);
      // Use the secret
      // ...
      // When finished, clear the secret
      Arrays.fill(secret, '\0');
   }
```

When the code in the `try` statement has finished the `SplitKeyEncryption` instance is automatically closed, even if an exception occurred anywhere in the processing.

#### Methods

An instance of `SplitKeyEncryption` is divided among the following dimensions:

- Encryption, decryption
- Data type: Byte array, character array, strings
- Using a subject or not

A "subject" is an optional parameter.
It is a string that is used as a so-called "domain separator".
Its purpose is to generate different encryption keys for different usages.
One could use the same instance of `SplitKeyEncryption` for different purposes, like e.g. different tables in a database.
In this example the "subject" would be the table name.
It could be any other meaningful separation.
And, of course, it may be not specified, at all.

##### Encryption

There are encryption methods for each data type and with and without a subject which makes 3*2=6 of them:

```java
public String encryptData(final byte[] byteArrayToEncrypt) throws InvalidCryptoParameterException;
public String encryptData(final byte[] byteArrayToEncrypt, final String subject) throws InvalidCryptoParameterException;
public String encryptData(final char[] characterArrayToEncrypt) throws InvalidCryptoParameterException;
public String encryptData(final char[] characterArrayToEncrypt, final String subject) throws InvalidCryptoParameterException;
public String encryptData(final String stringToEncrypt) throws InvalidCryptoParameterExceptionpublic synchronized String encryptData(final String stringToEncrypt, final String subject) throws InvalidCryptoParameterException;
public String encryptData(final String stringToEncrypt, final String subject) throws InvalidCryptoParameterException;
```

It is strongly advised to use the byte array or character array methods.
Strings are immutable in Java and secrets stored in them can not be cleared, so they will be visible in a memory dump.

##### Decryption

As with encryption, there are also 3*2=6 decryption methods.
Their respective names say what type of data they return.

```java
public byte[] decryptDataAsByteArray(final String stringToDecrypt) throws DataIntegrityException, InvalidCryptoParameterException;
public byte[] decryptDataAsByteArray(final String stringToDecrypt, final String subject) throws DataIntegrityException, InvalidCryptoParameterException;
public char[] decryptDataAsCharacterArray(final String stringToDecrypt) throws CharacterCodingException, DataIntegrityException, InvalidCryptoParameterException;
public char[] decryptDataAsCharacterArray(final String stringToDecrypt, final String subject) throws CharacterCodingException, DataIntegrityException, InvalidCryptoParameterException;
public String decryptDataAsString(final String stringToDecrypt) throws CharacterCodingException, DataIntegrityException, InvalidCryptoParameterException;
public String decryptDataAsString(final String stringToDecrypt, final String subject) throws CharacterCodingException, DataIntegrityException, InvalidCryptoParameterException;
```

The decryption methods need to be used with a `SplitKeyEncryption` instance that has **exactly** the same parameters as the encrypting `SplitKeyEncryption` instance.

Once again, it is advisable to use the byte or character array methods, as their secrets can be cleared after use.

##### Close

The `SplitKeyEncryption` class has one more method:

```java
public void close()
```

When the `close` method is called, the calculated key is cleared and the instance can no longer be used.
This way the key is removed from memory.
The method should always be called when the instance is no longer needed.
It is automatically called in a [try-with-resources](https://docs.oracle.com/javase/tutorial/essential/exceptions/tryResourceClose.html).

#### Exceptions

There are two custom exceptions thrown by the methods:

| Exception                         | Meaning                                                                                                  |
|-----------------------------------|----------------------------------------------------------------------------------------------------------|
| `DataIntegrityException`          | Thrown when one of the decryption methods is called and the data has been tampered with.                 |
| `InvalidCryptoParameterException` | A wrapper exception for the myriad of exceptions thrown when using crypto methods. It must never happen. |                                                                                        

A `DataIntegrityException` means that the secret was **not** decrypted and can not be used.

When an `InvalidCryptoParameterException` is thrown something is seriously wrong with Java's crypto methods.

### FileAndKeyEncryption

`FileAndKeyEncryption` is a wrapper around `SplitKeyEncryption`.
This instance needs to be created only once.
There is no need create an instance more than one time.

#### Constructor

`FileAndKeyEncryption` has one constructor:

```java
public FileAndKeyEncryption(final byte[] hmacKey, final String keyFilePath) throws InvalidKeyException, IOException, NoSuchAlgorithmException
```

The parameters have the following meanings:

| Parameter     | Meaning                                                                                                         |
|---------------|-----------------------------------------------------------------------------------------------------------------|
| `hmacKey`     | A byte array with a key for calculating the encryption key. This key can have a length between 14 and 32 bytes. |
| `keyFilePath` | The path to a file that is to be used as the source of bytes for the key calculation.                           | 

The only difference is that there is only one "source".
This constructor reads the data of the file as bytes and uses them as the one source for creating an instance of `SplitKeyEncryption`.

So, in effect, calling the above constructor

```java
final FileAndKeyEncryption myEncryptor = FileAndKeyEncryption(HMAC_KEY, keyFilePath);
```

is equivalent to

```java
final SplitKeyEncryption myEncryptor = SplitKeyEncryption(HMAC_KEY, contentOfFile(keyFilePath));
```

So, this instance has exactly the same methods and interfaces as a `SplitKeyEncryption` instance.

> [!IMPORTANT]
> This is a convenience class for older programs written against this library and should **not** be used in new programs.

# Example

In this chapter there is presented an example.
Only the parts that are necessary for using this library are shown.
So this is not a full-fledged application.

In the following these sources for the key derivation are assumed:

- An environment variable with the name `UI_COLOR` that contains some arbitrary string.
- A file with the name `logo_hi_res.png` that contains the image of a logo.
- The first input parameter from the call with some arbitrary data.

For the sake of the example there is also a variable called `tenant` that contains the name of the tenant the secrets are to be encrypted for.

First one would need a generator application that generates the tokens from the secrets.
This generator needs access to all the above sources.
It can be a command line program, have an UI or be some web service.
Whatever.

The generator would then need some code[^1] like the following:

[^1]: `Xoroshiro128plusplus` is a deterministic pseudo-random number generator that is present in the `numbers` package of this library.

```java
   {
      // 1. Create the HMAC key.
      //    Here a deterministic calculation is used to generate the key.
      final byte hmacKey = createHMACKey();

      // 2. Get sources.
      final byte[] uiColorBytes = System.getenv("UI_COLOR").getBytes(StandardCharsets.UTF_8);
      final byte[] logoBytes = Files.readAllBytes(Paths.get("logo_hi_res.png"));
      final byte[] parameterBytes = args[1].getBytes(StandardCharsets.UTF_8);

      // 3. Encrypt the secrets
      try{
         final SplitKeyEncryption encryptor = SplitKeyEncryption(hmacKey, uiColorBytes, logoBytes, parameterBytes);
         
         // Loop through the secrets wherever they come from
         for (secret: getSecrets()) {
            String tokenFromSecret = encryptor.encryptData(secret, tenant);
            // Now put out the token
         }
      }
   }
   
   private static byte[] createHMACKey() {
      final byte[] result = new byte[32];
      // TODO: Do not use this seed constant. Roll your own!!!!
      final Xoroshiro128plusplus xs128 = new Xoroshiro128plusplus(0x2BBE622F57254860L);

      for (int i = 0; i < result.length; i++)
         result[i] = xs128.nextByte();

      return result;
   }
```

This way one gets the encrypted tokens.

When using the tokens in the application that needs the secrets one would use the library like this:

```java
   {
      // The first two parts are *exactly* the same as with encryption!

      // 1. Create the HMAC key.
      //    Here a deterministic calculation is used to generate the key.
      final byte hmacKey = createHMACKey();

      // 2. Get sources.
      final byte[] uiColorBytes = System.getenv("UI_COLOR").getBytes(StandardCharsets.UTF_8);
      final byte[] logoBytes = Files.readAllBytes(Paths.get("logo_hi_res.png"));
      final byte[] parameterBytes = args[1].getBytes(StandardCharsets.UTF_8);

      // 3. Decrypt the tokens
      try{
         final SplitKeyEncryption decryptor = SplitKeyEncryption(hmacKey, uiColorBytes, logoBytes, parameterBytes);
         
         // Loop through the secrets wherever they come from
         String encryptedToken = getEncryptedToken();
         char[] secret = decryptor.decryptDataAsByteArray(encryptedToken, tenant);
         // Use the secret wherever it is needed

         // ...
      
         // Clear the secret when it is no longer needed 
         Arrays.fill(secret, '\0');
      }
   }
   
   private static byte[] createHMACKey() {
      final byte[] result = new byte[32];
      // TODO: Do not use this seed constant. Roll your own!!!!
      final Xoroshiro128plusplus xs128 = new Xoroshiro128plusplus(0x2BBE622F57254860L);

      for (int i = 0; i < result.length; i++)
         result[i] = xs128.nextByte();

      return result;
   }
```
