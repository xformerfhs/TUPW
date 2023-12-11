/*
 * SPDX-FileCopyrightText: 2020-2023 DB Systel GmbH
 * SPDX-FileCopyrightText: 2023 Frank Schwab
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Author: Frank Schwab
 *
 * Changes:
 *     2020-03-04: V1.0.0: Created. fhs
 *     2020-03-19: V1.1.0: Consolidated crypto parameter exceptions. fhs
 *     2020-03-23: V1.2.0: Restructured source code according to DBS programming guidelines. fhs
 *     2020-12-04: V1.2.1: Corrected several SonarLint findings. fhs
 *     2020-12-29: V1.3.0: Made thread safe. fhs
 *     2021-08-30: V2.0.0: Removed deprecated "DecryptData" methods. fhs
 *     2023-12-11: V2.0.1: Standard naming convention for instance variables. fhs
 */
package de.db.bcm.tupw.crypto;

import de.db.bcm.tupw.arrays.ArrayHelper;

import java.io.IOException;
import java.nio.charset.CharacterCodingException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

/**
 * Implement encryption by key generated from a file and a key
 *
 * <p>This class is just a wrapper for the more general "SplitKeyEncryption" class
 * for the special case of a file as the source for the key input.</p>
 *
 * @author Frank Schwab
 * @version 2.0.1
 */

public class FileAndKeyEncryption implements AutoCloseable {
   //******************************************************************
   // Instance variables
   //******************************************************************

   private final SplitKeyEncryption splitKeyEncryption;


   //******************************************************************
   // Constructor
   //******************************************************************

   /**
    * Constructor for this instance
    *
    * @param hmacKey     Key for the HMAC of the file
    * @param keyFilePath Key file path
    * @throws IllegalArgumentException The HMAC key or the size of the key file are not valid
    * @throws InvalidKeyException      if the key is invalid (must never happen)
    * @throws IOException              if there was an error while reading the key file
    * @throws NoSuchAlgorithmException if the encryption algorithm is invalid (must never happen)
    * @throws NullPointerException     if {@code hmacKey} or {@code keyFilePath} is {@code null}
    */
   public FileAndKeyEncryption(final byte[] hmacKey, final String keyFilePath)
         throws InvalidKeyException,
            IOException,
            NoSuchAlgorithmException {
      Objects.requireNonNull(hmacKey, "HMAC key is null");
      Objects.requireNonNull(keyFilePath, "Key file path is null");

      Path keyFile;

      try {
         keyFile = Paths.get(keyFilePath);
      } catch (Exception e) {
         throw new IllegalArgumentException("Key file path is invalid: " + e.getMessage());
      }

      final byte[] keyFileBytes = getContentOfFile(keyFile);

      try {
         splitKeyEncryption = new SplitKeyEncryption(hmacKey, keyFileBytes);
      } finally {
         ArrayHelper.clear(keyFileBytes);
      }
   }


   //******************************************************************
   // Public methods
   //******************************************************************

   /*
    * Encryption interfaces
    */

   /**
    * Encrypt a byte array under a subject
    *
    * @param byteArrayToEncrypt Byte array to encrypt
    * @param subject            The subject of this encryption
    * @return Printable form of the encrypted string
    * @throws InvalidCryptoParameterException    if a parameter of a cryptographic method is invalid (must never happen)
    * @throws NullPointerException               if {@code stringToEncrypt} or {@code subject} is {@code null}
    */
   public synchronized String encryptData(final byte[] byteArrayToEncrypt, final String subject)
         throws InvalidCryptoParameterException {
      return splitKeyEncryption.encryptData(byteArrayToEncrypt, subject);
   }

   /**
    * Encrypt a byte array
    *
    * @param byteArrayToEncrypt Byte array to encrypt
    * @return Printable form of the encrypted string
    * @throws InvalidCryptoParameterException    if a parameter of a cryptographic method is invalid (must never happen)
    * @throws NullPointerException               if {@code stringToEncrypt} or {@code subject} is {@code null}
    */
   public synchronized String encryptData(final byte[] byteArrayToEncrypt)
         throws InvalidCryptoParameterException {
      return splitKeyEncryption.encryptData(byteArrayToEncrypt);
   }

   /**
    * Encrypt a character array under a subject
    *
    * @param characterArrayToEncrypt Character array to encrypt
    * @param subject                 The subject of this encryption
    * @return Printable form of the encrypted string
    * @throws InvalidCryptoParameterException    if a parameter of a cryptographic method is invalid (must never happen)
    * @throws NullPointerException               if {@code stringToEncrypt} or {@code subject} is {@code null}
    */
   public synchronized String encryptData(final char[] characterArrayToEncrypt, final String subject)
         throws InvalidCryptoParameterException {
      return splitKeyEncryption.encryptData(characterArrayToEncrypt, subject);
   }

   /**
    * Encrypt a character array
    *
    * @param characterArrayToEncrypt Character array to encrypt
    * @return Printable form of the encrypted string
    * @throws InvalidCryptoParameterException    if a parameter of a cryptographic method is invalid (must never happen)
    * @throws NullPointerException               if {@code stringToEncrypt} or {@code subject} is {@code null}
    */
   public synchronized String encryptData(final char[] characterArrayToEncrypt)
         throws InvalidCryptoParameterException {
      return splitKeyEncryption.encryptData(characterArrayToEncrypt);
   }

   /**
    * Encrypt a string under a subject
    *
    * @param stringToEncrypt String to encrypt
    * @param subject         The subject of this encryption
    * @return Printable form of the encrypted string
    * @throws InvalidCryptoParameterException    if a parameter of a cryptographic method is invalid (must never happen)
    * @throws NullPointerException               if {@code stringToEncrypt} or {@code subject} is {@code null}
    */
   public synchronized String encryptData(final String stringToEncrypt, final String subject)
         throws InvalidCryptoParameterException {
      return splitKeyEncryption.encryptData(stringToEncrypt, subject);
   }

   /**
    * Encrypt a string
    *
    * @param stringToEncrypt String to encrypt
    * @return Printable form of the encrypted string
    * @throws InvalidCryptoParameterException    if a parameter of a cryptographic method is invalid (must never happen)
    * @throws NullPointerException               if {@code stringToEncrypt}is {@code null}
    */
   public synchronized String encryptData(final String stringToEncrypt)
         throws InvalidCryptoParameterException {
      return encryptData(stringToEncrypt, "");
   }

   /*
    * Decryption interfaces
    */

   /**
    * Decrypt an encrypted string under a subject as a byte array
    *
    * @param stringToDecrypt String to decrypt
    * @param subject         The subject of this decryption
    * @return Decrypted string as a byte array
    * @throws DataIntegrityException             if the checksum does not match the data
    * @throws IllegalArgumentException           if the given string does not adhere to the format specification
    * @throws InvalidCryptoParameterException    if a parameter of a cryptographic method is invalid (must never happen)
    * @throws NullPointerException               if {@code stringToDecrypt} or {@code subject} is {@code null}
    */
   public synchronized byte[] decryptDataAsByteArray(final String stringToDecrypt, final String subject)
         throws DataIntegrityException,
            InvalidCryptoParameterException {
      return splitKeyEncryption.decryptDataAsByteArray(stringToDecrypt, subject);
   }

   /**
    * Decrypt an encrypted string under a subject as a byte array
    *
    * @param stringToDecrypt String to decrypt
    * @return Decrypted string as a byte array
    * @throws DataIntegrityException             if the checksum does not match the data
    * @throws IllegalArgumentException           if the given string does not adhere to the format specification
    * @throws InvalidCryptoParameterException    if a parameter of a cryptographic method is invalid (must never happen)
    * @throws NullPointerException               if {@code stringToDecrypt} or {@code subject} is {@code null}
    */
   public synchronized byte[] decryptDataAsByteArray(final String stringToDecrypt)
         throws DataIntegrityException,
            InvalidCryptoParameterException {
      return splitKeyEncryption.decryptDataAsByteArray(stringToDecrypt);
   }

   /**
    * Decrypt an encrypted string under a subject as a character array
    *
    * @param stringToDecrypt String to decrypt
    * @param subject         The subject of this decryption
    * @return Decrypted string as a character array
    * @throws CharacterCodingException           if the data contain a byte sequence that can not be interpreted as a valid UTF-8 byte sequence
    * @throws DataIntegrityException             if the checksum does not match the data
    * @throws IllegalArgumentException           if the given string does not adhere to the format specification
    * @throws InvalidCryptoParameterException    if a parameter of a cryptographic method is invalid (must never happen)
    * @throws NullPointerException               if {@code stringToDecrypt} or {@code subject} is {@code null}
    */
   public synchronized char[] decryptDataAsCharacterArray(final String stringToDecrypt, final String subject)
         throws CharacterCodingException,
            DataIntegrityException,
            InvalidCryptoParameterException {
      return splitKeyEncryption.decryptDataAsCharacterArray(stringToDecrypt, subject);
   }

   /**
    * Decrypt an encrypted string as a character array
    *
    * @param stringToDecrypt String to decrypt
    * @return Decrypted string as a character array
    * @throws CharacterCodingException           if the data contain a byte sequence that can not be interpreted as a valid UTF-8 byte sequence
    * @throws DataIntegrityException             if the checksum does not match the data
    * @throws IllegalArgumentException           if the given string does not adhere to the format specification
    * @throws InvalidCryptoParameterException    if a parameter of a cryptographic method is invalid (must never happen)
    * @throws NullPointerException               if {@code stringToDecrypt} or {@code subject} is {@code null}
    */
   public synchronized char[] decryptDataAsCharacterArray(final String stringToDecrypt)
         throws CharacterCodingException,
            DataIntegrityException,
            InvalidCryptoParameterException {
      return splitKeyEncryption.decryptDataAsCharacterArray(stringToDecrypt);
   }

   /**
    * Decrypt an encrypted string under a subject as a string
    *
    * @param stringToDecrypt String to decrypt
    * @param subject         The subject of this decryption
    * @return Decrypted string
    * @throws CharacterCodingException           if the data contain a byte sequence that can not be interpreted as a valid UTF-8 byte sequence
    * @throws DataIntegrityException             if the checksum does not match the data
    * @throws IllegalArgumentException           if the given string does not adhere to the format specification
    * @throws InvalidCryptoParameterException    if a parameter of a cryptographic method is invalid (must never happen)
    * @throws NullPointerException               if {@code stringToDecrypt} or {@code subject} is {@code null}
    */
   public synchronized String decryptDataAsString(final String stringToDecrypt, final String subject)
         throws CharacterCodingException,
            DataIntegrityException,
            InvalidCryptoParameterException {
      return splitKeyEncryption.decryptDataAsString(stringToDecrypt, subject);
   }

   /**
    * Decrypt an encrypted string as a string
    *
    * @param stringToDecrypt String to decrypt
    * @return Decrypted string
    * @throws CharacterCodingException           if the data contain a byte sequence that can not be interpreted as a valid UTF-8 byte sequence
    * @throws DataIntegrityException             if the checksum does not match the data
    * @throws IllegalArgumentException           if the given string does not adhere to the format specification
    * @throws InvalidCryptoParameterException    if a parameter of a cryptographic method is invalid (must never happen)
    * @throws NullPointerException               if {@code stringToDecrypt}is {@code null}
    */
   public synchronized String decryptDataAsString(final String stringToDecrypt)
         throws CharacterCodingException,
            DataIntegrityException,
            InvalidCryptoParameterException {
      return splitKeyEncryption.decryptDataAsString(stringToDecrypt);
   }

   /*
    * Method for AutoCloseable interface
    */

   /**
    * Secure deletion of keys
    *
    * <p>This method is idempotent and never throws an exception.</p>
    */
   @Override
   public synchronized void close() {
      this.splitKeyEncryption.close();
   }


   //******************************************************************
   // Private methods
   //******************************************************************

   /**
    * Get the content of the key file
    *
    * @param keyFile Key file to be used
    * @throws IllegalArgumentException if key file does not exist
    * @throws IOException              if there is an error reading the key file
    */
   private byte[] getContentOfFile(final Path keyFile)
         throws IOException {
      final byte[] result;

      if (Files.exists(keyFile))
         result = Files.readAllBytes(keyFile);
      else
         throw new IllegalArgumentException("File '" + keyFile.toAbsolutePath() + "' does not exist");

      return result;
   }
}
