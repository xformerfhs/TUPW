/*
 * SPDX-FileCopyrightText: 2017-2023 DB Systel GmbH
 * SPDX-FileCopyrightText: 2023-2025 Frank Schwab
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
 *     2017-12-19: V1.0.0: Created. fhs
 *     2017-12-21: V1.0.1: Corrected comments, added safe data deletion in decryption interface. fhs
 *     2017-12-21: V1.1.0: Correct AByt padding to use cipher block size. fhs
 *     2018-05-17: V1.2.0: Use CTR mode instead of CFB. fhs
 *     2018-05-24: V1.2.1: Put encryption specifications in an array for easier handling. fhs
 *     2018-05-25: V1.2.2: A few changes to enhance readability. fhs
 *     2018-06-13: V1.3.0: Use constant time array comparison on HMAC check to thwart
 *                          timing attacks. fhs
 *     2018-06-22: V1.3.1: Use a StringBuilder with sufficient initial capacity. fhs
 *     2018-06-22: V1.3.2: Use dynamic StringBuilder capacity calculation. fhs
 *     2018-06-22: V1.3.3: Rethrow exception if hashing went wrong. fhs
 *     2018-08-07: V1.3.4: Some small improvements. fhs
 *     2018-08-15: V1.3.5: Added some "finals". fhs
 *     2018-08-16: V1.3.6: Moved secure PRNG generation to the one method that needs it. fhs
 *     2018-08-17: V1.4.0: Use blinding and random padding, made PRNG module visible again. fhs
 *     2019-03-07: V2.0.0: Add a "subject" that changes the encryption key. fhs
 *     2019-08-01: V2.1.0: Use CBC mode, as the encrypted part is protected by a HMAC and CBC does
 *                         not suffer from the stream cipher vulnerabilities of CFB and CTR mode.
 *                         Use Base64 encoding without padding. fhs
 *     2019-08-02: V2.1.1: New data integrity exception text. fhs
 *     2019-08-02: V2.2.0: Use strong SPRNG. fhs
 *     2019-08-03: V2.2.1: Refactored SPRNG instantiation. fhs
 *     2019-08-05: V2.2.2: Change method name of SPRNG instantiation. fhs
 *     2019-08-23: V2.2.3: Use SecureRandom singleton. fhs
 *     2020-02-12: V2.3.0: Correct wrong generation of keys with the "subject" parameter. fhs
 *     2020-02-19: V2.3.1: Some more zapping of intermediate key byte arrays. fhs
 *     2020-02-24: V3.0.0: Use any provided bytes as the sources for key derivation, not just
 *                         the contents of a file. fhs
 *     2020-02-27: V3.0.1: Added maximum HMAC key length. fhs
 *     2020-02-27: V3.1.0: Some hardening against null pointers. fhs
 *     2020-02-28: V3.2.0: Check entropy of provided source bytes. fhs
 *     2020-02-28: V3.2.1: Throw IllegalArgumentException when key file does not exist. fhs
 *     2020-02-28: V4.0.0: Rename class to "SplitKeyEncryption". fhs
 *     2020-03-09: V4.0.1: Add check for zero source byte length. fhs
 *     2020-03-13: V4.1.0: Use NUllPointerException instead of IllegalArgumentException for null pointers. fhs
 *     2020-03-19: V4.2.0: Consolidated crypto parameter exceptions. fhs
 *     2020-03-20: V4.3.0: Use a nested exception, instead of a suppressed exception. fhs
 *     2020-03-23: V4.4.0: Restructured source code according to DBS programming guidelines. fhs
 *     2020-03-26: V5.0.0: Provide interfaces for strings, character arrays and byte arrays. fhs
 *     2020-03-31: V5.0.1: Added some finals. fhs
 *     2020-04-22: V5.1.0: Corrected number range bug in class 'PackedUnsignedInteger'. fhs
 *     2020-05-14: V5.1.1: Removed unnecessary byte counting when checking source bytes. fhs
 *     2020-11-13: V5.3.0: Implemented V6 of the encoded format. fhs
 *     2020-12-04: V5.3.1: Corrected several SonarLint findings. fhs
 *     2020-12-29: V5.4.0: Made thread safe. fhs
 *     2020-12-30: V5.4.1: Removed synchronization where it was not necessary. fhs
 *     2021-01-04: V5.4.2: Corrected wrong method and variable names. fhs
 *     2021-05-17: V5.4.3: New version because Base32Encoding had a small change. fhs
 *     2021-05-28: V5.5.0: New version because of refactored ProtectedByteArray. fhs
 *     2021-08-30: V6.0.0: Some refactoring, removed deprecated "DecryptData" methods. fhs
 *     2021-08-30: V6.1.0: Ensure deletion of sensitive data. fhs
 *     2021-08-30: V6.1.1: Some refactoring. fhs
 *     2021-09-03: V6.1.2: Some refactoring in tests. fhs
 *     2021-09-23: V6.1.3: Ensure "equals" always clears sensitive data in SecureSecretKeySpec. fhs
 *     2021-10-18: V6.1.4: Corrected entropy threshold constant. fhs
 *     2023-03-29: V6.1.5: Corrected some typos. fhs
 *     2023-12-11: V6.1.6: Standard naming convention for instance variables. fhs
 *     2024-05-10: V6.1.7: Better documentation. fhs
 *     2024-05-12: V6.1.8: Simplified implementation of compressed integers. fhs
 *     2024-05-12: V7.0.0: Removed methods to encrypt and decrypt strings. fhs
 */
package de.db.bcm.tupw.crypto;

import de.db.bcm.tupw.arrays.ArrayHelper;
import de.db.bcm.tupw.arrays.Base32Encoding;
import de.db.bcm.tupw.statistics.EntropyCalculator;
import de.db.bcm.tupw.strings.CharacterArrayHelper;
import de.db.bcm.tupw.strings.StringSplitter;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

/**
 * Implement encryption by a key generated from several source bytes and a key creation key
 *
 * @author Frank Schwab
 * @version 7.0.0
 */

public class SplitKeyEncryption implements AutoCloseable {
   //******************************************************************
   // Private constants
   //******************************************************************

   /*
    * Constant for error messages
    */
   private static final String NULL_SUBJECT_ERROR_MESSAGE = "Subject is null";

   /*
    * Constant for empty data
    */
   private static final String NO_SUBJECT = "";

   /*
    * Boundaries for valid format ids.
    */
   private static final byte FORMAT_ID_MIN = (byte) 1;
   private static final byte FORMAT_ID_MAX = (byte) 6;

   private static final byte FORMAT_ID_USE_BLINDING = (byte) 3;
   private static final byte FORMAT_ID_USE_CORRECT_HMAC_KEY = (byte) 5;
   private static final byte FORMAT_ID_USE_SAFE_ENCODING = (byte) 6;

   /**
    * HMAC algorithm to be used
    */
   private static final String HMAC_256_ALGORITHM_NAME = "HmacSHA256";

   /**
    * Minimum length of key for HMAC algorithm
    */
   private static final int MIN_HMAC_KEY_LENGTH = 14;

   /**
    * Maximum length of key for HMAC algorithm
    *
    * <p>The HMAC key must not be larger than the block size of the underlying hash algorithm.
    * Here this is 32 bytes (256 bits). If the hash block size changes this constant
    * must be changed, as well.</p>
    */
   private static final int MAX_HMAC_KEY_LENGTH = 32;

   /**
    * Encryption algorithm
    */
   private static final String AES_ALGORITHM_NAME = "AES";

   private static final String CBC_NO_PADDING = "/CBC/NoPadding";

   /**
    * Encryption specifications with algorithm, mode and padding
    *
    * <p>The index of the string in the array corresponds to the format id.</p>
    */
   private static final String[] ENCRYPTION_SPECIFICATION = {"Invalid",
         AES_ALGORITHM_NAME + "/CFB/NoPadding",
         AES_ALGORITHM_NAME + "/CTR/NoPadding",
         AES_ALGORITHM_NAME + "/CTR/NoPadding",
         AES_ALGORITHM_NAME + CBC_NO_PADDING,
         AES_ALGORITHM_NAME + CBC_NO_PADDING,
         AES_ALGORITHM_NAME + CBC_NO_PADDING};

   /**
    * Character encoding to be used for encrypted data strings
    */
   private static final Charset CHARACTER_ENCODING_FOR_DATA = StandardCharsets.UTF_8;

   /**
    * Separator character in key representation
    */
   private static final String OLD_PARTS_SEPARATOR = "$";
   private static final String SAFE_PARTS_SEPARATOR = "1";

   /**
    * Minimum source bytes length
    */
   private static final int MIN_SOURCE_BYTES_LENGTH = 100;

   /**
    * Maximum source bytes length
    */
   private static final int MAX_SOURCE_BYTES_LENGTH = 10_000_000;

   /**
    * Minimum source bytes information in bits
    */
   private static final int MIN_SOURCE_BITS = 128;

   /**
    * Threshold below which the source bytes are considered to have not enough variations
    */
   private static final double ENTROPY_THRESHOLD = 0.0001220703125; // I.e. 1/2^13 which is representable as a simple floating point no.

   /**
    * Prefix salt for key modification with a "subject"
    */
   private static final byte[] PREFIX_SALT = {(byte) 84, (byte) 117}; // i.e "Tu"

   /**
    * Suffix salt for key modification with a "subject"
    */
   private static final byte[] SUFFIX_SALT = {(byte) 112, (byte) 87}; // i.e. "pW"

   //******************************************************************
   // Instance variables
   //******************************************************************

   /**
    * Instance of HMAC calculator
    *
    * <p>This is placed here so the expensive instantiation of the Mac class is
    * done only once.</p>
    * <p>Unfortunately it can not be made final as the constructor of this class
    * may throw an exception.</p>
    */
   private Mac hmac;

   /**
    * Instance of SecureRandom pseudo random number generator (PRNG)
    *
    * <p>This is placed here so the expensive instantiation of the SecureRandom class is
    * done only once.</p>
    */
   private SecureRandom secureRandom;


   //******************************************************************
   // Private classes
   //******************************************************************

   /**
    * Helper class to store encryption parameters
    *
    * <p>Because this needs to implement {@code AutoCloseable} it is not possible to use a record.</p>
    */
   private class EncryptionParts implements AutoCloseable {
      public byte formatId;
      public byte[] iv;
      public byte[] encryptedData;
      public byte[] checksum;

      @Override
      public void close() {
         formatId = (byte) 0;

         if (iv != null) {
            ArrayHelper.clear(iv);
            iv = null;
         }

         if (encryptedData != null) {
            ArrayHelper.clear(encryptedData);
            encryptedData = null;
         }

         if (checksum != null) {
            ArrayHelper.clear(checksum);
            checksum = null;
         }
      }
   }


   //******************************************************************
   // Instance variables
   //******************************************************************

   /** Protected encryption key */
   private ProtectedByteArray encryptionKey;

   /** Protected HMAC key */
   private ProtectedByteArray hmacKey;


   //******************************************************************
   // Constructor
   //******************************************************************

   /**
    * Constructor for this instance
    *
    * <p><b>Attention:</b> The caller is responsible for clearing the source byte arrays
    * with {@code Arrays.fill()} after they have been used here.</p>
    *
    * @param hmacKey     Key for the HMAC of the source bytes
    * @param sourceBytes Bytes that the key is derived from
    * @throws IllegalArgumentException Thrown, if the HMAC key or the source bytes are not valid
    * @throws InvalidKeyException      Thrown, if the key is invalid (must never happen)
    * @throws NoSuchAlgorithmException Thrown, if the encryption algorithm is invalid (must never happen)
    * @throws NullPointerException     Thrown, if {@code hmacKey} or any source byte array is {@code null}
    */
   public SplitKeyEncryption(final byte[] hmacKey, final byte[]... sourceBytes) throws
         InvalidKeyException,
         NoSuchAlgorithmException {
      checkHMACKey(hmacKey);

      checkSourceBytes(sourceBytes);

      setKeysFromKeyAndSourceBytes(hmacKey, sourceBytes);
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
    * @throws InvalidCryptoParameterException Thrown, if a parameter of a cryptographic method is invalid (must never happen)
    * @throws NullPointerException            Thrown, if {@code byteArrayToEncrypt} or {@code subject} is {@code null}
    */
   public synchronized String encryptData(final byte[] byteArrayToEncrypt, final String subject)
         throws InvalidCryptoParameterException {
      Objects.requireNonNull(byteArrayToEncrypt, "Byte array to encrypt is null");
      Objects.requireNonNull(subject, NULL_SUBJECT_ERROR_MESSAGE);

      return makeEncryptionStringFromSourceBytes(byteArrayToEncrypt, subject);
   }

   /**
    * Encrypt a byte array
    *
    * @param byteArrayToEncrypt Byte array to encrypt
    * @return Printable form of the encrypted string
    * @throws InvalidCryptoParameterException Thrown, if a parameter of a cryptographic method is invalid (must never happen)
    * @throws NullPointerException            Thrown, if {@code byteArrayToEncrypt} is {@code null}
    */
   public String encryptData(final byte[] byteArrayToEncrypt)
         throws InvalidCryptoParameterException {
      return encryptData(byteArrayToEncrypt, NO_SUBJECT);
   }

   /**
    * Encrypt a character array under a subject
    *
    * @param characterArrayToEncrypt Char array to encrypt
    * @param subject                 The subject of this encryption
    * @return Printable form of the encrypted string
    * @throws InvalidCryptoParameterException Thrown, if a parameter of a cryptographic method is invalid (must never happen)
    * @throws NullPointerException            Thrown, if {@code characterArrayToEncrypt} or {@code subject} is {@code null}
    */
   public synchronized String encryptData(final char[] characterArrayToEncrypt, final String subject)
         throws InvalidCryptoParameterException {
      Objects.requireNonNull(characterArrayToEncrypt, "Character array to encrypt is null");
      Objects.requireNonNull(subject, NULL_SUBJECT_ERROR_MESSAGE);

      String result;

      byte[] byteArrayToEncrypt = null;

      try {
         byteArrayToEncrypt = CharacterArrayHelper.convertCharacterArrayToUTF8ByteArray(characterArrayToEncrypt);

         result = makeEncryptionStringFromSourceBytes(byteArrayToEncrypt, subject);
      } finally {
         ArrayHelper.safeClear(byteArrayToEncrypt);
      }

      return result;
   }

   /**
    * Encrypt a character array
    *
    * @param characterArrayToEncrypt Char array to encrypt
    * @return Printable form of the encrypted string
    * @throws InvalidCryptoParameterException Thrown, if a parameter of a cryptographic method is invalid (must never happen)
    * @throws NullPointerException            Thrown, if {@code characterArrayToEncrypt} is {@code null}
    */
   public String encryptData(final char[] characterArrayToEncrypt)
         throws InvalidCryptoParameterException {
      return encryptData(characterArrayToEncrypt, NO_SUBJECT);
   }

   /*
    * Decryption interfaces
    */

   /**
    * Decrypt an encrypted string under a subject and return a byte array
    *
    * <p>The contents of a byte array can be cleared after use.</p>
    *
    * @param stringToDecrypt String to decrypt
    * @param subject         The subject of this decryption
    * @return Decrypted string as a byte array
    * @throws DataIntegrityException          Thrown, if the checksum does not match the data
    * @throws IllegalArgumentException        Thrown, if the given string does not adhere to the format specification
    * @throws InvalidCryptoParameterException Thrown, if a parameter of a cryptographic method is invalid (must never happen)
    * @throws NullPointerException            Thrown, if {@code stringToDecrypt} or {@code subject} is {@code null}
    */
   public synchronized byte[] decryptDataAsByteArray(final String stringToDecrypt, final String subject)
         throws DataIntegrityException,
         InvalidCryptoParameterException {
      Objects.requireNonNull(stringToDecrypt, "String to decrypt is null");
      Objects.requireNonNull(subject, NULL_SUBJECT_ERROR_MESSAGE);

      final byte[] subjectBytes = subject.getBytes(CHARACTER_ENCODING_FOR_DATA);

      byte[] result;

      try (EncryptionParts encryptionParts = getPartsFromPrintableString(stringToDecrypt)) {
         checkChecksumForEncryptionParts(encryptionParts, subjectBytes);

         result = rawDataDecryption(encryptionParts, subjectBytes);
      } catch (final BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
         throw new InvalidCryptoParameterException("Invalid cryptographic parameter: " + e, e);
      } finally {
         ArrayHelper.clear(subjectBytes);
      }

      return result;
   }

   /**
    * Decrypt an encrypted string and return a byte array
    *
    * <p>The contents of a byte array can be cleared after use.</p>
    *
    * @param stringToDecrypt String to decrypt
    * @return Decrypted string as a byte array
    * @throws DataIntegrityException          Thrown, if the checksum does not match the data
    * @throws IllegalArgumentException        Thrown, if the given string does not adhere to the format specification
    * @throws InvalidCryptoParameterException Thrown, if a parameter of a cryptographic method is invalid (must never happen)
    * @throws NullPointerException            Thrown, if {@code stringToDecrypt} is {@code null}
    */
   public byte[] decryptDataAsByteArray(final String stringToDecrypt)
         throws DataIntegrityException,
         InvalidCryptoParameterException {
      return decryptDataAsByteArray(stringToDecrypt, NO_SUBJECT);
   }

   /**
    * Decrypt an encrypted string under a subject and return a character array
    *
    * <p>The contents of a character array can be cleared after use.</p>
    *
    * @param stringToDecrypt String to decrypt
    * @param subject         The subject of this decryption
    * @return Decrypted string as a character array
    * @throws CharacterCodingException        Thrown, if the data contain a byte sequence that can not be interpreted as a valid UTF-8 byte sequence
    * @throws DataIntegrityException          Thrown, if the checksum does not match the data
    * @throws IllegalArgumentException        Thrown, if the given string does not adhere to the format specification
    * @throws InvalidCryptoParameterException Thrown, if a parameter of a cryptographic method is invalid (must never happen)
    * @throws NullPointerException            Thrown, if {@code stringToDecrypt} or {@code subject} is {@code null}
    */
   public synchronized char[] decryptDataAsCharacterArray(final String stringToDecrypt, final String subject)
         throws CharacterCodingException,
         DataIntegrityException,
         InvalidCryptoParameterException {
      final byte[] decryptedContent = decryptDataAsByteArray(stringToDecrypt, subject);

      final char[] result;

      try {
         result = CharacterArrayHelper.convertUTF8ByteArrayToCharacterArray(decryptedContent);
      } finally {
         ArrayHelper.clear(decryptedContent);
      }

      return result;
   }

   /**
    * Decrypt an encrypted string and return a character array
    *
    * <p>The contents of a character array can be cleared after use.</p>
    *
    * @param stringToDecrypt String to decrypt
    * @return Decrypted string as a character array
    * @throws CharacterCodingException        Thrown, if the data contain a byte sequence that can not be interpreted as a valid UTF-8 byte sequence
    * @throws DataIntegrityException          Thrown, if the checksum does not match the data
    * @throws IllegalArgumentException        Thrown, if the given string does not adhere to the format specification
    * @throws InvalidCryptoParameterException Thrown, if a parameter of a cryptographic method is invalid (must never happen)
    * @throws NullPointerException            Thrown, if {@code stringToDecrypt} or {@code subject} is {@code null}
    */
   public char[] decryptDataAsCharacterArray(final String stringToDecrypt)
         throws CharacterCodingException,
         DataIntegrityException,
         InvalidCryptoParameterException {
      return decryptDataAsCharacterArray(stringToDecrypt, NO_SUBJECT);
   }

   /**
    * Decrypt an encrypted string under a subject as a string
    *
    * @param stringToDecrypt String to decrypt
    * @param subject         The subject of this decryption
    * @return Decrypted data as a string
    * @throws CharacterCodingException        Thrown, if the data contain a byte sequence that can not be interpreted as a valid UTF-8 byte sequence
    * @throws DataIntegrityException          Thrown, if the checksum does not match the data
    * @throws IllegalArgumentException        Thrown, if the given string does not adhere to the format specification
    * @throws InvalidCryptoParameterException Thrown, if a parameter of a cryptographic method is invalid (must never happen)
    * @throws NullPointerException            Thrown, if {@code stringToDecrypt} or {@code subject} is {@code null}
    */
   public synchronized String decryptDataAsString(final String stringToDecrypt, final String subject)
         throws CharacterCodingException,
         DataIntegrityException,
         InvalidCryptoParameterException {
      // "new String(byteArray)" is *not* used here, as this does not throw a "CharacterCodingException"
      // on a malformed byte array. Instead, the decoded byte array is first converted to a character array
      // (which throws a "CharacterCodingException") and that is converted to a string.
      final char[] decryptedContent = decryptDataAsCharacterArray(stringToDecrypt, subject);

      // No need to use try here, as the only exception can happen in the line above
      final String result = new String(decryptedContent);

      ArrayHelper.clear(decryptedContent);

      return result;
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
      this.encryptionKey.close();
      this.hmacKey.close();
   }


   //******************************************************************
   // Private methods
   //******************************************************************

   /**
    * Get instance of HMAC
    *
    * @return HMAC instance
    * @throws NoSuchAlgorithmException Thrown, if the specified HMAC algorithm is not implemented
    */
   private Mac getHMACInstance()
         throws NoSuchAlgorithmException {
      if (hmac == null)
         hmac = Mac.getInstance(HMAC_256_ALGORITHM_NAME);

      return hmac;
   }

   /**
    * Get instance of SecureRandom
    *
    * @return SecureRandom instance
    */
   private SecureRandom getSecureRandomInstance() {
      if (secureRandom == null)
         secureRandom = SecureRandomFactory.getSensibleSingleton();

      return secureRandom;
   }

   /*
    * Check methods
    */

   /**
    * Check HMAC key size
    *
    * @param aHMACKey Key for HMAC calculation
    * @throws IllegalArgumentException Thrown, if the HMAC key does not have the correct length
    * @throws NullPointerException     Thrown, if {@code hmacKey} is {@code null}
    */
   private void checkHMACKey(final byte[] aHMACKey) {
      Objects.requireNonNull(aHMACKey, "HMAC key is null");

      if (aHMACKey.length < MIN_HMAC_KEY_LENGTH)
         throw new IllegalArgumentException("HMAC key length is less than " + MIN_HMAC_KEY_LENGTH);

      if (aHMACKey.length > MAX_HMAC_KEY_LENGTH)
         throw new IllegalArgumentException("HMAC key length is larger than " + MAX_HMAC_KEY_LENGTH);
   }

   /**
    * Check length of supplied source bytes
    *
    * @param sourceBytes Array of source byte arrays
    * @throws IllegalArgumentException Thrown, if any sourceByte array has 0 length or the source bytes are too few or too many
    *                                  Thrown, or there is no or not enough information in the source bytes
    * @throws NullPointerException     Thrown, if any sourceByte array is {@code null}
    */
   private void checkSourceBytes(final byte[]... sourceBytes) {
      final EntropyCalculator ec = getEntropyCalculatorForSourceBytes(sourceBytes);

      if (ec.getInformationInBits() < MIN_SOURCE_BITS) {
         final double entropy = ec.getEntropy();

         if (entropy > ENTROPY_THRESHOLD)
            throw new IllegalArgumentException("There is not enough information provided in the source bytes. Try to increase the length to at least " + (((int) Math.round(MIN_SOURCE_BITS / entropy)) + 1) + " bytes");
         else
            throw new IllegalArgumentException("There is no information provided in the source bytes (i.e. there are only identical byte values). Use bytes with varying values.");
      }

      if (ec.getCount() < MIN_SOURCE_BYTES_LENGTH)
         throw new IllegalArgumentException("There are less than " + MIN_SOURCE_BYTES_LENGTH + " source bytes");

      if (ec.getCount() > MAX_SOURCE_BYTES_LENGTH)
         throw new IllegalArgumentException("There are more than " + MAX_SOURCE_BYTES_LENGTH + " source bytes");
   }

   /**
    * Feed source bytes into the entropy calculator
    *
    * @param sourceBytes Source bytes to calculate the entropy for
    */
   private EntropyCalculator getEntropyCalculatorForSourceBytes(byte[][] sourceBytes) {
      EntropyCalculator result = new EntropyCalculator();

      for (int i = 0; i < sourceBytes.length; i++) {
         Objects.requireNonNull(sourceBytes[i], (i + 1) + ". source byte array is null");

         if (sourceBytes[i].length > 0) {
            result.addBytes(sourceBytes[i]);
         } else
            throw new IllegalArgumentException((i + 1) + ". source byte array has 0 length");
      }

      return result;
   }

   /**
    * Convert an encrypted text into its parts
    *
    * @param encryptionText Text to be decrypted
    * @return Encryption parameters as <code>EncryptionParts</code> object
    * @throws IllegalArgumentException Thrown, if the encrypted text has an invalid or unknown format id or not the correct
    *                                  number of separated parts
    */
   private EncryptionParts getPartsFromPrintableString(final String encryptionText) {
      final char formatCharacter = encryptionText.charAt(0);

      byte formatId;

      try {
         formatId = Byte.parseByte(String.valueOf(formatCharacter));
      } catch (final NumberFormatException e) {
         throw new IllegalArgumentException("Invalid format id");
      }

      if ((formatId < FORMAT_ID_MIN) || (formatId > FORMAT_ID_MAX))
         throw new IllegalArgumentException("Unknown format id");

      String separator;

      if (formatId >= FORMAT_ID_USE_SAFE_ENCODING)
         separator = SAFE_PARTS_SEPARATOR;
      else
         separator = OLD_PARTS_SEPARATOR;

      final String[] parts = StringSplitter.split(encryptionText, separator);  // Use my own string splitter to avoid Java's RegEx inefficiency
//        parts = encryptionText.split("\\Q$\\E");   // This should have been just "$". But Java stays true to its motto: Why make it simple when there's a complicated way to do it?

      final EncryptionParts result = new EncryptionParts();

      result.formatId = formatId;

      if (parts.length == 4) {
         if (formatId >= FORMAT_ID_USE_SAFE_ENCODING) {
            result.iv = Base32Encoding.decodeSpellSafe(parts[1]);
            result.encryptedData = Base32Encoding.decodeSpellSafe(parts[2]);
            result.checksum = Base32Encoding.decodeSpellSafe(parts[3]);
         } else {
            Base64.Decoder b64Decoder = Base64.getDecoder();

            result.iv = b64Decoder.decode(parts[1]);
            result.encryptedData = b64Decoder.decode(parts[2]);
            result.checksum = b64Decoder.decode(parts[3]);
         }
      } else
         throw new IllegalArgumentException("Number of '" + separator + "' separated parts in encrypted text is not 4");

      return result;
   }

   /**
    * Return unpadded data bytes depending on format id
    *
    * @param formatId                 Format id of data
    * @param paddedDecryptedDataBytes Byte array of padded decrypted bytes
    * @return Unpadded decrypted bytes
    */
   private byte[] getUnpaddedDataBytes(final byte formatId, final byte[] paddedDecryptedDataBytes) {
      // Formats 1 and 2 use padding. Starting from format 3 blinding is used.
      if (formatId >= FORMAT_ID_USE_BLINDING)
         return ByteArrayBlinding.unBlindByteArray(paddedDecryptedDataBytes);
      else
         return ArbitraryTailPadding.removePadding(paddedDecryptedDataBytes);
   }

   /**
    * Get SecureSecretKeySpec with respect to a subject
    *
    * <p>This method returns a 256 bit key, whereas, when there is no subject,
    * a 128 bit key is used.</p>
    *
    * @param hmacKey          The key to use for HMAC calculation
    * @param baseKey          The key the subject key is derived from as a byte array
    * @param keyAlgorithmName Algorithm name for the SecureSecretKeySpec to create
    * @param subjectBytes     The subject as a byte array
    * @return {@code SecureSecretKeySpec} built from the HMAC key, the base key and the subject
    * @throws InvalidKeyException      Thrown, if the key is not valid for the HMAC algorithm (must never happen)
    * @throws NoSuchAlgorithmException Thrown, if there is no HMAC-256 algorithm (must never happen)
    */
   private SecureSecretKeySpec getSecretKeySpecForKeyWithSubject(final ProtectedByteArray hmacKey,
                                                                 final ProtectedByteArray baseKey,
                                                                 final String keyAlgorithmName,
                                                                 final byte[] subjectBytes)
         throws InvalidKeyException,
         NoSuchAlgorithmException {
      final Mac dataHmac = getHMACInstance();

      byte[] baseKeyBytes = null;
      byte[] computedKey = null;
      SecureSecretKeySpec result;

      final byte[] hmacKeyBytes = hmacKey.getData();

      try (final SecureSecretKeySpec hmacKeySpec = new SecureSecretKeySpec(hmacKeyBytes, HMAC_256_ALGORITHM_NAME)) {
         dataHmac.init(hmacKeySpec);

         baseKeyBytes = baseKey.getData();

         dataHmac.update(baseKeyBytes);
         dataHmac.update(PREFIX_SALT);
         dataHmac.update(subjectBytes);
         computedKey = dataHmac.doFinal(SUFFIX_SALT);

         result = new SecureSecretKeySpec(computedKey, keyAlgorithmName);
      } finally {
         ArrayHelper.clear(hmacKeyBytes);
         ArrayHelper.safeClear(baseKeyBytes);
         ArrayHelper.safeClear(computedKey);
      }

      return result;
   }

   /**
    * Get default SecureSecretKeySpec for key
    *
    * @param baseKey          The key to wrap in a SecureSecretKeySpec
    * @param forAlgorithmName Algorithm name for the SecureSecretKeySpec to create
    * @return SecureSecretKeySpec of specified key
    */
   private SecureSecretKeySpec getDefaultSecretKeySpecForKey(final ProtectedByteArray baseKey,
                                                             final String forAlgorithmName) {
      final byte[] baseKeyBytes = baseKey.getData();
      final SecureSecretKeySpec result = new SecureSecretKeySpec(baseKeyBytes, forAlgorithmName);
      ArrayHelper.clear(baseKeyBytes);

      return result;
   }

   /**
    * Get default SecureSecretKeySpec for encryption
    *
    * @return SecureSecretKeySpec for default encryption key
    */
   private SecureSecretKeySpec getDefaultSecretKeySpecForEncryption() {
      return getDefaultSecretKeySpecForKey(this.encryptionKey, AES_ALGORITHM_NAME);
   }

   /**
    * Get default SecureSecretKeySpec for HMAC calculation
    *
    * @return SecureSecretKeySpec for default HMAC key
    */
   private SecureSecretKeySpec getDefaultSecretKeySpecForHMAC() {
      return getDefaultSecretKeySpecForKey(this.hmacKey, HMAC_256_ALGORITHM_NAME);
   }

   /**
    * Get encryption key depending on whether a subject is present or not
    *
    * @param subjectBytes The subject as a byte array (may have length 0)
    * @throws InvalidKeyException      Thrown, if the key is not valid for the HMAC algorithm (must never happen)
    * @throws NoSuchAlgorithmException Thrown, if there is no HMAC-256 algorithm (must never happen)
    */
   private SecureSecretKeySpec getSecretKeySpecForEncryptionDependingOnSubject(final byte[] subjectBytes)
         throws InvalidKeyException,
         NoSuchAlgorithmException {
      if (subjectBytes.length > 0)
         return getSecretKeySpecForKeyWithSubject(this.hmacKey, this.encryptionKey, AES_ALGORITHM_NAME, subjectBytes);
      else
         return getDefaultSecretKeySpecForEncryption();
   }

   /**
    * Get HMAC key depending on whether a subject is present or not
    *
    * @param subjectBytes The subject as a byte array (may have length 0)
    * @throws InvalidKeyException      Thrown, if the key is not valid for the HMAC algorithm (must never happen)
    * @throws NoSuchAlgorithmException Thrown, if there is no HMAC-256 algorithm (must never happen)
    */
   private SecureSecretKeySpec getSecretKeySpecForHMACDependingOnSubject(final byte[] subjectBytes)
         throws InvalidKeyException,
         NoSuchAlgorithmException {
      if (subjectBytes.length > 0)
         return getSecretKeySpecForKeyWithSubject(this.encryptionKey, this.hmacKey, HMAC_256_ALGORITHM_NAME, subjectBytes);
      else
         return getDefaultSecretKeySpecForHMAC();
   }

   /**
    * Decrypt data that have been created by the corresponding encryption
    *
    * @param encryptionParts The encryption parts of the data
    * @param subjectBytes    The subject for this decryption
    * @return Decrypted data as a byte array
    * @throws InvalidAlgorithmParameterException Thrown, if there was an invalid parameter for the encryption algorithm
    * @throws InvalidKeyException                Thrown, if the key is not valid for the encryption algorithm (must never happen)
    * @throws NoSuchAlgorithmException           Thrown, if there is no AES encryption (must never happen)
    * @throws BadPaddingException                Thrown, if unpadding does not work (must never happen)
    * @throws IllegalBlockSizeException          Thrown, if the block size is not valid for the encryption algorithm (must never happen)
    * @throws NoSuchPaddingException             Thrown, if there is no NoPadding padding (must never happen)
    */
   private byte[] rawDataDecryption(final EncryptionParts encryptionParts, final byte[] subjectBytes)
         throws BadPaddingException,
         IllegalBlockSizeException,
         InvalidAlgorithmParameterException,
         InvalidKeyException,
         NoSuchAlgorithmException,
         NoSuchPaddingException {
      // "encryptionParts.formatId" has been checked in "decryptData" and does not need to be checked here
      final String encryptionSpecification = ENCRYPTION_SPECIFICATION[encryptionParts.formatId];

      final Cipher aesCipher = Cipher.getInstance(encryptionSpecification);

      byte[] paddedDecryptedDataBytes = null;
      byte[] result;

      try {
         paddedDecryptedDataBytes = decryptWithSubject(encryptionParts, aesCipher, subjectBytes);

         result = getUnpaddedDataBytes(encryptionParts.formatId, paddedDecryptedDataBytes);
      } finally {
         ArrayHelper.safeClear(paddedDecryptedDataBytes);
      }

      return result;
   }

   /**
    * Decrypt data with subject
    *
    * @param encryptionParts The encryption parts to decrypt
    * @param cipher          The cipher to use for decryption
    * @param subjectBytes    The subject bytes to derive the key from
    * @return The decrypted data
    * @throws BadPaddingException                Thrown, if unpadding does not work (must never happen)
    * @throws IllegalBlockSizeException          Thrown, if the block size is not valid for the encryption algorithm (must never happen)
    * @throws InvalidAlgorithmParameterException Thrown, if there was an invalid parameter for the encryption algorithm
    * @throws InvalidKeyException                Thrown, if the key is not valid for the encryption algorithm (must never happen)
    * @throws NoSuchAlgorithmException           Thrown, if there is no AES encryption (must never happen)
    */
   private byte[] decryptWithSubject(final EncryptionParts encryptionParts, final Cipher cipher, final byte[] subjectBytes)
         throws BadPaddingException,
         IllegalBlockSizeException,
         InvalidAlgorithmParameterException,
         InvalidKeyException,
         NoSuchAlgorithmException {
      try (final SecureSecretKeySpec decryptionKey = getSecretKeySpecForEncryptionDependingOnSubject(subjectBytes)) {
         cipher.init(Cipher.DECRYPT_MODE, decryptionKey, new IvParameterSpec(encryptionParts.iv));

         return cipher.doFinal(encryptionParts.encryptedData);
      }
   }

   /**
    * Calculate capacity of StringBuilder for encryption parts
    *
    * <p>The size of the final string is 4 + SumOf(ceil(ArrayLength * 8 / 5)).
    * This is a complicated expression which is overestimated by the easier
    * expression 4 + SumOfArrayLengths * 7 / 4</p>
    *
    * @param encryptionParts Encryption parts to calculate the capacity for
    * @return Slightly overestimated capacity of the StringBuilder for the
    * supplied encryption parts
    */
   private int calculateStringBuilderCapacityForEncryptionParts(final EncryptionParts encryptionParts) {
      final int arrayLengths = encryptionParts.iv.length + encryptionParts.encryptedData.length + encryptionParts.checksum.length;

      return 4 + arrayLengths + (arrayLengths >>> 1) + (arrayLengths >>> 2);
   }

   /**
    * Build a printable string from the encrypted parts
    *
    * @param encryptionParts Parts to be printed
    * @return Printable string of the encrypted parts
    */
   private String makeEncryptionStringFromEncryptionParts(final EncryptionParts encryptionParts) {
      StringBuilder myStringBuilder = new StringBuilder(calculateStringBuilderCapacityForEncryptionParts(encryptionParts));

      myStringBuilder.append(encryptionParts.formatId);
      myStringBuilder.append(SAFE_PARTS_SEPARATOR);
      myStringBuilder.append(Base32Encoding.encodeSpellSafeNoPadding(encryptionParts.iv));
      myStringBuilder.append(SAFE_PARTS_SEPARATOR);
      myStringBuilder.append(Base32Encoding.encodeSpellSafeNoPadding(encryptionParts.encryptedData));
      myStringBuilder.append(SAFE_PARTS_SEPARATOR);
      myStringBuilder.append(Base32Encoding.encodeSpellSafeNoPadding(encryptionParts.checksum));

      return myStringBuilder.toString();
   }

   /**
    * Calculate the HMAC of the encrypted parts
    *
    * @param encryptionParts Encrypted parts to calculate the checksum for
    * @param subjectBytes    The subject for this HMAC calculation
    * @return Checksum of the encrypted parts with @code{subjectBytes}
    * @throws InvalidKeyException      Thrown, if the key is not valid for the HMAC algorithm (must never happen)
    * @throws NoSuchAlgorithmException Thrown, if there is no HMAC-256 algorithm (must never happen)
    */
   private byte[] getChecksumForEncryptionParts(final EncryptionParts encryptionParts, final byte[] subjectBytes)
         throws InvalidKeyException,
         NoSuchAlgorithmException {
      byte[] result;

      final Mac dataHmac = getHMACInstance();

      try (final SecureSecretKeySpec hmacSecretKeySpec = getHMACKeyForFormat(encryptionParts.formatId, subjectBytes)) {
         dataHmac.init(hmacSecretKeySpec);

         dataHmac.update(encryptionParts.formatId);
         dataHmac.update(encryptionParts.iv);
         dataHmac.update(encryptionParts.encryptedData);

         result = dataHmac.doFinal();
      }

      return result;
   }

   /**
    * Get the correct HMAC key for the specified format id
    *
    * @param formatId     Format id
    * @param subjectBytes Subject bytes
    * @return HMAC key
    * @throws InvalidKeyException      Thrown, if the key is not valid for the HMAC algorithm (must never happen)
    * @throws NoSuchAlgorithmException Thrown, if there is no HMAC-256 algorithm (must never happen)
    */
   private SecureSecretKeySpec getHMACKeyForFormat(final byte formatId, final byte[] subjectBytes)
         throws InvalidKeyException,
         NoSuchAlgorithmException {
      SecureSecretKeySpec hmacSecretKeySpec;

      if (formatId >= FORMAT_ID_USE_CORRECT_HMAC_KEY)
         hmacSecretKeySpec = getSecretKeySpecForHMACDependingOnSubject(subjectBytes);
      else
         hmacSecretKeySpec = getDefaultSecretKeySpecForHMAC();

      return hmacSecretKeySpec;
   }

   /**
    * Check the checksum of the encrypted parts that have been read
    *
    * @param encryptionParts Parts to be checked
    * @param subjectBytes    Subject bytes to use for HMAC key calculation.
    * @throws DataIntegrityException   Thrown, if the HMAC of the parts is not correct
    * @throws InvalidKeyException      Thrown, if the key is not valid for the HMAC algorithm (must never happen)
    * @throws NoSuchAlgorithmException Thrown, if there is no HMAC-256 algorithm (must never happen)
    */
   private void checkChecksumForEncryptionParts(final EncryptionParts encryptionParts, final byte[] subjectBytes)
         throws DataIntegrityException,
         InvalidKeyException,
         NoSuchAlgorithmException {
      final byte[] calculatedChecksum = getChecksumForEncryptionParts(encryptionParts, subjectBytes);

      if (!SafeArrays.constantTimeEquals(calculatedChecksum, encryptionParts.checksum))
         throw new DataIntegrityException("Checksum does not match data");
   }

   /**
    * Encrypt source bytes and return the formatted output string
    *
    * <p>This is a wrapper around {@code rawDataEncryption} that catches any encryption parameter errors and converts
    * them to a {@code InvalidCryptoParameterException}. Also it ensures that the {@code EncryptionParts} is
    * cleared so that nothing is leaked in memory through this object.</p>
    *
    * @param sourceBytes Source bytes to be encrypted
    * @param subject     The subject of this encryption
    * @return Formatted encryption string
    * @throws InvalidCryptoParameterException Thrown, if a parameter of a cryptographic method is invalid (must never happen)
    */
   private String makeEncryptionStringFromSourceBytes(final byte[] sourceBytes, final String subject)
         throws InvalidCryptoParameterException {
      String result;

      final byte[] subjectBytes = subject.getBytes(CHARACTER_ENCODING_FOR_DATA);

      try (EncryptionParts encryptionParts = rawDataEncryption(sourceBytes, subjectBytes)) {
         result = makeEncryptionStringFromEncryptionParts(encryptionParts);
      } catch (final BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
         throw new InvalidCryptoParameterException("Invalid cryptographic parameter: " + e, e);
      }

      return result;
   }

   /**
    * Encrypt source bytes
    *
    * @param sourceBytes  Source bytes to be encrypted
    * @param subjectBytes The subject of this encryption as a byte array
    * @return Raw encrypted data as a fully filled EncryptionParts object
    * @throws InvalidAlgorithmParameterException Thrown, if an invalid encryption parameter was specified (must never happen)
    * @throws InvalidKeyException                Thrown, if an invalid encryption key was specified (must never happen)
    * @throws NoSuchAlgorithmException           Thrown, if an invalid encryption algorithm was specified (must never happen)
    * @throws BadPaddingException                Thrown, if invalid padding data was specified (must never happen)
    * @throws IllegalBlockSizeException          Thrown, if an invalid block size was specified (must never happen)
    * @throws NoSuchPaddingException             Thrown, if an invalid padding was specified (must never happen)
    */
   private EncryptionParts rawDataEncryption(final byte[] sourceBytes, final byte[] subjectBytes)
         throws BadPaddingException,
         IllegalBlockSizeException,
         InvalidAlgorithmParameterException,
         InvalidKeyException,
         NoSuchAlgorithmException,
         NoSuchPaddingException {
      final EncryptionParts result = new EncryptionParts();

      result.formatId = FORMAT_ID_MAX;

      final String encryptionSpecification = ENCRYPTION_SPECIFICATION[result.formatId];

      final Cipher aesCipher = Cipher.getInstance(encryptionSpecification);

      byte[] unpaddedEncodedStringBytes = null;

      byte[] paddedEncodedStringBytes = null;

      try {
         // Ensure that blinded array needs at least 2 AES blocks, so the length of the encrypted data
         // can not be inferred to be no longer than block size - 3 bytes (= 13 bytes for AES).
         unpaddedEncodedStringBytes = ByteArrayBlinding.buildBlindedByteArray(sourceBytes, aesCipher.getBlockSize() + 1);

         paddedEncodedStringBytes = RandomPadding.addPadding(unpaddedEncodedStringBytes, aesCipher.getBlockSize());

         result.iv = getInitializationVector(aesCipher.getBlockSize());

         try (final SecureSecretKeySpec dataEncryptionKey = getSecretKeySpecForEncryptionDependingOnSubject(subjectBytes)) {
            // Encrypt the source string with the iv
            aesCipher.init(Cipher.ENCRYPT_MODE, dataEncryptionKey, new IvParameterSpec(result.iv));

            result.encryptedData = aesCipher.doFinal(paddedEncodedStringBytes);
         }

         result.checksum = getChecksumForEncryptionParts(result, subjectBytes);
      } finally {
         ArrayHelper.safeClear(unpaddedEncodedStringBytes);
         ArrayHelper.safeClear(paddedEncodedStringBytes);
      }

      return result;
   }

   /**
    * Get a random initialization vector
    *
    * @param blockSize Size of initialization vector
    * @return Random initialization vector
    */
   private byte[] getInitializationVector(final int blockSize) {
      final byte[] result = new byte[blockSize];

      getSecureRandomInstance().nextBytes(result);

      return result;
   }

   /**
    * Get HMAC value of an array of byte arrays
    *
    * @param key         The key for the HMAC
    * @param sourceBytes The source bytes to be hashed
    * @return HMAC value of the specified data with specified key
    * @throws InvalidKeyException      Thrown, if the key is not valid for the HMAC algorithm (must never happen)
    * @throws NoSuchAlgorithmException Thrown, if there is no HMAC-256 algorithm (must never happen)
    */
   private byte[] getHmacValueOfSourceBytes(final byte[] key, final byte[]... sourceBytes)
         throws InvalidKeyException,
         NoSuchAlgorithmException {
      final Mac dataHmac = getHMACInstance();

      byte[] result;

      try (SecureSecretKeySpec dataHmacKey = new SecureSecretKeySpec(key, HMAC_256_ALGORITHM_NAME)) {
         dataHmac.init(dataHmacKey);

         for (byte[] sourceByte : sourceBytes)
            dataHmac.update(sourceByte);

         result = dataHmac.doFinal();
      }

      return result;
   }

   /**
    * Set the keys of this instance from the supplied byte arrays and a HMAC key
    *
    * @param hmacKey     HMAC key to be used
    * @param sourceBytes bytes to be used for key derivation
    * @throws InvalidKeyException      Thrown, if the key is not valid for the HMAC algorithm (must never happen)
    * @throws NoSuchAlgorithmException Thrown, if there is no HMAC-256 algorithm (must never happen)
    */
   private void setKeysFromKeyAndSourceBytes(final byte[] hmacKey, final byte[]... sourceBytes)
         throws InvalidKeyException,
         NoSuchAlgorithmException {
      byte[] hmacOfSourceBytes = null;
      byte[] keyPart = null;

      try {
         hmacOfSourceBytes = getHmacValueOfSourceBytes(hmacKey, sourceBytes);

         // 1. half of source bytes HMAC is used as the encryption key of this instance
         keyPart = Arrays.copyOfRange(hmacOfSourceBytes, 0, 16);

         this.encryptionKey = new ProtectedByteArray(keyPart);

         // 2. half of source bytes HMAC is used as the HMAC key of this instance
         keyPart = Arrays.copyOfRange(hmacOfSourceBytes, 16, 32);

         ArrayHelper.clear(hmacOfSourceBytes);

         this.hmacKey = new ProtectedByteArray(keyPart);
      } finally {
         ArrayHelper.safeClear(hmacOfSourceBytes);
         ArrayHelper.safeClear(keyPart);
      }
   }
}
