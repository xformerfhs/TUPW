/*
 * SPDX-FileCopyrightText: 2021-2023 DB Systel GmbH
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
 *     2021-05-28: V1.0.0: Created. fhs
 *     2021-09-01: V1.0.1: Some small refactoring. fhs
 *     2022-11-07: V1.1.0: Better mixing of bytes from and to buffers. fhs
 *     2022-11-08: V1.2.0: Name all constants. fhs
 *     2022-12-22: V1.2.1: Removed unnecessary constant. fhs
 *     2023-12-11: V1.2.2: Standard naming convention for instance variables. fhs
 *     2025-02-20: V2.0.0: Simplify to sort of counter mode. fhs
 */
package de.xformerfhs.crypto;

import de.xformerfhs.arrays.ArrayHelper;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

/**
 * Class to get masks for array indices
 *
 * @author Frank Schwab, DB Systel
 * @version 2.0.0
 */
public class MaskedIndex {
   //******************************************************************
   // Private constants
   //******************************************************************

   /** Key size */
   static final int KEY_SIZE = 16;  // I.e. 128 bits

   /** Buffer size */
   static final int BUFFER_SIZE = 16;

   /** Index of middle 4 bytes in buffer */
   static final int MIDDLE_INDEX = 6;

   /** Offset of last byte of an integer in bytes */
   static final int INT_BYTE_OFFSET = 3;

   /** Number of bits to shift for a byte shift */
   static final int BYTE_SHIFT = 8;

   /** Byte mask for integers */
   static final int INT_BYTE_MASK = 0xff;

   //******************************************************************
   // Instance variables
   //******************************************************************

   /** Encryptor to use */
   private Cipher encryptor;

   /** Source buffer for mask generation */
   private final byte[] sourceBuffer = new byte[BUFFER_SIZE];

   /** Buffer for encryption result */
   private final byte[] maskBuffer = new byte[BUFFER_SIZE];

   /** High byte used for integer masks */
   private byte highByteForInt;

   /** High byte used for byte masks */
   private byte highByteForByte;

   //******************************************************************
   // Constructor
   //******************************************************************

   /**
    * The constructor for an instance of MaskedIndex
    */
   public MaskedIndex() {
      initializeCipher();
   }

   //******************************************************************
   // Public methods
   //******************************************************************

   /**
    * Get an integer mask for an index
    *
    * @param forIndex The index to use
    * @return The int mask for the given index
    */
   public synchronized int getIntMask(final int forIndex) {
      final int sanitizedIndex = forIndex & Integer.MAX_VALUE;

      getMaskBuffer(sanitizedIndex, highByteForInt);

      final int result = getMaskIntFromArray(maskBuffer, MIDDLE_INDEX);

      ArrayHelper.clear(maskBuffer);

      return result;
   }

   /**
    * Get a byte mask for an index
    *
    * @param forIndex The index to use
    * @return The byte mask for the given index
    */
   public synchronized byte getByteMask(final int forIndex) {
      final int sanitizedIndex = forIndex & Integer.MAX_VALUE;

      getMaskBuffer(sanitizedIndex, highByteForByte);

      final byte result = maskBuffer[MIDDLE_INDEX];

      ArrayHelper.clear(maskBuffer);

      return result;
   }

   //******************************************************************
   // Private methods
   //******************************************************************

   /**
    * Calculate a buffer full of mask bytes
    *
    * @param sanitizedIndex Sanitized index to use for the mask calculation
    */
   private void getMaskBuffer(final int sanitizedIndex, final byte highByte) {
      // Copy integer to middle 4 bytes of source buffer
      storeIntInArray(sanitizedIndex, sourceBuffer, MIDDLE_INDEX);

      // Set high byte
      sourceBuffer[0] = highByte;

      // And encrypt this buffer to get a mask
      try {
         encryptor.doFinal(sourceBuffer, 0, sourceBuffer.length, maskBuffer, 0);
      } catch (Exception ex) {
         // BadPaddingException, IllegalBlockSizeException and ShortBufferException can never happen
      }
   }

   /**
    * Initialize the cipher
    */
   private void initializeCipher() {
      final byte[] key = new byte[KEY_SIZE];

      final SecureRandom sprng = SecureRandomFactory.getSensibleSingleton();

      // Get random key
      sprng.nextBytes(key);

      // Fill source buffer with a random value
      sprng.nextBytes(sourceBuffer);

      // Set high bytes
      highByteForInt = sourceBuffer[0];
      highByteForByte = (byte) (highByteForInt ^ 0xff);

      try {
         // ECB is an insecure mode but that is not a problem as
         // the cipher is only used for generating an obfuscation mask.
         encryptor = Cipher.getInstance("AES/ECB/NoPadding");

         // This has to be "SecretKeySpec" and not "SecureSecretKeySpec".
         // Otherwise, we would have an infinite loop here.
         SecretKeySpec maskKey = new SecretKeySpec(key, "AES");

         encryptor.init(Cipher.ENCRYPT_MODE, maskKey);
      } catch (Exception ex) {
         // InvalidKeyException, NoSuchAlgorithmException and NoSuchPaddingException can never happen
      } finally {
         // Clear the key as it is only needed once and not again
         ArrayHelper.clear(key);
      }
   }

   /**
    * Stores the bytes of an integer in an existing array
    *
    * @param sourceInt Integer to convert
    * @param destArray Destination byte array
    * @param startPos Start position in the byte array
    */
   private void storeIntInArray(final int sourceInt, final byte[] destArray, final int startPos) {
      int toPos = startPos + INT_BYTE_OFFSET;
      int work = sourceInt;

      destArray[toPos] = (byte) (work & INT_BYTE_MASK);

      toPos--;
      work >>>= BYTE_SHIFT;
      destArray[toPos] = (byte) (work & INT_BYTE_MASK);

      toPos--;
      work >>>= BYTE_SHIFT;
      destArray[toPos] = (byte) (work & INT_BYTE_MASK);

      toPos--;
      work >>>= BYTE_SHIFT;
      destArray[toPos] = (byte) (work & INT_BYTE_MASK);
   }

   /**
    * Get a mask integer from the bytes in an array
    *
    * @param sourceArray Byte array to get the integer from
    * @param startPos Start position in the byte array
    * @return Mask integer
    */
   private int getMaskIntFromArray(final byte[] sourceArray, final int startPos) {
      int result;
      int fromPos = startPos;

      result = (sourceArray[fromPos] & INT_BYTE_MASK);  // This stupid Java sign extension!!!!

      result <<= BYTE_SHIFT;
      fromPos++;
      result |= (sourceArray[fromPos] & INT_BYTE_MASK);

      result <<= BYTE_SHIFT;
      fromPos++;
      result |= (sourceArray[fromPos] & INT_BYTE_MASK);

      result <<= BYTE_SHIFT;
      fromPos++;
      result |= (sourceArray[fromPos] & INT_BYTE_MASK);

      return result;
   }
}
