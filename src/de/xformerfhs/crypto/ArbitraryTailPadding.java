/*
 * SPDX-FileCopyrightText: 2017-2023 DB Systel GmbH
 * SPDX-FileCopyrightText: 2023-2024 Frank Schwab
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
 *     2017-12-21: V2.0.0: Pad to block size. fhs
 *     2018-06-11: V2.0.1: Block size must be greater than zero. fhs
 *     2018-08-15: V2.0.2: Added some "finals". fhs
 *     2019-05-17: V2.0.3: Added a missing "final". fhs
 *     2019-08-06: V2.0.4: Use SecureRandomFactory. fhs
 *     2019-08-23: V2.0.5: Use SecureRandom singleton. fhs
 *     2020-03-13: V2.1.0: Added checks for null. fhs
 *     2020-03-23: V2.2.0: Restructured source code according to DBS programming guidelines. fhs
 *     2020-08-13: V2.2.1: Improved getPaddingByteValue method. fhs
 *     2020-12-04: V2.2.2: Corrected several SonarLint findings. fhs
 *     2020-12-29: V2.3.0: Made thread safe. fhs
 *     2021-09-01: V2.3.1: Renamed instance variable. fhs
 *     2023-12-11: V2.3.2: Corrected comments. fhs
 */
package de.xformerfhs.crypto;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

/**
 * Implements arbitrary tail padding for block ciphers
 *
 * @author Frank Schwab
 * @version 2.3.2
 */
public class ArbitraryTailPadding {
   //******************************************************************
   // Private constants
   //******************************************************************

   /**
    * Maximum block size (64 KiB)
    */
   private static final int MAX_BLOCK_SIZE = 64 * 1024;

   /**
    * Instance of secure random number generator
    *
    * <p>This is placed here so the expensive instantiation of the SecureRandom
    * class is done only once.</p>
    */
   private static final SecureRandom secureRandom = SecureRandomFactory.getSensibleSingleton();


   //******************************************************************
   // Constructor
   //******************************************************************

   /**
    * Private constructor
    *
    * <p>This class is not meant to be instanced.</p>
    */
   private ArbitraryTailPadding() {
      throw new IllegalStateException("This class is not meant to be instanced");
   }


   //******************************************************************
   // Public methods
   //******************************************************************

   /**
    * Add padding bytes to source data
    *
    * @param unpaddedSourceData Data to be padded
    * @param blockSize          Block size in bytes
    * @return Data with padding bytes added
    * @throws IllegalArgumentException if block size is too small or too large
    * @throws NullPointerException     if {@code unpaddedSourceData} is {@code null}
    */
   public static synchronized byte[] addPadding(final byte[] unpaddedSourceData, final int blockSize) throws IllegalArgumentException, NullPointerException {
      Objects.requireNonNull(unpaddedSourceData, "Unpadded source data is null");

      // Check parameter validity
      checkBlockSize(blockSize);

      // Get pad byte value
      final byte padByte = getPaddingByteValue(unpaddedSourceData);

      // Get padding size
      final int paddingLength = getPaddingLength(unpaddedSourceData.length, blockSize);

      // Create padded byte array
      final byte[] result = Arrays.copyOf(unpaddedSourceData, unpaddedSourceData.length + paddingLength);

      // Add padding bytes
      Arrays.fill(result, unpaddedSourceData.length, result.length, padByte);

      return result;
   }

   /**
    * Remove padding bytes from source data
    *
    * @param paddedSourceData Data with padding bytes
    * @return Data without padding bytes
    * @throws NullPointerException if {@code paddedSourceData} is {@code null}
    */
   public static synchronized byte[] removePadding(final byte[] paddedSourceData) throws NullPointerException {
      Objects.requireNonNull(paddedSourceData, "Padded source data is null");

      // Return unpadded data
      return Arrays.copyOf(paddedSourceData, getUnpaddedDataLength(paddedSourceData));
   }


   //******************************************************************
   // Private methods
   //******************************************************************

   /**
    * Check block size
    *
    * @param blockSize Block size
    * @throws java.lang.IllegalArgumentException if block size is too small or too large
    */
   private static void checkBlockSize(final int blockSize) throws IllegalArgumentException {
      if (blockSize <= 0)
         throw new IllegalArgumentException("Block size must be greater than 0");

      if (blockSize > MAX_BLOCK_SIZE)
         throw new IllegalArgumentException("Block size must not be greater than " + MAX_BLOCK_SIZE);
   }

   /**
    * Get a random value as the padding byte
    * <p>
    * The padding byte must not have the same value as the last data byte
    * </p>
    *
    * @param unpaddedSourceData Unpadded source data (may be empty)
    * @return Random byte to be used as the padding byte
    */
   private static byte getPaddingByteValue(final byte[] unpaddedSourceData) {
      final byte[] padByte = new byte[1];

      secureRandom.nextBytes(padByte);

      if (unpaddedSourceData.length > 0) {
         final byte lastByte = unpaddedSourceData[unpaddedSourceData.length - 1];

         while (padByte[0] == lastByte)
            secureRandom.nextBytes(padByte);
      }

      return padByte[0];
   }

   /**
    * Calculate the padding length
    * <p>
    * If the unpadded data already have a length that is a multiple of blockSize
    * an additional block with only padding bytes is added.
    * </p>
    *
    * @param unpaddedLength Length of the unpadded data
    * @param blockSize      Block size of which the padding size has to be a multiple
    * @return Padding length that brings the total length to a multiple of {@code blockSize}
    */
   private static int getPaddingLength(final int unpaddedLength, final int blockSize) {
      return (blockSize - (unpaddedLength % blockSize));
   }

   /**
    * Get length of unpadded data
    *
    * @param paddedSourceData Padded source data
    * @return Length of unpadded data
    */
   private static int getUnpaddedDataLength(final byte[] paddedSourceData) {
      int result = paddedSourceData.length;

      if (result > 0) {
         result--;

         final byte padByte = paddedSourceData[result];

         while (result > 0) {
            result--;

            if (paddedSourceData[result] != padByte) {
               result++;
               break;
            }
         }
      }

      return result;
   }
}
