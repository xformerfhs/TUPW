/*
 * SPDX-FileCopyrightText: 2022-2023 DB Systel GmbH
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
 *     2018-08-16: V1.0.0: Created. fhs
 *     2019-08-06: V1.0.2: Use SecureRandomFactory. fhs
 *     2019-08-23: V1.0.3: Use SecureRandom singleton. fhs
 *     2020-03-13: V1.1.0: Added checks for null. fhs
 *     2020-03-16: V1.1.1: Added text to UnsupportedOperationException. fhs
 *     2020-03-23: V1.2.0: Restructured source code according to DBS programming guidelines. fhs
 *     2020-05-28: V2.0.0: Removed unnecessary "RemovePadding" method. fhs
 *     2020-12-04: V2.0.1: Corrected several SonarLint findings. fhs
 *     2020-12-29: V2.1.0: Made thread safe. fhs
 *     2021-09-01: V2.2.0: Added constructor. fhs
 */
package de.db.bcm.tupw.crypto;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

/**
 * Implements random padding for block ciphers
 *
 * <p>Attention: Random padding is <b>not</b> reversible.
 * It can only be used to pad data where the length is known.</p>
 *
 * @author Frank Schwab
 * @version 2.2.0
 */
public class RandomPadding {
   //******************************************************************
   // Private constants
   //******************************************************************

   /**
    * Maximum block size (64 KiB)
    */
   private static final int MAX_BLOCK_SIZE = 64 * 1024;


   //******************************************************************
   // Private variables
   //******************************************************************

   /**
    * Instance of secure random number generator
    *
    * <p>This is placed here so the expensive instantiation of the SecureRandom
    * class is done only once.</p>
    */
   private static final SecureRandom m_SecureRandom = SecureRandomFactory.getSensibleSingleton();

   //******************************************************************
   // Constructor
   //******************************************************************

   /**
    * Private constructor
    *
    * <p>This class is not meant to be instantiated.</p>
    */
   private RandomPadding() {
      throw new IllegalStateException("Utility class");
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
    * @throws IllegalArgumentException if the block size is too small or too large
    * @throws NullPointerException     if {@code unpaddedSourceData} is null
    */
   public static synchronized byte[] addPadding(final byte[] unpaddedSourceData, final int blockSize) throws IllegalArgumentException, NullPointerException {
      // Check parameter validity
      Objects.requireNonNull(unpaddedSourceData, "Unpadded source data is null");

      checkBlockSize(blockSize);

      // Get padding size
      final int paddingLength = getPaddingLength(unpaddedSourceData.length, blockSize);

      // Create padded byte array
      final byte[] result = Arrays.copyOf(unpaddedSourceData, unpaddedSourceData.length + paddingLength);

      // Pad with random bytes
      if (paddingLength > 0) {
         byte[] paddingBytes = new byte[paddingLength];

         m_SecureRandom.nextBytes(paddingBytes);

         System.arraycopy(paddingBytes, 0, result, unpaddedSourceData.length, paddingLength);
      }

      return result;
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
    * Calculate the padding length
    * <p>If the unpadded data already have a length that is a multiple of blockSize
    * no padding bytes are added.</p>
    *
    * @param unpaddedLength Length of the unpadded data
    * @param blockSize      Block size of which the padding size has to be a multiple
    * @return Padding length that brings the total length to a multiple of
    * {@code blockSize}
    */
   private static int getPaddingLength(final int unpaddedLength, final int blockSize) {
      return (blockSize - (unpaddedLength % blockSize));
   }
}
