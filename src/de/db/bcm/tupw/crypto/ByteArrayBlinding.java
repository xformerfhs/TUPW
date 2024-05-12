/*
 * SPDX-FileCopyrightText: 2018-2023 DB Systel GmbH
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
 *     2020-02-11: V1.1.0: Strengthen blinding length tests. fhs
 *     2020-03-13: V1.2.0: Added checks for null. fhs
 *     2020-03-19: V1.3.0: Removed ByteArrayOutputStream. fhs
 *     2020-03-20: V1.4.0: Refactored blinded bytes build process. fhs
 *     2020-03-23: V1.5.0: Restructured source code according to DBS programming guidelines. fhs
 *     2020-04-28: V1.5.1: Added missing null check. fhs
 *     2020-12-04: V1.5.2: Corrected several SonarLint findings. fhs
 *     2020-12-29: V1.6.0: Made thread safe. fhs
 *     2021-07-13: V1.6.1: Made blinding method a little easier to read. fhs
 */
package de.db.bcm.tupw.crypto;

import de.db.bcm.tupw.arrays.ArrayHelper;
import de.db.bcm.tupw.numbers.PackedUnsignedInteger;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

/**
 * Implements blinding for byte arrays
 *
 * @author Frank Schwab
 * @version 1.6.1
 */
public class ByteArrayBlinding {
   //******************************************************************
   // Private constants
   //******************************************************************

   /**
    * Class level secure pseudo random number generator
    */
   private static final SecureRandom SECURE_PRNG = SecureRandomFactory.getSensibleSingleton();

   /*
    * Constants for error messages
    */
   private static final String ERROR_MESSAGE_INVALID_ARRAY = "Invalid blinded byte array";
   private static final String ERROR_MESSAGE_INVALID_MIN_LENGTH = "Invalid minimum length";
   private static final String ERROR_MESSAGE_NULL_SOURCE_BYTES = "Source bytes is null";

   /*
    * Constants for indexing and lengths
    */
   private static final int INDEX_LENGTHS_PREFIX_LENGTH = 0;
   private static final int INDEX_LENGTHS_POSTFIX_LENGTH = 1;
   private static final int LENGTHS_LENGTH = 2;

   private static final int INDEX_SOURCE_PREFIX_LENGTH = 0;
   private static final int INDEX_SOURCE_POSTFIX_LENGTH = 1;
   private static final int INDEX_SOURCE_PACKED_LENGTH = 2;

   private static final int MAX_NORMAL_SINGLE_BLINDING_LENGTH = 15;   // This needs to be a power of 2 minus 1

   private static final int MAX_MINIMUM_LENGTH = 256;


   //******************************************************************
   // Constructor
   //******************************************************************

   /**
    * Private constructor
    *
    * <p>This class is not meant to be instanced.</p>
    */
   private ByteArrayBlinding() {
      throw new IllegalStateException("This class is not meant to be instanced");
   }


   //******************************************************************
   // Public methods
   //******************************************************************

   /**
    * Add blinders to a byte array
    *
    * <p>Note: There may be no blinding, at all! I.e. the "blinded" array is the same, as the source array
    * This behaviour is intentional. So an attacker will not known, whether there was blinding, or not.</p>
    *
    * @param sourceBytes   Source bytes to blinding
    * @param minimumLength Minimum length of blinded array
    * @return Blinded byte array
    * @throws IllegalArgumentException if minimum length is too small or too large
    */
   public static synchronized byte[] buildBlindedByteArray(final byte[] sourceBytes, final int minimumLength) throws IllegalArgumentException {
      Objects.requireNonNull(sourceBytes, ERROR_MESSAGE_NULL_SOURCE_BYTES);

      checkMinimumLength(minimumLength);

      final int sourceLength = sourceBytes.length;

      final byte[] packedSourceLength = PackedUnsignedInteger.fromInteger(sourceLength);
      final int packedSourceLengthLength = packedSourceLength.length;

      // Get the prefix and the postfix blinding lengths.
      // Java does not support multiple return values, so we have to take the detour with an array as the return value.
      final int[] blindingLength = getBalancedBlindingLengths(packedSourceLengthLength, sourceLength, minimumLength);
      final int prefixLength = blindingLength[INDEX_LENGTHS_PREFIX_LENGTH];
      final int postfixLength = blindingLength[INDEX_LENGTHS_POSTFIX_LENGTH];

      // There ought to be a method to put random bytes into a part of an existing array like e.g. "next(bytes, offset, length)".
      // Unfortunately Java does not provide such a method, so we have to allocate temporary arrays for the blinders and copy them.
      final byte[] prefixBlinding = createBlinding(prefixLength);
      final byte[] postfixBlinding = createBlinding(postfixLength);

      final int resultLength = 2 + packedSourceLengthLength + prefixLength + sourceLength + postfixLength;

      final byte[] result = new byte[resultLength];

      result[0] = (byte) prefixLength;
      result[1] = (byte) postfixLength;

      int resultIndex = LENGTHS_LENGTH;

      resultIndex += copyByteArrayAndZapSource(packedSourceLength, result, resultIndex);

      resultIndex += copyByteArrayAndZapSource(prefixBlinding, result, resultIndex);

      resultIndex += copyByteArray(sourceBytes, result, resultIndex);

      copyByteArrayAndZapSource(postfixBlinding, result, resultIndex);

      return result;
   }

   /**
    * Remove blinders from a byte array
    *
    * @param sourceBytes Blinded byte array
    * @return Byte array without blinders
    * @throws IllegalArgumentException if the source byte array is not correctly formatted
    * @throws NullPointerException     if {@code sourceBytes} is {@code null}
    */
   public static synchronized byte[] unBlindByteArray(final byte[] sourceBytes) throws IllegalArgumentException, NullPointerException {
      Objects.requireNonNull(sourceBytes, ERROR_MESSAGE_NULL_SOURCE_BYTES);

      if (sourceBytes.length > LENGTHS_LENGTH) {
         final int packedNumberLength = PackedUnsignedInteger.getExpectedLength(sourceBytes[INDEX_SOURCE_PACKED_LENGTH]);

         if (sourceBytes[INDEX_SOURCE_PREFIX_LENGTH] >= 0) {
            // No. of bytes to skip is the blinding prefix length plus the two length bytes plus the source length
            final int prefixBlindingLength = sourceBytes[INDEX_SOURCE_PREFIX_LENGTH] + 2 + packedNumberLength;

            if (sourceBytes[INDEX_SOURCE_POSTFIX_LENGTH] >= 0) {
               final int postfixBlindingLength = sourceBytes[INDEX_SOURCE_POSTFIX_LENGTH];

               final int totalBlindingLength = prefixBlindingLength + postfixBlindingLength;
               final int dataLength = PackedUnsignedInteger.toInteger(sourceBytes, INDEX_SOURCE_PACKED_LENGTH);

               // The largest number in the following addition can only be just over 1073741823
               // This can never overflow into negative values
               if ((totalBlindingLength + dataLength) <= sourceBytes.length)
                  return Arrays.copyOfRange(sourceBytes, prefixBlindingLength, dataLength + prefixBlindingLength);
            }
         }
      }

      throw new IllegalArgumentException(ERROR_MESSAGE_INVALID_ARRAY);
   }


   //******************************************************************
   // Private methods
   //******************************************************************

   /**
    * Check the validity of the requested minimum length
    *
    * @param minimumLength Requested minimum length
    * @throws IllegalArgumentException if minimum length is too small or too large
    */
   private static void checkMinimumLength(final int minimumLength) throws IllegalArgumentException {
      if ((minimumLength < 0) || (minimumLength > MAX_MINIMUM_LENGTH))
         throw new IllegalArgumentException(ERROR_MESSAGE_INVALID_MIN_LENGTH);
   }

   /**
    * Get the length for a blinding part
    *
    * @return Length for blinding
    */
   private static int getBlindingLength() {
      return SECURE_PRNG.nextInt() & MAX_NORMAL_SINGLE_BLINDING_LENGTH;
   }

   /**
    * Adapt blinding lengths to minimum length
    *
    * <p>The result will be returned in the array of blinding lengths</p>
    * <p>This may be much larger than MAX_NORMAL_SINGLE_BLINDING_LENGTH and is always smaller
    * than (MAX_MINIMUM_LENGTH >>> 1).</p>
    *
    * @param blindingLength Array of blinding lengths (just because Java is unable to have return parameters)
    * @param sourceLengthLength Length of the source length
    * @param sourceLength       Length of source
    * @param minimumLength      Required minimum length
    */
   private static void adaptBlindingLengthsToMinimumLength(final int[] blindingLength, final int sourceLengthLength, final int sourceLength, final int minimumLength) {
      final int combinedLength = 2 + sourceLengthLength + blindingLength[INDEX_LENGTHS_PREFIX_LENGTH] + sourceLength + blindingLength[INDEX_LENGTHS_POSTFIX_LENGTH];

      if (combinedLength < minimumLength) {
         final int diff = minimumLength - combinedLength;
         final int halfDiff = diff >>> 1;

         blindingLength[INDEX_LENGTHS_PREFIX_LENGTH] += halfDiff;
         blindingLength[INDEX_LENGTHS_POSTFIX_LENGTH] += halfDiff;

         // Adjust for odd difference
         if ((diff & 1) != 0)
            if ((diff & 2) != 0)
               blindingLength[INDEX_LENGTHS_PREFIX_LENGTH]++;
            else
               blindingLength[INDEX_LENGTHS_POSTFIX_LENGTH]++;
      }
   }

   /**
    * Create blinding lengths so that their combined lengths are at least minimum length
    *
    * @param sourceLengthLength Length of the source length
    * @param sourceLength       Length of source
    * @param minimumLength      Required minimum length
    */
   private static int[] getBalancedBlindingLengths(final int sourceLengthLength, final int sourceLength, final int minimumLength) {
      // Java is unable to return multiple values, so an array has to be used to return them
      final int[] result = new int[LENGTHS_LENGTH];

      result[INDEX_LENGTHS_PREFIX_LENGTH] = getBlindingLength();
      result[INDEX_LENGTHS_POSTFIX_LENGTH] = getBlindingLength();

      // If minimumLength is greater than 0 adapt blinding lengths to be at least minimum length when combined.
      if (minimumLength > 0)
         adaptBlindingLengthsToMinimumLength(result, sourceLengthLength, sourceLength, minimumLength);

      return result;
   }

   /**
    * Copy a byte array into another byte array
    *
    * @param sourceBytes      Source byte array
    * @param destinationBytes Destination byte array
    * @param startToIndex     Start index in the destination byte array
    * @return Length of the source bytes
    */
   private static int copyByteArray(final byte[] sourceBytes, final byte[] destinationBytes, final int startToIndex) {
      System.arraycopy(sourceBytes, 0, destinationBytes, startToIndex, sourceBytes.length);

      return sourceBytes.length;
   }

   /**
    * Copy a byte array into another byte array and fill the source byte array with 0s
    *
    * @param sourceBytes      Source byte array
    * @param destinationBytes Destination byte array
    * @param startToIndex     Start index in the destination byte array
    * @return Length of the source bytes
    */
   private static int copyByteArrayAndZapSource(final byte[] sourceBytes, final byte[] destinationBytes, final int startToIndex) {
      final int result = copyByteArray(sourceBytes, destinationBytes, startToIndex);

      ArrayHelper.clear(sourceBytes);

      return result;
   }

   /**
    * Create a blinding array
    *
    * @return New blinding array
    */
   private static byte[] createBlinding(final int blindingLength) {
      final byte[] result = new byte[blindingLength];

      SECURE_PRNG.nextBytes(result);

      return result;
   }
}
