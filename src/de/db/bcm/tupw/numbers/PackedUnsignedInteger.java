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
 *     2018-08-20: V1.1.0: Expand valuation of 2 to 4 byte compressed numbers. fhs
 *     2018-12-11: V1.1.1: Clarify exceptions and comments. fhs
 *     2019-03-07: V1.2.0: Added "toString" method. fhs
 *     2020-03-13: V1.3.0: Added checks for null. fhs
 *     2020-03-23: V1.4.0: Restructured source code according to DBS programming guidelines. fhs
 *     2020-04-22: V1.5.0: Corrected ranges for 3 and 4 byte values. fhs
 *     2020-04-22: V1.5.1: Removed unnecessary check and corrected some comments. fhs
 *     2020-12-04: V1.5.2: Corrected several SonarLint findings. fhs
 *     2020-12-29: V1.6.0: Made thread safe. fhs
 *     2024-05-12: V2.0.0: Complete rewrite with much less complexity. fhs
 */
package de.db.bcm.tupw.numbers;

import java.util.Arrays;
import java.util.Objects;

/**
 * Converts integers from and to an unsigned packed byte array
 *
 * @author FrankSchwab
 * @version 2.0.0
 */
public class PackedUnsignedInteger {
   //******************************************************************
   // Private constants
   //******************************************************************

   /** Minimum allowed value */
   private static final int MIN_INT_VALUE = 0;
   /** Maximum allowed value */
   private static final int MAX_INT_VALUE = 0x40404040 - 1;

   /** Offset for one result byte */
   private static final int OFFSET = 0x40;

   /** How many values can a byte hold */
   private static final int BYTE_RANGE = 256;
   /** Number of bits to shift a byte */
   private static final int BYTE_SHIFT = 8;
   /** Number of bits to shift for a length */
   private static final int LENGTH_SHIFT = BYTE_SHIFT - 2;

   /** Maximum result length */
   private static final int MAX_RESULT_LENGTH = 4;
   /** Maximum result index */
   private static final int MAX_RESULT_INDEX = MAX_RESULT_LENGTH - 1;

   /** Mask to get rid of the length bits */
   private static final int NO_LENGTH_MASK = 0x3f;
   /** Mask to get the byte of an integer */
   private static final int BYTE_MASK = 0xff;

   //******************************************************************
   // Constructor
   //******************************************************************

   /**
    * Private constructor
    *
    * <p>This class is not meant to be instanced.</p>
    */
   private PackedUnsignedInteger() {
      throw new IllegalStateException("This class is not meant to be instanced");
   }


   //******************************************************************
   // Public methods
   //******************************************************************

   /**
    * Convert an integer into a packed decimal byte array
    * <p>
    * Valid integers range from 0 to 1,077,952,575.
    * All other numbers throw an {@code IllegalArgumentException}
    * </p>
    *
    * @param anInteger Integer to convert
    * @return Packed decimal byte array with integer as value
    * @throws IllegalArgumentException if {@code aNumber} has not a value between 0 and 1,077,952,575 (inclusive)
    */
   public static synchronized byte[] fromInteger(final int anInteger) {
      if (anInteger < MIN_INT_VALUE)
         throw new IllegalArgumentException("Integer must not be negative");

      if (anInteger > MAX_INT_VALUE)
         throw new IllegalArgumentException("Integer too large for packed integer");

      byte[] result = new byte[MAX_RESULT_LENGTH];
      int intermediateInteger = anInteger;
      int actIndex = MAX_RESULT_INDEX;
      for (; intermediateInteger >= OFFSET; actIndex--) {
         int b = intermediateInteger & BYTE_MASK;
         intermediateInteger >>>= BYTE_SHIFT;

         if (b >= OFFSET) {
            b -= OFFSET;
         } else {
            b += (BYTE_RANGE - OFFSET);
            intermediateInteger--;
         }

         result[actIndex] = (byte)b;
      }

      final int resultLengthBits = (MAX_RESULT_INDEX - actIndex);
      // Leftmost byte is length bits and value
      result[actIndex] = (byte)(intermediateInteger |
                                resultLengthBits << LENGTH_SHIFT);

      // Return result if it is 4 bytes long
      // and a slice of the result, if it is less than 4 bytes long
      if (resultLengthBits == MAX_RESULT_INDEX)
         return result;
      else
         return Arrays.copyOfRange(result, actIndex, MAX_RESULT_LENGTH);
   }

   /**
    * Get expected length of packed decimal byte array from first byte
    *
    * @param firstByteOfPackedNumber First byte of packed decimal integer
    * @return Expected length (1 to 4)
    */
   public static synchronized int getExpectedLength(final byte firstByteOfPackedNumber) {
      return ((firstByteOfPackedNumber >>> 6) & 0x03) + 1;
   }

   /**
    * Convert a packed decimal byte array into an integer
    *
    * @param packedNumber Packed decimal byte array
    * @return Converted integer (value between 0 and 1,077,952,575)
    * @throws IllegalArgumentException if the actual length of the packed number does not match the expected length
    * @throws NullPointerException     if {@code packedNumber} is {@code null}
    */
   public static synchronized int toInteger(final byte[] packedNumber) {
      Objects.requireNonNull(packedNumber, "Packed number is null");

      final int expectedLength = getExpectedLength(packedNumber[0]);

      if (expectedLength != packedNumber.length)
         throw new IllegalArgumentException("Actual length of packed integer array does not match expected length");

      int result = packedNumber[0] & NO_LENGTH_MASK;
      for (int i = 1; i < expectedLength; i++) {
         result = ((result << 8) | (packedNumber[i] & BYTE_MASK)) + OFFSET;
      }

      return result;
   }

   /**
    * Convert a packed decimal byte array in a larger array to an integer
    *
    * @param arrayWithPackedNumber Array where the packed decimal byte array resides
    * @param startIndex            Start index of decimal byte array
    * @return Converted integer
    * @throws IllegalArgumentException if the array is not long enough
    * @throws NullPointerException     if {@code arrayWithPackedNumber} is {@code null}
    */
   public static synchronized int toInteger(final byte[] arrayWithPackedNumber, final int startIndex) {
      Objects.requireNonNull(arrayWithPackedNumber, "Packed number array is null");

      final int expectedLength = getExpectedLength(arrayWithPackedNumber[startIndex]);

      if ((startIndex + expectedLength) <= arrayWithPackedNumber.length)
         return toInteger(Arrays.copyOfRange(arrayWithPackedNumber, startIndex, startIndex + expectedLength));
      else
         throw new IllegalArgumentException("Array too short for packed integer");
   }

   /**
    * Convert a decimal byte array that is supposed to be a packed unsigned integer
    * into a string
    *
    * @param aPackedUnsignedInteger Byte array of packed unsigned integer
    * @return String representation of the given packed unsigned integer
    * @throws NullPointerException if {@code arrayWithPackedNumber} is {@code null}
    */
   public static synchronized String toString(final byte[] aPackedUnsignedInteger) {
      return Integer.toString(PackedUnsignedInteger.toInteger(aPackedUnsignedInteger));
   }
}
