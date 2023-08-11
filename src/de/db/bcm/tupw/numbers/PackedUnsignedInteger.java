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
 *     2018-08-20: V1.1.0: Expand valuation of 2 to 4 byte compressed numbers. fhs
 *     2018-12-11: V1.1.1: Clarify exceptions and comments. fhs
 *     2019-03-07: V1.2.0: Added "toString" method. fhs
 *     2020-03-13: V1.3.0: Added checks for null. fhs
 *     2020-03-23: V1.4.0: Restructured source code according to DBS programming guidelines. fhs
 *     2020-04-22: V1.5.0: Corrected ranges for 3 and 4 byte values. fhs
 *     2020-04-22: V1.5.1: Removed unnecessary check and corrected some comments. fhs
 *     2020-12-04: V1.5.2: Corrected several SonarLint findings. fhs
 *     2020-12-29: V1.6.0: Made thread safe. fhs
 */
package de.db.bcm.tupw.numbers;

import java.util.Arrays;
import java.util.Objects;

/**
 * Converts integers from and to an unsigned packed byte array
 *
 * @author FrankSchwab
 * @version 1.6.0
 */
public class PackedUnsignedInteger {
   //******************************************************************
   // Private constants
   //******************************************************************

   /*
    * Range start values
    */
   private static final int START_2_BYTE_VALUE = 0x40;
   private static final int START_3_BYTE_VALUE = 0x4040;
   private static final int START_4_BYTE_VALUE = 0x404040;
   private static final int START_TOO_LARGE_VALUE = 0x40404040;

   /*
    * Constants for masks
   */
   private static final int NO_LENGTH_MASK = 0x3f;
   private static final int BYTE_MASK = 0xff;

   /*
    * Constants for length indicators
    */
   // private static final byte LENGTH_1_MASK = (byte) 0;
   private static final byte LENGTH_2_MASK = (byte) 0x40;
   private static final byte LENGTH_3_MASK = (byte) 0x80;
   private static final byte LENGTH_4_MASK = (byte) 0xc0;

   //******************************************************************
   // Constructor
   //******************************************************************

   /**
    * Private constructor
    *
    * <p>This class is not meant to be instantiated.</p>
    */
   private PackedUnsignedInteger() {
      throw new IllegalStateException("Utility class");
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
      byte[] result;
      int intermediateInteger;

      if (anInteger >= 0)
         if (anInteger < START_2_BYTE_VALUE) {
            result = new byte[1];
            result[0] = (byte) anInteger;
         } else if (anInteger < START_3_BYTE_VALUE) {
            result = new byte[2];
            intermediateInteger = anInteger - START_2_BYTE_VALUE;

            result[1] = (byte) (intermediateInteger & BYTE_MASK);

            intermediateInteger >>>= 8;
            result[0] = (byte) (LENGTH_2_MASK | intermediateInteger);
         } else if (anInteger < START_4_BYTE_VALUE) {
            result = new byte[3];
            intermediateInteger = anInteger - START_3_BYTE_VALUE;

            result[2] = (byte) (intermediateInteger & BYTE_MASK);

            intermediateInteger >>>= 8;
            result[1] = (byte) (intermediateInteger & BYTE_MASK);

            intermediateInteger >>>= 8;
            result[0] = (byte) (LENGTH_3_MASK | intermediateInteger);
         } else if (anInteger < START_TOO_LARGE_VALUE) {
            result = new byte[4];
            intermediateInteger = anInteger - START_4_BYTE_VALUE;

            result[3] = (byte) (intermediateInteger & BYTE_MASK);

            intermediateInteger >>>= 8;
            result[2] = (byte) (intermediateInteger & BYTE_MASK);

            intermediateInteger >>>= 8;
            result[1] = (byte) (intermediateInteger & BYTE_MASK);

            intermediateInteger >>>= 8;
            result[0] = (byte) (LENGTH_4_MASK | intermediateInteger);
         } else
            throw new IllegalArgumentException("Integer too large for packed integer");
      else
         throw new IllegalArgumentException("Integer must not be negative");

      return result;
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

      int result = 0;

      final int expectedLength = getExpectedLength(packedNumber[0]);

      if (expectedLength == packedNumber.length)
         switch (expectedLength) {
            case 1:
               result = (packedNumber[0] & NO_LENGTH_MASK);
               break;

            case 2:
               result = (((packedNumber[0] & NO_LENGTH_MASK) << 8) |
                        (packedNumber[1] & BYTE_MASK)) +
                        START_2_BYTE_VALUE;
               break;

            case 3:
               result = (((((packedNumber[0] & NO_LENGTH_MASK) << 8) |
                            (packedNumber[1] & BYTE_MASK)) << 8) |
                            (packedNumber[2] & BYTE_MASK)) +
                        START_3_BYTE_VALUE;
               break;

            case 4:
               result = (((((((packedNumber[0] & NO_LENGTH_MASK) << 8) |
                              (packedNumber[1] & BYTE_MASK)) << 8) |
                              (packedNumber[2] & BYTE_MASK)) << 8) |
                              (packedNumber[3] & BYTE_MASK)) +
                        START_4_BYTE_VALUE;
               break;

            // There is no "else" case as all possible values of "expectedLength" are covered
         }
      else
         throw new IllegalArgumentException("Actual length of packed integer array does not match expected length");

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
   public static synchronized int toIntegerFromArray(final byte[] arrayWithPackedNumber, final int startIndex) {
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
