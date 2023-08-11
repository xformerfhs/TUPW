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
 *     2020-03-23: V1.0.0: Created. fhs
 *     2020-12-29: V1.1.0: Made thread safe. fhs
 *     2021-09-03: V1.1.1: Fixed comparison with constant of wrong type. fhs
 */

package de.db.bcm.tupw.numbers;

/**
 * Common class for a simple pseudo-random number generator that only supports getting numbers one by one.
 *
 * <p>All subclasses need to implement the {@code nextLong()} method. All other {@code next} methods are implemented here.</p>
 *
 * @author Frank Schwab
 * @version 1.1.1
 */
public class SimplePseudoRandomNumberGenerator {
   //******************************************************************
   // Public methods
   //******************************************************************

   /**
    * Get a pseudo-random {@code long} value.
    *
    * <p><b>Attention:</b> This method <b>must</b> be overridden by subclasses.</p>
    *
    * @return Never
    * @throws UnsupportedOperationException as this method <b>must</b> be overridden
    */
   public synchronized long nextLong() {
      throw new UnsupportedOperationException("Method must be overridden");
   }  // This method *must* be overridden

   /**
    * Get a pseudo-random {@code int} value
    *
    * @return Pseudo-random {@code int}
    */
   public synchronized int nextInt() {
      return (int) (this.nextLong() >>> 32);
   }

   /**
    * Get a pseudo-random {@code short} value
    *
    * @return Pseudo-random {@code short}
    */
   public synchronized short nextShort() {
      return (short) (this.nextLong() >>> 48);
   }

   /**
    * Get a pseudo-random {@code byte} value
    *
    * @return Pseudo-random {@code byte}
    */
   public synchronized byte nextByte() {
      return (byte) (this.nextLong() >>> 56);
   }

   /*
    * The following methods all implement the same algorithm for getting an equally distributed
    * pseudo-random number in a range for the specified data type.
    */

   /**
    * Get a pseudo-random long in a range
    *
    * @param fromInclusive Start value (inclusive)
    * @param toInclusive   End value (inclusive)
    * @return Pseudo-random number in the specified range
    */
   public synchronized long nextLong(long fromInclusive, long toInclusive) {
      long result;

      // Calculate the size of the interval that should be returned
      final long size = toInclusive - fromInclusive + 1L;  // This may be negative
      final long maxValue = size - 1L;  // This may be negative

      // If the size is a power of 2 we are done
      if ((size & maxValue) == 0L)
         result = (this.nextLong() & maxValue);
      else {
         // Size is not a power of two, so we need to calculate a pseudo-random
         // number that is not biased

         // Calculate the mask for the smallest power of two that is larger than maxValue
         long mask = -1L;
         mask >>>= Long.numberOfLeadingZeros(maxValue | 1L);

         // Now get a random number with the mask laid over it and reject all values that are too large
         do {
            result = (this.nextLong() & mask);
         } while (Long.compareUnsigned(result, maxValue) > 0);
      }

      // Return the calculated pseudo-random number in the interval plus the
      // minimum value
      return result + fromInclusive;
   }

   /**
    * Get a pseudo-random int in a range
    *
    * @param fromInclusive Start value (inclusive)
    * @param toInclusive   End value (inclusive)
    * @return Pseudo-random number in the specified range
    */
   public synchronized int nextInt(int fromInclusive, int toInclusive) {
      long result;

      // Calculate the size of the interval that should be returned
      final long size = (long) toInclusive - (long) fromInclusive + 1L;  // This is always nonnegative
      final long maxValue = size - 1L;  // This is always nonnegative

      // If the size is a power of 2 we are done
      if ((size & maxValue) == 0L)
         result = this.nextInt() & maxValue;
      else {
         // Size is not a power of two, so we need to calculate a pseudo-random
         // number that is not biased

         // Calculate the mask for the smallest power of two that is larger than maxValue
         long mask = -1;
         mask >>>= Long.numberOfLeadingZeros(maxValue | 1);

         // Now get a random number with the mask laid over it and reject all values that are too large
         do {
            result = this.nextInt() & mask;
         } while (result > maxValue);
      }

      // Return the calculated pseudo-random number in the interval plus the
      // minimum value
      return (int) (result + fromInclusive);
   }

   /**
    * Get a pseudo-random short in a range
    *
    * @param fromInclusive Start value (inclusive)
    * @param toInclusive   End value (inclusive)
    * @return Pseudo-random number in the specified range
    */
   public synchronized short nextShort(short fromInclusive, short toInclusive) {
      int result;

      // Calculate the size of the interval that should be returned
      final int size = toInclusive - fromInclusive + 1;  // This is always nonnegative
      final int maxValue = size - 1;  // This is always nonnegative

      // If the size is a power of 2 we are done
      if ((size & maxValue) == 0)
         result = this.nextShort() & maxValue;
      else {
         // Size is not a power of two, so we need to calculate a pseudo-random
         // number that is not biased

         // Calculate the mask for the smallest power of two that is larger than maxValue
         int mask = -1;
         mask >>>= Integer.numberOfLeadingZeros(maxValue | 1);

         // Now get a random number with the mask laid over it and reject all values that are too large
         do {
            result = this.nextShort() & mask;
         } while (result > maxValue);
      }

      // Return the calculated pseudo-random number in the interval plus the
      // minimum value
      return (short) (result + fromInclusive);
   }

   /**
    * Get a pseudo-random byte in a range
    *
    * @param fromInclusive Start value (inclusive)
    * @param toInclusive   End value (inclusive)
    * @return Pseudo-random number in the specified range
    */
   public synchronized byte nextByte(byte fromInclusive, byte toInclusive) {
      int result;

      // Calculate the size of the interval that should be returned
      final int size = toInclusive - fromInclusive + 1;  // This is always nonnegative
      final int maxValue = size - 1;  // This is always nonnegative

      // If the size is a power of 2 we are done
      if ((size & maxValue) == 0)
         result = this.nextByte() & maxValue;
      else {
         // Size is not a power of two, so we need to calculate a pseudo-random
         // number that is not biased

         // Calculate the mask for the smallest power of two that is larger than maxValue
         int mask = -1;
         mask >>>= Integer.numberOfLeadingZeros(maxValue | 1);

         // Now get a random number with the mask laid over it and reject all values that are too large
         do {
            result = this.nextByte() & mask;
         } while (result > maxValue);
      }

      // Return the calculated pseudo-random number in the interval plus the
      // minimum value
      return (byte) (result + fromInclusive);
   }
}
