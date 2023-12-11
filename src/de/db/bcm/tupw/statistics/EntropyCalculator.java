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
 *     2020-02-28: V1.0.0: Created. fhs
 *     2020-03-13: V1.1.0: Handle null arguments. fhs
 *     2020-03-23: V1.2.0: Restructured source code according to DBS programming guidelines. fhs
 *     2020-04-28: V1.2.1: Remove unused variable declaration. fhs
 *     2020-05-14: V1.3.0: Expose no. of processed bytes as a read-only property and corrected
 *                         calculation of relative entropy. fhs
 *     2020-12-04: V1.3.1: Corrected several SonarLint findings. fhs
 *     2020-12-29: V1.4.0: Made thread safe. fhs
 *     2020-12-30: V1.4.1: Removed synchronization where it was not necessary. fhs
 *     2023-12-11: V1.4.2: Standard naming convention for instance variables. fhs
 */

package de.db.bcm.tupw.statistics;

import de.db.bcm.tupw.arrays.ArrayHelper;

import java.util.Objects;

/**
 * Class to calculate the entropy of byte arrays
 *
 * @author Frank Schwab
 * @version 1.4.2
 */
public class EntropyCalculator {
   //******************************************************************
   // Private constants
   //******************************************************************
   private final double log2 = Math.log(2);


   //******************************************************************
   // Instance variables
   //******************************************************************
   private final int[] counter = new int[256];  // Array of how many times a specific byte value was counted
   private int byteCount = 0;             // Number of bytes that have been added to the statistic


   //******************************************************************
   // Public methods
   //******************************************************************
   /**
    * Reset the entropy statistics
    */
   public synchronized void reset() {
      ArrayHelper.clear(counter);

      byteCount = 0;
   }

   /**
    * Add bytes of a byte array to the entropy calculation starting from a specified index and
    * ending at another specified index
    *
    * <p>Here we use the strange and counterintuitive Java habit to specify the last index
    * as the one that should <b>not</b> be included.</p>
    *
    * @param aByteArray Byte array to add to the calculation
    * @param fromIndex  Start index (inclusive)
    * @param toIndex    End index (exclusive)
    * @throws NullPointerException if {@code aByteArray} is null
    */
   public synchronized void addBytes(final byte[] aByteArray, final int fromIndex, final int toIndex) {
      Objects.requireNonNull(aByteArray, "Byte array is null");

      int  counterIndex;

      for (int i = fromIndex; i < toIndex; i++) {
         counterIndex = aByteArray[i] & 0xff; // Explicitly calculate the index ...

         counter[counterIndex]++;   // ... as the compiler converts this to "m_Counter[counterIndex] = m_Counter[counterIndex] + 1"
      }

      byteCount += toIndex - fromIndex;
   }

   /**
    * Add bytes of a byte array to entropy calculation starting from a specified index
    *
    * @param aByteArray Byte array to add to the calculation
    * @param fromIndex  Start index (inclusive)
    * @throws NullPointerException if {@code aByteArray} is null
    */
   public synchronized void addBytes(final byte[] aByteArray, final int fromIndex) {
      addBytes(aByteArray, fromIndex, aByteArray.length);
   }

   /**
    * Add all bytes of a byte array to the entropy calculation
    *
    * @param aByteArray Byte array to add to the calculation
    * @throws NullPointerException if {@code aByteArray} is null
    */
   public synchronized void addBytes(final byte[] aByteArray) {
      addBytes(aByteArray, 0, aByteArray.length);
   }

   /**
    * Get the entropy per byte
    *
    * @return Entropy per byte
    */
   public synchronized double getEntropy() {
      double result = 0.0;

      if (byteCount > 0) {
         final double inverseByteCount = 1.0 / byteCount;

         double p;

         for (int value : counter) {
            p = value * inverseByteCount;

            if (p != 0.0)
               result -= p * Math.log(p);
         }
      }

      return result / log2;
   }

   /**
    * Get the relative entropy
    *
    * <p>The relative entropy is a value between 0.0 and 1.0 that says how much of the
    * maximum possible entropy the actual entropy value is.</p>
    *
    * @return Relative entropy
    */
   public double getRelativeEntropy() {
      return getEntropy() * 0.125; // Maximum entropy is 8, so relative entropy is entropy divided by 8
   }

   /**
    * Gets the information content in bits
    *
    * <P>Information content is the entropy per byte times the number of bytes</P>
    *
    * @return Information content in bits
    */
   public synchronized int getInformationInBits() {
      int result = 0;

      if (byteCount > 0)
         result = (int) Math.round((getEntropy() * byteCount));

      return result;
   }

   /**
    * Gets the count of bytes that have been processed
    *
    * @return Number of bytes that have been processed
    */
   public synchronized int getCount() {
      return byteCount;
   }
}
