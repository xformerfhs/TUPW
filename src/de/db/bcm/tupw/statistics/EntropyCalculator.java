/*
 * Copyright (c) 2020, DB Systel GmbH
 * All rights reserved.
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
 * Author: Frank Schwab, DB Systel GmbH
 *
 * Changes:
 *     2020-02-28: V1.0.0: Created. fhs
 *     2020-03-13: V1.1.0: Handle null arguments. fhs
 *     2020-03-23: V1.2.0: Restructured source code according to DBS programming guidelines. fhs
 */

package de.db.bcm.tupw.statistics;

import java.util.Arrays;
import java.util.Objects;

/**
 * Class to calculate the entropy of byte arrays
 *
 * @author Frank Schwab
 * @version 1.2.0
 */
public class EntropyCalculator {
   //******************************************************************
   // Private constants
   //******************************************************************
   private final double LOG_2 = Math.log(2);


   //******************************************************************
   // Instance variables
   //******************************************************************
   private final int[] m_Counter = new int[256];  // Array of how many times a specific byte value was counted
   private int m_ByteCount = 0;             // Number of bytes that have been added to the statistic


   //******************************************************************
   // Public methods
   //******************************************************************
   /**
    * Reset the entropy statistics
    */
   public void reset() {
      Arrays.fill(m_Counter, 0);

      m_ByteCount = 0;
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
   public void addBytes(final byte[] aByteArray, final int fromIndex, final int toIndex) throws NullPointerException {
      Objects.requireNonNull(aByteArray, "Byte array is null");

      byte aByte;
      int  counterIndex;

      for (int i = fromIndex; i < toIndex; i++) {
         counterIndex = aByteArray[i] & 0xff; // Explicitly calculate the index ...

         m_Counter[counterIndex]++;   // ... as the compiler converts this to "m_Counter[counterIndex] = m_Counter[counterIndex] + 1"
      }

      m_ByteCount += toIndex - fromIndex;
   }

   /**
    * Add bytes of a byte array to entropy calculation starting from a specified index
    *
    * @param aByteArray Byte array to add to the calculation
    * @param fromIndex  Start index (inclusive)
    * @throws NullPointerException if {@code aByteArray} is null
    */
   public void addBytes(final byte[] aByteArray, final int fromIndex) throws NullPointerException {
      addBytes(aByteArray, fromIndex, aByteArray.length);
   }

   /**
    * Add all bytes of a byte array to the entropy calculation
    *
    * @param aByteArray Byte array to add to the calculation
    * @throws NullPointerException if {@code aByteArray} is null
    */
   public void addBytes(final byte[] aByteArray) throws NullPointerException {
      addBytes(aByteArray, 0, aByteArray.length);
   }

   /**
    * Get the entropy per byte
    *
    * @return Entropy per byte
    */
   public double getEntropy() {
      double result = 0.0;

      if (m_ByteCount > 0) {
         final double inverseByteCount = 1.0 / m_ByteCount;

         double p;

         for (int value : m_Counter) {
            p = value * inverseByteCount;

            if (p != 0.0)
               result -= p * Math.log(p);
         }
      }

      return result / LOG_2;
   }

   /**
    * Get the relative entropy
    *
    * <p>The relative entropy is a value between 0.0 and 1.0 that says how much of the
    * maximum possible entropy the actual entropy value is.</p>
    *
    * @return Relative entropy
    * @throws UnsupportedOperationException if there are not enough bytes sampled
    */
   public double getRelativeEntropy() throws UnsupportedOperationException {
      if (m_ByteCount > 1)
         return getEntropy() / Math.log(m_ByteCount) * LOG_2;
      else
         throw new UnsupportedOperationException("At least 2 bytes are needed to calculate the relative entropy");
   }

   /**
    * Gets the information content in bits
    *
    * <P>Information content is the entropy per byte times the number of bytes</P>
    *
    * @return Information content in bits
    */
   public int getInformationInBits() {
      int result = 0;

      if (m_ByteCount > 0)
         result = (int) Math.round((getEntropy() * m_ByteCount));

      return result;
   }
}