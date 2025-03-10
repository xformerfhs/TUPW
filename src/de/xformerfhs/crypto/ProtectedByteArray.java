/*
 * SPDX-FileCopyrightText: 2015-2023 DB Systel GmbH
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
 *     2015-09-26: V1.0.0: Created. fhs
 *     2018-08-15: V1.0.1: Added a few more "finals". fhs
 *     2018-08-16: V1.0.2: Made name of SPRNG variable conform to class visible variable name. fhs
 *     2019-03-06: V1.1.0: Store array length in an obfuscated form. fhs
 *     2019-05-17: V1.1.1: Clear data first and then set flag that it is cleared. fhs
 *     2019-08-06: V1.1.2: Use SecureRandomFactory. fhs
 *     2019-08-23: V1.1.3: Use SecureRandom singleton. fhs
 *     2020-03-23: V1.2.0: Restructured source code according to DBS programming guidelines. fhs
 *     2020-12-04: V1.3.0: Corrected several SonarLint findings and made class serializable. fhs
 *     2020-12-29: V1.4.0: Made thread safe. fhs
 *     2021-05-21: V1.5.0: More store size variation for small source sizes, check max source size. fhs
 *     2021-05-27: V2.0.0: Byte array is protected by an index dependent masker now, no more need for an obfuscation array. fhs
 *     2021-06-09: V2.0.1: Simplified constructors. fhs
 *     2021-09-01: V2.0.2: Some refactoring. fhs
 *     2023-12-11: V2.0.3: Standard naming convention for instance variables. fhs
 *     2025-02-22: V2.1.0: Use Fisher-Yates shuffling for shuffling of index array. fhs
 *     2025-03-03: V2.2.0: Simplified creation of shuffled index array. fhs
 */
package de.xformerfhs.crypto;

import de.xformerfhs.arrays.ArrayHelper;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

/**
 * Stores a byte array in a protected form.
 *
 * <p>
 * The array is stored shuffled and masked.
 * </p>
 *
 * @author Frank Schwab
 * @version 2.2.0
 */
public final class ProtectedByteArray implements AutoCloseable {
   // ******** Private constants ********

   /**
    * Indices and data are stored in arrays which are multiples of this block size.
    */
   private static final int INDEX_BLOCK_SIZE = 50;

   /**
    * This class can store at most this many data.
    */
   private static final int MAX_SOURCE_ARRAY_LENGTH = (Integer.MAX_VALUE / INDEX_BLOCK_SIZE) * INDEX_BLOCK_SIZE;

   // Pro forma indices for special data.
   // They can have any negative value.

   /**
    * Pro forma index value for the data length.
    */
   private static final int INDEX_LENGTH =  -3;

   /**
    * Pro forma index value for the start index.
    */
   private static final int INDEX_START  = -97;

   // ******** Instance variables ********

   /**
    * Byte array to store the data in.
    */
   private byte[] dataArray;

   /**
    * Index array into {@code byteArray}.
    */
   private int[] indexArray;

   /**
    * Length of data in {@code byteArray} in obfuscated form.
    */
   private int storedArrayLength;

   /**
    * Start position in index array.
    */
   private int indexStart;

   /**
    * Hash code of data in {@code byteArray}.
    */
   private int hashCode;

   /**
    * Indicator whether the bytes of the source array have changed.
    */
   private boolean hasChanged;

   /**
    * Is data valid?
    */
   private boolean isValid;

   /**
    * Index masker.
    */
   private IndexedMask indexMasker;


   // ******** Constructor ********

   /**
    * Constructor for the protected byte array with a source array.
    *
    * @param sourceArray Source byte array.
    * @throws NullPointerException if {@code sourceArray} is {@code null}.
    * @throws IllegalArgumentException if {@code sourceArray} is too large.
    */
   public ProtectedByteArray(final byte[] sourceArray) {
      this(sourceArray, 0);
   }

   /**
    * Constructor for a protected byte array with a source array and an offset.
    *
    * @param sourceArray Source byte array.
    * @param offset      The offset of the data in the byte array.
    * @throws IllegalArgumentException if {@code sourceArray} is too large or {@code offset}
    *                                  is larger than the array length.
    * @throws NullPointerException if {@code sourceArray} is {@code null}.
    */
   public ProtectedByteArray(final byte[] sourceArray, final int offset) {
      Objects.requireNonNull(sourceArray, "Source array is null");

      initializeInstance(sourceArray, offset, sourceArray.length - offset);
   }

   /**
    * Creates a new {@code ProtectedByteArray} for the specified data
    * starting from {@code offset} with length {@code len}.
    *
    * @param sourceArray Source byte array.
    * @param offset      The offset of the data in the byte array.
    * @param len         The length of the data in the byte array.
    * @throws ArrayIndexOutOfBoundsException if {@code offset} or {@code len} are less than 0.
    * @throws IllegalArgumentException       if {@code sourceArray} is not long enough to get
    *                                        {@code len} bytes from position {@code offset} in
    *                                        array {@code sourceArray}.
    * @throws NullPointerException           if {@code sourceArray} is null
    */
   public ProtectedByteArray(final byte[] sourceArray, final int offset, final int len) {
      Objects.requireNonNull(sourceArray, "Source array is null");

      initializeInstance(sourceArray, offset, len);
   }


   // ******** Public methods ********

   // -------- Access methods --------

   /**
    * Gets the original array content.
    *
    * @return Original array content.
    * @throws IllegalStateException if the protected array has already been destroyed.
    */
   public synchronized byte[] getData() {
      checkState();

      return getValues();
   }

   /**
    * Gets an array element at a given position.
    *
    * @param externalIndex Index of the array element.
    * @return Value of the array element at the given position.
    * @throws ArrayIndexOutOfBoundsException if index is outside of allowed bounds.
    * @throws IllegalStateException          if array has already been destroyed.
    */
   public synchronized byte getAt(final int externalIndex) {
      checkStateAndExternalIndex(externalIndex);

      return (byte) (this.indexMasker.getByteMask(externalIndex) ^ this.dataArray[getArrayIndex(externalIndex)]);
   }

   /**
    * Sets the array element at a given position to a given value.
    *
    * @param externalIndex Index of the array element.
    * @param newValue      New value of the array element.
    * @throws ArrayIndexOutOfBoundsException if index is outside of allowed bounds.
    * @throws IllegalStateException          if array has already been destroyed.
    */
   public synchronized void setAt(final int externalIndex, final byte newValue) {
      checkStateAndExternalIndex(externalIndex);

      this.dataArray[getArrayIndex(externalIndex)] = (byte) (this.indexMasker.getByteMask(externalIndex) ^ newValue);

      this.hasChanged = true;
   }

   /**
    * Gets the real array length.
    *
    * @return Real length of stored array.
    * @throws IllegalStateException if the protected array has already been destroyed.
    */
   public synchronized int length() {
      checkState();

      return getRealLength();
   }

   /**
    * Checks whether this ProtectedByteArray is valid.
    *
    * @return {@code True}, if this ProtectedByteArray is valid.
    * {@code False}, if it has been deleted.
    */
   public synchronized boolean isValid() {
      return this.isValid;
   }

   /**
    * Returns the hash code of this {@code ProtectedByteArray} instance.
    *
    * @return The hash code.
    * @throws IllegalStateException if this protected byte array has already been destroyed.
    */
   @Override
   public synchronized int hashCode() {
      checkState();

      if (this.hasChanged)
         calculateHashCode();

      return this.hashCode;
   }

   /**
    * Compares the specified object with this {@code ProtectedByteArray} instance.
    *
    * @param obj The object to compare.
    * @return {@code true} if byte arrays of both object are equal, otherwise {@code false}.
    * @throws IllegalStateException if the protected array has already been destroyed.
    */
   @Override
   public synchronized boolean equals(final Object obj) {
      if (obj == null)
         return false;

      if (getClass() != obj.getClass())
         return false;

      boolean result;

      byte[] thisClearArray = null;
      byte[] otherClearArray = null;

      try {
         final ProtectedByteArray other = (ProtectedByteArray) obj;
         thisClearArray = this.getData();
         otherClearArray = other.getData();
         result = Arrays.equals(thisClearArray, otherClearArray);
      } finally {
         // Clear sensitive data
         ArrayHelper.safeClear(thisClearArray);
         ArrayHelper.safeClear(otherClearArray);
      }

      return result;
   }

   // -------- Method for AutoCloseable interface --------

   /**
    * Secure deletion of protected array.
    *
    * <p>This method is idempotent and never throws an exception.</p>
    */
   @Override
   public synchronized void close() {
      if (this.isValid)
         clearData();
   }


   // ******** Private methods ********

   // -------- Initialization methods --------

   /**
    * Initialize this instance from a source array.
    *
    * @param sourceArray Array to use as source.
    * @param offset      The offset of the data in the byte array.
    * @param len         The length of the data in the byte array.
    */
   private void initializeInstance(final byte[] sourceArray, final int offset, final int len) {
      checkOffsetAndLength(sourceArray, offset, len);

      initializeDataStructures(len);

      setValues(sourceArray, offset, len);

      calculateHashCode();
   }


   // -------- Check methods --------

   /**
    * Checks whether offset and length are valid for the array.
    *
    * @param sourceArray Source byte array.
    * @param offset      The offset of the data in the byte array.
    * @param len         The length of the data in the byte array.
    * @throws ArrayIndexOutOfBoundsException if {@code offset} or {@code len} are less than 0.
    * @throws IllegalArgumentException       if {@code sourceArray} is not long enough to get {@code len} bytes from position
    *                                        {@code offset} in array {@code sourceArray}.
    */
   private void checkOffsetAndLength(final byte[] sourceArray, final int offset, final int len) {
      if (len > MAX_SOURCE_ARRAY_LENGTH)
         throw new IllegalArgumentException("Source array is too large");

      if ((offset < 0) || (len < 0))
         throw new ArrayIndexOutOfBoundsException("Offset or length less than zero");

      if ((sourceArray.length - offset) < len)
         throw new IllegalArgumentException("Source array too short for offset and length");
   }

   /**
    * Checks whether the protected byte array is in a valid state.
    *
    * @throws IllegalStateException if the protected array has already been destroyed.
    */
   private void checkState() {
      if (!this.isValid)
         throw new IllegalStateException("ProtectedByteArray has already been destroyed");
   }

   /**
    * Checks whether a given external index is valid.
    *
    * @param externalIndex Index value to be checked.
    * @throws ArrayIndexOutOfBoundsException if index is out of array bounds.
    */
   private void checkExternalIndex(final int externalIndex) {
      if ((externalIndex < 0) || (externalIndex >= getRealLength()))
         throw new ArrayIndexOutOfBoundsException("Illegal index " + externalIndex);
   }

   /**
    * Checks the state and then the validity of the given external index.
    *
    * @param externalIndex Index value to be checked.
    * @throws ArrayIndexOutOfBoundsException if index is out of array bounds.
    * @throws IllegalStateException          if the protected array has already been destroyed.
    */
   private void checkStateAndExternalIndex(final int externalIndex) {
      checkState();
      checkExternalIndex(externalIndex);
   }

   // -------- Methods for data structure initialization and maintenance --------

   /**
    * Calculates the array size required for storing the data.
    *
    * @param forSize Original size.
    * @return Size of protected array.
    */
   private int getStoreLength(final int forSize) {
      final int padLength = INDEX_BLOCK_SIZE - (forSize % INDEX_BLOCK_SIZE);

      return forSize + padLength;
   }

   /**
    * Initializes the index array in a shuffled form.
    */
   private void initializeShuffledIndexArray(final SecureRandom sprng) {
      for (int i = 1; i < this.indexArray.length; i++) {
         int j = sprng.nextInt(i+1);
         this.indexArray[i] = this.indexArray[j];
         this.indexArray[j] = i;
      }
   }

   /**
    * Masks the index array.
    */
   private void maskIndexArray() {
      for (int i = 0; i < this.indexArray.length; i++)
         this.indexArray[i] ^= this.indexMasker.getIntMask(i);
   }

   /**
    * Sets up the index array by initializing and shuffling it.
    */
   private void setUpIndexArray(final SecureRandom sprng) {
      initializeShuffledIndexArray(sprng);
      maskIndexArray();
   }

   /**
    * Allocates and initializes all necessary arrays.
    *
    * @param sourceLength Length of source array.
    */
   private void initializeDataStructures(final int sourceLength) {
      this.indexMasker = new IndexedMask();

      final int storeLength = getStoreLength(sourceLength);

      this.dataArray = new byte[storeLength];

      SecureRandom sprng = SecureRandomFactory.getSensibleSingleton();

      sprng.nextBytes(this.dataArray);   // Initialize the data with random values

      this.indexArray = new int[storeLength];

      setUpIndexArray(sprng);

      this.indexStart = convertIndex(getStartIndex(sourceLength, storeLength, sprng), INDEX_START);
      this.storedArrayLength = convertIndex(sourceLength, INDEX_LENGTH);

      this.isValid = true;
   }

   /**
    * Calculate start index.
    *
    * @param sourceLength Length of source.
    * @param storeLength  Length of store.
    * @param sprng        Secure pseudo random number generator.
    * @return             Start index in index array.
    */
   private int getStartIndex(final int sourceLength, final int storeLength, final SecureRandom sprng) {
      final int supStart = storeLength - sourceLength + 1;

      if (supStart > 1)
         return sprng.nextInt(supStart);
      else
         return 0;
   }

   /**
    * Clears all data.
    */
   private void clearData() {
      this.hashCode = 0;

      this.storedArrayLength = 0;

      this.indexStart = 0;

      this.hasChanged = false;

      this.isValid = false;

      ArrayHelper.clear(this.dataArray);
      this.dataArray = null;

      ArrayHelper.clear(this.indexArray);
      this.indexArray = null;

      this.indexMasker = null;
   }

   /**
    * Convert between real index and masked index.
    *
    * @param sourceIndex The index value to convert.
    * @param forPosition The position of the index value.
    * @return Converted index.
    */
   private int convertIndex(final int sourceIndex, final int forPosition) {
      return this.indexMasker.getIntMask(forPosition) ^ sourceIndex;
   }

   /**
    * Gets the array index from the external index.
    *
    * @param externalIndex External index.
    * @return The index into the byte array.
    */
   private int getArrayIndex(final int externalIndex) {
      final int position = externalIndex + convertIndex(this.indexStart, INDEX_START);

      return convertIndex(this.indexArray[position], position);
   }

   /*
    * Methods for accessing data from or to byte array
    */

   /**
    * Gets the real array length without a state check.
    *
    * @return Real length.
    */
   private int getRealLength() {
      return convertIndex(this.storedArrayLength, INDEX_LENGTH);
   }

   /**
    * Sets the destination array to the values in the source array.
    *
    * @param sourceArray Source byte array.
    * @param offset      The offset of the data in the byte array.
    * @param len         The length of the data in the byte array.
    */
   private void setValues(final byte[] sourceArray, final int offset, final int len) {
      int sourceIndex = offset;

      for (int i = 0; i < len; i++) {
         this.dataArray[getArrayIndex(i)] = (byte) (this.indexMasker.getByteMask(i) ^ sourceArray[sourceIndex]);

         sourceIndex++;
      }
   }

   /**
    * Gets the values from the protected array.
    *
    * @return Values stored in protected byte array.
    */
   private byte[] getValues() {
      final byte[] result = new byte[getRealLength()];

      for (int i = 0; i < result.length; i++)
         result[i] = (byte) (this.indexMasker.getByteMask(i) ^ this.dataArray[getArrayIndex(i)]);

      return result;
   }

   /**
    * Calculates the hash code of the content.
    */
   private void calculateHashCode() {
      final byte[] content = getValues();

      this.hashCode = Arrays.hashCode(content);

      ArrayHelper.clear(content);  // Clear sensitive data

      this.hasChanged = false;
   }
}
