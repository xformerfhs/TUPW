/*
 * SPDX-FileCopyrightText: 2016-2023 DB Systel GmbH
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
 * All rights reserved.
 *
 * Changes:
 *     2016-09-26: V2.0.0: Use ProtectedByteArray. fhs
 *     2016-11-24: V2.1.0: Implement "javax.security.auth.Destroyable" interface. fhs
 *     2018-08-15: V2.1.1: Add a few "finals". fhs
 *     2020-03-10: V2.2.0: Make comparable with "SecretKeySpec", constructor argument checks,
 *                         throw IllegalStateExceptions when instance has been closed or destroyed. fhs
 *     2020-03-11: V2.2.1: Add some "throws" statements. fhs
 *     2020-03-13: V2.3.0: Add checks for null. fhs
 *     2020-03-23: V2.4.0: Restructured source code according to DBS programming guidelines. fhs
 *     2020-12-04: V2.5.0: Corrected several SonarLint findings and made class serializable. fhs
 *     2020-12-29: V2.6.0: Make thread safe. fhs
 *     2021-05-26: V2.7.0: This class is no longer serializable. It never should have been. fhs
 *     2021-09-03: V2.7.1: Correct signatures of Serializable methods. fhs
 *     2021-09-28: V2.7.2: Ensure "equals" clears sensitive array data. fhs
 *     2023-04-24: V2.7.3: Use modern generic Class declaration. fhs
 *     2023-05-19: V2.7.4: Make class variables static. fhs
 *     2023-05-20: V2.7.5: Annotate all serial methods. fhs
 *     2023-05-24: V2.7.6: Use "instanceof" for compatible class check. fhs
 *     2024-07-12: V2.8.0: Add constructor with ProtectedByteArray. fhs
 *     2024-07-19: V2.9.0: Use class for compatible class check. fhs
 */

package de.xformerfhs.crypto;

import de.xformerfhs.arrays.ArrayHelper;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.Destroyable;
import java.io.*;
import java.security.spec.KeySpec;
import java.util.Objects;

/**
 * A key specification for a {@code SecretKey} and also a secret key
 * implementation that is provider-independent. It can be used for raw secret
 * keys that can be specified as {@code byte[]}.
 *
 * <p>It is intended to be used as a drop-in replacement for {@code SecretKeySpec}.</p>
 *
 * @author Frank Schwab
 * @version 2.9.0
 */
public class SecureSecretKeySpec
      implements KeySpec, SecretKey, Destroyable, AutoCloseable {
   // ======== Class constants ========

   /*
    * This class implements the Serialization interface because it is inherited from SecretKey
    * but throws an exception whenever a serialization or deserialization is attempted.
    * A secret key must *never* be serializable as this leads to security vulnerabilities.
    */

   /**
    * Serial version UID for Serializable interface that is inherited from {@code javax.crypto.SecretKey}
    * which inherits it from {@code java.security.Key}
    */
   @Serial
   private static final long serialVersionUID = -6754161938847519344L;

   /**
    * This class for class tests.
    */
   private static final Class<?> thisClass = SecureSecretKeySpec.class;

   /**
    * Compatible class for class tests.
    */
   private static final Class<?> secretKeySpecClass = SecretKeySpec.class;


   // ======== Instance variables ========

   /**
    * The secret key to hide.
    */
   private final transient ProtectedByteArray key;

   /**
    * The algorithm name to hide.
    */
   private final transient ProtectedByteArray algorithm;

   /**
    * Is this instance valid
    */
   private transient boolean isValid;


   // ======== Constructors ========

   /**
    * Create a new {@code SecureSecretKeySpec} for the specified {@code key}
    * and {@code algorithm}.
    *
    * @param key       Key.
    * @param algorithm Algorithm name.
    * @throws NullPointerException if {@code key} or {@code algorithm} is null
    */
   public SecureSecretKeySpec(final byte[] key, final String algorithm) {
      // All the functionality of the other constructor has to be duplicated here
      // just because of the Java strangeness that a call to another constructor
      // *must* be the first statement in a constructor. This does not make sense,
      // at all! Real object-oriented languages do not have this limitation.

      checkKeyAndAlgorithm(key, algorithm);

      this.key = new ProtectedByteArray(key);

      this.algorithm = createNewAlgorithmArray(algorithm);

      this.isValid = true;
   }

   /**
    * Create a new {@code SecureSecretKeySpec} for the key data from the
    * specified buffer {@code key} starting at {@code offset} with
    * length {@code len} and the specified {@code algorithm} name.
    *
    * @param key       Key.
    * @param offset    Offset into the key.
    * @param len       Length of key.
    * @param algorithm Algorithm name.
    * @throws ArrayIndexOutOfBoundsException if {@code offset} or {@code len} is negative.
    * @throws IllegalArgumentException       if {@code key} or {@code algorithm} is empty or {@code offset} and {@code len}
    *                                        do not specify a valid chunk in the {@code key}.
    * @throws NullPointerException           if {@code key} or {@code algorithm} is null
    */
   public SecureSecretKeySpec(final byte[] key, final int offset, final int len, final String algorithm) {
      checkKeyAndAlgorithm(key, algorithm);

      this.key = new ProtectedByteArray(key, offset, len);

      this.algorithm = createNewAlgorithmArray(algorithm);
   }

   /**
    * Create a new {@code SecureSecretKeySpec} for the key data from the
    * specified protected byte array {@code key}.
    *
    * @param key       {@code ProtectedByteArray} with the key.
    * @param algorithm Algorithm name.
    * @throws ArrayIndexOutOfBoundsException if {@code offset} or {@code len} is negative.
    * @throws IllegalArgumentException       if {@code key} or {@code algorithm} is empty.
    * @throws NullPointerException           if {@code key} or {@code algorithm} is null
    */
   public SecureSecretKeySpec(final ProtectedByteArray key, final String algorithm) {
      // All the functionality of the other constructor has to be duplicated here
      // just because of the Java strangeness that a call to another constructor
      // *must* be the first statement in a constructor. This does not make sense,
      // at all! Real object-oriented languages do not have this limitation.

      byte[] keyBytes = key.getData();
      checkKeyAndAlgorithm(keyBytes, algorithm);
      this.key = new ProtectedByteArray(keyBytes);
      ArrayHelper.clear(keyBytes);

      this.algorithm = createNewAlgorithmArray(algorithm);

      this.isValid = true;
   }


   // ======== Public methods ========

   // -------- Interface methods --------

   /**
    * Return the algorithm name.
    *
    * @return Algorithm name.
    * @throws IllegalStateException if this instance has already been destroyed.
    */
   @Override
   public synchronized String getAlgorithm() {
      checkState();

      return new String(this.algorithm.getData());
   }

   /**
    * Return the name of the format used to encode the key.
    *
    * @return Format name "RAW".
    * @throws IllegalStateException if this instance has already been destroyed.
    */
   @Override
   public synchronized String getFormat() {
      checkState();

      return "RAW";
   }

   /**
    * Return the encoded form of this secret key.
    *
    * @return Encoded form of this secret key.
    * @throws IllegalStateException if this instance has already been destroyed.
    */
   @Override
   public synchronized byte[] getEncoded() {
      checkState();

      return this.key.getData();
   }

   /**
    * Return the hash code of this {@code SecureSecretKeySpec} instance.
    *
    * @return Hash code.
    * @throws IllegalStateException if this instance has already been destroyed.
    */
   @Override
   public synchronized int hashCode() {
      checkState();

      // Java does not indicate an over- or underflow, so it is safe
      // to multiply with a number that will overflow on multiplication
      return this.key.hashCode() * 79 + this.algorithm.hashCode();
   }

   /**
    * Compare the specified object with this {@code SecureSecretKeySpec} instance.
    *
    * @param obj Object to compare.
    * @return {@code true} if the algorithm name and key of both object are equal, otherwise {@code false}.
    * @throws IllegalStateException if this instance has already been destroyed.
    */
   @Override
   public synchronized boolean equals(final Object obj) {
      checkState();

      if (obj == null)
         return false;

      final Class<?> objClass = obj.getClass();
      if (thisClass != objClass &&
          secretKeySpecClass != objClass)
         return false;

      final SecretKey other = (SecretKey) obj;

      boolean result = this.getAlgorithm().equalsIgnoreCase(other.getAlgorithm());

      if (result) {
         byte[] thisKey = null;
         byte[] otherKey = null;

         try {
            thisKey = this.getEncoded();
            otherKey = other.getEncoded();

            result = ArrayHelper.constantTimeEquals(thisKey, otherKey);
         } finally {
            ArrayHelper.safeClear(thisKey);
            ArrayHelper.safeClear(otherKey);
         }
      }

      return result;
   }


   // ======== AutoCloseable interface ========

   /**
    * Secure deletion of key and algorithm.
    *
    * <p>This method is idempotent and never throws an exception.</p>
    */
   @Override
   public synchronized void close() {
      if (this.isValid) {
         this.key.close();
         this.algorithm.close();
         this.isValid = false;
      }
   }


   // ======== Destroyable interface ========

   /**
    * Secure destruction of this instance.
    *
    * <p>This method is idempotent and never throws an exception.</p>
    */
   @Override
   public synchronized void destroy() {
      this.close();
   }

   /**
    * Check if this instance is destroyed.
    */
   @Override
   public synchronized boolean isDestroyed() {
      return !this.isValid;
   }

   /**
    * Check if this SecureSecretKeySpec is valid.
    *
    * @return {@code true}, if this instance is valid. {@code false}, if it has been closed/deleted.
    */
   public synchronized boolean isValid() {
      return this.isValid;
   }


   // ======== Private methods ========

   // -------- Check methods --------

   /**
    * Check if the key and the algorithm are valid.
    *
    * @param key       Key array.
    * @param algorithm Algorithm name.
    * @throws IllegalArgumentException if {@code algorithm} or {@code key} is empty.
    * @throws NullPointerException     if {@code algorithm} or {@code key} is null.
    */
   private void checkKeyAndAlgorithm(final byte[] key, final String algorithm) {
      checkKey(key);
      checkAlgorithm(algorithm);
   }

   /**
    * Check if algorithm is valid.
    *
    * @param algorithm Algorithm name.
    * @throws IllegalArgumentException if {@code algorithm} is empty.
    * @throws NullPointerException     if {@code algorithm} is null.
    */
   private void checkAlgorithm(final String algorithm) {
      Objects.requireNonNull(algorithm, "Algorithm is null");

      if (algorithm.isEmpty())
         throw new IllegalArgumentException("Algorithm is empty");
   }

   /**
    * Check if key is valid.
    *
    * @param key Key array.
    * @throws IllegalArgumentException if {@code key} is empty.
    * @throws NullPointerException     if {@code key} is null.
    */
   private void checkKey(final byte[] key) {
      Objects.requireNonNull(key, "Key is null");

      if (key.length == 0)
         throw new IllegalArgumentException("Key is empty");
   }

   /**
    * Checks if this instance is in a valid state.
    *
    * @throws IllegalStateException if this instance has already been destroyed.
    */
   private void checkState() {
      if (!this.isValid)
         throw new IllegalStateException("SecureSecretKeySpec has already been destroyed");
   }


   // -------- Implementation --------

   /**
    * Create a new ProtectedByteArray for the algorithm name.
    *
    * @param algorithm Algorithm name.
    * @return ProtectedByteArray that hides the algorithm name.
    */
   private ProtectedByteArray createNewAlgorithmArray(final String algorithm) {
      final byte[] algorithmBytes = algorithm.getBytes();

      final ProtectedByteArray result = new ProtectedByteArray(algorithmBytes);

      ArrayHelper.clear(algorithmBytes); // Clear sensitive data

      return result;
   }


   // ======== Serializable interface ========

   // We do not serialize a secret key

   @Serial
   private void writeObject(ObjectOutputStream out) throws IOException {
      throw new NotSerializableException("Secret keys must not be serialized");
   }

   @Serial
   private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
      throw new NotSerializableException("Secret keys must not be deserialized");
   }

   @Serial
   private void readObjectNoData() throws ObjectStreamException {
      throw new NotSerializableException("Secret keys must not be deserialized");
   }
}
