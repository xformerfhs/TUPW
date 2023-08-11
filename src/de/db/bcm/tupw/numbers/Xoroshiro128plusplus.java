/*
 * SPDX-FileCopyrightText: 2020-2023 DB Systel GmbH
 * SPDX-FileCopyrightText: 2023 Frank Schwab
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * This is an implementation of the Xoroshiro128plusplus pseudo-random number generator
 * written in 2019 by David Blackman and Sebastiano Vigna.
 *
 * It is derived from the C source code at http://prng.di.unimi.it/xoroshiro128plusplus.c.
 *
 * The source code there has the following comment which is reproduced here:
 *
 * Written in 2019 by David Blackman and Sebastiano Vigna (vigna@acm.org)
 *
 * To the extent possible under law, the author has dedicated all copyright
 * and related and neighboring rights to this software to the public domain
 * worldwide. This software is distributed without any warranty.
 *
 * See <http://creativecommons.org/publicdomain/zero/1.0/>.
 *
 * This is xoroshiro128++ 1.0, one of our all-purpose, rock-solid,
 * small-state generators. It is extremely (sub-ns) fast and it passes all
 * tests we are aware of, but its state space is large enough only for
 * mild parallelism.
 *
 * For generating just floating-point numbers, xoroshiro128+ is even
 * faster (but it has a very mild bias, see notes in the comments).
 *
 * The state must be seeded so that it is not everywhere zero. If you have
 * a 64-bit seed, we suggest to seed a splitmix64 generator and use its
 * output to fill the state.
 *
 * Changes:
 *     2020-02-27: V1.0.0: Created. fhs
 *     2020-03-13: V1.1.0: Check for null. fhs
 *     2020-03-23: V1.2.0: Restructured source code according to DBS programming guidelines. fhs
 *     2020-12-04: V1.2.1: Corrected several SonarLint findings. fhs
 *     2020-12-29: V1.3.0: Made thread safe. fhs
 */

package de.db.bcm.tupw.numbers;

import java.util.Objects;

/**
 * Xoroshiro128plusplus pseudo-random number generator
 *
 * <p>It is derived from the <a href="http://prng.di.unimi.it/xoroshiro128plusplus.c">C source code</a>.</p>
 *
 * @author Frank Schwab
 * @version 1.3.0
 */
public class Xoroshiro128plusplus extends SimplePseudoRandomNumberGenerator {
   //******************************************************************
   // Instance variables
   //******************************************************************

   /**
    * The state variables
    */
   long m_State0 = -1L;
   long m_State1 = 1L;


   //******************************************************************
   // Constructors
   //******************************************************************

   /**
    * Constructor for Xoroshiro128plusplus with seed
    *
    * @param seed Initial seed
    */
   public Xoroshiro128plusplus(final long seed) {
      initializeState(seed);
   }

   /**
    * Constructor for Xoroshiro128plusplus with seed
    *
    * @param seed Initial seed
    * @throws NullPointerException if {@code seed} is null
    */
   public Xoroshiro128plusplus(final Long seed) {
      Objects.requireNonNull(seed, "Seed is null");

      // In a real object-oriented language one would place "this(seed.longValue());"
      // here. But this is Java, so it is not possible to do this.
      initializeState(seed.longValue());
   }

   /**
    * Constructor for Xoroshiro128plusplus with seed array.
    *
    * @param seed Initial seed array.
    */
   public Xoroshiro128plusplus(final long[] seed) {
      m_State0 = seed[0];
      m_State1 = seed[1];
   }

   /**
    * Constructor for Xoroshiro128plusplus with two seed values.
    *
    * @param seed0 Initial seed 1.
    * @param seed1 Initial seed 2.
    */
   public Xoroshiro128plusplus(final long seed0,final long seed1) {
      m_State0 = seed0;
      m_State1 = seed1;
   }

   //******************************************************************
   // Public methods
   //******************************************************************

   /**
    * Get next {@code long} pseudo-random number
    *
    * @return next pseudo-random long value
    */
   @Override
   public synchronized long nextLong() {
      final long s0 = m_State0;
      long s1 = m_State1;

      long result = s0 + s1;
      result = (result << 17 | result >>> 47) + s0;

      s1 ^= s0;

      m_State0 = (s0 << 49 | s0 >>> 15) ^ s1 ^ (s1 << 21);
      m_State1 = (s1 << 28 | s1 >>> 36);

      return result;
   }


   //******************************************************************
   // Private methods
   //******************************************************************

   /**
    * Unnecessary constructor method to initialize the state
    */
   private void initializeState(final long seed) {
      SplitMix64 sm64 = new SplitMix64(seed);

      m_State0 = sm64.nextLong();
      m_State1 = sm64.nextLong();
   }
}
