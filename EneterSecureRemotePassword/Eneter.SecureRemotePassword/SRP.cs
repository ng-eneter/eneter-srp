/*
 * Project: Eneter.SecureRemotePassword
 * Author:  Ondrej Uzovic
 * 
 * Copyright © Ondrej Uzovic 2016
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
*/


using System;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Eneter.SecureRemotePassword
{
    /// <summary>
    /// Sercure Remote Password (SRP-6a).
    /// </summary>
    /// <remarks>
    /// Provides functionality for implementing Secure Remote Password protocol.
    /// Names of methods match the naming convention which is defined in the protocol specification:<br/>
    /// http://srp.stanford.edu/design.html
    /// 
    /// Here is the summary of SRP parameters:
    /// N       A large safe prime(N = 2q+1, where q is prime)
    ///         All arithmetic is done modulo N.
    /// g       A generator modulo N
    /// k       Multiplier parameter
    /// s       User's salt
    /// I       Username
    /// p       Cleartext Password
    /// H()     One-way hash function
    /// ^       (Modular) Exponentiation
    /// u       Random scrambling parameter
    /// a, b    Secret ephemeral values
    /// A, B    Public ephemeral values
    /// x       Private key(derived from p and s)
    /// v       Password verifier
    /// </remarks>
    public static class SRP
    {
        private static RNGCryptoServiceProvider myRandomGenerator = new RNGCryptoServiceProvider();
        private static int myPrimeNumberSize = 128;
        private static BigInteger N = new BigInteger(Convert.FromBase64String("7q8Kua2zjdacM/gK+o/F6GByYYd1/zwLnqIxTJwlZXbWdN90luqB0zg7SBPWksbg4NXY4lC5i+SOSVwdYIna0V3H17RhVNa2zo70rWmxXUmCVZspe88YhcUp9WZmDlfsaO28PAVybMAv1Mv0l26qmv1ROP6DdkNbn8YdL8DrBuM="));
        private static BigInteger g = 2;
        private static BigInteger k = H(N, g);

        /// <summary>
        /// Allows to setup a different large prime number.
        /// </summary>
        /// <param name="largePrimeNumber"></param>
        public static void CustomInit(byte[] largePrimeNumber)
        {
            N = new BigInteger(largePrimeNumber);
            myPrimeNumberSize = largePrimeNumber.Length;
            k = H(N, g);
        }

        /// <summary>
        /// Generates 16 byte salt.
        /// </summary>
        /// <returns>salt 's'</returns>
        public static byte[] s()
        {
            byte[] aSalt = GetRandomNumber(16);
            return aSalt; 
        }

        /// <summary>
        /// Calculates user private key 'x' from user-password and salt.
        /// </summary>
        /// <remarks>
        /// Note that this key is not supposed to be stored. Database of users should store only salt 's' and verifier 'v'.
        /// </remarks>
        /// <param name="password">text of user password 'p'</param>
        /// <param name="sBytes">salt 's'</param>
        /// <returns>user private key 'x'</returns>
        public static byte[] x(string password, byte[] sBytes)
        {
            byte[] aPasswordBytes = Encoding.UTF8.GetBytes(password);

            // x = H(s, p)
            byte[] xBytes = H(sBytes, aPasswordBytes);
            return xBytes;
        }

        /// <summary>
        /// Calculates verifier 'v' from the user private key 'x'.
        /// </summary>
        /// <param name="xBytes">user private key 'x'</param>
        /// <returns>verifier 'v'</returns>
        public static byte[] v(byte[] xBytes)
        {
            BigInteger x = new BigInteger(xBytes);

            // v = g^x % N
            BigInteger v = BigInteger.ModPow(g, x, N);
            return v.ToByteArray();
        }


        /// <summary>
        /// Generates secret ephemeral value 'a' for client.
        /// </summary>
        /// <returns>client secret ephemeral value 'a'</returns>
        public static byte[] a()
        {
            return GetRandomNumber(myPrimeNumberSize);
        }

        /// <summary>
        /// Calculates public ephemeral value 'A' for client.
        /// </summary>
        /// <param name="aBytes">client secret ephemeral value 'a'</param>
        /// <returns>client public ephemeral value 'A'</returns>
        public static byte[] A(byte[] aBytes)
        {
            BigInteger a = new BigInteger(aBytes);

            // A = g^a % N
            BigInteger A = BigInteger.ModPow(g, a, N);
            return A.ToByteArray();
        }

        /// <summary>
        /// Used by the service to check public ephemeral value 'A' from the client.
        /// </summary>
        /// <param name="ABytes">client public ephemeral value</param>
        /// <returns>true if the value is ok</returns>
        public static bool IsValid_A(byte[] ABytes)
        {
            BigInteger a = new BigInteger(ABytes);
            return a % N != 0;
        }

        /// <summary>
        /// Generates secret ephemeral value 'b' for service.
        /// </summary>
        /// <returns>service secret ephemeral value 'b'</returns>
        public static byte[] b()
        {
            return GetRandomNumber(myPrimeNumberSize);
        }

        /// <summary>
        /// Calculates public ephemeral value 'B' for service.
        /// </summary>
        /// <param name="bBytes">service secret ephemeral value 'b'</param>
        /// <param name="vBytes">verifier 'v'</param>
        /// <returns>service public ephemeral value 'B'</returns>
        public static byte[] B(byte[] bBytes, byte[] vBytes)
        {
            BigInteger b = new BigInteger(bBytes);
            BigInteger v = new BigInteger(vBytes);

            // B = (kv + (g^b % N)) % N
            BigInteger B = (k * v + BigInteger.ModPow(g, b, N)) % N;
            return B.ToByteArray();
        }

        /// <summary>
        /// Calculates random scrambling parameter.
        /// </summary>
        /// <param name="ABytes">client public ephemeral value 'A'</param>
        /// <param name="BBytes">service public ephemeral value 'B'</param>
        /// <returns>random scrambling parameter</returns>
        public static byte[] u(byte[] ABytes, byte[] BBytes)
        {
            // u = H(A, B)
            byte[] uBytes = H(ABytes, BBytes);
            return uBytes;
        }

        /// <summary>
        /// Used by the client to check public ephemeral value 'B' from the client
        /// and to check calculated scrambling parameter.
        /// </summary>
        /// <param name="BBytes">service public ephemeral value 'B</param>
        /// <param name="uBytes">random scrambling parameter 'u'</param>
        /// <returns></returns>
        public static bool IsValid_B_u(byte[] BBytes, byte[] uBytes)
        {
            BigInteger B = new BigInteger(BBytes);
            BigInteger u = new BigInteger(uBytes);
            return B % N != 0 && u != 0;
        }

        /// <summary>
        /// Calculates session key 'K' for the client.
        /// </summary>
        /// <param name="BBytes">service public ephemeral value 'B'</param>
        /// <param name="xBytes">user private key 'x'</param>
        /// <param name="uBytes">random scrambling parameter</param>
        /// <param name="aBytes">client secret ephemeral value 'a'</param>
        /// <returns>session key 'K'</returns>
        public static byte[] K_Client(byte[] BBytes, byte[] xBytes, byte[] uBytes, byte[] aBytes)
        {
            BigInteger B = new BigInteger(BBytes);
            BigInteger x = new BigInteger(xBytes);
            BigInteger u = new BigInteger(uBytes);
            BigInteger a = new BigInteger(aBytes);

            // S = (B − k * (g^x % N))^(a + u * x) % N
            BigInteger S = BigInteger.ModPow(B - k * BigInteger.ModPow(g, x, N), a + u * x, N);

            // K = H(S)
            BigInteger K = H(S);
            return K.ToByteArray();
        }

        /// <summary>
        /// Calculates session key 'K' for service.
        /// </summary>
        /// <param name="ABytes">client public ephemeral value 'A'</param>
        /// <param name="vBytes">verifier 'v'</param>
        /// <param name="uBytes">random scrambling parameter</param>
        /// <param name="bBytes">service secret ephemeral value 'b'</param>
        /// <returns>session key 'K'</returns>
        public static byte[] K_Service(byte[] ABytes, byte[] vBytes, byte[] uBytes, byte[] bBytes)
        {
            BigInteger A = new BigInteger(ABytes);
            BigInteger v = new BigInteger(vBytes);
            BigInteger u = new BigInteger(uBytes);
            BigInteger b = new BigInteger(bBytes);

            // S = (A * (v^u % N))^b % N
            BigInteger S = BigInteger.ModPow(A * BigInteger.ModPow(v, u, N), b, N);

            // K = H(S)
            BigInteger K = H(S);
            return K.ToByteArray();
        }

        /// <summary>
        /// Calculates evidence message 'M1' which can be sent from client to service.
        /// </summary>
        /// <param name="ABytes">client public ephemeral value 'A'</param>
        /// <param name="BBytes">service public ephemeral value 'B'</param>
        /// <param name="KBytes">session key 'K'</param>
        /// <returns>evidence message</returns>
        public static byte[] M1(byte[] ABytes, byte[] BBytes, byte[] KBytes)
        {
            return H(ABytes, BBytes, KBytes);
        }

        /// <summary>
        /// Calculates evidence message 'M2' which can be sent from service to client.
        /// </summary>
        /// <param name="ABytes">client public ephemeral value 'A'</param>
        /// <param name="M1Bytes">evidence message 'M1' received from the client</param>
        /// <param name="KBytes">session key 'K'</param>
        /// <returns>evidence message</returns>
        public static byte[] M2(byte[] ABytes, byte[] M1Bytes, byte[] KBytes)
        {
            return H(ABytes, M1Bytes, KBytes);
        }

        private static BigInteger H(params BigInteger[] values)
        {
            byte[][] aParams = values.Select(x => x.ToByteArray()).ToArray();
            byte[] aHash = H(aParams);
            return new BigInteger(aHash);
        }

        private static byte[] H(params byte[][] values)
        {
            byte[] aBytes;

            if (values.Length == 1)
            {
                aBytes = values[0];
            }
            else
            {
                int aSize = values.Sum(x => x.Length);
                aBytes = new byte[aSize];
                for (int i = 0; i < values.Length; ++i)
                {
                    int aDstOffset = (i == 0) ? 0 : values[i - 1].Length;
                    Buffer.BlockCopy(values[i], 0, aBytes, aDstOffset, values[i].Length);
                }
            }

            // Compute the hash.
            SHA256 aSha = SHA256.Create();

            // Concatenate 0 byte to ensure the generated hash number will be understood as a positive number.
            byte[] aHash = aSha.ComputeHash(aBytes).Concat(new byte[] { 0 }).ToArray();
            return aHash;
        }

        private static byte[] GetRandomNumber(int length)
        {
            byte[] retval = new byte[length];
            myRandomGenerator.GetBytes(retval);

            // Set last byte to 0 to ensure the generated number is understood as a positive number.
            retval[retval.Length - 1] = 0;

            return retval;
        }

    }
}
