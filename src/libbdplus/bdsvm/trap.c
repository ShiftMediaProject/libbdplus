/*
 * This file is part of libbdplus
 * Copyright (C) 2008-2010  Accident
 * Copyright (C) 2013       VideoLAN
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include "trap.h"
#include "trap_helper.h"
#include "diff.h"
#include "sha1.h"

#include "libbdplus/bdplus_config.h"

#include "file/file.h"
#include "util/logging.h"
#include "util/macro.h"
#include "util/strutl.h"

#include <gcrypt.h>

#include <inttypes.h>
#include <string.h>
#include <stdio.h>   /* SEEK_* */
#if HAVE_TIME_H
#include <time.h>
#endif
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

/* Set this in CFLAGS to debug gcrypt MPIs and S-expressions */
#ifndef GCRYPT_DEBUG
#define GCRYPT_DEBUG 0
#endif

// trap_MediaShaFileHash
#define AES_BLOCK_SIZE 16

#define SVM_HEADER_SIZE 0x18


uint32_t TRAP_Finished(void)
{
    BD_DEBUG(DBG_BDPLUS_TRAP,"[TRAP] TRAP_Finished()\n");
    return STATUS_OK; // Not used

}


uint32_t TRAP_FixUpTableSend(uint32_t len)
{
    BD_DEBUG(DBG_BDPLUS_TRAP,"[TRAP] TRAP_FixUpTableSend(%u/%u)\n", (unsigned int)len, (unsigned int)(len* sizeof(uint32_t)));

#if 0
    if (len) {
        FILE *fd;
        fd = fopen("dat/conv_tab2.bin", "wb");
        if (fd) {
            BD_DEBUG(DBG_BDPLUS,"[TRAP] writing dat/conv_tab.bin\n");
            fwrite(Table, len * sizeof(uint32_t), 1, fd);
            fclose(fd);
        }
    }
#endif

    return STATUS_OK;
}

/*
 * TRAP_Aes()
 *
 * Description:
 * ------------
 *
 * Performs the AES ECB algorithm on len blocks from src and stores
 * the decryption result at dst using the key at key (as transformed
 * below). The value for opOrKeyID specifies how the key should be
 * derived and whether to perform AES encryption or decryption. The
 * following values for opOrKeyID are supported:
 * opOrKeyID=AES_ECB_ENCRYPT(0xFFF10000)-Encrypt the data using ECB
 * mode with the 16-byte key at key. opOrKeyID=AES_ECB_DECRYPT
 * (0xFFF10001)-Decrypt the data using ECB mode with the 16-byte key
 * at key. opOrKeyID=AES_ECB_DECRYPT_MEDIA_KEY(0xFFF10002)-Decrypt an
 * encrypted key value at key using the media key for the
 * currently-inserted media, then use the result as a key to decrypt
 * the data at src using ECB mode. opOrKeyID=any other value. Decrypt
 * the enciphered key at the pointer key using the player key
 * identified by opOrKeyID, then use the resulting decrypted key to
 * decrypt the data at the pointer src using ECB mode. (Note: Content
 * code can check the player's certificate to determine the key range
 * for the player's main AES key set; these keys do not necessarily
 * begin at 0, and there may be multiple sets of keys.) While keys
 * selected by opOrKeyID may be located in the player application,
 * keys may (without limitation) also be located in the drive, in
 * device drivers, in displays/output devices, located remotely across
 * networks, located in a user-removable smart cards (or other tamper
 * resistant chips), located in non-removable tamper resistant chips,
 * split among multiple devices, etc. The first decryption operation
 * (decrypting the content-specified encrypted key) may be performed
 * by the device containing the identified key, while the bulk
 * processing (i.e., decrypting the data at src) may be performed
 * elsewhere (e.g., in a high-speed cryptographic module that lacks
 * nonvolatile memory for key storage).
 *
 * Cryptographic operations, particularly those involving external
 * devices, may also be implemented via TRAP_DeviceDiscovery and/or
 * TRAP_DeviceAccess. Cipher block chaining (CBC), counter mode, and
 * other block cipher modes may be implemented from ECB operations
 * using content code (optionally with operations such as
 * TRAP_Xor). Alternate embodiments may also directly provide
 * algorithms other than AES and/or modes other than ECB.
 *
 **/
uint32_t TRAP_Aes(bdplus_config_t *config, uint8_t *dst, uint8_t *src, uint32_t len, const uint8_t *key, uint32_t opOrKeyID,
                  const uint8_t *mk) {
    gcry_cipher_hd_t gcry_h;
    gcry_error_t gcry_err;
    uint32_t i;
    uint8_t decryptedKey[AES_BLOCK_SIZE]; // Temporary key
    char errstr[100];

    BD_DEBUG(DBG_BDPLUS_TRAP,"[TRAP] TRAP_Aes(KeyID %08X)\n", opOrKeyID);

    if (opOrKeyID == 0xFFF10002) {
        BD_DEBUG(DBG_BDPLUS_TRAP | DBG_CRIT, "[TRAP] TRAP_Aes(AES_ECB_DECRYPT_MEDIA_KEY) not implemented\n");
        return STATUS_INVALID_PARAMETER;
    }

    if (opOrKeyID > 0xFFF10002)
        return STATUS_INVALID_PARAMETER;
    if ((opOrKeyID < 0xFFF10000) && (opOrKeyID > 6))
        return STATUS_INVALID_PARAMETER;

    gcry_cipher_open(&gcry_h, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_ECB, 0);

    switch(opOrKeyID) {

    case 0xFFF10000: // AES_ENCRYPT
        BD_DEBUG(DBG_BDPLUS,"[TRAP] TRAP_Aes(AES_ENCRYPT): %p->%p (%d)\n", src, dst, len);
        gcry_err = gcry_cipher_setkey(gcry_h, key, AES_BLOCK_SIZE);
        if (gcry_err)
        {
          memset(errstr, 0, sizeof(errstr));
          gpg_strerror_r(gcry_err, errstr, sizeof(errstr));
          BD_DEBUG(DBG_BDPLUS|DBG_CRIT,"[TRAP] TRAP_Aes(AES_ENCRYPT) %s.\n", errstr);
        }
        for (i = 0; i < len; i++) {
            gcry_err =
                gcry_cipher_encrypt(gcry_h,
                    &dst[ i * AES_BLOCK_SIZE], AES_BLOCK_SIZE,
                    &src[ i * AES_BLOCK_SIZE], AES_BLOCK_SIZE);
            if (gcry_err)
            {
              memset(errstr, 0, sizeof(errstr));
              gpg_strerror_r(gcry_err, errstr, sizeof(errstr));
              BD_DEBUG(DBG_BDPLUS|DBG_CRIT,"[TRAP] TRAP_Aes(AES_ENCRYPT) step %d: %s.\n",
                    i, errstr);
            }
        }
        break;

    case 0xFFF10002: // AES_DECRYPT_MEDIA_KEY
        key = mk;
        // TODO

    case 0xFFF10001: // AES_DECRYPT
        BD_DEBUG(DBG_BDPLUS,"[TRAP] TRAP_Aes(AES_DECRYPT): %p->%p (%d)\n", src, dst, len);
        gcry_err = gcry_cipher_setkey(gcry_h, key, AES_BLOCK_SIZE);
        if (gcry_err)
        {
          memset(errstr, 0, sizeof(errstr));
          gpg_strerror_r(gcry_err, errstr, sizeof(errstr));
          BD_DEBUG(DBG_BDPLUS|DBG_CRIT,"[TRAP] TRAP_Aes(AES_DECRYPT) %s.\n", errstr);
        }
        for (i = 0; i < len; i++) {
            gcry_err =
                gcry_cipher_decrypt(gcry_h,
                    &dst[ i * AES_BLOCK_SIZE], AES_BLOCK_SIZE,
                    &src[ i * AES_BLOCK_SIZE], AES_BLOCK_SIZE);
            if (gcry_err)
            {
              memset(errstr, 0, sizeof(errstr));
              gpg_strerror_r(gcry_err, errstr, sizeof(errstr));
              BD_DEBUG(DBG_BDPLUS|DBG_CRIT,"[TRAP] TRAP_Aes(AES_DECRYPT) step %d: %s.\n",
                    i, errstr);
            }
        }
        break;

    default:         // decryption with encrypted key using secret player keys
        BD_DEBUG(DBG_BDPLUS,"[TRAP] TRAP_Aes(AES_DECRYPT_PLAYERKEYS): %p->%p (%d key %d)\n", src, dst, len, opOrKeyID);

        if (!config || !config->aes_keys) {
            BD_DEBUG(DBG_BDPLUS | DBG_CRIT, "[TRAP] TRAP_Aes: AES keys not loaded.\n");
            return STATUS_INVALID_PARAMETER;
        }

        if ((int)opOrKeyID >= config->num_aes_keys) {
            BD_DEBUG(DBG_BDPLUS|DBG_CRIT,"[TRAP] TRAP_Aes(AES_DECRYPT_PLAYERKEYS): Key %u does not exist in config.\n", opOrKeyID);
            return STATUS_INVALID_PARAMETER;
        }

        gcry_err = gcry_cipher_setkey(gcry_h, config->aes_keys[ opOrKeyID ].key,
                                      AES_BLOCK_SIZE);
        if (gcry_err)
        {
          memset(errstr, 0, sizeof(errstr));
          gpg_strerror_r(gcry_err, errstr, sizeof(errstr));
          BD_DEBUG(DBG_BDPLUS|DBG_CRIT,"[TRAP] TRAP_Aes(AES_DECRYPT_PLAYERKEYS) %s.\n",
                errstr);
        }

        // decrypt the encrypted key with the specified player key
        gcry_err =
            gcry_cipher_decrypt(gcry_h,
                decryptedKey, AES_BLOCK_SIZE,
                key, AES_BLOCK_SIZE);
        if (gcry_err)
        {
          memset(errstr, 0, sizeof(errstr));
          gpg_strerror_r(gcry_err, errstr, sizeof(errstr));
          BD_DEBUG(DBG_BDPLUS|DBG_CRIT,"[TRAP] TRAP_Aes(AES_DECRYPT_PLAYERKEYS) %s.\n",
                errstr);
        }

        gcry_err = gcry_cipher_setkey(gcry_h, decryptedKey, AES_BLOCK_SIZE);
        if (gcry_err)
        {
          memset(errstr, 0, sizeof(errstr));
          gpg_strerror_r(gcry_err, errstr, sizeof(errstr));
          BD_DEBUG(DBG_BDPLUS|DBG_CRIT,"[TRAP] TRAP_Aes(AES_DECRYPT_PLAYERKEYS) %s.\n",
                errstr);
        }

        for (i = 0; i < len; i++) {
            gcry_err =
                gcry_cipher_decrypt(gcry_h,
                    &dst[ i * AES_BLOCK_SIZE], AES_BLOCK_SIZE,
                    &src[ i * AES_BLOCK_SIZE], AES_BLOCK_SIZE);
            if (gcry_err)
            {
              memset(errstr, 0, sizeof(errstr));
              gpg_strerror_r(gcry_err, errstr, sizeof(errstr));
              BD_DEBUG(DBG_BDPLUS|DBG_CRIT,"[TRAP] TRAP_Aes(AES_DECRYPT_PLAYERKEYS) "
                    "step %d: %s.\n",
                    i, errstr);
            }
        }
        break;
    } // opOrKeyID

    gcry_cipher_close(gcry_h);

    return STATUS_OK;
}


/*
  ------------------------------------------------------------------------------------------------------------------
  -- trap #0120 = UINT32 TRAP_PrivateKey(UINT32 keyID, UINT8 *dst, UINT8 *src, UINT32 srcLen, UINT32 controlWord) --
  ------------------------------------------------------------------------------------------------------------------

  Description:
  ------------

  This operation uses the ECDSA private key selected by keyID
  (normally 0), or some other asymmetric key in the player (or in a
  device accessible by the player), to transform some data. From the
  keyID, the length of the result and the operation type (e.g.,
  signing or decryption) is implicit. Information about available
  keys, including corresponding public keys and certificates (which
  the content code can verify), may be obtained using
  TRAP_DeviceDiscovery and/or TRAP_DeviceAccess. The choice of what
  data to submit is up to the content code (e.g., any function of any
  data from the media and/or TRAPs can be submitted). For example, the
  value submitted for a signing operation can be tied to user
  interface (and other) events by incorporating event data (see
  TRAP_EventGet) in generating the data signed.

  For the player's main ECDSA private key (keyID=0), this operation
  produces a 320-bit ECDSA signature of a SHA-1 hash. The hash is
  computed as follows: (a) hashing the value of srcLen, encoded as 4
  bytes (MSB first); (b) hashing the contents of the user-specified
  buffer (i.e., srcLen bytes at src); (c) hashing the value of
  controlWord, encoded as 4 bytes (MSB first); (d) If controlWord bit
  31 (the MSB) is set, hashing the value of the media ID; (e) If
  controlWord bit 30 is set, setting the destination pointer to PC+4,
  overriding dst; (f) if controlWord bit 29 is set, hashing the
  (control word mod 2.sup.16) code bytes beginning with the current
  program counter; then (g) if controlWord bit 28 is set,
  incorporating the current value of PC in the hash.

  For verifying signatures, the player's public exponent is 3, and the
  public modulus can be obtained by the content code by verifying the
  player's certificate using a system-wide public key (which can be a
  constant contained in the content code, optionally in obfuscated
  form).

  The options provided by the control word allow content code to
  obtain attestations about the execution environment, such as
  detecting the situation where signatures are being performed by a
  compliant device other than the one containing the
  interpreter. Verifiable binding between the interpreter and the
  content code can be useful to address situations where an attacker
  tries to use malicious content running on a legitimate player to
  produce cryptographic results for use by a malicious player running
  legitimate content.

  Embodiments may support any combination of asymmetric cryptographic
  algorithms (RSA, DSA, elliptic curve variants, Diffie-Hellman,
  etc.), operations (signing, verification, key agreement, etc.), and
  key sizes may be supported. Symmetric operations may also be
  integrated with asymmetric operations. Note that some cryptographic
  operations, such as ECDSA signature verification, can be implemented
  in content code without any special traps, or using only
  general-purpose performance acceleration operations (e.g.,
  TRAP_AddWithCarry, etc.) An example of a more complex cryptographic
  TRAP would be one that does some or all of the following: (a)
  performs an ECDSA public key operation to verify a signature on a
  block of data, (b) if the signature is valid, performs an ECDSA
  private key operation to decrypt a block data in the verified
  portion to recover a symmetric key, (c) if the ECDSA decryption is
  successful, uses the symmetric key to decrypt and verify (e.g.,
  using HMAC-SHA) some data (e.g., data in the signed block following
  the encrypted key), then (d) use the interpreter to process the
  decrypted data as code.)

  In alternate embodiments, cryptographic support may be provided for
  signing, verifying, decrypting, encrypting, or otherwise processing
  the inputs and outputs of any manner of other computational
  operations (such as other TRAPs).

*/
uint32_t TRAP_PrivateKey(bdplus_config_t *config, uint32_t keyID, uint8_t *dst, uint8_t *src, uint32_t srcLen, uint32_t controlWord)
{
    uint8_t *message = NULL;
    gcry_error_t gcry_err;
    gcry_mpi_t mpi_hash;
    gcry_sexp_t sexp_key, sexp_data, sexp_sig, sexp_r, sexp_s;
    char errstr[100];

    if (!config || !config->ecdsa_keys) {
        BD_DEBUG(DBG_BDPLUS | DBG_CRIT, "[TRAP] TRAP_PrivateKey: ECDSA keys not loaded.\n");
        return STATUS_INVALID_PARAMETER;
    }

    //
    // define the curve parameters and public/private key pairs
    //

    // the curve y^2 = x^3 + a * x + b ( mod q )
    const char CA_q[]    = "96609D9E935E52C683DBFC3A7D783EA942BDE8CB"; // q (known as p for libgcrypt)
    const char CA_a[]    = "96609D9E935E52C683DBFC3A7D783EA942BDE8C8"; // a = -3 (mod q)
    const char CA_b[]    = "3E567D8DEC27873BCF86F5FBB595DB288C62C721"; // b

    // the base point (a point on the above curve like the public key)
    const char CA_x_G[]  = "05FC5B0B2360AC50A76E1511BC5C9AF67A004D0D"; // the x-coordinate of the base point
    const char CA_y_G[]  = "09B0D43F319B09A5B679CCF264E1ABA4D56594EA"; // the y-coordinate of the base point

    // large modulus n
    const char CA_n[]    = "96609d9e935e52c683dafdc49216143f9a24373d"; // n

    // the public/private key pair 0
    const char *CA_d0   = config->ecdsa_keys[0].d;
    const char *CA_x_Q0 = config->ecdsa_keys[0].Qx;
    const char *CA_y_Q0 = config->ecdsa_keys[0].Qy;

    // the public/private key pair 1
    const char *CA_d1   = config->ecdsa_keys[1].d;
    const char *CA_x_Q1 = config->ecdsa_keys[1].Qx;
    const char *CA_y_Q1 = config->ecdsa_keys[1].Qy;

    // 'r' and 's' will hold the raw signature to be written to the vm memory
    uint8_t *r = NULL, *s = NULL;
    uint8_t hash[SHA_DIGEST_LENGTH];

    BD_DEBUG(DBG_BDPLUS_TRAP,"[TRAP] TRAP_PrivateKey(%X, %08X)\n", keyID, controlWord);

    if ( keyID > 1 )
        return STATUS_INVALID_PARAMETER;

    //
    // create message to be signed
    //

    message = (uint8_t *) malloc(16 + srcLen); // message header 16 bytes
    if (!message)
        return STATUS_INTERNAL_ERROR;

    memcpy(message, "BDSVM_PK", 8);
    STORE4(&message[  8 ], controlWord);
    STORE4(&message[ 12 ], srcLen);
    // Copy message payload
    memcpy(&message[ 16 ], src, srcLen);

    /* Calculate the SHA1 hash of the message and build an MPI out of the
     * resulting hash.
     */
    gcry_md_hash_buffer(GCRY_MD_SHA1, hash, message, 16 + srcLen);
    gcry_mpi_scan(&mpi_hash, GCRYMPI_FMT_USG, hash, sizeof(hash), NULL);

    /* Dump information about the hash MPI when debugging */
    if (GCRYPT_DEBUG)
    {
      BD_DEBUG(DBG_BDPLUS,"[TRAP] TRAP_PrivateKey(%X, %08X) mpi_hash dump\n",
            keyID, controlWord);
      gcry_mpi_dump(mpi_hash);
    }

    /* Build an s-expression for the hash */
    gcry_sexp_build(&sexp_data, NULL,
                    "(data"
#if defined(GCRYPT_VERSION_NUMBER) && GCRYPT_VERSION_NUMBER >= 0x010600
                    /*
                     * For some reason gcrypt 1.6.0
                     * requires 'param' flag here and not
                     * in key, probably a bug.
                     */
                    "  (flags raw param)"
#else
                    "  (flags raw)"
#endif
                    "  (value %m))",
                    mpi_hash
                    );

    /* Dump information about the data s-expression when debugging */
    if (GCRYPT_DEBUG)
    {
      BD_DEBUG(DBG_BDPLUS,"[TRAP] TRAP_PrivateKey(%X, %08X) sexp_data dump\n",
            keyID, controlWord);
      gcry_sexp_dump(sexp_data);
    }

    /* Prepare the string that will represent S-expression for the key.
     * The S-expression here is in the form:
     * "(private-key"
     * "(ecdsa"
     * "(p #<p hexstring>#)"
     * "(a #<a hexstring>#)"
     * "(b #<b hexstring>#)"
     * "(g #<format>"
     *     "<G.x hexstring>"
     *     "<G.y hexstring>"
     *     "#)"
     * "(n #<n hexstring>#)"
     * "(q #<format>"
     *     "<Q.x hexstring>"
     *     "<Q.y hexstring>"
     *     "#)"
     * "(d #<d hexstring>#)))"
     */
    char *strfmt_key = NULL;
    if ( keyID == 0 ) {
      strfmt_key = (char*)malloc(
        sizeof("(private-key") +
        sizeof("(ecdsa") +
        sizeof("(p #00") + sizeof(CA_q) + sizeof("#)") +
        sizeof("(a #00") + sizeof(CA_a) + sizeof("#)") +
        sizeof("(b #00") + sizeof(CA_b) + sizeof("#)") +
        sizeof("(g #04") +
            sizeof(CA_x_G) +
            sizeof(CA_y_G) +
            sizeof("#)") +
        sizeof("(n #00") + sizeof(CA_n) + sizeof("#)") +
        sizeof("(q #04") +
            strlen(CA_x_Q0) +
            strlen(CA_y_Q0) +
            sizeof("#)") +
        sizeof("(d #00") + strlen(CA_d0) + sizeof("#)))") + 1);
      sprintf(strfmt_key,
        "(private-key"
        "(ecdsa"
        "(p #00%s#)"
        "(a #00%s#)"
        "(b #00%s#)"
        "(g #04"
            "%s"
            "%s"
            "#)"
        "(n #00%s#)"
        "(q #04"
            "%s"
            "%s"
            "#)"
        "(d #00%s#)))",
        CA_q,
        CA_a,
        CA_b,
        CA_x_G,
        CA_y_G,
        CA_n,
        CA_x_Q0,
        CA_y_Q0,
        CA_d0
        );
    }
    else
    {
      strfmt_key = (char*)malloc(
        sizeof("(private-key") +
        sizeof("(ecdsa") +
        sizeof("(p #00") + sizeof(CA_q) + sizeof("#)") +
        sizeof("(a #00") + sizeof(CA_a) + sizeof("#)") +
        sizeof("(b #00") + sizeof(CA_b) + sizeof("#)") +
        sizeof("(g #04") +
            sizeof(CA_x_G) +
            sizeof(CA_y_G) +
            sizeof("#)") +
        sizeof("(n #00") + sizeof(CA_n) + sizeof("#)") +
        sizeof("(q #04") +
            strlen(CA_x_Q1) +
            strlen(CA_y_Q1) +
            sizeof("#)") +
        sizeof("(d #00") + strlen(CA_d1) + sizeof("#)))") + 1);
      sprintf(strfmt_key,
        "(private-key"
        "(ecdsa"
        "(p #00%s#)"
        "(a #00%s#)"
        "(b #00%s#)"
        "(g #04"
            "%s"
            "%s"
            "#)"
        "(n #00%s#)"
        "(q #04"
            "%s"
            "%s"
            "#)"
        "(d #00%s#)))",
        CA_q,
        CA_a,
        CA_b,
        CA_x_G,
        CA_y_G,
        CA_n,
        CA_x_Q1,
        CA_y_Q1,
        CA_d1
        );
    }

    /* Now build the S-expression */
    gcry_err = gcry_sexp_build(&sexp_key, NULL, strfmt_key);
    if (gcry_err)
    {
      memset(errstr, 0, sizeof(errstr));
      gpg_strerror_r(gcry_err, errstr, sizeof(errstr));
      BD_DEBUG(DBG_BDPLUS|DBG_CRIT,"[TRAP] TRAP_PrivateKey(%X, %08X) error building "
            "sexp_key: %s\n",
            keyID, controlWord, errstr);
    }

    /* Dump information about the key s-expression when debugging */
    if (GCRYPT_DEBUG)
    {
      BD_DEBUG(DBG_BDPLUS,"[TRAP] TRAP_PrivateKey(%X, %08X) sexp_key dump\n",
            keyID, controlWord);
      gcry_sexp_dump(sexp_key);
    }

    /* Sign the hash with the ECDSA key. The resulting s-expression should be
     * in the form:
     * (sig-val
     *   (dsa
     *     (r r-mpi)
     *     (s s-mpi)))
     */
    gcry_err = gcry_pk_sign(&sexp_sig, sexp_data, sexp_key);
    if (gcry_err)
    {
      memset(errstr, 0, sizeof(errstr));
      gpg_strerror_r(gcry_err, errstr, sizeof(errstr));
      BD_DEBUG(DBG_BDPLUS|DBG_CRIT,"[TRAP] TRAP_PrivateKey(%X, %08X) error signing "
            "data: %s\n",
            keyID, controlWord, errstr);
    }

    /* Dump information about the signature s-expression when debugging */
    if (GCRYPT_DEBUG)
    {
      BD_DEBUG(DBG_BDPLUS,"[TRAP] TRAP_PrivateKey(%X, %08X) sexp_sig dump\n",
            keyID, controlWord);
      gcry_sexp_dump(sexp_sig);
    }

    /* Get the resulting s-expressions for 'r' and 's' */
    sexp_r = gcry_sexp_find_token(sexp_sig, "r", 0);
    sexp_s = gcry_sexp_find_token(sexp_sig, "s", 0);

    /* Dump information about 'r' and 's' values when debugging */
    if (GCRYPT_DEBUG)
    {
      BD_DEBUG(DBG_BDPLUS,"[TRAP] TRAP_PrivateKey(%X, %08X) sexp_r dump\n",
            keyID, controlWord);
      gcry_sexp_dump(sexp_r);
      BD_DEBUG(DBG_BDPLUS,"[TRAP] TRAP_PrivateKey(%X, %08X) sexp_s dump\n",
            keyID, controlWord);
      gcry_sexp_dump(sexp_s);
    }

    /* Convert the data for 'r' and 's' into unsigned char form */
    r = (unsigned char*)gcry_sexp_nth_string(sexp_r, 1);
    s = (unsigned char*)gcry_sexp_nth_string(sexp_s, 1);

    /* Finally concatenate 'r' and 's' to get the ECDSA signature */
    memcpy(dst, r, 20);
    memcpy(dst + 20, s, 20);

    /* Free allocated memory */
    gcry_mpi_release(mpi_hash);
    gcry_sexp_release(sexp_key);
    gcry_sexp_release(sexp_data);
    gcry_sexp_release(sexp_sig);
    gcry_sexp_release(sexp_r);
    gcry_sexp_release(sexp_s);
    gcry_free(r);
    gcry_free(s);
    X_FREE(message);
    X_FREE(strfmt_key);

    return STATUS_OK;
}

// write <len> random bytes to <dst>
uint32_t TRAP_Random(uint8_t *dst, uint32_t len)
{
    BD_DEBUG(DBG_BDPLUS_TRAP,"[TRAP] TRAP_Random(%u)\n", len);

    gcry_randomize(dst, len, GCRY_STRONG_RANDOM);
    return STATUS_OK;
}

//
// This function is not required, but used to be identical to reference
// player, which really isn't required.
//
// uint32_t sha_reference(uint8_t *dst, SHA_CTX *sha, uint32_t len,  uint32_t total_len)
// {
//     uint32_t xlen, i;
// 
//     memcpy(&dst[ 0  ], &sha->h0, sizeof(sha->h0) );
//     memcpy(&dst[ 4  ], &sha->h1, sizeof(sha->h1) );
//     memcpy(&dst[ 8  ], &sha->h2, sizeof(sha->h2) );
//     memcpy(&dst[ 12 ], &sha->h3, sizeof(sha->h3) );
//     memcpy(&dst[ 16 ], &sha->h4, sizeof(sha->h4) );
// 
//     // Move all 4 bytes first:
//     BD_DEBUG(DBG_BDPLUS,"reference: copying all even 4s from %u\n", len);
//     i = 0;
//     xlen = len;
//     while(xlen >= 4) {
//         xlen -= 4;
//         // Refence is big-endian.
//         memcpy(&dst[ 20+i ], &sha->data[i/4], sizeof(sha->data[0]));
//         i += 4;
//     }
// 
//     BD_DEBUG(DBG_BDPLUS,"reference: dealing with half-words: %u\n", len-i);
// 
//     // Deal with the remainder.
//     switch(len - i) {
//     case 0:
//         break;
//     case 3:
//         dst[20 + i ]    = (sha->data[i/4] & 0xFF00) >> 8;
//         dst[20 + i + 1] = (sha->data[i/4] & 0xFF0000) >> 16;
//         dst[20 + i + 2] = (sha->data[i/4] & 0xFF000000) >> 24;
//         break;
//     case 2:
//         dst[20 + i ]    = (sha->data[i/4] & 0xFF0000) >> 16;
//         dst[20 + i + 1] = (sha->data[i/4] & 0xFF000000) >> 24;
//         break;
//     case 1:
//         dst[20 + i] = (sha->data[i/4] & 0xFF000000) >> 24;
//         break;
//     }
// 
//     // Update len field, if needed
//     if (total_len) {
//         BD_DEBUG(DBG_BDPLUS,"reference: updating total size %u\n", total_len);
// 
//         dst[340] = (uint8_t) ( total_len & 0xFF );
//         dst[348] = (uint8_t) (( total_len * 8 ) & 0xFF );
//         dst[349] = (uint8_t) ((( total_len * 8 ) & 0xFF00 ) >> 8 );
//     }
// 
//     return 0;
// }

static uint32_t sha_reference(uint8_t *dst, SHA1_CTX *sha)//, uint32_t len,  uint32_t total_len)
{
    int i;

    for (i = 0; i < SHA1_DIGEST_SIZE; i++) {
        dst[i] = (uint8_t) ((sha->state[i>>2] >> ((3-(i & 3)) * 8) ) & 255);
    }

    // TODO: check how to fill in input data. Do not overflow (context is 352 bytes)
    // Note endianess.
    // is this correct ???
    memcpy(dst + 20, sha->buffer, (sha->count[0] >> 3) & 63);

    // Update len field
    uint32_t total_len = (sha->count[0] >> 3);
    dst[340] = (uint8_t) ( total_len & 0xFF );
    dst[348] = (uint8_t) (( total_len * 8 ) & 0xFF );
    dst[349] = (uint8_t) ((( total_len * 8 ) & 0xFF00 ) >> 8 );

    return 0;
}

uint32_t TRAP_Sha1(sha_t **sha_head, uint8_t *dst, uint8_t *src, uint32_t len, uint32_t op)
{
    sha_t *matched_ctx = NULL;

    // TODO: use VM memory to store context.

    switch(op) {
    case SHA_INIT:
        BD_DEBUG(DBG_BDPLUS_TRAP,"[trap] TRAP_Sha1(INIT)\n");
        matched_ctx = get_sha_ctx(sha_head, dst);
        memset(dst, 0, 352); //352, according to jumper snapshots
        if (matched_ctx) {
        sha_SHA1_Init(&matched_ctx->sha);
        // Call UPDATE if we were also given data
        TRAP_Sha1(sha_head, dst, src, len, SHA_UPDATE);
        }
        break;

    case SHA_UPDATE:
        BD_DEBUG(DBG_BDPLUS_TRAP,"[trap] TRAP_Sha1(UPDATE)\n");
        matched_ctx = get_sha_ctx(sha_head, dst);
        if (matched_ctx) {
        sha_SHA1_Update(&matched_ctx->sha, src, len);
        // This call is not required, only here to make "dst" be identical
        // to reference player.
        sha_reference(dst, &matched_ctx->sha);
        }
        break;

    case SHA_FINAL:
      {
        uint8_t digest[20];

        BD_DEBUG(DBG_BDPLUS_TRAP,"[trap] TRAP_Sha1(FINAL)\n");
        matched_ctx = get_sha_ctx(sha_head, dst);
        if (matched_ctx) {
        // UPDATE if we were also given data.
        TRAP_Sha1(sha_head, dst, src, len, SHA_UPDATE);
        // Call FINAL.
        sha_SHA1_Final(&matched_ctx->sha, digest);

        // Copy over the digest
        memcpy(dst, digest, sizeof(digest));

        free_sha_ctx(sha_head, matched_ctx);
        }
        break;
      }

    case SHA_BLOCK:
        BD_DEBUG(DBG_BDPLUS_TRAP,"[trap] TRAP_Sha1(BLOCK)\n");
        gcry_md_hash_buffer(GCRY_MD_SHA1, dst, src, len);
        break;
    default: // Unknown op
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_OK;
}


/*
  This operation performs a multi-word addition operation with carry
  propagation. The value at src[0...len-1] is added to
  dst[0...len-1]. The values src and dst can each be verified as
  pointing to a large number stored as len words and encoded with the
  most-significant word at address src[0] or dst[0], respectively. The
  least-significant words are located at src[len-1] and dst[len--1],
  respectively.

  For example, the number 0x08090A0B0C0D0E0F would have len=2 and
  would be stored with 0x08090AB at the location specified by the
  pointer (e.g., src[0]) and the value 0x0C0D0E0F at the byte offset
  referenced by the pointer plus 4 (e.g., src[1]).

  If the source and destination areas overlap, correct operation is
  guaranteed only if src=dst. The operation's return value is 1 if the
  final (most-significant or left-hand) addition step produced a
  carry, and zero otherwise.

  (Note: The TRAP_AddWithcarry operation, along with various other
  TRAP operations, could also be implemented using content code
  without a separate TRAP, but a dedicated TRAP enables player
  designers to chose the most efficient technique available on each
  platform, thereby enabling better performance guarantees across a
  broad variety of possible player designs.)
*/
uint32_t TRAP_AddWithCarry(uint32_t *dst, uint32_t *src, uint32_t len)
{
    int32_t i, carry;
    uint32_t valA, valB;
    uint64_t sum;

    BD_DEBUG(DBG_BDPLUS_TRAP,"[TRAP] TRAP_AddWithCarry(%p + %p) %d \n", dst, src, len);

    /*
    for (i = 0; i < len*4; i++) {
        if (!(i%16)) printf("\n%08x: ", i);
        printf("%02X ", ((uint8_t *)src)[i]);
    }

    for (i = 0; i < len*4; i++) {
        if (!(i%16)) printf("\n%08x: ", i);
        printf("%02X ", ((uint8_t *)dst)[i]);
    }
    printf("\n");
    */

    for (i = len-1, carry = 0;
         i >= 0;
         i--) {

        valA = FETCH4((uint8_t *)(&src[ i ]));
        valB = FETCH4((uint8_t *)(&dst[ i ]));
        sum = (uint64_t)valA + (uint64_t)valB + (uint64_t)carry;
        // The sum should be BIGGER, or the same, as EITHER number, BUT we
        // might overflow from carry, and either number is 0.
        carry = (sum > 0xFFFFFFFF ) ? 1 : 0;

        STORE4((uint8_t *)(&dst[ i ]), sum&0xFFFFFFFF);
    }

    return carry;
}


/*
  This operation multiplies multiplicand onto the number in
  dst[0...len-1]. The result is len+1 words long. The most-significant
  word of the result is returned, and the rest is stored in
  dst[0...len-1]. The value of dst should point to a large number
  stored as len words and encoded with the most-significant word at
  the address pointed to by dst.
 */
// Untested function
uint32_t TRAP_MultiplyWithCarry(uint32_t *dst, uint32_t *src, uint32_t len, uint32_t multiplicand)
{
    uint64_t sum, carry;
    uint32_t val;
    int i;

    BD_DEBUG(DBG_BDPLUS_TRAP,"[TRAP] TRAP_MultiplyWithCarry(%08X) %d\n", multiplicand, len);

    /*
    for (i = 0; i < len*4; i++) {
        if (!(i%16)) printf("\n%08x: ", i);
        printf("%02X ", ((uint8_t *)src)[i]);
    }
    printf("\n");
    */

    if (!len) {
        STORE4((uint8_t *)(&dst[ 0 ]), 0);
        return STATUS_OK;
    }

    // Magic goes here.
    for (i = len-1, carry = 0;
         i >= 0;
         i--) {

        val = FETCH4((uint8_t *)(&src[ i ]));
        sum = ((uint64_t) val) * multiplicand;
        sum += carry;

        // Carry is the high bits 63-32
        carry = sum >> 32;

        // dst gets low bits 31-0
        STORE4((uint8_t *)(&dst[ i + 1 ]), (uint32_t)sum&0xFFFFFFFF);
    }

    STORE4((uint8_t *)(&dst[ 0 ]), (uint32_t)carry&0xFFFFFFFF);

    return STATUS_OK;
}


uint32_t TRAP_XorBlock(uint32_t *dst, uint32_t *src, uint32_t len)
{
    uint32_t i;

    BD_DEBUG(DBG_BDPLUS_TRAP,"[TRAP] TRAP_XorBlock()\n");

    for (i = 0; i<len; i++)
        dst[i] = src[i] ^ dst[i];

    return 0;
}


uint32_t TRAP_Memmove(uint8_t *dst, uint8_t *src, uint32_t len)
{
    BD_DEBUG(DBG_BDPLUS_TRAP,"[TRAP] TRAP_Memmove()\n");

    memmove(dst, src, len);

    return STATUS_OK;
}


/*
  This operation searches memory for one or more bytes. In particular,
  it finds the first occurrence of the searchData (which has a length
  of searchDataLen bytes) within region (which has a length of
  regionLen bytes). Matches will be found if they occur entirely
  within region[0...regionLen-1]; matches that begin in this range but
  extend beyond the end are not counted. The operation returns a
  pointer to the first match. If no match is found within region, the
  return value is NULL.
 */
uint32_t TRAP_MemSearch(uint8_t *Region, uint32_t RegionLen, uint8_t *SearchData, uint32_t SearchDataLen, uint32_t *Dst)
{
    uint32_t i, j;

    BD_DEBUG(DBG_BDPLUS_TRAP,"[TRAP] TRAP_MemSearch(): %d, %d\n", RegionLen, SearchDataLen);

    if ( RegionLen == 0 ) {
        *Dst = 0;
        return STATUS_OK ;
    }
    if ( SearchDataLen == 0 ) {
        *Dst = 0;
        return STATUS_OK ;
    }
    if ( RegionLen < SearchDataLen ) {
        *Dst = 0;
        return STATUS_OK ;
    }

#if 0
    { int i;
    printf("Looking for data:\n");
    for (i = 0; i < SearchDataLen; i++)
        printf("%s%02X ", !(i%16) ? "\n" : "", SearchData[i]);
    printf("\nIn the memory of: \n");
    for (i = 0; i < RegionLen; i++)
        printf("%s%02X ", !(i%16) ? "\n" : "", Region[i]);
    printf("\n");
    }
#endif

    // Search memory.
    for (i = 0; i < (RegionLen - SearchDataLen + 1); i++) {
        for (j = 0; j < SearchDataLen; j++) {
            if (Region[i + j] != SearchData[ j ]) break;//differs,stop j,loop i
        } // j
        if (j == SearchDataLen) { // j loop got to end, all equals!
            BD_DEBUG(DBG_BDPLUS,"[TRAP] found at %08X + %08X = %08X\n", *Dst, i, *Dst + i);
            *Dst += i;  // Region offset
            return STATUS_OK;
        }
    } // i

    *Dst = 0;
    return STATUS_OK;
}

uint32_t TRAP_Memset(uint8_t *dst, uint8_t fillvalue, uint32_t len)
{
    BD_DEBUG(DBG_BDPLUS_TRAP,"[TRAP] TRAP_Memset(%02X) %d\n", fillvalue, len);

    memset(dst, fillvalue, len);

    return STATUS_OK;
}


uint32_t TRAP_ApplicationLayer(bdplus_config_t *config, uint32_t dev, uint32_t opID, uint32_t *buf)
{
    BD_DEBUG(DBG_BDPLUS_TRAP,"[TRAP] TRAP_ApplicationLayer(%08X %X)\n", dev, opID);

    if ( dev >= 3 )
        return STATUS_INVALID_PARAMETER;
    if ( opID > 1 )
        return STATUS_INVALID_PARAMETER;
    if ( (dev == 1) && (opID == 1) )
        return STATUS_INVALID_PARAMETER;

    if (!config || !config->regs) {
        BD_DEBUG(DBG_BDPLUS | DBG_CRIT, "[TRAP] ApplicationLayer: WARNING player registers not available!\n");
        return STATUS_OK;
    }

    // 102 = PSR_BDPLUS_TO_APPL_DATA
    // 103 = PSR_APPL_TO_BDPLUS_DATA
    // 104 = PSR_BDPLUS_SHARED_DATA

    if (opID == 0) {
        // receive data from application
        uint32_t val = config->psr_read(config->regs, 102+dev);
        STORE4((uint8_t *)buf, val);
    }
    if (opID == 1) {
        // send data to application
        uint32_t val = FETCH4((uint8_t*)buf);
        config->psr_write(config->regs, 102+dev, val);
    }
    BD_DEBUG(DBG_BDPLUS,"[TRAP] ApplicationLayer: WARNING %s PSR10%d! (0x%08x)\n",
          opID?"writing to":"reading from", dev+2, buf[0]);

    return STATUS_OK; // snapshots return OK.
}

uint32_t TRAP_Discovery(bdplus_config_t *config, uint32_t dev, uint32_t qID, uint8_t *pBuf, uint32_t *pLen, uint8_t *volumeID)
{
    uint32_t len;
    time_t now;
    struct tm *tnow;
    struct timeval tp;

    BD_DEBUG(DBG_BDPLUS_TRAP,"[TRAP] TRAP_DeviceDiscovery(%u,%u,%u):\n", dev, qID, *pLen);

    if (!*pLen)
        return STATUS_INVALID_PARAMETER;
    if ( (dev != 1) && (dev != 2) )
        return STATUS_INVALID_PARAMETER;
    if ( (dev == 1) && (qID != 1) && (qID != 2) && (qID != 3) )
        return STATUS_INVALID_PARAMETER;
    if ( (dev == 2) & (qID != 0) & (qID != 1) )
        return STATUS_NOT_SUPPORTED;

    if (!config || !config->dev) {
        BD_DEBUG(DBG_BDPLUS | DBG_CRIT, "[TRAP] TRAP_Discovery: data not loaded.\n");
        return STATUS_INVALID_PARAMETER;
    }

    switch( dev ) {


        // *****************************************************
    case 0x00000001: // Question to device 1 (player?)

        switch (qID) { // Kind of question

        case 0x00000001: // Player: DEV_DISC1 284 0x11c
            len = config->dev[0].size;
            if (*pLen < len) return STATUS_INVALID_PARAMETER;

            memcpy(pBuf, config->dev[0].mem, len);
             *pLen = len;
            return STATUS_OK;

        case 0x00000002: // Player: DEV_DISC2 292
            len = config->dev[1].size;
            if (*pLen < len) return STATUS_INVALID_PARAMETER;

            memcpy(pBuf, config->dev[1].mem, len);
            *pLen = len;
            return STATUS_OK;

        case 0x00000003: // Player: VolumeID and timestamp 60/0x3c
            len = config->dev[2].size;
            if (*pLen < len) return STATUS_INVALID_PARAMETER;

            memcpy(pBuf, config->dev[2].mem, len);
            //            *pLen = len;
            // Copy in the volume ID at offset 24
            memcpy(&pBuf[24], volumeID, 16);
            // Timestamp in offset 0
            time(&now);
            tnow = localtime(&now);
            gettimeofday(&tp, NULL);
            STORE2(pBuf, tnow->tm_year + 1900);
            pBuf[2] = tnow->tm_mon;              // month
            pBuf[3] = tnow->tm_mday;             // day_of_month
            pBuf[4] = tnow->tm_hour;             // hour_of_day
            pBuf[5] = tnow->tm_min;              // minute
            pBuf[6] = tnow->tm_sec;              // second
            pBuf[7] = (uint8_t)tp.tv_usec/10;    // millisecond / 10

            *pLen = len;
            return STATUS_OK;
        default:
            BD_DEBUG(DBG_CRIT, "[TRAP] unknown DeviceDiscovery for dev 1: %d\n", qID);
            break;
        }

        break; // Switch qID: Player


        // *****************************************************
    case 0x00000002: // Question to device 2 (drive?)

        switch (qID) { // Kind of question

        case 0x00000000: // Drive: DISC4 128
            len = config->dev[3].size;
            //if (*pLen < len) return STATUS_INVALID_PARAMETER;

            memcpy(pBuf, config->dev[3].mem, len);
            return STATUS_OK;

        case 0x00000001: // Drive: DISC5 128
            len = config->dev[4].size;
            //if (*pLen < len) return STATUS_INVALID_PARAMETER;

            memcpy(pBuf, config->dev[4].mem, len);
            return STATUS_OK;

        case 0x00000002:
            //return STATUS_NOT_SUPPORTED;
            return STATUS_INVALID_PARAMETER;

        default:
            BD_DEBUG(DBG_CRIT, "[TRAP] unknown DeviceDiscovery for dev 2: %d\n", qID);
            break;
        } // qID

    default:
        BD_DEBUG(DBG_CRIT, "[TRAP] unknown DeviceDiscovery for unknown dev %d: %d\n", dev, qID);
        break;

    } // switch dev


    return STATUS_INVALID_PARAMETER;

}


// DiscoveryRAM is in ram.c


//
// Filename "00001" -> "BDSVM/00001.svm".
//
uint32_t TRAP_LoadContentCode(bdplus_config_t *config, uint8_t *FileName, uint32_t Section, uint32_t Unknown, uint32_t *len, uint8_t *dst)
{
    BDPLUS_FILE_H *fd;
    int64_t rbytes;
    char *fname;

    BD_DEBUG(DBG_BDPLUS_TRAP,"[TRAP] TRAP_LoadContentCode('%s':%08X -> %p)\n", FileName, *len, dst);


    // Build the real filename.
    fname = str_printf("BDSVM/%s.svm", (char *) FileName);
    if (!fname) {
        BD_DEBUG(DBG_BDPLUS | DBG_CRIT, "out of memory\n");
        return STATUS_INVALID_PARAMETER;
    }

    BD_DEBUG(DBG_BDPLUS,"[TRAP] reading '%s': unknown %08X\n", fname, Unknown);

    fd = file_open(config, fname);
    X_FREE(fname);

    if (!fd) {
        BD_DEBUG(DBG_BDPLUS | DBG_CRIT,"[TRAP] ERROR: cant open %s\n", (char*)FileName);
        return STATUS_INVALID_PARAMETER; // FIXME
    }

    // Skip the SVM header.
    if (file_seek(fd, SVM_HEADER_SIZE, SEEK_SET) < 0) {
        BD_DEBUG(DBG_BDPLUS | DBG_CRIT,"[TRAP] ERROR: seeking %s (header) failed\n", (char*)FileName);
        file_close(fd);
        return STATUS_INVALID_PARAMETER;
    }
    if (file_seek(fd, Section * 0x200000, SEEK_CUR) < 0) { // locate wanted section
        BD_DEBUG(DBG_BDPLUS | DBG_CRIT,"[TRAP] ERROR: seeking %s to section %d failed\n", (char*)FileName, Section);
        file_close(fd);
        return STATUS_INVALID_PARAMETER;
    }

    // They assume the memory wraps, and sometimes deliberately load near the
    // end of the memory.
    BD_DEBUG(DBG_BDPLUS,"[TRAP] reading %d/%08X bytes into %p\n", *len, *len, dst);
    rbytes = file_read(fd, dst, *len);
    if (rbytes < 0 || rbytes != (int64_t)*len) {
        BD_DEBUG(DBG_BDPLUS | DBG_CRIT,"[TRAP] ERROR: read %"PRId64" bytes of %d from %s\n", rbytes, *len, (char*)FileName);
        file_close(fd);
        return STATUS_INVALID_PARAMETER;
    }
    file_close(fd);

    BD_DEBUG(DBG_BDPLUS,"[TRAP] read %"PRId64" bytes. %p-%p\n", rbytes, dst, &dst[rbytes]);
    *len = rbytes;

    return 0;
}


uint32_t TRAP_DiscoveryRAM(bdplus_config_t *config, uint32_t src, uint8_t *buffer, uint32_t len)
{
    uint32_t i;
    uint32_t address;

    //[dlx] DiscoveryRAM(00000000, 00002E58, 00002000)
    BD_DEBUG(DBG_BDPLUS_TRAP,"[TRAP] TRAP_DiscoveryRAM(%08X): %d\n", src, len);

    if (!config || !config->ram) {
        BD_DEBUG(DBG_BDPLUS | DBG_CRIT, "[TRAP] TRAP_DiscoveryRAM: data not loaded.\n");
        return STATUS_INVALID_PARAMETER;
    }

    for ( i = 0; i < len; i++ ) {

        address = src + i;

        bdplus_ram_area_t *ram = NULL;
        unsigned ii;
        for (ii = 0; ii < config->ram->num_area; ii++) {
          if (address >= config->ram->area[ii].start_address &&
              address < config->ram->area[ii].start_address + config->ram->area[ii].size ) {
            ram = &config->ram->area[ii];
            break;
          }
        }
        if (ram) {
            if (ram->type & (MEM_TYPE_PSR | MEM_TYPE_GPR)) {
                /* need endian swap for register files. */
                /* TODO: should memory (register file) be locked ??? */
                union {
                    uint8_t  u8[4];
                    uint32_t u32;
                } val;
                uint32_t a   = address - ram->start_address;
                val.u32 = *(const uint32_t *)(&ram->mem[ a & (~3) ]);
                buffer[i] = val.u8[(a & 3) ^ 3];
                BD_DEBUG(DBG_BDPLUS, "[TRAP] Reading RAM at register %d[%04d] val 0x%08x [%d]=> 0x%02X\n", ram->type, a / 4, val.u32, a & 3, val.u8[a & 3]);
            } else {
                buffer[i] = ram->mem[ address - ram->start_address ];
            }

            if ( address >= 0x00250000 && address <= 0x0028FFFF ) {
                buffer[i] ^= (uint8_t) ( ( 3 * address * address + 1 ) & 0xFF );
            }
        } else {
            if ( address > 0x400000 ) {
                buffer[i] = 0x00;
            } else {
                BD_DEBUG(DBG_BDPLUS | DBG_CRIT, "[TRAP] reading from unmapped address 0x%x\n", address);
            }
        }
    }

    return STATUS_OK;
}

uint32_t TRAP_MediaCheck(bdplus_config_t *config, uint8_t *FileName, uint32_t FileNameLen, uint32_t FileOffsetHigh, uint32_t FileOffsetLow, uint32_t *len, uint8_t *dst)
{
    uint8_t buffer[SHA_BLOCK_SIZE]; // fix me
    BDPLUS_FILE_H *fd;
    uint32_t j;
    uint64_t seek;

    BD_DEBUG(DBG_BDPLUS_TRAP,"[TRAP] TRAP_MediaCheck(%d/%d)\n", *len, FileNameLen);

#if 0
    // Skip past "BDMV/" if string starts with it..
    subfilename = FileName;
    if ((FileNameLen > 5) && *FileName &&
        !strncasecmp("BDMV/", (char *)FileName, 5))
        subfilename = &FileName[5];
#endif

    //if ( x != 0 ) return 0x80FFFFFF

    seek = ((uint64_t)FileOffsetHigh << 32) | (uint64_t)FileOffsetLow;

    BD_DEBUG(DBG_BDPLUS,"[TRAP] reading '%s' at pos %016"PRIx64"\n", FileName, seek);

    fd = file_open(config, (char *)FileName);
    if (!fd) {
        BD_DEBUG(DBG_BDPLUS|DBG_CRIT, "[TRAP] TRAP_MediaCheck: failed to open %s\n", FileName);
        file_close(fd);
        return STATUS_INVALID_PARAMETER;
    }
#if 0
    if (!fd) {
        BD_DEBUG(DBG_BDPLUS|DBG_CRIT, "[TRAP] TRAP_MediaCheck: failed to open %s\n", FileName);
        // Attempt to load it via hashdb
        full_name = (uint8_t *)str_printf("%s/hash_db.bin", device_path);
        j =  diff_hashdb_load(full_name,
                              FileName,
                              seek, len, dst);
        X_FREE(full_name);
        return j;
    }
#endif

    if (file_seek(fd, seek, SEEK_SET)) {
        BD_DEBUG(DBG_BDPLUS|DBG_CRIT, "[TRAP] TRAP_MediaCheck: failed to seek %s to %"PRIu64"\n", (char *)FileName, seek);
        file_close(fd);
        return STATUS_INVALID_PARAMETER;
    }

    for (j = 0; j < ((*len) / SHA_BLOCK_SIZE); j++) {  // "/ 0x200"

        if (file_read(fd, buffer, SHA_BLOCK_SIZE) != SHA_BLOCK_SIZE) {
            BD_DEBUG(DBG_BDPLUS,"[TRAP] MediaCheck warning short read: %d\n", j);
            break;
        }
        BD_DEBUG(DBG_BDPLUS,"[TRAP] read bytes and SHA_BLOCK\n");

        gcry_md_hash_buffer(GCRY_MD_SHA1, &dst[ j*SHA_DIGEST_LENGTH ],
                            buffer, SHA_BLOCK_SIZE);
    }

    file_close(fd);

    *len = j * SHA_BLOCK_SIZE;
    BD_DEBUG(DBG_BDPLUS,"[TRAP] MediaCheck returning size %08X\n", j * SHA_BLOCK_SIZE);

    for (j = 0; j < SHA_DIGEST_LENGTH; j++) {
        BD_DEBUG(DBG_BDPLUS,"%02X ", dst[ j ]);
    }
    BD_DEBUG(DBG_BDPLUS,"\n");


    return STATUS_OK;
}

#if 0
uint32_t TRAP_RunNative()
{
    BD_DEBUG(DBG_BDPLUS_TRAP | DBG_CRIT,"[TRAP] TRAP_RunNative()\n");

    return 0;
}
#endif

#if 0
uint32_t TRAP_000570(/* ? nop/vendor specific?*/)
{
    BD_DEBUG(DBG_BDPLUS_TRAP | DBG_CRIT,"[TRAP] TRAP_000570()\n");

    return 0;
}
#endif

uint32_t TRAP_DebugLog(uint8_t *txt, uint32_t len)
{
    BD_DEBUG(DBG_BDPLUS_TRAP | DBG_CRIT,"[TRAP] TRAP_DebugLog(%d): '%s'\n", len, ((len > 0)&&txt&&*txt) ? (char *)txt : "(null)");

    return STATUS_INTERNAL_ERROR;
}


#if 0
uint32_t TRAP_008020()
{
    BD_DEBUG(DBG_BDPLUS_TRAP | DBG_CRIT,"[TRAP] TRAP_008020()\n");

    return STATUS_NOT_SUPPORTED;
}
#endif

#if 0
uint32_t TRAP_008030()
{
    BD_DEBUG(DBG_BDPLUS_TRAP | DBG_CRIT,"[TRAP] TRAP_008030()\n");

    return STATUS_NOT_SUPPORTED;
}
#endif

