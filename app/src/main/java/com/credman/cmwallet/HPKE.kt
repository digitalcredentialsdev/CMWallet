package com.credman.cmwallet

import java.nio.ByteBuffer
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * A Kotlin implementation of Hybrid Public Key Encryption (HPKE) as specified in RFC 9180.
 *
 * This implementation focuses on the base encryption mode and supports the ciphersuite
 * using DHKEM(X25519), HKDF-SHA256, and AES-128-GCM.
 *
 * @property suite The HPKE ciphersuite to be used for all operations.
 */
class Hpke(val suite: HpkeCipherSuite) {

    /**
     * Data class to hold a public/private key pair.
     */
    data class HpkeKeyPair(val privateKey: PrivateKey, val publicKey: PublicKey)

    /**
     * Data class to hold the result of an HPKE seal (encryption) operation.
     * @param enc The encapsulated ephemeral public key.
     * @param ciphertext The encrypted message, including the authentication tag.
     */
    data class HpkeSealedData(val enc: ByteArray, val ciphertext: ByteArray)

    /**
     * Custom exception for HPKE-specific failures.
     */
    class HpkeException(message: String, cause: Throwable? = null) : GeneralSecurityException(message, cause)

    /**
     * Represents the supported HPKE ciphersuites.
     * Each suite defines the KEM, KDF, and AEAD algorithms.
     * Values are taken from RFC 9180, Section 7.
     *
     * @param kemId The IANA-registered value for the KEM.
     * @param kdfId The IANA-registered value for the KDF.
     * @param aeadId The IANA-registered value for the AEAD.
     * @param keyBitLength (`Nk`) The length of the AEAD key in bits.
     * @param nonceBitLength (`Nn`) The length of the AEAD nonce in bits.
     * @param hashBitLength (`Nh`) The length of the KDF hash output in bits.
     * @param dhKeyBitLength (`Npk`) The length of the public key in bits.
     * @param keyAlgorithm The JCA algorithm name for the KEM.
     * @param kdfAlgorithm The JCA algorithm name for the KDF MAC.
     * @param aeadAlgorithm The JCA algorithm name for the AEAD cipher.
     */
    enum class HpkeCipherSuite(
        val kemId: Short,
        val kdfId: Short,
        val aeadId: Short,
        val keyBitLength: Int,
        val nonceBitLength: Int,
        val hashBitLength: Int,
        val dhKeyBitLength: Int,
        val keyAlgorithm: String,
        val kemAlgorithm: String,
        val kdfAlgorithm: String,
        val aeadAlgorithm: String,
    ) {
        DHKEM_P256_HKDF_SHA256_AES_128_GCM(
            kemId = 0x0010,
            kdfId = 0x0001,
            aeadId = 0x0001,
            keyBitLength = 128,
            nonceBitLength = 96,
            hashBitLength = 256,
            dhKeyBitLength = 256,
            keyAlgorithm = "EC",
            kemAlgorithm = "ECDH",
            kdfAlgorithm = "HmacSHA256",
            aeadAlgorithm = "AES/GCM/NoPadding"
        );

        val keyByteLength: Int get() = keyBitLength / 8
        val nonceByteLength: Int get() = nonceBitLength / 8
        val hashByteLength: Int get() = hashBitLength / 8
        val dhKeyByteLength: Int get() = dhKeyBitLength / 8
    }

    // Internal container for the derived secrets from the key schedule.
    private data class HpkeContext(val key: ByteArray, val baseNonce: ByteArray, val exporterSecret: ByteArray)

    private val suiteId: ByteArray = "HPKE".toByteArray(Charsets.UTF_8) + ByteBuffer.allocate(6)
        .putShort(suite.kemId)
        .putShort(suite.kdfId)
        .putShort(suite.aeadId)
        .array()

    companion object {
        private const val HPKE_VERSION_LABEL = "HPKE-v1"
        private const val HPKE = "HPKE"
        private const val KEM = "KEM"

        fun generateKeyPair(suite: HpkeCipherSuite): HpkeKeyPair {
            val kpg = KeyPairGenerator.getInstance(suite.keyAlgorithm)
            val spec = when (suite) {
                HpkeCipherSuite.DHKEM_P256_HKDF_SHA256_AES_128_GCM -> ECGenParameterSpec("secp256r1")
            }
            kpg.initialize(spec)
            val kp = kpg.generateKeyPair()
            return HpkeKeyPair(kp.private, kp.public)
        }
    }

    /**
     * Encrypts a message for a recipient. This is the `Seal` operation.
     * See RFC 9180, Section 5.1.1.
     *
     * @param recipientPublicKey The public key of the recipient.
     * @param info Application-specific information (can be empty).
     * @param aad Additional Associated Data to be authenticated (can be empty).
     * @param plaintext The message to encrypt.
     * @return An HpkeSealedData object containing the encapsulated key and the ciphertext.
     */
    fun seal(recipientPublicKey: PublicKey, info: ByteArray, aad: ByteArray, plaintext: ByteArray): HpkeSealedData {
        // Step 1: Ephemeral key generation and DH
        val ephemeralKeyPair = generateKeyPair(this.suite)
        val sharedSecret = dh(ephemeralKeyPair.privateKey, recipientPublicKey)
        val enc = ephemeralKeyPair.publicKey.encoded

        // Step 2: Derive HPKE context
        // This combines SetupS from RFC 9180, Section 5.1.1
        val context = keySchedule(sharedSecret, info)

        // Step 3: Encrypt the plaintext
        // This is the AeadSeal operation from RFC 9180, Section 5.2
        val ciphertext = aeadSeal(context.key, context.baseNonce, aad, plaintext)

        return HpkeSealedData(enc, ciphertext)
    }

    /**
     * Decrypts a message. This is the `Open` operation.
     * See RFC 9180, Section 5.1.1.
     *
     * @param sealedData The object containing the encapsulated key and ciphertext.
     * @param recipientKeyPair The key pair of the recipient.
     * @param info Application-specific information (must match the info used for sealing).
     * @param aad Additional Associated Data (must match the aad used for sealing).
     * @return The decrypted plaintext, or throws an exception if decryption fails.
     */
    fun open(sealedData: HpkeSealedData, recipientKeyPair: PrivateKey, info: ByteArray, aad: ByteArray): ByteArray {
        val (enc, ciphertext) = sealedData

        // Step 1: Perform DH with the encapsulated ephemeral public key
        val ephemeralPublicKey = KeyFactory.getInstance(suite.keyAlgorithm).generatePublic(X509EncodedKeySpec(enc))
        val sharedSecret = dh(recipientKeyPair, ephemeralPublicKey)

        // Step 2: Derive HPKE context
        // This combines SetupR from RFC 9180, Section 5.1.1
        val context = keySchedule(sharedSecret, info)

        // Step 3: Decrypt the ciphertext
        // This is the AeadOpen operation from RFC 9180, Section 5.2
        return aeadOpen(context.key, context.baseNonce, aad, ciphertext)
    }

    /**
     * Performs the Diffie-Hellman key exchange.
     * Corresponds to `DH(sk, pk)` in the RFC.
     */
    private fun dh(privateKey: PrivateKey, publicKey: PublicKey): ByteArray {
        val ka = KeyAgreement.getInstance(suite.kemAlgorithm)
        ka.init(privateKey)
        ka.doPhase(publicKey, true)
        return ka.generateSecret()
    }

    /**
     * Implements the HPKE Key Schedule for base mode.
     * See RFC 9180, Section 5.1.
     *
     * @param sharedSecret The result of the Diffie-Hellman exchange.
     * @param info Application-specific information.
     * @return An HpkeContext containing the derived key, nonce, and exporter secret.
     */
    private fun keySchedule(sharedSecret: ByteArray, info: ByteArray): HpkeContext {
        // In "base" mode, psk and psk_id are empty.
        val emptySalt = ByteArray(suite.hashByteLength)

        // secret = LabeledExtract("", "secret", shared_secret)
        val secret = labeledExtract(emptySalt, "secret", sharedSecret)

        // key = LabeledExpand(secret, "key", info, Nk)
        val key = labeledExpand(secret, "key", info, suite.keyByteLength)

        // base_nonce = LabeledExpand(secret, "base_nonce", info, Nn)
        val baseNonce = labeledExpand(secret, "base_nonce", info, suite.nonceByteLength)

        // exporter_secret = LabeledExpand(secret, "exp", info, Nh)
        val exporterSecret = labeledExpand(secret, "exp", info, suite.hashByteLength)

        return HpkeContext(key, baseNonce, exporterSecret)
    }

    /**
     * AEAD Encryption (AES-GCM). Corresponds to `AeadSeal(key, nonce, aad, pt)`.
     * See RFC 9180, Section 5.2.
     * The sequence number is always 0 for single-shot encryption.
     */
    private fun aeadSeal(key: ByteArray, nonce: ByteArray, aad: ByteArray, pt: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(suite.aeadAlgorithm)
        val keySpec = SecretKeySpec(key, "AES")
        // Tag length for AES-GCM is typically 128 bits (16 bytes).
        val gcmSpec = GCMParameterSpec(128, nonce)
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)
        cipher.updateAAD(aad)
        return cipher.doFinal(pt)
    }

    /**
     * AEAD Decryption (AES-GCM). Corresponds to `AeadOpen(key, nonce, aad, ct)`.
     * See RFC 9180, Section 5.2.
     */
    private fun aeadOpen(key: ByteArray, nonce: ByteArray, aad: ByteArray, ct: ByteArray): ByteArray {
        try {
            val cipher = Cipher.getInstance(suite.aeadAlgorithm)
            val keySpec = SecretKeySpec(key, "AES")
            val gcmSpec = GCMParameterSpec(128, nonce)
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)
            cipher.updateAAD(aad)
            return cipher.doFinal(ct)
        } catch (e: GeneralSecurityException) {
            // Catches AEADBadTagException and others, indicating a decryption failure.
            throw HpkeException("AEAD decryption failed, likely due to invalid authentication tag.", e)
        }
    }

    /**
     * HKDF-Extract operation.
     * See RFC 5869.
     */
    private fun hkdfExtract(salt: ByteArray, ikm: ByteArray): ByteArray {
        val mac = Mac.getInstance(suite.kdfAlgorithm)
        mac.init(SecretKeySpec(salt, suite.kdfAlgorithm))
        return mac.doFinal(ikm)
    }

    /**
     * HKDF-Expand operation.
     * See RFC 5869.
     */
    private fun hkdfExpand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        val mac = Mac.getInstance(suite.kdfAlgorithm)
        mac.init(SecretKeySpec(prk, suite.kdfAlgorithm))

        val result = ByteArray(length)
        var currentInfo = info
        var t = ByteArray(0)
        var i: Byte = 1
        var bytesCopied = 0

        while (bytesCopied < length) {
            mac.update(t)
            mac.update(currentInfo)
            mac.update(i)
            t = mac.doFinal()

            val toCopy = minOf(length - bytesCopied, t.size)
            System.arraycopy(t, 0, result, bytesCopied, toCopy)
            bytesCopied += toCopy

            currentInfo = ByteArray(0) // Subsequent rounds use only the previous T value
            i++
        }
        return result
    }

    /**
     * Implements the `LabeledExtract` function from RFC 9180, Section 4.
     */
    private fun labeledExtract(salt: ByteArray, label: String, ikm: ByteArray): ByteArray {
        val labeledIkm = HPKE_VERSION_LABEL.toByteArray() + suiteId + label.toByteArray() + ikm
        return hkdfExtract(salt, labeledIkm)
    }

    /**
     * Implements the `LabeledExpand` function from RFC 9180, Section 4.
     */
    private fun labeledExpand(prk: ByteArray, label: String, info: ByteArray, length: Int): ByteArray {
        val lengthBytes = ByteBuffer.allocate(2).putShort(length.toShort()).array()
        val labeledInfo = lengthBytes + HPKE_VERSION_LABEL.toByteArray() + suiteId + label.toByteArray() + info
        return hkdfExpand(prk, labeledInfo, length)
    }
}