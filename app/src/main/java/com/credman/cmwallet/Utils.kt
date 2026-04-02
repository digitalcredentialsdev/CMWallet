package com.credman.cmwallet

import android.util.Log
import com.credman.cmwallet.sdjwt.jwsSignatureToDer
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.encodeToJsonElement
import org.jose4j.jwe.kdf.ConcatKeyDerivationFunction
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Arrays
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

fun loadECPrivateKey(keyDer: ByteArray): PrivateKey {
    val devicePrivateKeySpec = PKCS8EncodedKeySpec(keyDer)
    val kf = KeyFactory.getInstance("EC")
    return kf.generatePrivate(devicePrivateKeySpec)!!
}

fun intToBigEndianByteArray(source: Int): ByteArray {
    val buffer = ByteBuffer.allocate(Int.SIZE_BYTES)
    buffer.order(ByteOrder.BIG_ENDIAN)
    buffer.putInt(source)
    return buffer.array()
}

fun BigInteger.toFixedByteArray(requiredLength: Int): ByteArray {
    val bytes = this.toByteArray()
    var offset = 0
    var pad = 0
    var length = bytes.size
    if (length == requiredLength) {
        return bytes
    }
    val fixedArray = ByteArray(requiredLength)
    if (length > requiredLength) {
        offset = length - requiredLength
        length = requiredLength
    } else {
        pad = requiredLength - length
    }
    bytes.copyInto(fixedArray, pad, offset, offset + length)
    return fixedArray
}

fun ecJwkThumbprintSha256(jwk: JSONObject): ByteArray {
    val jwkWithRequired = JSONObject().apply {
        put("crv", jwk.get("crv"))
        put("kty", jwk.get("kty"))
        put("x", jwk.get("x"))
        put("y", jwk.get("y"))
    }
    val md = MessageDigest.getInstance("SHA-256")
    return md.digest(jwkWithRequired.toString().toByteArray())
}

fun PublicKey.toJWK(): JsonElement {
    when (this) {
        is ECPublicKey -> {
            val x = this.w.affineX.toFixedByteArray(32).toBase64UrlNoPadding()
            val y = this.w.affineY.toFixedByteArray(32).toBase64UrlNoPadding()
            return Json.encodeToJsonElement(
                mapOf(
                    Pair("kty", "EC"),
                    Pair("crv", "P-256"),
                    Pair("x", x),
                    Pair("y", y)
                )
            )
        }

        else -> {
            throw IllegalArgumentException("Only support EC Keys for now")
        }
    }
}

@OptIn(ExperimentalEncodingApi::class)
fun ByteArray.toBase64UrlNoPadding(): String {
    return Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).encode(this)
}

@OptIn(ExperimentalEncodingApi::class)
fun ByteArray.toBase64NoPadding(): String {
    return Base64.Default.withPadding(Base64.PaddingOption.ABSENT).encode(this)
}

@OptIn(ExperimentalEncodingApi::class)
fun String.decodeBase64UrlNoPadding(): ByteArray {
    return Base64.UrlSafe.withPadding(kotlin.io.encoding.Base64.PaddingOption.ABSENT).decode(this)
}

@OptIn(ExperimentalEncodingApi::class)
fun String.decodeBase64(): ByteArray {
    return Base64.decode(this)
}

fun createJWTES256(
    header: JsonElement,
    payload: JsonElement,
    privateKey: PrivateKey
): String {
    val headerB64 = Json.encodeToString(header).encodeToByteArray().toBase64UrlNoPadding()
    val payloadB64 = Json.encodeToString(payload).encodeToByteArray().toBase64UrlNoPadding()
    val signatureDer = Signature.getInstance("SHA256withECDSA").run {
        initSign(privateKey)
        update(("$headerB64.$payloadB64").encodeToByteArray())
        sign()
    }
    return "$headerB64.$payloadB64.${convertDerToRaw(signatureDer).toBase64UrlNoPadding()}"
}

fun convertDerToRaw(signature: ByteArray): ByteArray {
    val ret = ByteArray(64)

    var rOffset = 4
    if ((signature[1].toInt() and 0x80) != 0) {
        rOffset += signature[1].toInt() and 0x7f
    }

    var rLen = signature[rOffset - 1].toInt() and 0xFF
    var rPad = 0

    if (rLen > 32) {
        rOffset += (rLen - 32)
        rLen = 32
    } else {
        rPad = 32 - rLen
    }
    signature.copyInto(ret, rPad, rOffset, rOffset + rLen)

    var sOffset = rOffset + rLen + 2
    var sLen = signature[sOffset - 1].toInt() and 0xFF
    var sPad = 0

    if (sLen > 32) {
        sOffset += (sLen - 32)
        sLen = 32
    } else {
        sPad = 32 - sLen
    }
    signature.copyInto(ret, 32 + sPad, sOffset, sOffset + sLen)

    return ret
}

/** Return pair of header and payload, if valid. Else throws if signature validation fails. */
fun jwsDeserialization(jws: String): Pair<JSONObject, JSONObject> {
    val parts = jws.split(".")
    val header = JSONObject(String(parts[0].decodeBase64UrlNoPadding()))
    val payload = String(parts[1].decodeBase64UrlNoPadding())
    val signature = jwsSignatureToDer(parts[2], 256)

    Log.d("Utils", "Header: $header")
    Log.d("Utils", "Payload: $payload")

    val certificate = header["x5c"] as JSONArray
    val factory = CertificateFactory.getInstance("X.509")
    val cert = factory.generateCertificate(ByteArrayInputStream((certificate[0] as String).decodeBase64())) as X509Certificate
    val sig = Signature.getInstance("SHA256withECDSA")
    sig.initVerify(cert.publicKey)
    val signingInput = jws.substringBeforeLast('.')
    sig.update(signingInput.toByteArray())
    require(sig.verify(signature)) { "Signature validation failed" }

    return Pair(header, JSONObject(payload))
}

fun toEcPublicKey(x: String, y: String): PublicKey {
    val kf = KeyFactory.getInstance("EC")
    val parameters = AlgorithmParameters.getInstance("EC")
    parameters.init(ECGenParameterSpec("secp256r1"))
    return kf.generatePublic(
        ECPublicKeySpec(
            ECPoint(
                BigInteger(1, x.decodeBase64UrlNoPadding()),
                BigInteger(1, y.decodeBase64UrlNoPadding())
            ),
            parameters.getParameterSpec(ECParameterSpec::class.java)
        )
    )
}

/** ECDH-ES key agreement, A128GCM encryption, JWE Compact Serialization */
fun jweSerialization(recipientKeyJwk: JSONObject, plainText: String): String {
    val kid = recipientKeyJwk.optString("kid")
    val publicKey = toEcPublicKey(recipientKeyJwk.getString("x"), recipientKeyJwk.getString("y"))
    val kpg =  KeyPairGenerator.getInstance("EC")
    kpg.initialize(ECGenParameterSpec("secp256r1"))
    val kp = kpg.genKeyPair()
    val partyUInfo = ByteArray(0)
    val partyVInfo = ByteArray(0)
    val header = JSONObject()
    header.put("apu", partyUInfo.toBase64UrlNoPadding())
    header.put("apv", partyVInfo.toBase64UrlNoPadding())
    header.put("alg", "ECDH-ES")
    header.put("kid", kid)
    header.put("enc", "A128GCM")
    header.put("epk", JSONObject(kp.public.toJWK().toString()))
    val headerEncoded = header.toString().toByteArray().toBase64UrlNoPadding()

    val keyAgreement = KeyAgreement.getInstance("ECDH")
    keyAgreement.init(kp.private)
    keyAgreement.doPhase(publicKey, true)
    val sharedSecret = keyAgreement.generateSecret()
    val concatKdf = ConcatKeyDerivationFunction("SHA-256")

    val algOctets = "A128GCM".toByteArray()
    val keydatalen = 128

    val derivedKey = concatKdf.kdf(
        sharedSecret,
        keydatalen,
        intToBigEndianByteArray(algOctets.size) + algOctets,
        intToBigEndianByteArray(partyUInfo.size) + partyUInfo,
        intToBigEndianByteArray(partyVInfo.size) + partyVInfo,
        intToBigEndianByteArray(keydatalen),
        ByteArray(0)
    )
    val sks = SecretKeySpec(derivedKey, "AES")
    val aesCipher = Cipher.getInstance("AES/GCM/NoPadding")
    val iv = ByteArray(12)
    SecureRandom().nextBytes(iv)
    val ivEncoded = iv.toBase64UrlNoPadding()
    aesCipher.init(Cipher.ENCRYPT_MODE, sks, GCMParameterSpec(128, iv))
    aesCipher.updateAAD(headerEncoded.toByteArray())
    val encrypted = aesCipher.doFinal(plainText.toByteArray())
    val ct = encrypted.slice(0 until (encrypted.size - 16)).toByteArray()
    val ctEncoded = ct.toBase64UrlNoPadding()
    val tag = encrypted.slice((encrypted.size - 16) until encrypted.size).toByteArray()
    val tagEncoded = tag.toBase64UrlNoPadding()
    return "${headerEncoded}..${ivEncoded}.${ctEncoded}.${tagEncoded}"
}

fun jweDecrypt(jwe: String, privateKey: PrivateKey): String {
    val parts = jwe.split(".")

    val headerB64 = parts[0]
    val ivB64 = parts[2]
    val ciphertextB64 = parts[3]
    val tagB64 = parts[4]

    val headerJsonStr = String(headerB64.decodeBase64UrlNoPadding(), Charsets.UTF_8)
    val header = JSONObject(headerJsonStr)

    val alg = header.optString("alg")
    val enc = header.optString("enc")
    require(alg == "ECDH-ES" && enc == "A128GCM") { "Unsupported algorithms: alg=$alg, enc=$enc" }

    val epk = header.getJSONObject("epk")
    require(epk.getString("crv") == "P-256") { "Only P-256 curve is supported" }

    val publicKey = toEcPublicKey(epk.getString("x"), epk.getString("y"))

    val keyAgreement = KeyAgreement.getInstance("ECDH")
    keyAgreement.init(privateKey)
    keyAgreement.doPhase(publicKey, true)
    val sharedSecret = keyAgreement.generateSecret()
    val concatKdf = ConcatKeyDerivationFunction("SHA-256")

    val algOctets = "A128GCM".toByteArray()
    val keydatalen = 128

    val apu = if (header.has("apu")) header.getString("apu").decodeBase64UrlNoPadding() else ByteArray(0)
    val apv = if (header.has("apv")) header.getString("apv").decodeBase64UrlNoPadding() else ByteArray(0)

    val derivedKey = concatKdf.kdf(
        sharedSecret,
        keydatalen,
        intToBigEndianByteArray(algOctets.size) + algOctets,
        intToBigEndianByteArray(apu.size) + apu,
        intToBigEndianByteArray(apv.size) + apv,
        intToBigEndianByteArray(keydatalen),
        ByteArray(0)
    )

    val iv = ivB64.decodeBase64UrlNoPadding()
    val ciphertext = ciphertextB64.decodeBase64UrlNoPadding()
    val tag = tagB64.decodeBase64UrlNoPadding()

    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    val secretKey = SecretKeySpec(derivedKey, "AES")

    cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, iv))

    cipher.updateAAD(headerB64.toByteArray())

    // In Java/Android, the Cipher expects the ciphertext and authentication tag to be concatenated
    val combinedCiphertextAndTag = ciphertext + tag
    val plaintextBytes = cipher.doFinal(combinedCiphertextAndTag)

    return String(plaintextBytes, Charsets.UTF_8)
}
