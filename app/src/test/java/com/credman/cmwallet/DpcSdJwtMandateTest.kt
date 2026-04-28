package com.credman.cmwallet

import com.credman.cmwallet.openid4vp.DelegateProposal
import com.credman.cmwallet.openid4vp.OpenId4VP
import com.credman.cmwallet.sdjwt.SdJwt
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64 as JBase64

/**
 * dSD-JWT HITL mandate tests for [SdJwt.presentWithDelegations].
 *
 * The scenario: a DPC SD-JWT credential is presented in response to an OID4VP request that
 * carries two mandate proposals via `transaction_data[].type = "delegate"`:
 *   1. checkout mandate  (vct = "mandate.checkout.1", checkout_hash)
 *   2. payment mandate   (vct = "mandate.payment",    open with constraints)
 *
 * Wallet produces a dSD-JWT chain:
 *   dpc_issuer_jwt ~ dpc_discs ~ checkout_discs ~ KB-SD-JWT_checkout
 *                  ~ payment_discs ~ KB-SD-JWT_payment ~
 *
 * All KB-SD-JWTs signed by the holder's device key.
 * The agent appends its own KB-JWT (with its key from cnf.jwk) when presenting to a verifier.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE, sdk = [33])
class DpcSdJwtMandateTest {

    // Holder (device) private key PKCS8 – from databasenew.json dpc_v3_2_sdjwt
    private val holderPrivKeyB64Url =
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgD17D2RSlvQ8ElFrP" +
        "qEG3JfXTjxyKEH9DMpFnWp_Z63ihRANCAATyMFauK4kFj767__aM4l9xfgmPiQSp" +
        "jgJRf1x_VtB11nLB9pDhoZXpoUUbj1GBSiWGYFahF0IdiX6LUShkTHyx"

    private lateinit var dpcCredential: String
    private lateinit var holderKey: PrivateKey
    private lateinit var agentPubKeyJwk: JSONObject

    private val TEST_NONCE = "test-nonce-abc123"
    private val TEST_AUD   = "origin:https://pay.example.com"
    private val DPC_CRED_ID = "dpc_credential"

    @Before
    fun setUp() {
        dpcCredential = DPC_SDJWT_CREDENTIAL

        // Decode the Base64URL PKCS#8 key string into a PrivateKey object
        val keyBytes = JBase64.getUrlDecoder().decode(holderPrivKeyB64Url)
        val keySpec = PKCS8EncodedKeySpec(keyBytes)
        val keyFactory = KeyFactory.getInstance("EC")
        holderKey = keyFactory.generatePrivate(keySpec)

        // Generate agent key pair
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))
        val agentKp = kpg.generateKeyPair()
        val agentPub = agentKp.public as ECPublicKey
        agentPubKeyJwk = JSONObject().apply {
            put("kty", "EC"); put("crv", "P-256"); put("use", "sig")
            put("x", encodeCoord(agentPub.w.affineX.toByteArray()))
            put("y", encodeCoord(agentPub.w.affineY.toByteArray()))
        }
    }

    private fun encodeCoord(raw: ByteArray): String {
        val fixed = if (raw.size > 32) raw.copyOfRange(raw.size - 32, raw.size)
                    else raw.copyOf(32).also { raw.copyInto(it, 32 - raw.size) }
        return JBase64.getUrlEncoder().withoutPadding().encodeToString(fixed)
    }

    // ── Fixture builders ───────────────────────────────────────────────────────

    private fun checkoutPayload(checkoutHash: String = "oK0usjWjRUaXbH2PHBvhRGfldH4") =
        JSONObject().apply {
            put("vct", "mandate.checkout.1")
            put("exp", 9_999_999_999L)
            put("cnf", JSONObject().put("jwk", agentPubKeyJwk))
            put("checkout_hash", checkoutHash)
            put("checkout_jwt", "eyJhbGciOiJFUzI1NiIsInR5cCI6ImNoZWNrb3V0K2p3dCJ9.eyJpZCI6Im9yZGVyXzEyMyJ9.sig")
        }

    private fun paymentPayload(transactionId: String = "oK0usjWjRUaXbH2PHBvhRGfldH4") =
        JSONObject().apply {
            put("vct", "mandate.payment")
            put("exp", 9_999_999_999L)
            put("cnf", JSONObject().put("jwk", agentPubKeyJwk))
            put("transaction_id", transactionId)
            put("payee", JSONObject().apply { put("id", "m_lyft_001"); put("name", "Lyft") })
            put("payment_amount", JSONObject().apply { put("amount", 4622); put("currency", "USD") })
            put("payment_instrument", JSONObject().apply {
                put("id", "b3f1c8a2-6d4e-4f9a-9e3d-8a7c2f1b9d34")
                put("type", "dpc")
                put("description", "DPC ···· 4444")
            })
        }

    private fun encodeDelegateItem(
        delegatePayloads: List<JSONObject>,
        delegateDisclosures: List<String> = emptyList()
    ): String {
        val item = JSONObject().apply {
            put("type", "delegate")
            put("format", "dc+sd-jwt")
            put("credential_ids", JSONArray().put(DPC_CRED_ID))
            put("delegate_payload", JSONArray().apply { delegatePayloads.forEach { put(it) } })
            put("delegate_disclosures", JSONArray().apply { delegateDisclosures.forEach { put(it) } })
        }
        return JBase64.getUrlEncoder().withoutPadding()
            .encodeToString(item.toString().toByteArray())
    }

    // Convenience overload for single payload (backward compat in tests)
    private fun encodeDelegateItem(
        delegatePayload: JSONObject,
        delegateDisclosures: List<String> = emptyList()
    ) = encodeDelegateItem(listOf(delegatePayload), delegateDisclosures)

    private fun oid4vpRequest(txItems: List<String> = emptyList()) = JSONObject().apply {
        put("nonce", TEST_NONCE)
        put("client_id", TEST_AUD)
        put("dcql_query", JSONObject().apply {
            put("credentials", JSONArray().put(JSONObject().apply {
                put("id", DPC_CRED_ID)
                put("format", "dc+sd-jwt")
                put("meta", JSONObject().put("vct_values", JSONArray().put("com.emvco.dpc")))
                put("claims", JSONArray().apply {
                    put(JSONObject().put("path", JSONArray().put("card_last_four")))
                    put(JSONObject().put("path", JSONArray().put("credential_id")))
                })
            }))
        })
        if (txItems.isNotEmpty()) put("transaction_data", JSONArray().apply { txItems.forEach { put(it) } })
    }

    private fun decodeJwt(compact: String): Pair<JSONObject, JSONObject> {
        fun dec(b64: String): JSONObject {
            val p = b64.padEnd(b64.length + (4 - b64.length % 4) % 4, '=')
            return JSONObject(String(JBase64.getUrlDecoder().decode(p)))
        }
        val parts = compact.split(".")
        return dec(parts[0]) to dec(parts[1])
    }

    private fun sha256b64url(input: String): String =
        JBase64.getUrlEncoder().withoutPadding()
            .encodeToString(MessageDigest.getInstance("SHA-256").digest(input.toByteArray()))

    private fun agentAddKbJwt(chainPrefix: String, agentNonce: String, agentAud: String): String {
        require(chainPrefix.endsWith("~")) { "Chain prefix must end with ~" }
        val sdHash = sha256b64url(chainPrefix)
        val header = """{"typ":"kb+jwt","alg":"ES256"}"""
        val payload = """{"iat":${System.currentTimeMillis()/1000},"aud":"$agentAud","nonce":"$agentNonce","sd_hash":"$sdHash"}"""
        val h64 = JBase64.getUrlEncoder().withoutPadding().encodeToString(header.toByteArray())
        val p64 = JBase64.getUrlEncoder().withoutPadding().encodeToString(payload.toByteArray())
        val sig = java.security.Signature.getInstance("SHA256withECDSA").apply {
            initSign(holderKey); update("$h64.$p64".toByteArray())
        }.sign()
        val r = sig.copyOfRange(4, 4 + sig[3].toInt())
        val s = sig.copyOfRange(4 + sig[3].toInt() + 2, sig.size)
        val rawR = if (r.size > 32) r.copyOfRange(r.size - 32, r.size) else r.copyOf(32).also { r.copyInto(it, 32 - r.size) }
        val rawS = if (s.size > 32) s.copyOfRange(s.size - 32, s.size) else s.copyOf(32).also { s.copyInto(it, 32 - s.size) }
        val rawSig = JBase64.getUrlEncoder().withoutPadding().encodeToString(rawR + rawS)
        return chainPrefix + "$h64.$p64.$rawSig"
    }

    private fun decodeDisclosure(b64: String): JSONArray {
        val pad = 4 - b64.length % 4
        return JSONArray(String(JBase64.getUrlDecoder().decode(b64 + "=".repeat(pad % 4))))
    }

    // ── Tests ──────────────────────────────────────────────────────────────────

    @Test
    fun `OpenId4VP correctly parses two delegate proposals from single transaction_data item`() {
        val item = encodeDelegateItem(listOf(checkoutPayload(), paymentPayload()))
        val oid4vp = OpenId4VP(oid4vpRequest(listOf(item)), TEST_AUD, "openid4vp-v1-qrcode")

        assertEquals(2, oid4vp.delegateProposals.size)
        with(oid4vp.delegateProposals[0]) {
            assertEquals("dc+sd-jwt", format)
            assertEquals("mandate.checkout.1", delegatePayload.getString("vct"))
            assertTrue(delegatePayload.has("checkout_hash"))
            assertTrue(delegatePayload.has("cnf"))
        }
        with(oid4vp.delegateProposals[1]) {
            assertEquals("mandate.payment", delegatePayload.getString("vct"))
            assertTrue(delegatePayload.has("transaction_id"))
            assertTrue(delegatePayload.has("payee"))
            assertTrue(delegatePayload.has("payment_amount"))
            assertTrue(delegatePayload.has("payment_instrument"))
        }
    }

    @Test
    fun `no delegate proposals means empty list`() {
        val oid4vp = OpenId4VP(oid4vpRequest(), TEST_AUD, "openid4vp-v1-qrcode")
        assertTrue(oid4vp.delegateProposals.isEmpty())
    }

    @Test
    fun `chain has exactly one KB-SD-JWT`() {
        val proposals = listOf(
            DelegateProposal("e1", "dc+sd-jwt", checkoutPayload(), emptyList(), listOf(DPC_CRED_ID)),
            DelegateProposal("e2", "dc+sd-jwt", paymentPayload(),  emptyList(), listOf(DPC_CRED_ID))
        )
        val chain = SdJwt(dpcCredential, holderKey).presentWithDelegations(
            null, TEST_NONCE, TEST_AUD, emptyMap(), proposals
        )
        val parts = chain.split("~").filter { it.isNotEmpty() }
        val compactJwts = parts.filter { it.split(".").size == 3 }
        // issuer JWT + one KB-SD-JWT = 2 compact JWTs total
        assertEquals("Chain must have exactly 2 compact JWTs (issuer + one KB-SD-JWT)", 2, compactJwts.size)
    }

    @Test
    fun `chain ends with trailing tilde`() {
        val proposals = listOf(
            DelegateProposal("e1", "dc+sd-jwt", checkoutPayload(), emptyList(), listOf(DPC_CRED_ID)),
            DelegateProposal("e2", "dc+sd-jwt", paymentPayload(),  emptyList(), listOf(DPC_CRED_ID))
        )
        val chain = SdJwt(dpcCredential, holderKey).presentWithDelegations(
            null, TEST_NONCE, TEST_AUD, emptyMap(), proposals
        )
        assertTrue("Chain must end with ~", chain.endsWith("~"))
    }

    @Test
    fun `KB-SD-JWT header has typ kb-sd-jwt+kb`() {
        val proposals = listOf(
            DelegateProposal("e1", "dc+sd-jwt", checkoutPayload(), emptyList(), listOf(DPC_CRED_ID)),
            DelegateProposal("e2", "dc+sd-jwt", paymentPayload(),  emptyList(), listOf(DPC_CRED_ID))
        )
        val chain = SdJwt(dpcCredential, holderKey).presentWithDelegations(
            null, TEST_NONCE, TEST_AUD, emptyMap(), proposals
        )
        val parts = chain.split("~").filter { it.isNotEmpty() }
        val kbSdJwt = parts.first { it.split(".").size == 3 && it != parts[0] }
        val (header, _) = decodeJwt(kbSdJwt)
        assertEquals("kb-sd-jwt+kb", header.getString("typ"))
        assertEquals("ES256", header.getString("alg"))
    }

    @Test
    fun `KB-SD-JWT header has typ kb-sd-jwt when cnf is missing`() {
        val checkoutNoCnf = checkoutPayload().apply { remove("cnf") }
        val paymentNoCnf = paymentPayload().apply { remove("cnf") }
        val proposals = listOf(
            DelegateProposal("e1", "dc+sd-jwt", checkoutNoCnf, emptyList(), listOf(DPC_CRED_ID)),
            DelegateProposal("e2", "dc+sd-jwt", paymentNoCnf,  emptyList(), listOf(DPC_CRED_ID))
        )
        val chain = SdJwt(dpcCredential, holderKey).presentWithDelegations(
            null, TEST_NONCE, TEST_AUD, emptyMap(), proposals
        )
        val parts = chain.split("~").filter { it.isNotEmpty() }
        val kbSdJwt = parts.first { it.split(".").size == 3 && it != parts[0] }
        val (header, _) = decodeJwt(kbSdJwt)
        assertEquals("kb-sd-jwt", header.getString("typ"))
        assertEquals("ES256", header.getString("alg"))
    }
    @Test
    fun `KB-SD-JWT delegate_payload has one digest per mandate`() {
        val proposals = listOf(
            DelegateProposal("e1", "dc+sd-jwt", checkoutPayload(), emptyList(), listOf(DPC_CRED_ID)),
            DelegateProposal("e2", "dc+sd-jwt", paymentPayload(),  emptyList(), listOf(DPC_CRED_ID))
        )
        val chain = SdJwt(dpcCredential, holderKey).presentWithDelegations(
            null, TEST_NONCE, TEST_AUD, emptyMap(), proposals
        )
        val parts = chain.split("~").filter { it.isNotEmpty() }
        val kbSdJwt = parts.first { it.split(".").size == 3 && it != parts[0] }
        val (_, payload) = decodeJwt(kbSdJwt)

        assertTrue("KB-SD-JWT must have delegate_payload", payload.has("delegate_payload"))
        val dp = payload.getJSONArray("delegate_payload")
        assertEquals("delegate_payload must have one digest per mandate", 2, dp.length())

        // Each entry must be a non-empty string (base64url digest)
        for (i in 0 until dp.length()) {
            val digest = dp.getString(i)
            assertTrue("Digest must be non-empty", digest.isNotEmpty())
            assertTrue("Digest must be base64url (no +/=)", !digest.contains('+') && !digest.contains('='))
        }
    }

    @Test
    fun `KB-SD-JWT has standard KB fields and sd_hash covers DPC base`() {
        val proposals = listOf(
            DelegateProposal("e1", "dc+sd-jwt", checkoutPayload(), emptyList(), listOf(DPC_CRED_ID)),
            DelegateProposal("e2", "dc+sd-jwt", paymentPayload(),  emptyList(), listOf(DPC_CRED_ID))
        )
        val chain = SdJwt(dpcCredential, holderKey).presentWithDelegations(
            null, TEST_NONCE, TEST_AUD, emptyMap(), proposals
        )
        val parts = chain.split("~").filter { it.isNotEmpty() }
        val kbPos = parts.indexOfFirst { it.split(".").size == 3 && it != parts[0] }
        val (_, payload) = decodeJwt(parts[kbPos])

        assertEquals(TEST_NONCE, payload.getString("nonce"))
        assertEquals(TEST_AUD, payload.getString("aud"))
        assertTrue(payload.has("iat"))
        assertEquals("sha-256", payload.getString("_sd_alg"))

        // sd_hash = SHA-256(issuer_jwt ~ dpc_discs ~)
        val dpcBase = parts.subList(0, kbPos).joinToString("~", postfix = "~")
        val expectedSdHash = sha256b64url(dpcBase)
        assertEquals("sd_hash must cover DPC base only", expectedSdHash, payload.getString("sd_hash"))
    }

    @Test
    fun `mandate disclosures come after KB-SD-JWT in chain`() {
        val proposals = listOf(
            DelegateProposal("e1", "dc+sd-jwt", checkoutPayload(), emptyList(), listOf(DPC_CRED_ID)),
            DelegateProposal("e2", "dc+sd-jwt", paymentPayload(),  emptyList(), listOf(DPC_CRED_ID))
        )
        val chain = SdJwt(dpcCredential, holderKey).presentWithDelegations(
            null, TEST_NONCE, TEST_AUD, emptyMap(), proposals
        )
        val parts = chain.split("~").filter { it.isNotEmpty() }
        val kbPos = parts.indexOfFirst { it.split(".").size == 3 && it != parts[0] }

        // Everything after KB-SD-JWT must be disclosures (base64url arrays, not compact JWTs)
        val afterKb = parts.subList(kbPos + 1, parts.size)
        assertEquals("Must have exactly 2 mandate disclosures after KB-SD-JWT", 2, afterKb.size)
        afterKb.forEach { part ->
            assertEquals("Mandate disc must not be a compact JWT", 1, part.split(".").size)
            // Must decode to a 2-element array [salt, mandate_object]
            val decoded = decodeDisclosure(part)
            assertEquals("Mandate disclosure must be 2-element array [salt, object]", 2, decoded.length())
            assertTrue("Second element must be a JSON object", decoded.get(1) is JSONObject)
        }
    }

    @Test
    fun `each mandate digest in delegate_payload matches its disclosure`() {
        val proposals = listOf(
            DelegateProposal("e1", "dc+sd-jwt", checkoutPayload(), emptyList(), listOf(DPC_CRED_ID)),
            DelegateProposal("e2", "dc+sd-jwt", paymentPayload(),  emptyList(), listOf(DPC_CRED_ID))
        )
        val chain = SdJwt(dpcCredential, holderKey).presentWithDelegations(
            null, TEST_NONCE, TEST_AUD, emptyMap(), proposals
        )
        val parts = chain.split("~").filter { it.isNotEmpty() }
        val kbPos = parts.indexOfFirst { it.split(".").size == 3 && it != parts[0] }
        val (_, kbPayload) = decodeJwt(parts[kbPos])
        val delegatePayload = kbPayload.getJSONArray("delegate_payload")
        val mandateDiscs = parts.subList(kbPos + 1, parts.size)

        assertEquals(delegatePayload.length(), mandateDiscs.size)
        for (i in 0 until delegatePayload.length()) {
            val expectedDigest = delegatePayload.getString(i)
            val actualDigest = sha256b64url(mandateDiscs[i])
            assertEquals("Digest in delegate_payload[$i] must match SHA-256(mandate_disc[$i])",
                expectedDigest, actualDigest)
        }
    }

    @Test
    fun `checkout mandate object is correctly embedded in its disclosure`() {
        val checkout = checkoutPayload("specific-hash-123")
        val proposals = listOf(
            DelegateProposal("e1", "dc+sd-jwt", checkout, emptyList(), listOf(DPC_CRED_ID)),
            DelegateProposal("e2", "dc+sd-jwt", paymentPayload(), emptyList(), listOf(DPC_CRED_ID))
        )
        val chain = SdJwt(dpcCredential, holderKey).presentWithDelegations(
            null, TEST_NONCE, TEST_AUD, emptyMap(), proposals
        )
        val parts = chain.split("~").filter { it.isNotEmpty() }
        val kbPos = parts.indexOfFirst { it.split(".").size == 3 && it != parts[0] }
        val checkoutDiscRaw = parts[kbPos + 1]  // first mandate disc = checkout
        val discArr = decodeDisclosure(checkoutDiscRaw)
        val mandateObj = discArr.getJSONObject(1)

        assertEquals("mandate.checkout.1", mandateObj.getString("vct"))
        assertEquals("specific-hash-123", mandateObj.getString("checkout_hash"))
        assertTrue(mandateObj.has("cnf"))
        assertTrue(mandateObj.has("checkout_jwt"))
    }

    @Test
    fun `payment mandate object is correctly embedded in its disclosure`() {
        val proposals = listOf(
            DelegateProposal("e1", "dc+sd-jwt", checkoutPayload(), emptyList(), listOf(DPC_CRED_ID)),
            DelegateProposal("e2", "dc+sd-jwt", paymentPayload(), emptyList(), listOf(DPC_CRED_ID))
        )
        val chain = SdJwt(dpcCredential, holderKey).presentWithDelegations(
            null, TEST_NONCE, TEST_AUD, emptyMap(), proposals
        )
        val parts = chain.split("~").filter { it.isNotEmpty() }
        val kbPos = parts.indexOfFirst { it.split(".").size == 3 && it != parts[0] }
        val paymentDiscRaw = parts[kbPos + 2]  // second mandate disc = payment
        val discArr = decodeDisclosure(paymentDiscRaw)
        val mandateObj = discArr.getJSONObject(1)

        assertEquals("mandate.payment", mandateObj.getString("vct"))
        assertTrue(mandateObj.has("transaction_id"))
        assertTrue(mandateObj.has("payee"))
        assertTrue(mandateObj.has("payment_amount"))
        assertTrue(mandateObj.has("payment_instrument"))
        assertTrue(mandateObj.has("cnf"))
    }

    @Test
    fun `checkout mandate independently presentable to merchant`() {
        val proposals = listOf(
            DelegateProposal("e1", "dc+sd-jwt", checkoutPayload(), emptyList(), listOf(DPC_CRED_ID)),
            DelegateProposal("e2", "dc+sd-jwt", paymentPayload(), emptyList(), listOf(DPC_CRED_ID))
        )
        val chain = SdJwt(dpcCredential, holderKey).presentWithDelegations(
            null, TEST_NONCE, TEST_AUD, emptyMap(), proposals
        )
        val parts = chain.split("~").filter { it.isNotEmpty() }
        val kbPos = parts.indexOfFirst { it.split(".").size == 3 && it != parts[0] }

        // Agent builds checkout-only presentation: dpc_base + KB-SD-JWT + checkout_mandate_disc
        val checkoutDisc = parts[kbPos + 1]
        val checkoutPrefix = (parts.subList(0, kbPos + 1) + checkoutDisc).joinToString("~", postfix = "~")

        val merchantNonce = "merchant-nonce-xyz"
        val merchantAud   = "https://lyft.com"
        val presented = agentAddKbJwt(checkoutPrefix, merchantNonce, merchantAud)

        assertFalse("Presented chain must not end with ~", presented.endsWith("~"))
        val pParts = presented.split("~").filter { it.isNotEmpty() }

        // Agent KB-JWT sd_hash covers dpc_base + KB-SD-JWT + checkout_disc
        val (_, agentKb) = decodeJwt(pParts.last())
        assertEquals(merchantNonce, agentKb.getString("nonce"))
        assertEquals(merchantAud, agentKb.getString("aud"))
        assertEquals(sha256b64url(checkoutPrefix), agentKb.getString("sd_hash"))

        // Chain contains only checkout mandate disc, not payment mandate disc
        val discsAfterKb = pParts.drop(kbPos + 1).dropLast(1)
        assertEquals("Only checkout disc should be in merchant presentation", 1, discsAfterKb.size)
        val obj = decodeDisclosure(discsAfterKb[0]).getJSONObject(1)
        assertEquals("mandate.checkout.1", obj.getString("vct"))

        println("✓ Checkout-only presentation to merchant: ${pParts.size} parts")
    }

    @Test
    fun `payment mandate independently presentable to credential provider`() {
        val proposals = listOf(
            DelegateProposal("e1", "dc+sd-jwt", checkoutPayload(), emptyList(), listOf(DPC_CRED_ID)),
            DelegateProposal("e2", "dc+sd-jwt", paymentPayload(), emptyList(), listOf(DPC_CRED_ID))
        )
        val chain = SdJwt(dpcCredential, holderKey).presentWithDelegations(
            null, TEST_NONCE, TEST_AUD, emptyMap(), proposals
        )
        val parts = chain.split("~").filter { it.isNotEmpty() }
        val kbPos = parts.indexOfFirst { it.split(".").size == 3 && it != parts[0] }

        // Agent builds payment-only presentation: dpc_base + KB-SD-JWT + payment_mandate_disc
        val paymentDisc = parts[kbPos + 2]
        val paymentPrefix = (parts.subList(0, kbPos + 1) + paymentDisc).joinToString("~", postfix = "~")

        val cpNonce = "cp-nonce-xyz"
        val cpAud   = "https://credential-provider.paynet.example"
        val presented = agentAddKbJwt(paymentPrefix, cpNonce, cpAud)

        assertFalse(presented.endsWith("~"))
        val pParts = presented.split("~").filter { it.isNotEmpty() }

        val (_, agentKb) = decodeJwt(pParts.last())
        assertEquals(cpNonce, agentKb.getString("nonce"))
        assertEquals(sha256b64url(paymentPrefix), agentKb.getString("sd_hash"))

        // Chain contains only payment mandate disc, not checkout
        val discsAfterKb = pParts.drop(kbPos + 1).dropLast(1)
        assertEquals("Only payment disc in CP presentation", 1, discsAfterKb.size)
        val obj = decodeDisclosure(discsAfterKb[0]).getJSONObject(1)
        assertEquals("mandate.payment", obj.getString("vct"))

        println("✓ Payment-only presentation to credential provider: ${pParts.size} parts")
    }


    companion object {
        /**
         * DPC SD-JWT credential from databasenew.json (dpc_v3_2_sdjwt).
         * issuer_jwt~disc1~...~disc8~   (8 selective disclosures, trailing ~)
         */
        const val DPC_SDJWT_CREDENTIAL =
            "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImRjK3NkLWp3dCIsICJ4NWMiOiBbIk1JSUM1akNDQW8yZ0F3" +
            "SUJBZ0lVRVJjNEQzRVpQY25MdXg2N1ZWZDU4d2lrWGRjd0NnWUlLb1pJemowRUF3SXdlakVMTUFrR0Ex" +
            "VUVCaE1DVlZNeEV6QVJCZ05WQkFnTUNrTmhiR2xtYjNKdWFXRXhGakFVQmdOVkJBY01EVTF2ZFc1MFlX" +
            "bHVJRlpwWlhjeEhEQWFCZ05WQkFvTUUwUnBaMmwwWVd3Z1EzSmxaR1Z1ZEdsaGJITXhJREFlQmdOVkJB" +
            "TU1GMlJwWjJsMFlXd3RZM0psWkdWdWRHbGhiSE11WkdWMk1CNFhEVEkxTURReU5URTBNVEl5TmxvWERU" +
            "STJNRFF5TlRFME1USXlObG93ZWpFTE1Ba0dBMVVFQmhNQ1ZWTXhFekFSQmdOVkJBZ01Da05oYkdsbWIz" +
            "SnVhV0V4RmpBVUJnTlZCQWNNRFUxdmRXNTBZV2x1SUZacFpYY3hIREFhQmdOVkJBb01FMFJwWjJsMFlX" +
            "d2dRM0psWkdWdWRHbGhiSE14SURBZUJnTlZCQU1NRjJScFoybDBZV3d0WTNKbFpHVnVkR2xoYkhNdVpH" +
            "VjJNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUV1TGQ1aUhPK05UNlJzNDZwQkFrQWM4" +
            "RW1mb3gvOGtqSXJFclF2UGFBSjMxemRWWEV2a1pPZFFqV0wydy9xblJKZ2c4c2hETnp5RUZ0UENqMTg0" +
            "WExGcU9COERDQjdUQWZCZ05WSFNNRUdEQVdnQlQ2aVpRaFo4NG83Mi9lWGZyZHpxMXBUSTdQQ2pBZEJn" +
            "TlZIUTRFRmdRVWc3ZE1LSjViaElVTnBsS2RmWFlhUkdQQ2dOVXdJZ1lEVlIwUkJCc3dHWUlYWkdsbmFY" +
            "UmhiQzFqY21Wa1pXNTBhV0ZzY3k1a1pYWXdOQVlEVlIwZkJDMHdLekFwb0NlZ0pZWWphSFIwY0hNNkx5" +
            "OWthV2RwZEdGc0xXTnlaV1JsYm5ScFlXeHpMbVJsZGk5amNtd3dLZ1lEVlIwU0JDTXdJWVlmYUhSMGNI" +
            "TTZMeTlrYVdkcGRHRnNMV055WldSbGJuUnBZV3h6TG1SbGRqQU9CZ05WSFE4QkFmOEVCQU1DQjRBd0ZR" +
            "WURWUjBsQVFIL0JBc3dDUVlIS0lHTVhRVUJBakFLQmdncWhrak9QUVFEQWdOSEFEQkVBaUFnR3VXekxp" +
            "dnJGbTRWOU45SEN5Z1ErbHU2am9zN2FlZ0d1N2xaOEs1WFFRSWdLM1N0Rm5nL2YwTTdhcUZGWGs1S0VU" +
            "UTN1UUZtY3JUcVE3eHJwWWF3dTFNPSIsICJNSUlDdVRDQ0FsK2dBd0lCQWdJVVE3aG5TbTNrSWRGdUFO" +
            "YW5GcGs0ekVkeW4xc3dDZ1lJS29aSXpqMEVBd0l3ZWpFTE1Ba0dBMVVFQmhNQ1ZWTXhFekFSQmdOVkJB" +
            "Z01Da05oYkdsbWIzSnVhV0V4RmpBVUJnTlZCQWNNRFUxdmRXNTBZV2x1SUZacFpYY3hIREFhQmdOVkJB" +
            "b01FMFJwWjJsMFlXd2dRM0psWkdWdWRHbGhiSE14SURBZUJnTlZCQU1NRjJScFoybDBZV3d0WTNKbFpH" +
            "VnVkR2xoYkhNdVpHVjJNQjRYRFRJMU1EUXlOVEUwTVRJeU5sb1hEVE0xTURReE16RTBNVEl5Tmxvd2Vq" +
            "RUxNQWtHQTFVRUJoTUNWVk14RXpBUkJnTlZCQWdNQ2tOaGJHbG1iM0p1YVdFeEZqQVVCZ05WQkFjTURV" +
            "MXZkVzUwWVdsdUlGWnBaWGN4SERBYUJnTlZCQW9NRTBScFoybDBZV3dnUTNKbFpHVnVkR2xoYkhNeElE" +
            "QWVCZ05WQkFNTUYyUnBaMmwwWVd3dFkzSmxaR1Z1ZEdsaGJITXVaR1YyTUZrd0V3WUhLb1pJemowQ0FR" +
            "WUlLb1pJemowREFRY0RRZ0FFcUlEL0lLV21UMGVlYmQzaEd5OEIwQ2R6VDlxclliOG5IYVFSNGJFNG5Y" +
            "UVFCSEF3ZFd5bTJqakxmYjVXbzJzSCtSdkZrRkFwUG5tdjBhcFA3SXkwaTZPQndqQ0J2ekFpQmdOVkhS" +
            "RUVHekFaZ2hka2FXZHBkR0ZzTFdOeVpXUmxiblJwWVd4ekxtUmxkakFkQmdOVkhRNEVGZ1FVK29tVUlX" +
            "Zk9LTzl2M2wzNjNjNnRhVXlPendvd0h3WURWUjBqQkJnd0ZvQVUrb21VSVdmT0tPOXYzbDM2M2M2dGFV" +
            "eU96d293RWdZRFZSMFRBUUgvQkFnd0JnRUIvd0lCQURBT0JnTlZIUThCQWY4RUJBTUNBUVl3S2dZRFZS" +
            "MFNCQ013SVlZZmFIUjBjSE02THk5a2FXZHBkR0ZzTFdOeVpXUmxiblJwWVd4ekxtUmxkakFKQmdOVkhS" +
            "OEVBakFBTUFvR0NDcUdTTTQ5QkFNQ0EwZ0FNRVVDSUEwdFc0ayt1SEFsOXRmNFdOa3NxRVIwT1JLK2pH" +
            "d1NoV2Z2RjJtVzZKenZBaUVBaGhjQUxxNm1sSmd2MThwZnpjZ1B6N3lPMTc1bmxFWTF0ZVlpYVBmWWlu" +
            "cz0iXX0.eyJfc2QiOiBbIjB5Z1NJTWJ5Q3pfU0FMN0NyWmVEZ19DM0FucUpWZ2YzNUkxdDFpZTBSWnMi" +
            "LCAiMWlwU2VqQUF3X2xBU09lTnNHYmozUl8zTVpOUnRhbGdVOU1ZdmM3M1o1ZyIsICIzZF9rc0xhWTdO" +
            "QXl1OVBRWm9kUkI0WHNxRjJqcXVDc2wyYXZPbG5XQ244IiwgIlBCaFc0MkFUSnFjczNfb2RWaEh1VEdF" +
            "RGhON2lkRG1aTUxMT1JSLWxBZWMiLCAiUE5TSlJYekdQY0J5RUwzX2pGbWM0amd6eEpVSnNUbXVESkZv" +
            "amtUeXNEMCIsICJSQVdnNVhmOXFoaVA3N3BiMVI0TVlZLXJWMjExSlRvS3ZBeF9SdzVzUjd3IiwgInBY" +
            "amJuUmpuMjhKUlVKRHcxa3VVOGtIck5HQWZUQXNzazhCTTF5MUlEd0kiLCAieUdYclZnYjlIS0dJVTlu" +
            "NndFVlBkc3hhZmRGSUllVllSZHI3MkRVOWdpTSJdLCAiaXNzIjogImh0dHBzOi8vZGlnaXRhbC1jcmVk" +
            "ZW50aWFscy5kZXYiLCAiaWF0IjogMTY4MzAwMDAwMCwgImV4cCI6IDE4ODMwMDAwMDAsICJ2Y3QiOiAi" +

            "Y29tLmVtdmNvLmRwYyIsICJfc2RfYWxnIjogInNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6" +
            "ICJFQyIsICJjcnYiOiAiUC0yNTYiLCAieCI6ICI4akJXcml1SkJZLS11X18yak9KZmNYNEpqNGtFcVk0" +
            "Q1VYOWNmMWJRZGRZIiwgInkiOiAiY3NIMmtPR2hsZW1oUlJ1UFVZRktKWVpnVnFFWFFoMkpmb3RSS0dS" +
            "TWZMRSJ9fX0.Coglr0YLOqUrjDLP7nBl_OCWggnn8mO_DrL_Oc7XI2R8xHJvA0fzK3nnSns0sDZ_sAvP" +
            "7wbmR28eJj1dk8XmDw~WyJiWk5wbVRlb0w1dFlVN2dLVFZrVFVBIiwgImNhcmRfbGFzdF9mb3VyIiwgI" +
            "jQ0NDQiXQ~WyJXR01wb2pPQWMtcUVfaUV5bUEyUmlRIiwgImNhcmRfYXJ0X3VybCIsICJodHRwczovL3" +
            "BvY2tldGJhbmsuZXhhbXBsZS9jYXJkLnBuZyJd~WyJCdThHaWU5NDluQWdCZEw2QjY1N013IiwgImNhc" +
            "mRfbmV0d29ya19jb2RlIiwgIkFDTUUiXQ~WyJlNVlrMS01RjM2RlNpa2JWUVhCRFh3IiwgImNhcmRfY2" +
            "9iYWRnZWRfbmV0d29ya19jb2RlIiwgIkxBU0VSIl0~WyJ2eklEdUdxOFcxMTcybW5UWUcxOEp3IiwgIm" +

            "NhcmRfYmluIiwgIjk5MDAwMSJd~WyJFbHIxTmV6QVVHTzBLN21UNUNhVDN3IiwgImNhcmRfaWQiLCAiN" +
            "WQ4ZjdlOWMwYTEyIl0~WyIzOGtxMzBtYzZmZ1MxYnVyeTh1UWtnIiwgImNhcmRfcGFyIiwgIjk5MDBBQ" +
            "kMxMjNYWVo3ODlMTU5PUFFSU1RVVldYIl0~WyJNUThsck5rQXdZbGF2TVQ4b3duNERBIiwgImNyZWRlb" +
            "nRpYWxfaWQiLCAiYjNmMWM4YTItNmQ0ZS00ZjlhLTllM2QtOGE3YzJmMWI5ZDM0Il0~"
    }
}
