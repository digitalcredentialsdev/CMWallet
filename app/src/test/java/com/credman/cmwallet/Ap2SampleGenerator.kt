package com.credman.cmwallet

import com.credman.cmwallet.openid4vp.DelegateProposal
import com.credman.cmwallet.sdjwt.SdJwt
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64 as JBase64

/**
 * Generates a concrete annotated OID4VP request+response sample for AP2 HITL mandate flow.
 * Run with: ./gradlew testDebugUnitTest --tests "*Ap2SampleGenerator*"
 * Output goes to stdout / test report.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE, sdk = [33])
class Ap2SampleGenerator {

    private val holderPrivKeyB64Url =
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgD17D2RSlvQ8ElFrP" +
                "qEG3JfXTjxyKEH9DMpFnWp_Z63ihRANCAATyMFauK4kFj767__aM4l9xfgmPiQSp" +
                "jgJRf1x_VtB11nLB9pDhoZXpoUUbj1GBSiWGYFahF0IdiX6LUShkTHyx"

    private val dpcCredential = DpcSdJwtMandateTest.DPC_SDJWT_CREDENTIAL

    @Test
    fun `generate annotated AP2 end-to-end sample`() {

        // ── Agent key pair (AI agent that will hold the mandates) ──────────────
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))
        val agentKp   = kpg.generateKeyPair()
        val agentPub  = agentKp.public as ECPublicKey

        fun coord(raw: ByteArray): String {
            val fixed = if (raw.size > 32) raw.copyOfRange(raw.size - 32, raw.size)
            else raw.copyOf(32).also { raw.copyInto(it, 32 - raw.size) }
            return JBase64.getUrlEncoder().withoutPadding().encodeToString(fixed)
        }
        val agentJwk = JSONObject().apply {
            put("kty", "EC"); put("crv", "P-256"); put("use", "sig")
            put("x", coord(agentPub.w.affineX.toByteArray()))
            put("y", coord(agentPub.w.affineY.toByteArray()))
        }

        // ── Build a realistic checkout_jwt (merchant-signed, here just a compact JWT stub) ─
        val checkoutJwtPayload = JSONObject().apply {
            put("id",       "order_20260330_9f3a")
            put("status",   "pending_payment")
            put("currency", "USD")
            put("merchant", JSONObject().apply { put("id", "m_lyft_001"); put("name", "Lyft") })
            put("line_items", JSONArray().put(JSONObject().apply {
                put("title", "Ride to SFO"); put("quantity", 1); put("unit_price", "42.50")
            }))
            put("totals", JSONObject().apply {
                put("subtotal", "42.50"); put("tax", "3.72"); put("total", "46.22")
            })
        }
        // checkout_jwt = "merchant.header.sig" (stub — in real flow merchant signs this)
        val checkoutJwtStub  = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImNoZWNrb3V0K2p3dCJ9" +
                "." + JBase64.getUrlEncoder().withoutPadding()
            .encodeToString(checkoutJwtPayload.toString().toByteArray()) +
                ".MERCHANT_SIGNATURE_STUB"
        val checkoutHash = JBase64.getUrlEncoder().withoutPadding()
            .encodeToString(MessageDigest.getInstance("SHA-256")
                .digest(checkoutJwtStub.toByteArray()))

        // ── Selective disclosure for checkout_jwt in the checkout mandate ──────
        // Merchant pre-computes: disclosure = base64url(["salt","checkout_jwt","<value>"])
        val checkoutDisclosureArr = JSONArray()
            .put("8eONq8oSDj4kQ7R2aF5Lnw")
            .put("checkout_jwt")
            .put(checkoutJwtStub)
        val checkoutDisclosure = JBase64.getUrlEncoder().withoutPadding()
            .encodeToString(checkoutDisclosureArr.toString().toByteArray())
        val checkoutDiscDigest = JBase64.getUrlEncoder().withoutPadding()
            .encodeToString(MessageDigest.getInstance("SHA-256")
                .digest(checkoutDisclosure.toByteArray()))

        // ── Delegate payloads ──────────────────────────────────────────────────
        val checkoutDelegatePayload = JSONObject().apply {
            put("vct",          "mandate.checkout.1")
            put("exp",          9_999_999_999L)
            put("cnf",          JSONObject().put("jwk", agentJwk))
            put("checkout_hash", checkoutHash)
            put("_sd",          JSONArray().put(checkoutDiscDigest))
            put("_sd_alg",      "sha-256")
        }

        val paymentDelegatePayload = JSONObject().apply {
            put("vct",  "mandate.payment")
            put("exp",  9_999_999_999L)
            put("cnf",  JSONObject().put("jwk", agentJwk))
            put("constraints", JSONArray().apply {
                put(JSONObject().apply {
                    put("type", "payment.amount"); put("currency", "USD"); put("max", "46.22")
                })
                put(JSONObject().apply {
                    put("type", "payment.allowed_payees")
                    put("allowed", JSONArray().put("lyft.com"))
                })
                put(JSONObject().apply {
                    put("type", "payment.reference")
                    put("checkout_reference", checkoutHash)
                })
            })
        }

        // ── Encode transaction_data items ─────────────────────────────────────
        fun encodeTd(payload: JSONObject, discs: List<String> = emptyList()): String {
            val item = JSONObject().apply {
                put("type",            "delegate")
                put("format",          "dc+sd-jwt")
                put("credential_ids",  JSONArray().put("dpc_credential"))
                put("delegate_payload", JSONArray().put(payload))
                put("delegate_disclosures", JSONArray().apply { discs.forEach { put(it) } })
            }
            return JBase64.getUrlEncoder().withoutPadding()
                .encodeToString(item.toString().toByteArray())
        }
        val td0 = encodeTd(checkoutDelegatePayload, listOf(checkoutDisclosure))
        val td1 = encodeTd(paymentDelegatePayload)

        // ── OID4VP Authorization Request ───────────────────────────────────────
        val nonce     = "s6FhdRcsNDIIm_4YmFDd1A"
        val clientId  = "origin:https://agent.ap2.example"
        val request = JSONObject().apply {
            put("nonce",     nonce)
            put("client_id", clientId)
            put("response_type", "vp_token")
            put("response_mode", "dc_api")
            put("dcql_query", JSONObject().apply {
                put("credentials", JSONArray().put(JSONObject().apply {
                    put("id",     "dpc_credential")
                    put("format", "dc+sd-jwt")
                    put("meta",   JSONObject().put("vct_values", JSONArray().put("com.emvco.dpc")))
                    put("claims", JSONArray().apply {
                        put(JSONObject().put("path", JSONArray().put("card_last_four")))
                        put(JSONObject().put("path", JSONArray().put("card_network_code")))
                        put(JSONObject().put("path", JSONArray().put("credential_id")))
                    })
                }))
            })
            put("transaction_data", JSONArray().put(td0).put(td1))
        }

        // ── Wallet processes the request ───────────────────────────────────────
        val keyBytes = JBase64.getUrlDecoder().decode(holderPrivKeyB64Url)
        val keySpec = PKCS8EncodedKeySpec(keyBytes)
        val keyFactory = KeyFactory.getInstance("EC")
        val holderKey = keyFactory.generatePrivate(keySpec)

        val proposals = listOf(
            DelegateProposal("e1","dc+sd-jwt", checkoutDelegatePayload,
                listOf(checkoutDisclosure), listOf("dpc_credential")),
            DelegateProposal("e2","dc+sd-jwt", paymentDelegatePayload,
                emptyList(), listOf("dpc_credential"))
        )
        val dpcSdJwt  = SdJwt(dpcCredential, holderKey)
        val vpChain   = dpcSdJwt.presentWithDelegations(
            claimSets             = null,
            nonce                 = nonce,
            aud                   = clientId,
            transactionDataHashes = emptyMap(),
            delegateProposals     = proposals
        )

        // ── Parse the chain for annotation ────────────────────────────────────
        val chainParts = vpChain.split("~").dropLast(1)
        fun dec(b64: String): JSONObject {
            val p = b64.padEnd(b64.length + (4-b64.length%4)%4,'=')
            return JSONObject(String(JBase64.getUrlDecoder().decode(p)))
        }
        fun decJwt(c: String) = c.split(".").let { dec(it[0]) to dec(it[1]) }
        val isCompact = { s: String -> s.split(".").size == 3 }

        val issuerJwt      = chainParts[0]
        val dpcDiscs       = chainParts.drop(1).filter { !isCompact(it) }.takeWhile { !isCompact(it) }
        // KB-SD-JWTs: compact JWTs after index 0
        val kbSdJwts       = chainParts.drop(1).filter { isCompact(it) }
        val (_, issPayload) = decJwt(issuerJwt)
        val (kb1Header, kb1Payload) = decJwt(kbSdJwts[0])
        val (kb2Header, kb2Payload) = decJwt(kbSdJwts[1])

        val sep = "═".repeat(72)
        val sep2 = "─".repeat(72)

        println("\n$sep")
        println("  AP2 HITL dSD-JWT MANDATE FLOW — END-TO-END SAMPLE")
        println(sep)

        println("""
┌─────────────────────────────────────────────────────────────────────┐
│  OVERVIEW                                                           │
│                                                                     │
│  User opens AI shopping agent. Agent wants to pay for a Lyft ride  │
│  on the user's behalf (HITL consent). Flow:                         │
│                                                                     │
│  1. Agent constructs OID4VP request with two mandate proposals      │
│  2. Wallet presents DPC SD-JWT + signs two KB-SD-JWTs (mandates)   │
│  3. Agent stores the dSD-JWT chain (trailing ~, no agent KB-JWT)   │
│                                                                     │
│  Later (user offline):                                              │
│  4. Agent → merchant:  chain prefix [DPC~discs~KB-checkout~] + KB  │
│  5. Agent → payment:   full chain   [DPC~discs~KB-checkout~KB-pay~] + KB │
└─────────────────────────────────────────────────────────────────────┘""")

        println("\n$sep")
        println("  STEP 1 — OID4VP AUTHORIZATION REQUEST  (agent → DC API)")
        println(sep)
        println("""
  protocol:      openid4vp-v1-qrcode
  response_type: vp_token
  response_mode: dc_api

  nonce:     $nonce
  client_id: $clientId

  dcql_query:
    credentials[0]:
      id:     "dpc_credential"
      format: "dc+sd-jwt"
      meta:   { vct_values: ["com.emvco.dpc"] }
      claims: [ card_last_four, card_network_code, credential_id ]

  transaction_data[0]  ← checkout mandate proposal
    (base64url-decoded):
    {
      "type":            "delegate",
      "format":          "dc+sd-jwt",
      "credential_ids":  ["dpc_credential"],
      "delegate_payload": [{
        "vct":           "mandate.checkout.1",
        "exp":           9999999999,
        "cnf":           { "jwk": { "kty":"EC","crv":"P-256",
                           "x":"${agentJwk.getString("x").take(22)}...",
                           "y":"${agentJwk.getString("y").take(22)}..." } },
        "checkout_hash": "${checkoutHash.take(32)}...",
        "_sd":           ["${checkoutDiscDigest.take(32)}..."],
        "_sd_alg":       "sha-256"
      }],
      "delegate_disclosures": [
        // disclosure for checkout_jwt (selectively disclosed):
        // base64url(["8eONq8oSDj4kQ7R2aF5Lnw", "checkout_jwt", "<checkout_jwt_value>"])
        "${checkoutDisclosure.take(40)}..."
      ]
    }

  transaction_data[1]  ← payment mandate proposal
    (base64url-decoded):
    {
      "type":            "delegate",
      "format":          "dc+sd-jwt",
      "credential_ids":  ["dpc_credential"],
      "delegate_payload": [{
        "vct":  "mandate.payment",
        "exp":  9999999999,
        "cnf":  { "jwk": { ... same agent key ... } },
        "constraints": [
          { "type":"payment.amount",        "currency":"USD", "max":"46.22"  },
          { "type":"payment.allowed_payees","allowed":["lyft.com"]           },
          { "type":"payment.reference",     "checkout_reference":"${checkoutHash.take(20)}..." }
        ]
      }],
      "delegate_disclosures": []
    }""")

        println("\n$sep")
        println("  STEP 2 — WALLET PROCESSES REQUEST")
        println(sep)
        println("""
  DPC credential matched:  dpc_v3_2_sdjwt  (card ending 4444, ACME network)
  Holder device key:       EC P-256 (software key bound to DPC via cnf.jwk)

  delegateProposals parsed:
    [0] format=dc+sd-jwt  vct=mandate.checkout.1  discs=1
    [1] format=dc+sd-jwt  vct=mandate.payment     discs=0

  → User sees:  "Lyft wants to charge up to ${"$"}46.22 to card ending 4444"
  → User approves via biometric
  → Wallet calls presentWithDelegations()""")

        println("\n$sep")
        println("  STEP 3 — VP TOKEN  (dSD-JWT chain, trailing ~)")
        println(sep)
        println("""
  vp_token: {
    "dpc_credential": "<dSD-JWT chain>"
  }

  Chain structure (parts joined by ~):

  ┌─ [0] DPC ISSUER JWT  (compact JWT, signed by EMVCo issuer)
  │    typ: dc+sd-jwt
  │    iss: https://digital-credentials.dev
  │    vct: com.emvco.dpc
  │    iat: ${issPayload.optLong("iat")}
  │    exp: ${issPayload.optLong("exp")}
  │    cnf.jwk.x: "${issPayload.optJSONObject("cnf")?.optJSONObject("jwk")?.optString("x")?.take(30)}..."
  │              ↑ holder device key (P-256)
  │    _sd: [8 digests for card_last_four, card_art_url, card_network_code, ...]
  │    value: ${issuerJwt.take(50)}...
  │
  ├─ [1..8] DPC SELECTIVE DISCLOSURES  (${dpcDiscs.size + chainParts.drop(1).filter { !isCompact(it) && chainParts.indexOf(it) > 0 }.size} disclosures)
  │    Each: base64url(["<salt>", "<claim_name>", "<value>"])
  │    card_last_four    → "4444"
  │    card_network_code → "ACME"
  │    credential_id     → "b3f1c8a2-6d4e-4f9a-9e3d-8a7c2f1b9d34"
  │    (+ 5 others: card_art_url, card_cobadged_network_code, card_bin, card_id, card_par)
  │
  ├─ [9] CHECKOUT DISCLOSURE  (from delegate_disclosures[0])
  │    base64url(["8eONq8oSDj4kQ7R2aF5Lnw", "checkout_jwt", "<checkout_jwt>"])
  │    value: ${checkoutDisclosure.take(50)}...
  │
  ├─ [10] KB-SD-JWT_1  ← CHECKOUT MANDATE  (signed by device key)
  │    typ:           ${kb1Header.optString("typ")}
  │    alg:           ES256
  │    vct:           ${kb1Payload.optString("vct")}
  │    exp:           ${kb1Payload.optLong("exp")}
  │    cnf.jwk.x:    "${kb1Payload.optJSONObject("cnf")?.optJSONObject("jwk")?.optString("x")?.take(30)}..."
  │                   ↑ AGENT key (delegatee)
  │    checkout_hash: "${kb1Payload.optString("checkout_hash").take(32)}..."
  │    _sd:           ["${kb1Payload.optJSONArray("_sd")?.optString(0)?.take(20)}..."]
  │    nonce:         ${kb1Payload.optString("nonce")}
  │    aud:           ${kb1Payload.optString("aud")}
  │    iat:           ${kb1Payload.optLong("iat")}
  │    sd_hash:       ${kb1Payload.optString("sd_hash").take(32)}...
  │                   ↑ SHA-256(parts[0..9]~) = commits to DPC + all disclosures
  │    value: ${kbSdJwts[0].take(50)}...
  │
  ├─ [11] KB-SD-JWT_2  ← PAYMENT MANDATE  (signed by device key)
  │    typ:      ${kb2Header.optString("typ")}
  │    alg:      ES256
  │    vct:      ${kb2Payload.optString("vct")}
  │    exp:      ${kb2Payload.optLong("exp")}
  │    cnf.jwk.x: "${kb2Payload.optJSONObject("cnf")?.optJSONObject("jwk")?.optString("x")?.take(30)}..."
  │               ↑ AGENT key (same delegatee)
  │    constraints: [
  │      { type:payment.amount,        currency:USD, max:46.22 }
  │      { type:payment.allowed_payees, allowed:[lyft.com]     }
  │      { type:payment.reference,     checkout_reference:...  }
  │    ]
  │    nonce:    ${kb2Payload.optString("nonce")}
  │    aud:      ${kb2Payload.optString("aud")}
  │    iat:      ${kb2Payload.optLong("iat")}
  │    sd_hash:  ${kb2Payload.optString("sd_hash").take(32)}...
  │              ↑ SHA-256(parts[0..10]~) = commits to DPC + discs + KB-SD-JWT_checkout
  │              ↑ Payment mandate is cryptographically bound to the checkout mandate
  │    value: ${kbSdJwts[1].take(50)}...
  │
  └─ [trailing ~]  ← no agent KB-JWT yet; agent appends when presenting""")

        // ── Incremental presentations ──────────────────────────────────────────
        // Compute where KB-SD-JWT_1 is in parts
        val kbPos1 = chainParts.indexOfFirst { isCompact(it) && chainParts.indexOf(it) > 0 }
        val checkoutOnlyChain = chainParts.subList(0, kbPos1 + 1).joinToString("~", postfix = "~")
        val sdHashCheckout = JBase64.getUrlEncoder().withoutPadding()
            .encodeToString(MessageDigest.getInstance("SHA-256").digest(checkoutOnlyChain.toByteArray()))

        val fullChain = chainParts.joinToString("~", postfix = "~")
        val sdHashFull = JBase64.getUrlEncoder().withoutPadding()
            .encodeToString(MessageDigest.getInstance("SHA-256").digest(fullChain.toByteArray()))

        println("\n$sep")
        println("  STEP 4a — AGENT PRESENTS CHECKOUT MANDATE  (agent → merchant)")
        println(sep)
        println("""
  Agent takes prefix of chain up to KB-SD-JWT_checkout, appends its own KB-JWT:

  dpc_jwt ~ dpc_discs(8) ~ checkout_disc(1) ~ KB-SD-JWT_checkout ~ [AGENT_KB-JWT]

  AGENT_KB-JWT:
    typ:     kb+jwt
    alg:     ES256  (signed with AGENT private key, matching cnf.jwk in KB-SD-JWT_checkout)
    aud:     https://lyft.com/checkout-verifier
    nonce:   <merchant-session-nonce>
    sd_hash: $sdHashCheckout
             ↑ SHA-256(dpc_jwt~discs~checkout_disc~KB-SD-JWT_checkout~)
             ↑ covers DPC + checkout mandate only

  Merchant verifies:
    1. DPC issuer JWT  → valid x5c chain to EMVCo root
    2. KB-SD-JWT_checkout as the KB-JWT → signed by device key (cnf of DPC) ✓
    3. KB-SD-JWT_checkout as SD-JWT → vct=mandate.checkout.1, checkout_hash matches ✓
    4. checkout_jwt disclosure → reveals full checkout object ✓
    5. AGENT_KB-JWT → signed by agent key (cnf.jwk of KB-SD-JWT_checkout) ✓""")

        println("\n$sep")
        println("  STEP 4b — AGENT PRESENTS PAYMENT MANDATE  (agent → payment network)")
        println(sep)
        println("""
  Agent uses full chain (both KB-SD-JWTs), appends its own KB-JWT:

  dpc_jwt ~ dpc_discs(8) ~ checkout_disc(1) ~ KB-SD-JWT_checkout ~ KB-SD-JWT_payment ~ [AGENT_KB-JWT]

  AGENT_KB-JWT:
    typ:     kb+jwt
    alg:     ES256  (signed with AGENT private key)
    aud:     https://paymentnetwork.example/auth
    nonce:   <payment-session-nonce>
    sd_hash: $sdHashFull
             ↑ SHA-256(dpc_jwt~discs~checkout_disc~KB-SD-JWT_checkout~KB-SD-JWT_payment~)
             ↑ covers DPC + checkout mandate + payment mandate

  Payment network verifies:
    1. DPC issuer JWT         → valid, vct=com.emvco.dpc ✓
    2. KB-SD-JWT_checkout     → sd_hash covers DPC only; signed by device key ✓
    3. KB-SD-JWT_payment      → sd_hash covers DPC + checkout (binding!) ✓
                                vct=mandate.payment, amount≤46.22 USD, payee=lyft.com ✓
                                constraints[payment.reference] links to checkout_hash ✓
    4. AGENT_KB-JWT           → signed by agent key (cnf.jwk of KB-SD-JWT_payment) ✓
    5. card_last_four=4444, credential_id=b3f1c8a2-... ✓ (from DPC disclosures)""")

        println("\n$sep")
        println("  KEY SECURITY PROPERTIES")
        println(sep)
        println("""
  ✓ User consent is biometric-bound  (device key signs KB-SD-JWTs)
  ✓ Checkout mandate → presentable independently to merchant
  ✓ Payment mandate  → carries full consent chain (binds to checkout via sd_hash)
  ✓ Agent cannot forge mandates  (device key required for signing)
  ✓ Agent cannot strip checkout from payment presentation  (sd_hash locks it in)
  ✓ Replay prevented  (nonce+aud in each KB-SD-JWT; nonce+aud in agent KB-JWT)
  ✓ DPC selective disclosure  (only card_last_four, card_network_code, credential_id revealed)
  ✓ checkout_jwt selectively disclosed  (only revealed to checkout verifier if needed)
  ✓ Chain is extensible  (more mandate types → more KB-SD-JWTs appended)""")

        println("\n$sep\n")
    }

    @Test
    fun `output raw request and response JSON`() {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))
        val agentKp  = kpg.generateKeyPair()
        val agentPub = agentKp.public as ECPublicKey
        fun coord(raw: ByteArray): String {
            val fixed = if (raw.size > 32) raw.copyOfRange(raw.size - 32, raw.size)
            else raw.copyOf(32).also { raw.copyInto(it, 32 - raw.size) }
            return JBase64.getUrlEncoder().withoutPadding().encodeToString(fixed)
        }
        val agentJwk = JSONObject().apply {
            put("kty","EC"); put("crv","P-256"); put("use","sig")
            put("x", coord(agentPub.w.affineX.toByteArray()))
            put("y", coord(agentPub.w.affineY.toByteArray()))
        }

        val checkoutJwtPayload = JSONObject().apply {
            put("id","order_20260331_9f3a"); put("status","pending_payment"); put("currency","USD")
            put("merchant", JSONObject().apply { put("id","m_lyft_001"); put("name","Lyft") })
            put("line_items", JSONArray().put(JSONObject().apply {
                put("title","Ride to SFO"); put("quantity",1); put("unit_price","42.50")
            }))
            put("totals", JSONObject().apply { put("subtotal","42.50"); put("tax","3.72"); put("total","46.22") })
        }
        val checkoutJwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImNoZWNrb3V0K2p3dCJ9." +
                JBase64.getUrlEncoder().withoutPadding().encodeToString(checkoutJwtPayload.toString().toByteArray()) +
                ".MERCHANT_SIG"
        val checkoutHash = JBase64.getUrlEncoder().withoutPadding()
            .encodeToString(MessageDigest.getInstance("SHA-256").digest(checkoutJwt.toByteArray()))

        val checkoutDiscArr = JSONArray().put("8eONq8oSDj4kQ7R2aF5Lnw").put("checkout_jwt").put(checkoutJwt)
        val checkoutDisc = JBase64.getUrlEncoder().withoutPadding()
            .encodeToString(checkoutDiscArr.toString().toByteArray())
        val checkoutDiscDigest = JBase64.getUrlEncoder().withoutPadding()
            .encodeToString(MessageDigest.getInstance("SHA-256").digest(checkoutDisc.toByteArray()))

        val checkoutPayload = JSONObject().apply {
            put("vct","mandate.checkout.1"); put("exp",9_999_999_999L)
            put("cnf", JSONObject().put("jwk", agentJwk))
            put("checkout_hash", checkoutHash)
            put("_sd", JSONArray().put(checkoutDiscDigest)); put("_sd_alg","sha-256")
        }
        val paymentPayload = JSONObject().apply {
            put("vct","mandate.payment"); put("exp",9_999_999_999L)
            put("cnf", JSONObject().put("jwk", agentJwk))
            put("constraints", JSONArray().apply {
                put(JSONObject().apply { put("type","payment.amount"); put("currency","USD"); put("max","46.22") })
                put(JSONObject().apply { put("type","payment.allowed_payees"); put("allowed", JSONArray().put("lyft.com")) })
                put(JSONObject().apply { put("type","payment.reference"); put("checkout_reference", checkoutHash) })
            })
        }

        fun encodeTd(p: JSONObject, discs: List<String> = emptyList()) =
            JBase64.getUrlEncoder().withoutPadding().encodeToString(
                JSONObject().apply {
                    put("type","delegate"); put("format","dc+sd-jwt")
                    put("credential_ids", JSONArray().put("dpc_credential"))
                    put("delegate_payload", JSONArray().put(p))
                    put("delegate_disclosures", JSONArray().apply { discs.forEach { put(it) } })
                }.toString().toByteArray()
            )

        val nonce = "s6FhdRcsNDIIm_4YmFDd1A"
        val clientId = "origin:https://agent.ap2.example"
        val td0 = encodeTd(checkoutPayload, listOf(checkoutDisc))
        val td1 = encodeTd(paymentPayload)

        val request = JSONObject().apply {
            put("nonce", nonce); put("client_id", clientId)
            put("response_type","vp_token"); put("response_mode","dc_api")
            put("dcql_query", JSONObject().apply {
                put("credentials", JSONArray().put(JSONObject().apply {
                    put("id","dpc_credential"); put("format","dc+sd-jwt")
                    put("meta", JSONObject().put("vct_values", JSONArray().put("com.emvco.dpc")))
                    put("claims", JSONArray().apply {
                        put(JSONObject().put("path", JSONArray().put("card_last_four")))
                        put(JSONObject().put("path", JSONArray().put("card_network_code")))
                        put(JSONObject().put("path", JSONArray().put("credential_id")))
                    })
                }))
            })
            put("transaction_data", JSONArray().put(td0).put(td1))
        }

        val keyBytes = JBase64.getUrlDecoder().decode(holderPrivKeyB64Url)
        val keySpec = PKCS8EncodedKeySpec(keyBytes)
        val keyFactory = KeyFactory.getInstance("EC")
        val holderKey = keyFactory.generatePrivate(keySpec)

        val proposals = listOf(
            DelegateProposal("e1","dc+sd-jwt",checkoutPayload,listOf(checkoutDisc),listOf("dpc_credential")),
            DelegateProposal("e2","dc+sd-jwt",paymentPayload,emptyList(),listOf("dpc_credential"))
        )
        val chain = SdJwt(dpcCredential, holderKey).presentWithDelegations(
            null, nonce, clientId, emptyMap(), proposals
        )

        // sd_hashes for agent KB-JWTs
        val parts = chain.split("~").dropLast(1)
        val isCompact = { s: String -> s.split(".").size == 3 }
        val kbPositions = parts.indices.filter { it > 0 && isCompact(parts[it]) }
        val checkoutPrefix = parts.subList(0, kbPositions[0]+1).joinToString("~", postfix="~")
        val fullPrefix = parts.joinToString("~", postfix="~")
        val sdHashCheckout = JBase64.getUrlEncoder().withoutPadding()
            .encodeToString(MessageDigest.getInstance("SHA-256").digest(checkoutPrefix.toByteArray()))
        val sdHashFull = JBase64.getUrlEncoder().withoutPadding()
            .encodeToString(MessageDigest.getInstance("SHA-256").digest(fullPrefix.toByteArray()))

        println("RAW_REQUEST_START")
        println(request.toString(2))
        println("RAW_REQUEST_END")
        println("RAW_RESPONSE_START")
        println("""{"vp_token":{"dpc_credential":"${chain.take(200)}..."}}""")
        println("RAW_CHAIN_PARTS_START")
        parts.forEachIndexed { i, p -> println("PART[$i]: ${p.take(80)}") }
        println("RAW_CHAIN_PARTS_END")
        println("SD_HASH_CHECKOUT: $sdHashCheckout")
        println("SD_HASH_FULL: $sdHashFull")
        println("CHECKOUT_HASH: $checkoutHash")
        println("CHECKOUT_DISC: $checkoutDisc")
        println("AGENT_JWK_X: ${agentJwk.getString("x")}")
        println("AGENT_JWK_Y: ${agentJwk.getString("y")}")
        println("CHECKOUT_JWT: $checkoutJwt")
        println("RAW_RESPONSE_END")
    }
}
