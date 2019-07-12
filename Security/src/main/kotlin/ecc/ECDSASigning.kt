/*
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package ecc

import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.util.encoders.Hex
import java.security.*

private const val CURVE_P256 = "p-256"
private const val CURVE_P384 = "p-384"
private const val CURVE_ED25519 = "curve25519"

private const val SIGN_ALG_SHA256_ECDSA = "SHA256withECDSA"
private const val SIGN_ALG_SHA512_ECDSA = "SHA512withECDSA"

private val SIGN_MESSAGE = "There is no dark side of the moon really. Matter of fact it's all dark.".toByteArray()

/**
 * ECC key generation and ECDSA sign/verify sample with BC provider and default provider (SunEC)
 *
 * @author justy.wong
 *
 */
fun main() {
    Security.addProvider(org.bouncycastle.jce.provider.BouncyCastleProvider())

    testP384()

    test22519()
}

fun testP384() {
    println("<top>.testP384")
    // generate ECC keypair (P-384) with default provider, e.g. "SunEC"
    val kp = genKeypair(384)
    if (kp != null) {
        // sign and verify again with default provider, e.g. "SunEC"
        signVerify(kp, SIGN_ALG_SHA512_ECDSA)
    } else {
        println("ERROR: fail to generate keypair")
    }
}

fun test22519() {
    println("<top>.test22519")
    // generate ED25519 keypair with BC
    val kp = genKeypair(CURVE_ED25519, "BC")
    if (kp != null) {
        // sign and verify again with BC
        signVerify(kp, SIGN_ALG_SHA512_ECDSA, "BC")
    } else {
        println("ERROR: fail to generate keypair")
    }
}

fun genKeypair(keySize:Int, curve:String?, provider:String?, debug:Boolean): KeyPair? {
    try {
        val kpGen = if (provider == null)
            KeyPairGenerator.getInstance("EC")
        else
            KeyPairGenerator.getInstance("EC", provider)
        if (debug)
            println("provider = ${kpGen.provider}")
        if (curve != null) {
            if (debug)
                println("curve = ${curve}")
            kpGen.initialize(ECNamedCurveTable.getParameterSpec(curve), SecureRandom())
        } else {
            if (debug)
                println("keySize = ${keySize}")
            kpGen.initialize(keySize, SecureRandom())
        }

        val kp = kpGen.generateKeyPair()
        val keyPub = kp.public
        val keyPriv = kp.private

        if (debug) {
            println("keyPub = ${keyPub}")
            println("keyPriv = ${keyPriv}")
        }
        return kp
    } catch (e: Exception) {
        println("error = ${e}")
        return null
    }
}

fun genKeypair(keySize:Int): KeyPair? {
    return genKeypair(keySize, null, null, true)
}

fun genKeypair(keySize:Int, provider:String): KeyPair? {
    return genKeypair(keySize, null, provider, true)
}

fun genKeypair(curve:String, provider:String): KeyPair? {
    return genKeypair(-1, curve, provider, true)
}

private fun signVerify(kp:KeyPair, algorithm: String) {
    signVerify(kp, algorithm, null)
}

private fun signVerify(kp:KeyPair, algorithm: String, provider: String?) {
    println("=============================================")
    println("<top>.signVerify")
    println("algorithm = ${algorithm}")
    try {
        val signature = sign(kp.private, SIGN_MESSAGE, algorithm, provider)
        println("signature " + String(Hex.encode(signature)))

        val result = verify(kp.public, SIGN_MESSAGE, signature, algorithm, provider)
        println("result = ${result}")
    } catch (e:Exception) {
        println("error = ${e}")
    }
    println("=============================================")
}

private fun sign(key: PrivateKey, data:ByteArray, algorithm:String, provider: String?):ByteArray {
    val signer = if (provider == null)
        Signature.getInstance(algorithm)
    else
        Signature.getInstance(algorithm, provider)

    println("signer.provider = ${signer.provider}")
    signer.initSign(key)
    signer.update(data)
    return signer.sign()
}

private fun verify(key: PublicKey, data:ByteArray, signature:ByteArray, algorithm: String, provider: String?):Boolean {
    val verifier = if (provider == null)
        Signature.getInstance(algorithm)
    else
        Signature.getInstance(algorithm, provider)

    println("verifier.provider = ${verifier.provider}")
    verifier.initVerify(key)
    verifier.update(data)
    return verifier.verify(signature)
}
