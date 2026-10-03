package kmakowski.jwt

import org.jose4j.jwk.JsonWebKey
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jwk.RsaJsonWebKey
import org.jose4j.jwk.RsaJwkGenerator
import java.util.*

object JwkGenerator {
    
    fun generateRandomRsaKey(keySize: Int = 2048): String {
        val rsaKey: RsaJsonWebKey = RsaJwkGenerator.generateJwk(keySize)
        rsaKey.keyId = UUID.randomUUID().toString()
        rsaKey.use = "sig"
        rsaKey.algorithm = "RS256"
        return rsaKey.toJson(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE)
    }
    
    fun generateRandomKeySet(keyCount: Int = 2): String {
        val keys = (1..keyCount).map { 
            JsonWebKey.Factory.newJwk(generateRandomRsaKey())
        }
        return JsonWebKeySet(keys).toJson(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE)
    }
    
    fun generatePublicKeySet(privateKeySetJson: String): String {
        val keySet = JsonWebKeySet(privateKeySetJson)
        return keySet.toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY)
    }
}