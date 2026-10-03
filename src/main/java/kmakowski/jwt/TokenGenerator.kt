package kmakowski.jwt

import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jwk.RsaJsonWebKey
import org.jose4j.jws.AlgorithmIdentifiers
import org.jose4j.jws.JsonWebSignature
import org.jose4j.jwt.JwtClaims
import java.util.*

data class GenerateTokenRequest(
    val keySet: String,
    val subject: String,
    val email: String,
    val groupNames: List<String> = emptyList(),
    val issuer: String = "",
    val audience: String = "",
    /**
     * "id" or "refresh"
     */
    val tokenType: String = "id",
    val expirationTimeMinutes: Float = 10F
)

fun generateToken(req: GenerateTokenRequest): String {
    val signingKey: RsaJsonWebKey = selectSigningKey(req.keySet)
    val claims = JwtClaims()
    claims.issuer = req.issuer
    claims.setAudience(req.audience)
    claims.setExpirationTimeMinutesInTheFuture(req.expirationTimeMinutes)
    claims.setGeneratedJwtId()
    claims.setIssuedAtToNow()
    claims.setNotBeforeMinutesInThePast(2f)
    claims.subject = req.subject
    claims.setClaim("email", req.email)
    claims.setClaim("tokenType", req.tokenType)
    claims.setStringListClaim("groups", req.groupNames)

    val jws = JsonWebSignature()
    jws.payload = claims.toJson()
    jws.key = signingKey.rsaPrivateKey
    jws.keyIdHeaderValue = signingKey.keyId
    jws.algorithmHeaderValue = AlgorithmIdentifiers.RSA_USING_SHA256
    return jws.compactSerialization
}

fun selectSigningKey(keySet: String): RsaJsonWebKey {
    val jsonWebKeySet = JsonWebKeySet(keySet)
    val jsonWebKeys = jsonWebKeySet.jsonWebKeys

    return jsonWebKeys[Random().nextInt(jsonWebKeys.size)] as RsaJsonWebKey
}