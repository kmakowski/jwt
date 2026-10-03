package kmakowski.jwt

import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jwt.consumer.InvalidJwtException
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import org.jose4j.keys.resolvers.JwksVerificationKeyResolver

data class Claims(
    val email: String,
    val tokenType: String = "id",
    val name: String,
    val subject: String,
    val groups: List<String> = emptyList(),
    val permissions: List<String> = emptyList()
)

class InvalidTokenException(throwable: Throwable):RuntimeException(throwable)

fun extractClaims(token: String, publicKeysJson: String, expectedAudience: String): Claims {
    val jsonWebKeySet = JsonWebKeySet(publicKeysJson)

    val jwtConsumer = JwtConsumerBuilder()
        .setRequireExpirationTime()
        .setAllowedClockSkewInSeconds(30)
        .setRequireSubject()
        .setExpectedAudience(false, expectedAudience)
        .setVerificationKeyResolver(JwksVerificationKeyResolver(jsonWebKeySet.jsonWebKeys))
        .build()

    try {
        val jwtClaims = jwtConsumer.processToClaims(token)
        
        val subject = jwtClaims.subject
        val email = jwtClaims.claimsMap["email"].toString()
        val tokenType = jwtClaims.claimsMap["tokenType"].toString()
        val name = jwtClaims.getStringClaimValue("name") ?: ""
        val groups = jwtClaims.getStringListClaimValue("groups")
        
        return Claims(email = email, subject = subject, name = name, groups = groups, tokenType = tokenType)
    } catch (e: InvalidJwtException) {
        throw InvalidTokenException(e)
    }
}