package io.waterkite94.stalk.apigateway.filter

import io.jsonwebtoken.Jwts
import org.apache.http.HttpHeaders
import org.springframework.cloud.gateway.filter.GatewayFilter
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory
import org.springframework.core.env.Environment
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Flux
import reactor.core.publisher.Mono
import java.nio.charset.StandardCharsets
import java.util.Base64
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

@Component
class AuthorizationHeaderFilter(
    private val env: Environment
) : AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config>(Config::class.java) {
    class Config

    override fun apply(config: Config): GatewayFilter {
        return GatewayFilter { exchange, chain ->
            val request = exchange.request

            if (!request.headers.containsKey(HttpHeaders.AUTHORIZATION)) {
                return@GatewayFilter onError(exchange, "No authorization header", HttpStatus.UNAUTHORIZED)
            }

            val authorizationHeader =
                request.headers[HttpHeaders.AUTHORIZATION]?.get(0) ?: return@GatewayFilter onError(
                    exchange,
                    "No authorization header",
                    HttpStatus.UNAUTHORIZED
                )
            val jwt = authorizationHeader.replace("Bearer", "").trim()

            if (!isJwtValid(jwt)) {
                return@GatewayFilter onError(exchange, "JWT token is not valid", HttpStatus.UNAUTHORIZED)
            }

            chain.filter(exchange)
        }
    }

    private fun onError(
        exchange: ServerWebExchange,
        err: String,
        httpStatus: HttpStatus
    ): Mono<Void> {
        val response = exchange.response
        response.statusCode = httpStatus

        val bytes = "The requested token is invalid.".toByteArray(StandardCharsets.UTF_8)
        val buffer = exchange.response.bufferFactory().wrap(bytes)
        return response.writeWith(Flux.just(buffer))
    }

    private fun isJwtValid(jwt: String): Boolean {
        val secretKeyBytes = Base64.getEncoder().encode(env.getProperty("token.secret")!!.toByteArray())
        val signingKey: SecretKey = SecretKeySpec(secretKeyBytes, "HmacSHA512")

        var returnValue = true
        var subject: String? = null

        try {
            val jwtParser =
                Jwts
                    .parser()
                    .verifyWith(signingKey)
                    .build()

            val claimsJws = jwtParser.parseSignedClaims(jwt)
            subject = claimsJws.payload.subject
        } catch (ex: Exception) {
            returnValue = false
        }

        if (subject.isNullOrEmpty()) {
            returnValue = false
        }

        return returnValue
    }
}
