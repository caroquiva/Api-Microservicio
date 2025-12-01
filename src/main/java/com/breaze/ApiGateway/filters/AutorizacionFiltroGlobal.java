package com.breaze.ApiGateway.filters; // Reemplaza con tu paquete

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.List;

@Component
public class AutorizacionFiltroGlobal implements GlobalFilter, Ordered {

    @Value("${jwt.secret}")
    private String secretKey;

    private static final String AUTH_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        if (path.startsWith("/autenticacion")) {
            return chain.filter(exchange);
        }

        List<String> authHeaders = request.getHeaders().get(AUTH_HEADER);
        if (authHeaders == null || authHeaders.isEmpty() || !authHeaders.get(0).startsWith(BEARER_PREFIX)) {
            return this.onError(exchange, "Token no presente o formato inválido", HttpStatus.UNAUTHORIZED);
        }

        String token = authHeaders.get(0).substring(BEARER_PREFIX.length());

        try {
            Claims claims = this.validateAndGetClaims(token);

            String userId = claims.getSubject();
            String roles = claims.get("roles", String.class);

            ServerHttpRequest modifiedRequest = request.mutate()
                    .header("X-User-ID", userId)
                    .header("X-User-Roles", roles != null ? roles : "")
                    .build();

            return chain.filter(exchange.mutate().request(modifiedRequest).build());

        } catch (ExpiredJwtException e) {
            return this.onError(exchange, "Token expirado", HttpStatus.UNAUTHORIZED);
        } catch (SignatureException | MalformedJwtException e) {
            return this.onError(exchange, "Token inválido (firma o formato)", HttpStatus.FORBIDDEN);
        } catch (Exception e) {
            return this.onError(exchange, "Error de validación: Acceso denegado", HttpStatus.FORBIDDEN);
        }
    }

    // Método que realiza la validación usando la clave secreta
    private Claims validateAndGetClaims(String token) {
        // Usa la clave inyectada para crear el objeto SecretKey
        SecretKey key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));

        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    // Método de utilidad para manejar errores y detener la cadena
    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        // Opcional: Loggear el error o añadir un cuerpo de respuesta JSON
        return response.setComplete();
    }

    @Override
    public int getOrder() {
        // Asegura que el filtro de seguridad se ejecute primero
        return -1;
    }
}