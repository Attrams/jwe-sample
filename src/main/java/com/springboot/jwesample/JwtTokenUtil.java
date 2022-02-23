package com.springboot.jwesample;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.AESDecrypter;
import com.nimbusds.jose.crypto.AESEncrypter;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * This class is used for generating and validating Json Web Token(JWT).
 *
 * @author Papa Attrams
 * @since 1.0
 */

public class JwtTokenUtil {

    public static final String ISSUER = "http://localhost:8080/";
    public static final String AUTHORITIES = "Authorities";
    public static final String JWT_SECRET_KEY = "2s5v8y/B?E(H+MbQeTgJmZq4t6w9z$C&F)J@NcRsfee2r5u8x!A%D*G-KaD"; // length must be 32 characters or more
    public static final String JWE_ENCRYPTION_KEY = "n2r5u8x/AEfJ+Kgg"; // length must be 16, 24 or 32 bytes(characters).

    /**
     * Generates a Json Web Token(JWT) which is having the subject, issuer, issueTime, notBeforeTime, expirationTime
     * and authorities claims. The Generated token is then used as the payload for an encrypted Json Web Token(JWE).
     * Using the {@link JWEAlgorithm}.A128GCMKW algorithm and {@link EncryptionMethod}.A128GCM method, a JWE is created.
     *
     * @param username The Username
     * @return an encrypted Json Web Token(JWE).
     */
    public String create(String username) {
        String[] claims = getClaimsFromUser(); // Get the roles the user is having

        //Create Jwt Claims
        JWTClaimsSet claimsSet = new JWTClaimsSet
                .Builder()
                .subject(username)
                .issuer(ISSUER)
                .issueTime(new Date(System.currentTimeMillis()))
                .notBeforeTime(new Date(System.currentTimeMillis()))
                .claim(AUTHORITIES, claims)
                .expirationTime(new Date(System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(30)))
                .build();

        // Create JWS header
        JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.HS256);

        // Create JWT
        SignedJWT signedJWT = new SignedJWT(jwsHeader, claimsSet);

        try {
            // Sign the JWT
            signedJWT.sign(new MACSigner(JWT_SECRET_KEY));
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }

        // Create JWE Algorithm
        JWEAlgorithm jweAlgorithm = JWEAlgorithm.A128GCMKW;

        // Create the EncryptionMethod
        EncryptionMethod encryptionMethod = EncryptionMethod.A128GCM;

        // Create JWE Header
        JWEHeader header = new JWEHeader(jweAlgorithm, encryptionMethod);

        // Create JWE object with the signed JWT as payload
        JWEObject jweObject = new JWEObject(header, new Payload(signedJWT));

        try {
            // Encrypt with AESEncrypter with Key
            jweObject.encrypt(new AESEncrypter(JWE_ENCRYPTION_KEY.getBytes(StandardCharsets.UTF_8)));
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }

        // Serialize to JWE compact form
        return jweObject.serialize();
    }

    /**
     * Decrypts the encrypted Json Web Token(JWE) and get the payload which is a Json Web Token(JWT).
     * The payload(a JWT) is then returned.
     *
     * @param token The Encrypted Json Web Token(JWE)
     * @return payload of the JWE which is a Json Web Token(JWT) itself.
     * @throws ParseException This Exception is thrown when an encrypted JWT format doesn't match the required format.
     * @throws JOSEException  This Exception is thrown when an error occurs during decryption of encrypted JWT.
     */
    public String read(String token) throws ParseException, JOSEException {
        // Parse the JWE string
        JWEObject jweObject = JWEObject.parse(token);
        AESDecrypter aesDecrypter = new AESDecrypter(JWE_ENCRYPTION_KEY.getBytes(StandardCharsets.UTF_8));
        jweObject.decrypt(aesDecrypter); // Decrypt with AESDecrypter with specified key

        // Extract payload
        SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();

        return signedJWT.serialize();
    }

    /**
     * This method gets the claims(roles) from the token(JWT) using the {@link #getClaimsFromToken(String)} and return
     * them as a List of String.
     *
     * @param token The Json Web Token(JWT).
     * @return A String List of roles.
     * @throws ParseException This Exception is thrown when the JWT format doesn't match the required format.
     * @throws JOSEException  This Exception is thrown when JWT signature or issuer is incorrect.
     */
    public List<String> getAuthorities(String token) throws ParseException, JOSEException {
        String[] claims = getClaimsFromToken(token); // Get the roles from the token

        return Arrays.stream(claims).map(String::new).collect(Collectors.toList());
    }

    /**
     * This method checks if the token(JWT) has not expired and also if there is a username.
     *
     * @param username The Username
     * @param token    The Json Web Token(JWT)
     * @return True if token(JWT) is valid else False.
     * @throws ParseException This Exception is thrown when the JWT format doesn't match the required format.
     * @throws JOSEException  This Exception is thrown when JWT signature or issuer is incorrect.
     */
    public boolean isTokenValid(String username, String token) throws ParseException, JOSEException {
        JWSVerifier jwsVerifier = getJWSVerifier();
        SignedJWT jwt = SignedJWT.parse(token); // convert token from string to SignedJWT
        verifyJwt(jwt, jwsVerifier);

        return username.length() > 0 && !isTokenExpired(jwsVerifier, token);
    }

    /**
     * This method gets the subject from the token(JWT).
     *
     * @param token The Json Web Token(JWT)
     * @return The Subject of the token(JWT).
     * @throws JOSEException  This Exception is thrown when JWT signature or issuer is incorrect.
     * @throws ParseException This Exception is thrown when the JWT format doesn't match the required format.
     */
    public String getSubject(String token) throws JOSEException, ParseException {
        JWSVerifier jwsVerifier = getJWSVerifier();
        SignedJWT jwt = SignedJWT.parse(token); // convert token from string to SignedJWT
        verifyJwt(jwt, jwsVerifier);

        return jwt.getJWTClaimsSet().getSubject();
    }

    /**
     * This method checks if the token(JWT) hasn't expired.
     *
     * @param verifier The JWSVerifier
     * @param token    The token(JWT)
     * @return True if the token(JWT) hasn't expired else False.
     * @throws ParseException This Exception is thrown when the JWT format doesn't match the required format.
     * @throws JOSEException  This Exception is thrown when JWT signature or issuer is incorrect.
     */
    private boolean isTokenExpired(JWSVerifier verifier, String token) throws ParseException, JOSEException {
        SignedJWT jwt = SignedJWT.parse(token); // convert token from string to SignedJWT
        verifyJwt(jwt, verifier);
        Date expiration = jwt.getJWTClaimsSet().getExpirationTime();

        return expiration.before(new Date());
    }

    /**
     * @return JWSVerifier
     */
    private JWSVerifier getJWSVerifier() {
        JWSVerifier jwsVerifier;
        try {
            jwsVerifier = new MACVerifier(JWT_SECRET_KEY);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
        return jwsVerifier;
    }

    /**
     * This method extracts the claims(roles) from the token(JWT).
     *
     * @param token The Json Web Token
     * @return A String array containing the claims from the token(roles).
     * @throws ParseException This Exception is thrown when the JWT format doesn't match the required format.
     * @throws JOSEException  This Exception is thrown when JWT signature or issuer is incorrect.
     */
    public String[] getClaimsFromToken(String token) throws ParseException, JOSEException {
        JWSVerifier jwsVerifier = getJWSVerifier();
        SignedJWT jwt = SignedJWT.parse(token); // convert token from string to SignedJWT
        verifyJwt(jwt, jwsVerifier);

        JSONArray jsonArray = (JSONArray) jwt.getJWTClaimsSet().getClaim(AUTHORITIES);

        List<String> authorities = new ArrayList<>();
        for (Object element : jsonArray) {
            authorities.add(element.toString());
        }

        return authorities.toArray(new String[]{}); // cast the authorities to string before returning
    }

    /**
     * This method gets the claims(roles) from the user.
     *
     * @return String Array containing the claims(roles).
     */
    public String[] getClaimsFromUser() {
        List<String> authorities = List.of("ROLE_USER", "ROLE_ADMIN");

        return authorities.toArray(new String[0]);
    }

    /**
     * This method checks if the token(JWT) and issuer are valid.
     *
     * @param signedJWT   The SignedJWT
     * @param jwsVerifier The JWSVerifier
     * @throws JOSEException  This Exception is thrown when the JWT format doesn't match the required format.
     * @throws ParseException This Exception is thrown when JWT signature or issuer is incorrect.
     */
    private void verifyJwt(SignedJWT signedJWT, JWSVerifier jwsVerifier) throws JOSEException, ParseException {
        if (!signedJWT.verify(jwsVerifier)) {
            throw new JOSEException("Invalid Signature");
        }
        if (!signedJWT.getJWTClaimsSet().getIssuer().equals(ISSUER)) {
            throw new JOSEException("Incorrect audience");
        }
    }
}
