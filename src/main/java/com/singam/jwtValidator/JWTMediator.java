package com.singam.jwtValidator;

import com.google.gson.Gson;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import net.minidev.json.JSONObject;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.mediators.AbstractMediator;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class JWTMediator extends AbstractMediator {

    SignedJWT signedJWT;
    private   RSAPublicKey RSA_publicKey;
    private  String sharedSecret;
    private ECPublicKey ECDSA_publicKey;

    public boolean mediate(MessageContext messageContext) {

        Object headers = ((Axis2MessageContext) messageContext).getAxis2MessageContext().getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);
        if (headers != null && headers instanceof Map) {
            Map headersMap = (Map) headers;
            if (headersMap.get("Authorization") == null) {
                System.out.println("No JWT found");
                return false;


            } else {
                String authHeader = (String) headersMap.get("Authorization");
                String credentials = authHeader.substring(6).trim();

                try {
                    signedJWT = SignedJWT.parse(credentials);
                    JWSAlgorithm algorithm= signedJWT.getHeader().getAlgorithm();
                    System.out.println(algorithm.getClass());
                    if (JWSAlgorithm.Family.RSA.contains(algorithm.) && RSA_publicKey!= null ){
                        if (RSAValidation(credentials)) {
                            return true;
                        } else {
                            System.out.println("Invalid credentials");
                            return false;
                        }
                    }
                    else if (JWSAlgorithm.Family.HMAC_SHA.contains(algorithm) && sharedSecret != null){
                        if (MACValidation(credentials)){
                            return true;
                        } else {
                            System.out.println("Invalid credentials");
                            return false;
                        }
                    }
                    else if (JWSAlgorithm.Family.EC.contains(algorithm))
                    {
                        if (ECDSAValidation(credentials)){
                            return true;
                        } else {
                            System.out.println("Invalid credentials");
                            return false;
                        }
                    }

                } catch (ParseException e) {
                    e.printStackTrace();
                } catch (JOSEException e) {
                    e.printStackTrace();
                } catch (BadJOSEException e) {
                    e.printStackTrace();
                } catch (MalformedURLException | InvalidKeySpecException | NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }
                catch (Exception e){
                    e.printStackTrace();
                }
            }
        }
        return false;
    }

    private boolean RSAValidation(String credentials) throws ParseException, MalformedURLException, BadJOSEException, JOSEException, InvalidKeySpecException, NoSuchAlgorithmException {



//        ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();
//        JWKSource keySource = new RemoteJWKSet(new URL("https://demo.c2id.com/c2id/jwks.json"));
//        JWSAlgorithm expectedJWSAlg = JWSAlgorithm.parse(alg);
//        JWSKeySelector keySelector = new JWSVerificationKeySelector(expectedJWSAlg, keySource);
//        jwtProcessor.setJWSKeySelector(keySelector);
//
//        SecurityContext ctx = null; // optional context parameter, not required here
//        JWTClaimsSet claimsSet = jwtProcessor.process(credentials, ctx);
//// Print out the token claims set
//        System.out.println(claimsSet.toJSONObject());




        this.testRSA_PublicKey();;

        try {
            signedJWT = SignedJWT.parse(credentials);

            JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) RSA_publicKey);
            return signedJWT.verify(verifier);
        } catch (ParseException | JOSEException e) {
            return false;
        }


    }

    private boolean MACValidation(String credentials) throws ParseException, JOSEException {
        this.testSharedSecret();
        signedJWT = SignedJWT.parse(credentials);
        JWSVerifier verifier = new MACVerifier(sharedSecret);

        return signedJWT.verify(verifier);

    }


    private boolean ECDSAValidation(String credentials) throws JOSEException, ParseException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        this.testECDSA_publicKey();
        signedJWT = SignedJWT.parse(credentials);
        JWSVerifier verifier = new ECDSAVerifier(ECDSA_publicKey);
        return signedJWT.verify(verifier);
    }
    public void setRSA_publicKey(String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory kFactory = KeyFactory.getInstance("RSA");
        // decode base64 of your key
        byte RSA_key[] =  Base64.getDecoder().decode(publicKey);
        // generate the public key
        X509EncodedKeySpec spec =  new X509EncodedKeySpec(RSA_key);
        RSA_publicKey = (RSAPublicKey) kFactory.generatePublic(spec);
    }

    public void setSharedSecret(String sharedSecret) {
        this.sharedSecret = sharedSecret;
    }

    public void setECDSA_publicKey(String publicKey) throws InvalidKeySpecException, NoSuchProviderException, NoSuchAlgorithmException {
        KeyFactory factory = KeyFactory.getInstance("ECDSA", "BC");

        byte ECDSA_key [] = Base64.getDecoder().decode(publicKey);

        ECDSA_publicKey = (ECPublicKey) factory.generatePublic(new X509EncodedKeySpec(ECDSA_key));
    }

    public void testRSA_PublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String key= "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCKXsBGx7l8ze1Dqlbgt3sFPYgBBWg4lwDb5KbB1KBvQB0mMZIu/9qZUToFyztbYZCJ7Utb9bYfvkDsVDa9Bqn4zkoSJUDQqac2uRHo3Up4WFMzhT2EB1iKZRYAteBG7Dr+i0e/kPes+3uentGPnBeQHGfZCgzAG1cYNoxB/PJ7uwIDAQAB";
        KeyFactory kFactory = KeyFactory.getInstance("RSA");
        // decode base64 of your key
        byte yourKey[] =  Base64.getDecoder().decode(key);
        // generate the public key
        X509EncodedKeySpec spec =  new X509EncodedKeySpec(yourKey);
        RSA_publicKey = (RSAPublicKey) kFactory.generatePublic(spec);
    }

    public void testSharedSecret() throws JOSEException {
        sharedSecret= "apple";
    }

    public void testECDSA_publicKey() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        String publicKey= "";
        KeyFactory factory = KeyFactory.getInstance("ECDSA", "BC");

        byte ECDSA_key [] = Base64.getDecoder().decode(publicKey);

        ECDSA_publicKey = (ECPublicKey) factory.generatePublic(new X509EncodedKeySpec(ECDSA_key));

    }
}
