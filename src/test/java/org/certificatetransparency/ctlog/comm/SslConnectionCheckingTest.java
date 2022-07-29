package org.certificatetransparency.ctlog.comm;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.net.URL;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;

import org.apache.http.client.utils.URIBuilder;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.util.encoders.Base64;
import org.certificatetransparency.ctlog.CertificateInfo;
import org.certificatetransparency.ctlog.LogInfo;
import org.certificatetransparency.ctlog.LogSignatureVerifier;
import org.certificatetransparency.ctlog.proto.Ct;
import org.certificatetransparency.ctlog.utils.VerifySignature;
import org.junit.Test;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import utility.Fetch;

/**
 * This test checks that SSL connections to servers with a known good certificate can be verified
 * and connections without can be rejected. It serves as a programming example on how to use the
 * ctlog library.
 *
 * <p>There are three ways that certificate transparency information can be exchanged in the
 * connection handshake:
 *
 * <ul>
 *   <li>X509v3 certificate extension
 *   <li>TLS extension
 *   <li>OCSP stapling
 * </ul>
 *
 * This test only demonstrates how to validate using the first approach.
 *
 * @author Warwick Hunter
 * @since 0.1.3
 */
public class SslConnectionCheckingTest {

  /** I want at least two different CT logs to verify the certificate */
  private static final int MIN_VALID_SCTS = 2;

  /** A CT log's Id is created by using this hash algorithm on the CT log public key */
  private static final String LOG_ID_HASH_ALGORITHM = "SHA-256";

  private static final Boolean VERBOSE = false;

  @BeforeAll
  static void setUpBeforeClass() throws InstantiationException {
  }

  @AfterAll
  static void tearDownAfterClass() {}

  @BeforeEach
  void setUp() {}

  @AfterEach
  void tearDown() {}

  private Map<String, LogSignatureVerifier> verifiers = new HashMap<String, LogSignatureVerifier>();

  public SslConnectionCheckingTest() throws NoSuchAlgorithmException, InvalidKeySpecException {
    buildLogSignatureVerifiers();
  }

  @Test
  public void test() {
    checkConnection("https://github.com", true);
    checkConnection("https://letsencrypt.org", true);
    checkConnection("https://invalid-expected-sct.badssl.com/", false);
  }

  /**
   * Check if the certificates provided by a server have good certificate transparency information
   * in them that can be verified against a trusted certificate transparency log.
   *
   * @param urlString the URL of the server to check.
   * @param shouldPass true if the server will give good certificates, false otherwise.
   */
  private void checkConnection(String urlString, boolean shouldPass) {
    HttpsURLConnection con = null;
    try {
      URL url = new URL(urlString);
      con = (HttpsURLConnection) url.openConnection();
      con.connect();

      v(urlString);
      assertEquals(isGood(con.getServerCertificates()), shouldPass);

      int statusCode = con.getResponseCode();
      switch (statusCode) {
        case 200:
        case 403:
          break;
        default:
          fail(String.format("Unexpected HTTP status code: %d", statusCode));
      }
    } catch (IOException e) {
    	if(e.getClass().equals(javax.net.ssl.SSLHandshakeException.class)) {
    		if(e.getLocalizedMessage().contains("PKIX path building failed")) {
    			if(shouldPass) {
    				fail(e.toString());
    			}
    		}
    		else {
    			fail(e.toString());
    		}
    	}
   		else {
   			fail(e.toString());
   		}
    } finally {
      if (con != null) {
        con.disconnect();
      }
    }
  }

  /**
   * Check if the certificates provided by a server contain Signed Certificate Timestamps from a
   * trusted CT log.
   *
   * @param certificates the certificate chain provided by the server
   * @return true if the certificates can be trusted, false otherwise.
   */
  private boolean isGood(Certificate[] certificates) {

    if (!(certificates[0] instanceof X509Certificate)) {
      v("  This test only supports SCTs carried in X509 certificates, of which there are none.");
      return false;
    }

    X509Certificate leafCertificate = (X509Certificate) certificates[0];

    if (!CertificateInfo.hasEmbeddedSCT(leafCertificate)) {
      v("  This certificate does not have any Signed Certificate Timestamps in it.");
      return false;
    }

    try {
      List<Ct.SignedCertificateTimestamp> sctsInCertificate =
          VerifySignature.parseSCTsFromCert(leafCertificate);
      if (sctsInCertificate.size() < MIN_VALID_SCTS) {
        v(
            "  Too few SCTs are present, I want at least "
                + MIN_VALID_SCTS
                + " CT logs to vouch for this certificate.");
        return false;
      }

      List<Certificate> certificateList = Arrays.asList(certificates);

      int validSctCount = 0;
      for (Ct.SignedCertificateTimestamp sct : sctsInCertificate) {
        String logId = Base64.toBase64String(sct.getId().getKeyId().toByteArray());
        if (verifiers.containsKey(logId)) {
          v("  SCT trusted log " + logId);
          if (verifiers.get(logId).verifySignature(sct, certificateList)) {
            ++validSctCount;
          }
        } else {
          v("  SCT untrusted log " + logId);
        }
      }

      if (validSctCount < MIN_VALID_SCTS) {
        v(
            "  Too few SCTs are present, I want at least "
                + MIN_VALID_SCTS
                + " CT logs to vouch for this certificate.");
      }
      return validSctCount >= MIN_VALID_SCTS;

    } catch (IOException e) {
      if (VERBOSE) {
        e.printStackTrace();
      }
      return false;
    }
  }

  // A collection of CT logs that are trusted for the purposes of this test. Derived from
  // https://www.certificate-transparency.org/known-logs -> https://www.gstatic.com/ct/log_list/log_list.json
  private final static String[] TRUSTED_LOG_KEYS = {
			//"Google 'Argon2022' log",
			"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeIPc6fGmuBg6AJkv/z7NFckmHvf/OqmjchZJ6wm2qN200keRDg352dWpi7CHnSV51BpQYAj1CQY5JuRAwrrDwg==",
			//"Google 'Argon2023' log",
			"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0JCPZFJOQqyEti5M8j13ALN3CAVHqkVM4yyOcKWCu2yye5yYeqDpEXYoALIgtM3TmHtNlifmt+4iatGwLpF3eA==",
			//"Google 'Xenon2022' log",
			"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+WS9FSxAYlCVEzg8xyGwOrmPonoV14nWjjETAIdZvLvukPzIWBMKv6tDNlQjpIHNrUcUt1igRPpqoKDXw2MeKw==",
			//"Google 'Xenon2023' log",
			"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEchY+C+/vzj5g3ZXLY3q5qY1Kb2zcYYCmRV4vg6yU84WI0KV00HuO/8XuQqLwLZPjwtCymeLhQunSxgAnaXSuzg==",
			//"Google 'Icarus' log",
			"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETtK8v7MICve56qTHHDhhBOuV4IlUaESxZryCfk9QbG9co/CqPvTsgPDbCpp6oFtyAHwlDhnvr7JijXRD9Cb2FA==",
			//"Google 'Pilot' log",
			"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfahLEimAoz2t01p3uMziiLOl/fHTDM0YDOhBRuiBARsV4UvxG2LdNgoIGLrtCzWE0J5APC2em4JlvR8EEEFMoA==",
			//"Google 'Rocketeer' log",
			"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIFsYyDzBi7MxCAC/oJBXK7dHjG+1aLCOkHjpoHPqTyghLpzA9BYbqvnV16mAw04vUjyYASVGJCUoI3ctBcJAeg==",
			//"Google 'Skydiver' log",
			"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEmyGDvYXsRJsNyXSrYc9DjHsIa2xzb4UR7ZxVoV6mrc9iZB7xjI6+NrOiwH+P/xxkRmOFG6Jel20q37hTh58rA==",
			//"Google 'Submariner' log",
			"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOfifIGLUV1Voou9JLfA5LZreRLSUMOCeeic8q3Dw0fpRkGMWV0Gtq20fgHQweQJeLVmEByQj9p81uIW4QkWkTw==",
			//"Google 'Daedalus' log",
			"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbgwcuu4rakGFYB17fqsILPwMCqUIsz7VcCTRbR0ttrfzizbcI02VYxK75IaNzOnR7qFAot8LowYKMMqNrKQpVg==",
			//"Google 'Testtube' log",
			"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEw8i8S7qiGEs9NXv0ZJFh6uuOmR2Q7dPprzk9XNNGkUXjzqx2SDvRfiwKYwBljfWujozHESVPQyydGaHhkaSz/g==",
			//"Google 'Crucible' log",
			"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKATl2B3SAbxyzGOfNRB+AytNTGvdF/FFY6HzWb+/HPE4lJ37vx2nEm99KYUy9SoNzF5VyTwCQG5nL/c5Q77yQQ==",
			//"Google 'Solera2018' log",
			"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEuFqn5cy1nACARlWIUjeJaRDKl0mcf9gvFZXpPhHsyykizXvULF5GZNGfucWIyUccBRfmYJZTTrXqw0mVts7hA==",
			//"Google 'Solera2019' log",
			"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJUwGinXUWVNaBiK2Vl/rdyMkxKaWJHR8dj9yD5AlZEtEbfvAMQQ8o7DQyXVm7TX+eAA9wL2Vtt6DpoMEL0q/rw==",
			//"Google 'Solera2020' log",
			"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiKfWtuoWCPMEzSKySjMjXpo38WOdZr6Yq0WYa2JQOv1uVMxkqHywf9Gz1kGeRLq/Rz3tVVvXgqb4jQ1UqKVKnw==",
			//"Google 'Solera2021' log",
			"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1glwxqXsw2VqlAbHSeWbTthMGNIuACVn8Jj/jrnY2iN2uVUrEEwLj5VUCb+WF2XY44+mfUVYY7R/d8TIZ4olnw==",
			//"Google 'Solera2022' log",
			"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFWj6UQDxzHWmgzQtQQ7REDC0nxnU9mpOmA0lv5trA0t7IRzSkh4DOznPe+nkxmaC8iS1capCtKjyYhUNRrvWqA==",
			//"Google 'Solera2023' log",
			"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEK9Y56IP6DGQy2d9moYGJChZPoktXoYwaG0MBN/4X5MSFmBaYJfNm3mCwzLVefkjh2wz8Q6q2S75hS/OeHGiZUg==",
			//"Cloudflare 'Nimbus2022' Log",
			"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESLJHTlAycmJKDQxIv60pZG8g33lSYxYpCi5gteI6HLevWbFVCdtZx+m9b+0LrwWWl/87mkNN6xE0M4rnrIPA/w==",
			//"Cloudflare 'Nimbus2023' Log",
			"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEi/8tkhjLRp0SXrlZdTzNkTd6HqmcmXiDJz3fAdWLgOhjmv4mohvRhwXul9bgW0ODgRwC9UGAgH/vpGHPvIS1qA==",
			//"DigiCert Yeti2023 Log",
			"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfQ0DsdWYitzwFTvG3F4Nbj8Nv5XIVYzQpkyWsU4nuSYlmcwrAp6m092fsdXEw6w1BAeHlzaqrSgNfyvZaJ9y0Q==",
			//"DigiCert Nessie2022 Log",
			"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJyTdaAMoy/5jvg4RR019F2ihEV1McclBKMe2okuX7MCv/C87v+nxsfz1Af+p+0lADGMkmNd5LqZVqxbGvlHYcQ==",
			//"DigiCert Nessie2023 Log",
			"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEXu8iQwSCRSf2CbITGpUpBtFVt8+I0IU0d1C36Lfe1+fbwdaI0Z5FktfM2fBoI1bXBd18k2ggKGYGgdZBgLKTg==",
			//"DigiCert Yeti2022-2 Log",
			"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHWlePwrycXfNnV3DNEkA7mB34XJ2dKh8XH0J8jIdBX4u/lsx1Tr9czRuSRROUFiWWsTH9L4FZKT31+WxbTMMww==",
			//"Symantec Deneb",
			"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEloIeo806gIQel7i3BxmudhoO+FV2nRIzTpGI5NBIUFzBn2py1gH1FNbQOG7hMrxnDTfouiIQ0XKGeSiW+RcemA==",
			//"Sectigo 'Sabre' CT log",
			"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8m/SiQ8/xfiHHqtls9m7FyOMBg4JVZY9CgiixXGz0akvKD6DEL8S0ERmFe9U4ZiA0M4kbT5nmuk3I85Sk4bagA==",
			//"Sectigo 'Mammoth' CT log",
			"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7+R9dC4VFbbpuyOL+yy14ceAmEf7QGlo/EmtYU6DRzwat43f/3swtLr/L8ugFOOt1YU/RFmMjGCL17ixv66MZw==",
			//"Sectigo 'Dodo' CT log",
			"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELPXCMfVjQ2oWSgrewu4fIW4Sfh3lco90CwKZ061pvAI1eflh6c8ACE90pKM0muBDHCN+j0HV7scco4KKQPqq4A==",
			//"Let's Encrypt 'Oak2022' log",
			"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhjyxDVIjWt5u9sB/o2S8rcGJ2pdZTGA8+IpXhI/tvKBjElGE5r3de4yAfeOPhqTqqc+o7vPgXnDgu/a9/B+RLg==",
			//"Let's Encrypt 'Oak2023' log",
			"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsz0OeL7jrVxEXJu+o4QWQYLKyokXHiPOOKVUL3/TNFFquVzDSer7kZ3gijxzBp98ZTgRgMSaWgCmZ8OD74mFUQ==",
			//"Let's Encrypt 'Testflume2019' log",
			"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAg3+vFOesFW51rKECekioAt9Zo50atRoOJ0qLxF7DIEHsHneXLEpgO1WMreleRy1vEbUJD7TXoH9r8qSDGvyew==",
			//"Let's Encrypt 'Testflume2020' log",
			"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjdjcoKpeBShHgHvRm3BxD5+l+eHZudv3KmD5SDcLcI01Vj5TDTmxanQKCgpvm9pfnfB6URMQV3hhU1I02jRoRw==",
			//"Let's Encrypt 'Testflume2021' log",
			"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdCLoJNt1QcNa7sNDp7g7oTJ+o/UIYEM6N/IZWT+dhdqtJZC+AODJ/4exdOwG04B4K6WrN1VB2ELKQIc/wU1lCw==",
			//"Let's Encrypt 'Testflume2022' log",
			"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjy/rXcABuf0yhrm1+XgjDnh4XPD7vfMoyJOyT+KA+c2zuXVR98yQmp/Bl5ZFdGFwJuFcVrCw7IDo0EGKs7UCww==",
			//"Let's Encrypt 'Testflume2023' log",
			"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8aLpnumqeISmQEB3hKPgtPJQG3jP2IftfaUQ4WPUihNBwUOEk1R9BMg5RGQwebWSsRlGIRiCvtE97Q45Vh3mqA==",
			//"Let's Encrypt 'Clicky' log",
			"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHxoVg3cAdWK5n/YGBe2ViYNBgZfn4NQz/na6O8lJws3xz/4ScNe+qCJfsqRnAntxrh2sqOnRCNXO7zN6w18A3A==",
			//"Trust Asia Log2022",
			"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEu1LyFs+SC8555lRtwjdTpPX5OqmzBewdvRbsMKwu+HliNRWOGtgWLuRIa/bGE/GWLlwQ/hkeqBi4Dy3DpIZRlw==",
			//"Trust Asia Log2023",
			"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpBFS2xdBTpDUVlESMFL4mwPPTJ/4Lji18Vq6+ji50o8agdqVzDPsIShmxlY+YDYhINnUrF36XBmhBX3+ICP89Q==",
			//"Nordu 'flimsy' log",
			"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4qWq6afhBUi0OdcWUYhyJLNXTkGqQ9PMS5lqoCgkV2h1ZvpNjBH2u8UbgcOQwqDo66z6BWQJGolozZYmNHE2kQ==",
			//"Nordu 'plausible' log",
			"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9UV9+jO2MCTzkabodO2F7LM03MUBc8MrdAtkcW6v6GA9taTTw9QJqofm0BbdAsbtJL/unyEf0zIkRgXjjzaYqQ==",
			//"Up In The Air 'Behind the Sofa' log",
			"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWTmyppTGMrn+Y2keMDujW9WwQ8lQHpWlLadMSkmOi4+3+MziW5dy1eo/sSFI6ERrf+rvIv/f9F87bXcEsa+Qjw=="};

  /**
   * Construct LogSignatureVerifiers for each of the trusted CT logs.
   *
   * @throws InvalidKeySpecException the CT log key isn't RSA or EC, the key is probably corrupt.
   * @throws NoSuchAlgorithmException the crypto provider couldn't supply the hashing algorithm or
   *     the key algorithm. This probably means you are using an ancient or bad crypto provider.
   */
  private void buildLogSignatureVerifiers()
      throws InvalidKeySpecException, NoSuchAlgorithmException {
    MessageDigest hasher = MessageDigest.getInstance(LOG_ID_HASH_ALGORITHM);
    for (String trustedLogKey : TRUSTED_LOG_KEYS) {
      hasher.reset();
      byte[] keyBytes = Base64.decode(trustedLogKey);
      String logId = Base64.toBase64String(hasher.digest(keyBytes));
      KeyFactory keyFactory = KeyFactory.getInstance(determineKeyAlgorithm(keyBytes));
      PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes));
      verifiers.put(logId, new LogSignatureVerifier(new LogInfo(publicKey)));
    }
  }

  /** Parses a key and determines the key algorithm (RSA or EC) based on the ASN1 OID. */
  private static String determineKeyAlgorithm(byte[] keyBytes) {
    ASN1Sequence seq = ASN1Sequence.getInstance(keyBytes);
    DLSequence seq1 = (DLSequence) seq.getObjects().nextElement();
    ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) seq1.getObjects().nextElement();
    if (oid.equals(PKCSObjectIdentifiers.rsaEncryption)) {
      return "RSA";
    } else if (oid.equals(X9ObjectIdentifiers.id_ecPublicKey)) {
      return "EC";
    } else {
      throw new IllegalArgumentException("Unsupported key type " + oid);
    }
  }

  private void v(String message) {
    if (VERBOSE) {
      System.out.println(message);
    }
  }
}
