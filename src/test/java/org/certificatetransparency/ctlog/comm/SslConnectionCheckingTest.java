package org.certificatetransparency.ctlog.comm;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.net.URL;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLHandshakeException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.util.encoders.Base64;
import org.certificatetransparency.ctlog.CertificateInfo;
import org.certificatetransparency.ctlog.LogInfo;
import org.certificatetransparency.ctlog.LogSignatureVerifier;
import org.certificatetransparency.ctlog.proto.Ct;
import org.certificatetransparency.ctlog.utils.VerifySignature;
import org.junit.Test;

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

  private Map<String, LogSignatureVerifier> verifiers = new HashMap<String, LogSignatureVerifier>();

  public SslConnectionCheckingTest() throws NoSuchAlgorithmException, InvalidKeySpecException {
    buildLogSignatureVerifiers();
  }
  
  
  @Test
  public void test_Time() {
	  // If this fails, update the certificates in TRUSTED_LOG_KEYS
	  assertTrue(System.currentTimeMillis() < 1759302000000L);
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
      assertEquals(shouldPass,isGood(con.getServerCertificates()));

      int statusCode = con.getResponseCode();
      switch (statusCode) {
        case 200:
        case 403:
          break;
        default:
          fail(String.format("Unexpected HTTP status code: %d", statusCode));
      }
    } catch (SSLHandshakeException e) {
      if (shouldPass) {
        fail(urlString + " " + e.toString());
      }
    } catch (IOException e) {
      fail(e.toString());
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
  private static final String[] TRUSTED_LOG_KEYS = {
		// "Google 'Argon2024' log"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHblsqctplMVc5ramA7vSuNxUQxcomQwGAVAdnWTAWUYr3MgDHQW0LagJ95lB7QT75Ve6JgT2EVLOFGU7L3YrwA==",
		// "Google 'Argon2025h1' log"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIIKh+WdoqOTblJji4WiH5AltIDUzODyvFKrXCBjw/Rab0/98J4LUh7dOJEY7+66+yCNSICuqRAX+VPnV8R1Fmg==",
		// "Google 'Argon2025h2' log"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEr+TzlCzfpie1/rJhgxnIITojqKk9VK+8MZoc08HjtsLzD8e5yjsdeWVhIiWCVk6Y6KomKTYeKGBv6xVu93zQug==",
		// "Google 'Argon2026h1' log"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEB/we6GOO/xwxivy4HhkrYFAAPo6e2nc346Wo2o2U+GvoPWSPJz91s/xrEvA3Bk9kWHUUXVZS5morFEzsgdHqPg==",
		// "Google 'Argon2026h2' log"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKjpni/66DIYrSlGK6Rf+e6F2c/28ZUvDJ79N81+gyimAESAyeNZ++TRgjHWg9TVQnKHTSU0T1TtqDupFnSQTIg==",
		// "Google 'Xenon2024' log"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEuWDgNB415GUAk0+QCb1a7ETdjA/O7RE+KllGmjG2x5n33O89zY+GwjWlPtwpurvyVOKoDIMIUQbeIW02UI44TQ==",
		// "Google 'Xenon2025h1' log"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEguLOkEA/gQ7f6uEgK14uMFRGgblY7a+9/zanngtfamuRpcGY4fLN6xcgcMoqEuZUeFDc/239HKe2Oh/5JqkbvQ==",
		// "Google 'Xenon2025h2' log"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEa+Cv7QZ8Pe/ZDuRYSwTYKkeZkIl6uTaldcgEuMviqiu1aJ2IKaKlz84rmhWboD6dlByyt0ryUexA7WJHpANJhg==",
		// "Google 'Xenon2026h1' log"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOh/Iu87VkEc0ysoBBCchHOIpPZK7kUXHWj6l1PIS5ujmQ7rze8I4r/wjigVW6wMKMMxjbNk8vvV7lLqU07+ITA==",
		// "Google 'Xenon2026h2' log"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5Xd4lXEos5XJpcx6TOgyA5Z7/C4duaTbQ6C9aXL5Rbqaw+mW1XDnDX7JlRUninIwZYZDU9wRRBhJmCVopzwFvw==",
		// "Cloudflare 'Nimbus2024' Log"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEd7Gbe4/mizX+OpIpLayKjVGKJfyTttegiyk3cR0zyswz6ii5H+Ksw6ld3Ze+9p6UJd02gdHrXSnDK0TxW8oVSA==",
		// "Cloudflare 'Nimbus2025'"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGoAaFRkZI3m0+qB5jo3VwdzCtZaSfpTgw34UfAoNLUaonRuxQWUMX5jEWhd5gVtKFEHsr6ldDqsSGXHNQ++7lw==",
		// "Cloudflare 'Nimbus2026'"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2FxhT6xq0iCATopC9gStS9SxHHmOKTLeaVNZ661488Aq8tARXQV+6+jB0983v5FkRm4OJxPqu29GJ1iG70Ahow==",
		// "DigiCert Yeti2024 Log"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEV7jBbzCkfy7k8NDZYGITleN6405Tw7O4c4XBGA0jDliE0njvm7MeLBrewY+BGxlEWLcAd2AgGnLYgt6unrHGSw==",
		// "DigiCert Yeti2025 Log"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE35UAXhDBAfc34xB00f+yypDtMplfDDn+odETEazRs3OTIMITPEy1elKGhj3jlSR82JGYSDvw8N8h8bCBWlklQw==",
		// "DigiCert Nessie2024 Log"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELfyieza/VpHp/j/oPfzDp+BhUuos6QWjnycXgQVwa4FhRIr4OxCAQu0DLwBQIfxBVISjVNUusnoWSyofK2YEKw==",
		// "DigiCert Nessie2025 Log"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8vDwp4uBLgk5O59C2jhEX7TM7Ta72EN/FklXhwR/pQE09+hoP7d4H2BmLWeadYC3U6eF1byrRwZV27XfiKFvOA==",
		// "DigiCert 'Wyvern2024h2' Log"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqHMSnFTQen3FtRcrcVKJBJC7QvGd+BzeTM+CPL03G3RMPMejE4cBURMU2qISmITOHL7PT3rvFfrQ7u3tB61xbQ==",
		// "DigiCert 'Wyvern2025h1' Log"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEp8uAYYYbH7WrKyB2WYNmDs6uuG87iALrQ/SHkMuL2qwOGVDg+SQOqyaTjD+eDZZYRJ07ioDFyL7hiUZrSEzWCQ==",
		// "DigiCert 'Wyvern2025h2' Log"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4NtB7+QEvctrLkzM8WzeQVh//pT2evZg7Yt2cqOiHDETMjWh8gjSaMU0p1YIHGPeleKBaZeNHqi3ZlEldU14Lg==",
		// "DigiCert 'Wyvern2026h1'"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7Lw0OeKajbeZepHxBXJS2pOJXToHi5ntgKUW2nMhIOuGlofFxtkXum65TBNY1dGD+HrfHge8Fc3ASs0qMXEHVQ==",
		// "DigiCert 'Wyvern2026h2'"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEenPbSvLeT+zhFBu+pqk8IbhFEs16iCaRIFb1STLDdWzL6XwTdTWcbOzxMTzB3puME5K3rT0PoZyPSM50JxgjmQ==",
		// "DigiCert 'Sphinx2024h2' Log"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2wlBhOfR8VslCXvoxphRXimF/YHeidfQhqSw5RXsXXsXVV/JeY3kIjbn6b84P9Hp1AmEgb62we0bF+oml7rpmg==",
		// "DigiCert 'Sphinx2025h1' Log"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4y8fTYkFdSl4uyI9B2JRFHCU5zzq9e6upkiahlJOnlzjlZcou1JLKv3IyYlORTEX043y584YEViYLGBvWCA2bg==",
		// "DigiCert 'Sphinx2025h2' Log"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQYxQE1SxGQW3f0ogbqN1Y8o09Mx06jI7tosDFKhSfzKHXlmeD6sYnilstXJ3GidUhV3BeySoNOPNiM7UUBu+aQ==",
		// "DigiCert 'Sphinx2026h1'"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEq4S++DyHokIlmmacritS51r5IRsZA6UH4kYLH4pefGyu/xl3huh7/O5rNk/yvMOeBQKaCAG1SSM1xNNQK1Hp9A==",
		// "DigiCert 'Sphinx2026h2'"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEquD0JkRQT/2inuaA4HC1sc6UpfiXgURVQmQcInmnZFnTiZMhZvsJgWAfYlU0OIykOC6slQzr7U9kvEVC9wZ6zQ==",
		// "Sectigo 'Sabre' CT log"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8m/SiQ8/xfiHHqtls9m7FyOMBg4JVZY9CgiixXGz0akvKD6DEL8S0ERmFe9U4ZiA0M4kbT5nmuk3I85Sk4bagA==",
		// "Sectigo 'Sabre2024h2'"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEehBMiucie20quo76a0qB1YWuA+//S/xNUz23jLt1CcnqFn7BdxbSwkV0bY3E4Yg339TzYGX8oHXwIGaOSswZ2g==",
		// "Sectigo 'Sabre2025h1'"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfi858egjjrMyBK9NV/bbxXSkem07B1EMWvuAMAXGWgzEdtYGqFdN+9/kgpDCQa5wszGi4/o9XyxdBM20nVWrQQ==",
		// "Sectigo 'Sabre2025h2'"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhRMRLXvzk4HkuXzZZDvntYOZZnlZR2pCXta9Yy63kUuuvFbExW4JoNdkGsjBr4mL9VjYuut7g1Lp9OClzc2SzA==",
		// "Sectigo 'Mammoth2024h2'"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhWYiJG6+UmIKoK/DJRo2LqdgiaJlv6RfvYVqlAWBNZBUMZXnEZ6jLg+F76eIV4tjGoHBQZ197AE627nBJ/RlHg==",
		// "Sectigo 'Mammoth2025h1'"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEzxBtTB9LkqhqGvSxVdrmP5+79Uh4rpdsLqFEW6U4D2ojm1WjUQCnrCDzFTfm05yYks8DDLdhvvrPmbNd1hb5Q==",
		// "Sectigo 'Mammoth2025h2'"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiOLHs9c3o5HXs8XaB1EEK4HtwkQ7daDmZeFKuhuxnKkqhDEprh2L8TOfEi6QsRVnZqB8C1tif2yaajCbaAIWbw==",
		// "Sectigo 'Mammoth2026h1'"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEnssMilHMiuILzoXmr00x2xtqTP2weWuZl8Bd+25FUB1iqsafm2sFPaKrK12Im1Ao4p5YpaX6+eP6FSXjFBMyxA==",
		// "Sectigo 'Mammoth2026h2'"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7INh8te0u+TkO+vIY3WYz2GQYxQ9XyLfdLpQp1ibaX3mY4lt2ddRhD/4AtjI/8KXceV+J/VysY8kJ1cKDXTAtg==",
		// "Sectigo 'Sabre2026h1'"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhCa8Nr3YjTyHnuAQr82U2de5UYA0fvdYXHPq6wmTuBB7kJx9x82WQ+1TbpUhRmdR8N62yZ6q4oBtziWBNNdqYA==",
		// "Sectigo 'Sabre2026h2'"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzjXK7DkHgtp3J4bk8n7F3Djym6mrjKfA7YMePmobwPCVVroyM0x1fAkH6eE+ZTVj8Em+ctGqna99CMS0jVk9cw==",
		// "Let's Encrypt 'Oak2024H2' log"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE13PWU0fp88nVfBbC1o9wZfryUTapE4Av7fmU01qL6E8zz8PTidRfWmaJuiAfccvKu5+f81wtHqOBWa+Ss20waA==",
		// "Let's Encrypt 'Oak2025h1'"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKeBpU9ejnCaIZeX39EsdF5vDvf8ELTHdLPxikl4y4EiROIQfS4ercpnMHfh8+TxYVFs3ELGr2IP7hPGVPy4vHA==",
		// "Let's Encrypt 'Oak2025h2'"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtXYwB63GyNLkS9L1vqKNnP10+jrW+lldthxg090fY4eG40Xg1RvANWqrJ5GVydc9u8H3cYZp9LNfkAmqrr2NqQ==",
		// "Let's Encrypt 'Oak2026h1'"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmdRhcCL6d5MNs8eAliJRvyV5sQFC6UF7iwzHsmVaifT64gJG1IrHzBAHESdFSJAjQN56TYky+9cK616MovH2SQ==",
		// "Let's Encrypt 'Oak2026h2'"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEanCds5bj7IU2lcNPnIvZfMnVkSmu69aH3AS8O/Y0D/bbCPdSqYjvuz9Z1tT29PxcqYxf+w1g5CwPFuwqsm3rFQ==",
		// "Trust Asia Log2024-2"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEp2TieYE/YdfsxvhlKB2gtGYzwyXVCpV4nI/+pCrYj35y4P6of/ixLYXAjhJ0DS+Mq9d/eh7ZhDM56P2JX5ZICA==",
		// "TrustAsia Log2025a"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcOWxpAl5K534o6DfGO+VXQNse6GRqbiAfexcAgjibi98MnC9loRfpmLpZbV8kFi6ItX59WlUt6iUTjIJriYRTQ==",
		// "TrustAsia Log2025b"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqqCL22cUXZeJHQiNBtfBlI6w+kxG1VMIeCsEU2zz3rHRU0DakFfmGp48xwO4vS+pz+h7XuFLYOU4Q2CXwVsvZQ==",
		// "TrustAsia 'log2026a'"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEp056yaYH+f907JjLSeEAJLNZLoP9wHA1M0xjynSDwDxbU0B8MR81pF8P5O5PiRfoWy7FrAAFyXY3RZcDFf9gWQ==",
		// "TrustAsia 'log2026b'"
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDxKMqebj7GLu31jIUOYmcHYQtwQ5s6f4THM7wzhaEgBM4NoOFopFMgoxqiLHnX0FU8eelOqbV0a/T6R++9/6hQ=="
  };

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
