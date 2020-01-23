package com.example.utils;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;

public class PGPUtils {

	@SuppressWarnings("unchecked")
	public static PGPPublicKey readPublicKey(InputStream in) throws IOException, PGPException {
		in = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(in);

		PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(in);

		//
		// we just loop through the collection till we find a key suitable for
		// encryption, in the real
		// world you would probably want to be a bit smarter about this.
		//
		PGPPublicKey key = null;

		//
		// iterate through the key rings.
		//
		Iterator<PGPPublicKeyRing> rIt = pgpPub.getKeyRings();

		while (key == null && rIt.hasNext()) {
			PGPPublicKeyRing kRing = rIt.next();
			Iterator<PGPPublicKey> kIt = kRing.getPublicKeys();
			while (key == null && kIt.hasNext()) {
				PGPPublicKey k = kIt.next();

				if (k.isEncryptionKey()) {
					key = k;
				}
			}
		}

		if (key == null) {
			throw new IllegalArgumentException("Can't find encryption key in key ring.");
		}

		return key;
	}

	private static void extracted(OutputStream out, PGPLiteralData literalData) throws IOException {
		InputStream unc = literalData.getInputStream();
		int ch;
		while ((ch = unc.read()) >= 0) {
			out.write(ch);
		}
	}

	/**
	 * Load a secret key ring collection from keyIn and find the secret key
	 * corresponding to keyID if it exists.
	 *
	 * @param keyIn input stream representing a key ring collection.
	 * @param keyID keyID we want.
	 * @param pass  passphrase to decrypt secret key with.
	 * @return
	 * @throws IOException
	 * @throws PGPException
	 * @throws NoSuchProviderException
	 */
	private static PGPPrivateKey findSecretKey(InputStream keyIn, long keyID, char[] pass)
			throws IOException, PGPException, NoSuchProviderException {

		PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
				org.bouncycastle.openpgp.PGPUtil.getDecoderStream(keyIn));

		PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);

		if (pgpSecKey == null) {
			return null;
		}

		return pgpSecKey.extractPrivateKey(pass, "BC");
	}

	/**
	 * @param signedKey
	 * @param plainFact
	 * @param message
	 * @return
	 * @throws IOException
	 * @throws PGPException
	 * @throws NoSuchProviderException
	 * @throws SignatureException
	 */
	private static boolean verifyMessageSignature(InputStream signedKey, PGPObjectFactory plainFact, Object message)
			throws IOException, PGPException, NoSuchProviderException, SignatureException {
		PGPPublicKey publicKey;
		PGPOnePassSignatureList onePassSignatureList = (PGPOnePassSignatureList) message;
		PGPOnePassSignature ops = onePassSignatureList.get(0);
		PGPPublicKeyRingCollection pgpRing = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(signedKey));
		publicKey = pgpRing.getPublicKey(ops.getKeyID());
		try {
			ops.initVerify(publicKey, "BC");
		} catch (ClassCastException e) {
			return false;
		}
		if (ops != null) {
			Object o = plainFact.nextObject();
			PGPSignatureList signatureList = (PGPSignatureList) plainFact.nextObject();
			System.out.println("signature list (" + signatureList.size() + " sigs) is " + signatureList);
			PGPSignature messageSignature = (PGPSignature) signatureList.get(0);
			// Verify the calculated signature against the passed in PGPSignature
			if (!ops.verify(messageSignature)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * decrypt the passed in message stream
	 * 
	 * @param signedKey
	 * @throws Exception
	 */
	@SuppressWarnings({ "unchecked", "unused" })
	public static void decryptFile(InputStream in, OutputStream out, InputStream keyIn, char[] passwd,
			InputStream signedKey) {
		Security.addProvider(new BouncyCastleProvider());
		try {
			in = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(in);
			InputStream inv = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(in);

			PGPObjectFactory pgpF = new PGPObjectFactory(in);
			PGPEncryptedDataList enc;

			Object o = pgpF.nextObject();
			//
			// the first object might be a PGP marker packet.
			//
			if (o instanceof PGPEncryptedDataList) {
				enc = (PGPEncryptedDataList) o;
			} else {
				enc = (PGPEncryptedDataList) pgpF.nextObject();
			}
			//
			// find the secret keypgpObjectFactory
			//
			Iterator<PGPPublicKeyEncryptedData> it = enc.getEncryptedDataObjects();
			PGPPrivateKey sKey = null;
			PGPPublicKeyEncryptedData pbe = null;

			while (sKey == null && it.hasNext()) {
				pbe = it.next();
				sKey = findSecretKey(keyIn, pbe.getKeyID(), passwd);
			}

			if (sKey == null) {
				throw new IllegalArgumentException("Secret key for messagcalculatedSignaturee not found.");
			}

			InputStream clear = pbe.getDataStream(sKey, "BC");
			PGPObjectFactory plainFact = new PGPObjectFactory(clear);
			Object message = plainFact.nextObject();
			PGPPublicKey publicKey = null;
			PGPLiteralData ld = null;

			if (message instanceof PGPCompressedData) {
				PGPCompressedData cData = (PGPCompressedData) message;
				PGPObjectFactory pgpFact = new PGPObjectFactory(cData.getDataStream());

				message = pgpFact.nextObject();
			}
			if (message instanceof PGPLiteralData) {
				ld = (PGPLiteralData) message;
				extracted(out, ld);
			} else if (message instanceof PGPOnePassSignatureList) {

				boolean verified = verifyMessageSignature(signedKey, plainFact, message);
				if (verified) {
					Object literaldata = plainFact.nextObject();
					if (literaldata instanceof PGPLiteralData) {
						ld = (PGPLiteralData) literaldata;
					}
					extracted(out, ld);
				} else {
					throw new PGPException("Encrypted message contains a signed message - not literal data.");
				}
			} else {
				throw new PGPException("Message is not a simple encrypted file - type unknown.");
			}

			if (pbe.isIntegrityProtected()) {
				if (!pbe.verify()) {
					throw new PGPException("Message failed integrity check");
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	public static void encryptFile(OutputStream out, String fileName, PGPPublicKey encKey, boolean armor,
			boolean withIntegrityCheck) throws IOException, NoSuchProviderException, PGPException {
		Security.addProvider(new BouncyCastleProvider());

		if (armor) {
			out = new ArmoredOutputStream(out);
		}

		ByteArrayOutputStream bOut = new ByteArrayOutputStream();

		PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);

		org.bouncycastle.openpgp.PGPUtil.writeFileToLiteralData(comData.open(bOut), PGPLiteralData.BINARY,
				new File(fileName));

		comData.close();

		PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(PGPEncryptedData.CAST5, withIntegrityCheck,
				new SecureRandom(), "BC");

		cPk.addMethod(encKey);

		byte[] bytes = bOut.toByteArray();

		OutputStream cOut = cPk.open(out, bytes.length);
		cOut.write(bytes);
		cOut.close();
		out.close();
	}

}