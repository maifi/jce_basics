package testing;

import iaik.asn1.structures.AlgorithmID;
import iaik.security.dh.ESDHKEKParameterSpec;
import iaik.security.dh.ESDHPrivateKey;
import iaik.security.dh.ESDHPublicKey;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import javax.crypto.KeyAgreement;

public class testing {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub
	    iaik.security.provider.IAIK iaik = new
	    		iaik.security.provider.IAIK();
	    iaik.addAsProvider(true);  
		esdh();
	}
	
	private static void esdh(){
        try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ESDH","IAIK");
			keyGen.initialize(1024);
			KeyPair dh_keypair = keyGen.generateKeyPair();
			ESDHPrivateKey esdh_priv_key = (ESDHPrivateKey)dh_keypair.getPrivate();
			ESDHPublicKey esdh_pub_key = (ESDHPublicKey)dh_keypair.getPublic();
			
			 // we want AES key wrap
			 AlgorithmID aesWrap = AlgorithmID.cms_aes128_wrap;
			 // key length of KEK:
			 int keyLength = 128;
			 // generate the OtherInfo
			 ESDHKEKParameterSpec otherInfo = new ESDHKEKParameterSpec(aesWrap.getAlgorithm(), keyLength);
			 // the sender has supplied random patryAInfo:
			 otherInfo.setPartyAInfo(null);
			 // now create an ESDHKeyAgreement object:
			 KeyAgreement esdh_key_agreement = KeyAgreement.getInstance("ESDH", "IAIK");
			 SecureRandom sr = new iaik.security.random.SHA1Random();
			 

			 esdh_key_agreement.init(esdh_priv_key, otherInfo, sr);
			 
			 KeyPairGenerator gen_from_other_entity = KeyPairGenerator.getInstance("ESDH", "IAIK");
			 gen_from_other_entity.initialize(1024);
			 KeyPair dh_keypair_from_other = gen_from_other_entity.generateKeyPair();
			 
			 ESDHPublicKey esdhPubKey_from_other_entity = (ESDHPublicKey) dh_keypair_from_other.getPublic();
			 ESDHPrivateKey esdhPrivKey_from_other_entity = (ESDHPrivateKey) dh_keypair_from_other.getPrivate();
			 
			 esdh_key_agreement.doPhase(esdhPubKey_from_other_entity, true);
			 
			 byte[] shared_secret = esdh_key_agreement.generateSecret();
			 
			 System.out.println(shared_secret[0]);
			 
			 //receiver get key
			 KeyAgreement esdh_key_agreement_other = KeyAgreement.getInstance("ESDH", "IAIK");
			 ESDHKEKParameterSpec otherInfo_other = new ESDHKEKParameterSpec(aesWrap.getAlgorithm(), keyLength);
			 SecureRandom sr1 = new iaik.security.random.SHA1Random();
			 esdh_key_agreement_other.init(esdhPrivKey_from_other_entity, otherInfo_other, sr1);
			 
			 esdh_key_agreement_other.doPhase(esdh_pub_key, true);
			 
			 byte[] shared_secret1 = esdh_key_agreement.generateSecret();
			 System.out.println(shared_secret1[0]);
			 
			
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
