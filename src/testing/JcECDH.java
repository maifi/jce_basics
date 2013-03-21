package testing;


import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.DESKey;
import javacard.security.ECPublicKey;
import javacard.security.Key;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.PrivateKey;
import javacardx.crypto.Cipher;

import javax.crypto.KeyGenerator;

public class JcECDH extends Applet {

	final static byte CLASS  = (byte) 0x67;
	final static byte AGREEMENT  = (byte) 0x01;

	public static void install(byte[] buffer, short offset, byte length) {
		new JcECDH().register();
	}

	@Override
	public void process(APDU apdu) throws ISOException {
		
		byte[] cmd = apdu.getBuffer();
		short incomeBytes = apdu.setIncomingAndReceive(); //very important, else we wont get any data bytes
		byte[] otherPublicKey = null;
		byte[] agreedSymmetricKey = null;
		
	    if (cmd[ISO7816.OFFSET_CLA] == CLASS) {  
	    	switch(cmd[ISO7816.OFFSET_INS]) {      
	        	case AGREEMENT:
	        		//we dont care of P1 and P2 now
	        		short data_len = (short)(cmd[ISO7816.OFFSET_LC] & 0x00FF);
	        		otherPublicKey = new byte[data_len];
	        		
	        		Util.arrayCopy(cmd, ISO7816.OFFSET_CDATA, otherPublicKey, (short) 0, data_len);
	        		
	        		agreedSymmetricKey = ECDHKeyAgreement(otherPublicKey);
	        		
		            apdu.setOutgoing();            
		            apdu.setOutgoingLength((short)agreedSymmetricKey.length);
		            apdu.sendBytesLong(agreedSymmetricKey, (short)0, (short)agreedSymmetricKey.length);
	        		break;

	        	default:
	        		ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
	        } 
	      }  
	      else {         
	        ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
	      }  // else
		
	} 
	
	private byte[] ECDHKeyAgreement(byte[] publicKeyOther){
		KeyPair keypair = new KeyPair(KeyPair.ALG_EC_F2M,KeyBuilder.LENGTH_EC_F2M_113);
		keypair.genKeyPair();
        PrivateKey privateEphemeralKey = keypair.getPrivate();
        ECPublicKey publicEphemeralKey = (ECPublicKey) keypair.getPublic();

        KeyAgreement keyagreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
        
        keyagreement.init(privateEphemeralKey);
        
        byte[] symmetric_secret = new byte[16];
        
		keypair.genKeyPair();
        ECPublicKey publicKeyOtherval = (ECPublicKey) keypair.getPublic();
        System.out.println("Keysize: "+publicKeyOtherval.getSize());
        publicKeyOther = new byte[128];//publicKeyOtherval.
       
        publicKeyOtherval.getW(publicKeyOther, (short) 0);
        keyagreement.generateSecret(publicKeyOther, (short) 0, (short) symmetric_secret.length, symmetric_secret, (short) 0);

		return symmetric_secret;
	}
}