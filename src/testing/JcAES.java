package testing;


import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.DESKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;

import javax.crypto.KeyGenerator;

public class JcAES extends Applet {

	final static byte CLASS  = (byte) 0x66;
	final static byte ENCRYPT  = (byte) 0x01;
	final static byte DECRYPT  = (byte) 0x02;
	final static byte ENCRYPT_DES  = (byte) 0x03;
	final static byte DECRYPT_DES  = (byte) 0x04;
	
	//secret key
	final static byte[] _aesKey = {(byte) 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
	final static byte[] _desKey = {(byte) 0x02,0x02,0x03,0x04,0x05,0x06,0x07,0x08};

	public static void install(byte[] buffer, short offset, byte length) {
		new JcAES().register();
	}

	@Override
	public void process(APDU apdu) throws ISOException {
		
		byte[] cmd = apdu.getBuffer();
		short incomeBytes = apdu.setIncomingAndReceive(); //very important, else we wont get any data bytes
		byte[] dataToEncrypt = null;
		byte[] encryptedData = null;
		
	    if (cmd[ISO7816.OFFSET_CLA] == CLASS) {  
	    	switch(cmd[ISO7816.OFFSET_INS]) {      
	        	case ENCRYPT:
	        		//we dont care of P1 and P2 now
	        		short data_len = (short)(cmd[ISO7816.OFFSET_LC] & 0x00FF);
	        		dataToEncrypt = new byte[data_len];
	        		
	        		Util.arrayCopy(cmd, ISO7816.OFFSET_CDATA, dataToEncrypt, (short) 0, data_len);
	        		
	        		encryptedData = aesEncrypt(dataToEncrypt);
	        		
		            apdu.setOutgoing();            
		            apdu.setOutgoingLength((short)encryptedData.length);
		            apdu.sendBytesLong(encryptedData, (short)0, (short)encryptedData.length);
	        		break;
	        		
	        	case DECRYPT:
	        		data_len = (short)(cmd[ISO7816.OFFSET_LC] & 0x00FF);
	        		byte[] dataToDecrypt = new byte[data_len];
	        		byte[] decryptedData;
	        		Util.arrayCopy(cmd, ISO7816.OFFSET_CDATA, dataToDecrypt, (short) 0, data_len);
	        		
	        		decryptedData = aesDecrypt(dataToDecrypt);
	        		
		            apdu.setOutgoing();            
		            apdu.setOutgoingLength((short)decryptedData.length);
		            apdu.sendBytesLong(decryptedData, (short)0, (short)decryptedData.length);
		            break;
		            
	        	case ENCRYPT_DES:
	        		//we dont care of P1 and P2 now
	        		data_len = (short)(cmd[ISO7816.OFFSET_LC] & 0x00FF);
	        		dataToEncrypt = new byte[data_len];
	        		Util.arrayCopy(cmd, ISO7816.OFFSET_CDATA, dataToEncrypt, (short) 0, data_len);
	        		
	        		encryptedData = desEncrypt(dataToEncrypt);
	        		
		            apdu.setOutgoing();            
		            apdu.setOutgoingLength((short)encryptedData.length);
		            apdu.sendBytesLong(encryptedData, (short)0, (short)encryptedData.length);
	        		break;
	        		
	        	case DECRYPT_DES:
	        		data_len = (short)(cmd[ISO7816.OFFSET_LC] & 0x00FF);
	        		dataToDecrypt = new byte[data_len];
	        		Util.arrayCopy(cmd, ISO7816.OFFSET_CDATA, dataToDecrypt, (short) 0, data_len);
	        		
	        		decryptedData = desDecrypt(dataToDecrypt);
	        		
		            apdu.setOutgoing();            
		            apdu.setOutgoingLength((short)decryptedData.length);
		            apdu.sendBytesLong(decryptedData, (short)0, (short)decryptedData.length);
		            break;
	        	default:
	        		ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
	        } 
	      }  
	      else {         
	        ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
	      }  // else
		
	} 
	
	private byte[] aesEncrypt(byte[] data){
		
		try{
		Cipher cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD,false);
		AESKey aeskey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
		aeskey.setKey(_aesKey, (short) 0);
		boolean a = aeskey.isInitialized();//true
		cipher.init((Key)aeskey, Cipher.MODE_ENCRYPT);// error here!
		
		byte[] result = new byte[data.length];
		int len = data.length;
		cipher.doFinal(data, (short) 0, (byte) data.length, result, (short) 0);
		return result;
		}catch(CryptoException c){
			c.printStackTrace();
			System.out.println(c.getReason()); //no such algorithm... on jcardsim
		}catch(Exception e){
			e.printStackTrace();
		}
		return null;
	}
	
	private byte[] aesDecrypt(byte[] data){
		
		try{
		Cipher cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD,false);
		AESKey aeskey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
		aeskey.setKey(_aesKey, (short) 0);
		cipher.getAlgorithm();
		cipher.init((Key)aeskey, Cipher.MODE_DECRYPT);
		byte[] result = new byte[16];
		cipher.doFinal(data, (short) 0, (byte) result.length, result, (short) 0);
		return result;
		}catch(Exception e){
			e.printStackTrace();
		}
		return null;
	}
	
private byte[] desEncrypt(byte[] data){
		
		try{
		Cipher cipher = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD,false);
		DESKey deskey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);
		deskey.setKey(_desKey, (short) 0);

		cipher.init((Key)deskey, Cipher.MODE_ENCRYPT);
		byte[] result = new byte[data.length];
		int len = data.length;
		cipher.doFinal(data, (short) 0, (byte) data.length, result, (short) 0);
		return result;
		}catch(CryptoException c){
			c.printStackTrace();
			System.out.println(c.getReason());
		}catch(Exception e){
			e.printStackTrace();
		}
		return null;
	}

	private byte[] desDecrypt(byte[] data){
		
		try{
		Cipher cipher = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD,false);
		DESKey deskey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);
		deskey.setKey(_desKey, (short) 0);

		cipher.init((Key)deskey, Cipher.MODE_DECRYPT);
		byte[] result = new byte[8];
		//cipher.update(data, (short) 0, (byte) 0x08, result, (short) 0);
		cipher.doFinal(data, (short) 0, (byte) 0x08, result, (short) 0);
		return result;
		}catch(Exception e){
			e.printStackTrace();
		}
		return null;
	}
	
}
