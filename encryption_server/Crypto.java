import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Hashtable;
import com.dropbox.core.*;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class Crypto {
	
	private KeyPair keys; //receiver's public and private key
	private static final String AES = "AES";	
	private static final String RSA = "RSA";

	private static final byte[] keyValue = new byte[] { 'T', 'h', 'e', 'B', 'e', 's', 't', 'S', 'e', 'c', 'r','e', 't', 'K', 'e', 'y' };
	private static String currentFolder = "";
	private static Hashtable<String, PrivateKey> storePrivateKey = new Hashtable<String, PrivateKey>();
	//private SecretKeySpec symmetricKey;
	
	/*
	 * Generates the user's public and private key
	 */
	private KeyPair generateKeyPairs()
	{
		KeyPair keyPair=null;
		try {
            keyPair = KeyPairGenerator.getInstance(RSA).generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Algorithm not supported! " + e.getMessage() + "!");
        }
		keys = keyPair;
        return keyPair;
	}
	

	public void createNewUserFolder(String name)
	{
		currentFolder = name;
	}
	
	/*
	 * @param filename The name of the guest eg guest.txt
	 * @param client Dropbox client
	 * Uploads the guest's public key under the filename
	 */
	public void createPublicKey(String filename, DbxClient client)
	{
		KeyPair keypair = generateKeyPairs();
		String name = filename.substring(0, filename.indexOf('.'));
		storePrivateKey.put(name, keypair.getPrivate());
		//create a public key file
		byte[] array = keypair.getPublic().getEncoded();
        byte[] encoded = Base64.getEncoder().encode(array);
        String content = new String(encoded);
		File file = new File(filename);
		FileWriter fw=null;
		try {
			fw = new FileWriter(file.getAbsoluteFile());
		} catch (IOException e) {
			e.printStackTrace();
		}
		BufferedWriter bw = new BufferedWriter(fw);
		try {
			bw.write(content);
		} catch (IOException e) {
			e.printStackTrace();
		}
		try {
			bw.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		uploadFile(client, filename);
	}
	
	/*
	 * @param fileToEncrypt any file format that the admin wishes to encrypt
	 * @param pubKey the filename of the public key of the guest
	 * Creates a symmetric key and organises the encryption of the two files
	 */
	public void beginEncryption(String fileToEncrypt, String pubKey, DbxClient client)
	{
		currentFolder = pubKey.substring(0, pubKey.indexOf('.'));
		System.out.println(currentFolder);
		SecretKeySpec symmetricKey = createSymmetricKey();
		try {
			encryptSymmetricKey(pubKey, symmetricKey, client);
		} catch (Exception e) {
			e.printStackTrace();
		}
		String extension = extractExtension(fileToEncrypt);
		encryptFile(fileToEncrypt, symmetricKey, extension, client);
	}
	
	/*
	 * Generates a symmetric key for the file to be encrypted by admin
	 */
	private SecretKeySpec createSymmetricKey()
	{
		SecretKeySpec symmetricKey=null;
		try {
			symmetricKey = generateSymmetricKey();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return symmetricKey;
	}
	
	/*
	 * @param pubkey the key filename used for encrypting symmetric key
	 * @param symm the symmetric key to be encrypted
	 * 
	 * Encrypts and uploads the encrypted symmetric key using the RSA
	 * algorithm
	 */
	private void encryptSymmetricKey(String pubkey, SecretKeySpec symm, DbxClient client) throws Exception
	{
		byte[] encodedKey = symm.getEncoded();
        //extract the public key
        String keyText = "";
        BufferedReader br = null;
        try {
        	String current;
        	br = new BufferedReader(new FileReader(pubkey));
        	while ((current = br.readLine()) != null) {
        		keyText = keyText + current;
        	}
        } catch (IOException e) {
        	e.printStackTrace();
        } finally {
        	try {
        		if (br != null)br.close();
        	} catch (IOException ex) {
        		ex.printStackTrace();
        	}
        }
        
        byte array1[] = keyText.getBytes();
        byte[] publicBytes = Base64.getDecoder().decode(array1);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
        KeyFactory keyFactory=null;
		try {
			keyFactory = KeyFactory.getInstance(RSA);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
        PublicKey pubKey=null;
		try {
			pubKey = keyFactory.generatePublic(keySpec);
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		Cipher cipher=null;
		try {
			cipher = Cipher.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		}

		try {
			cipher.init(Cipher.ENCRYPT_MODE, pubKey);
		} catch (InvalidKeyException e1) {
			e1.printStackTrace();
		} //init cipher to encrypt anything in doFinal

		byte[] encryptedBytes=null;
		try {
			encryptedBytes = cipher.doFinal(encodedKey);
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} //encrypt

		//create encrypted symmetric file
		File filey = new File("EncryptedSymmetricKey.txt");
		String ciphertext = new String(Base64.getEncoder().encode(encryptedBytes));
		FileWriter fw=null;
		try {
			fw = new FileWriter(filey.getAbsoluteFile());
		} catch (IOException e) {
			e.printStackTrace();
		}
		BufferedWriter bw = new BufferedWriter(fw);
		try {
			bw.write(ciphertext);
		} catch (IOException e) {
			e.printStackTrace();
		}
		try {
			bw.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		//upload to dropbox
		uploadFile(client, "EncryptedSymmetricKey.txt");
	}

	/*
	 * @param nameOfFile the file to be encrypted by aes
	 * @param symmetric the key to encrypt nameOfFile with
	 * @param extension the extension of the file
	 * Encrypts and uploads the file using AES algorithm
	 */
	private void encryptFile(String nameOfFile, SecretKeySpec symmetric, String extension, DbxClient client)
	{
		 //convert file to byte array
		FileInputStream fileInputStream=null;
        File file = new File("filesToSend/"+nameOfFile);
        byte[] byteFile = new byte[(int) file.length()];
        
        try {
           
	    fileInputStream = new FileInputStream(file);
	    fileInputStream.read(byteFile);
	    fileInputStream.close();
        }catch(Exception e){
        	e.printStackTrace();
        }

		// ENCRYPT byte array using the symmetric key
        Cipher c=null;
		try {
			c = Cipher.getInstance(AES);
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		} catch (NoSuchPaddingException e1) {
			e1.printStackTrace();
		}
		try {
			c.init(Cipher.ENCRYPT_MODE, symmetric);
		} catch (InvalidKeyException e1) {
			e1.printStackTrace();
		}
		byte[] encVal=null;
		try {
			encVal = c.doFinal(byteFile);
		} catch (IllegalBlockSizeException e1) {
			e1.printStackTrace();
		} catch (BadPaddingException e1) {
			e1.printStackTrace();
		}
		//create encrypted file
		FileOutputStream fos=null;
		try {
			fos = new FileOutputStream("encryptedFile" + extension);
		} catch (FileNotFoundException e1) {
			e1.printStackTrace();
		}
		try {
			fos.write(encVal);
		} catch (IOException e) {
			e.printStackTrace();
		}
		try {
			fos.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		//upload to dropbox
		uploadFile(client, ("encryptedFile" + extension));
	}
	
	/*
	 * @param fileToDecrypt the name of the file to decrypt
	 * @param keyToDecrypt the name of the symmetric key file to decrypt
	 * 
	 * Organises the decryption of the two files
	 */
	public void beginDecryption(String fileToDecrypt, String keyToDecrypt, DbxClient client)
	{
		SecretKeySpec decryptedSymmetricKey = decryptSymmetricKey(keyToDecrypt);
		String extension = extractExtension(fileToDecrypt);
		decryptFile(fileToDecrypt, decryptedSymmetricKey, extension, client);
	}
	
	/*
	 * @param name Name of the symmetric key
	 * Decrypts using rsa the symmetric key
	 */
	private SecretKeySpec decryptSymmetricKey(String name)
	{
		//read encrypted key file and convert to byte array
		//read encrypted file
		String ciphertext = "";
		BufferedReader br = null;
		try {
			String current;
			br = new BufferedReader(new FileReader(name));
			while ((current = br.readLine()) != null) {
				ciphertext = ciphertext + current;
			}
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				if (br != null)br.close();
			} catch (IOException ex) {
				ex.printStackTrace();
			}
		}
        Cipher cipher = null;
        PrivateKey privkey = storePrivateKey.get(currentFolder);
		try {
			cipher = Cipher.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		}
		try {
			cipher.init(Cipher.DECRYPT_MODE, privkey);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} 
        byte[] ciphertextBytes = Base64.getDecoder().decode(ciphertext.getBytes());
        byte[] decryptedBytes=null;
		try {
			decryptedBytes = cipher.doFinal(ciphertextBytes);
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		SecretKeySpec originalKey = new SecretKeySpec(decryptedBytes, AES);
		return originalKey;
        
	}
	
	/*
	 * @param name the file to be decrypted by aes
	 * @param symmetric the key to decrypt name with
	 * @param extension the extension of the file
	 * Decrypts the file using AES algorithm
	 */
	public void decryptFile(String name, SecretKeySpec key, String extension, DbxClient client)
	{
		byte[] bFile = downloadFile(client, name);
		//decrypt byte array using aes
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance(AES);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		}
		try {
			cipher.init(Cipher.DECRYPT_MODE, key);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} //init cipher to decrypt anything in doFinal
        byte[] decryptedBytes=null;
		try {
			decryptedBytes = cipher.doFinal(bFile);
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		//convert decrypted bytes to file
		FileOutputStream fos=null;
		try {
			fos = new FileOutputStream("decryptedFile" + extension);
		} catch (FileNotFoundException e1) {
			e1.printStackTrace();
		}
		try {
			fos.write(decryptedBytes);
		} catch (IOException e) {
			e.printStackTrace();
		}
		try {
			fos.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
        
	}
	
	/*
	 * Generates a symmetric key for file encryption for the admin
	 */
	private static SecretKeySpec generateSymmetricKey() throws Exception 
	{
		SecretKeySpec key = new SecretKeySpec(keyValue, AES);
		return key;
	}
	
	/*
	 * Extracts the extension of a filename
	 */
	private static String extractExtension(String filename)
	{
		return filename.substring((filename.indexOf('.')), filename.length());
	}
	
	/*
	 * @param client The dropbox client 
	 * @param filename The name of the file to upload to dropbox
	 */
	private static void uploadFile(DbxClient client, String filename)
	{
		File inputFile = new File(filename);
        FileInputStream inputStream = null;
		try {
			inputStream = new FileInputStream(inputFile);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
        try {
            DbxEntry.File uploadedFile = null;
			try {
				uploadedFile = client.uploadFile("/"+currentFolder+"/"+filename,
				    DbxWriteMode.add(), inputFile.length(), inputStream);
			} catch (DbxException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
        } finally {
            try {
				inputStream.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
        }
	}
	
	/*
	 * @param client The dropbox client 
	 * @param filename The name of the file to download from dropbox
	 */
	private static byte[] downloadFile(DbxClient client, String filename)
	{
		FileOutputStream outputStream = null;
		DbxEntry.File downloadedFile=null;
		try {
			outputStream = new FileOutputStream(filename);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
        try {
			try {
				downloadedFile = client.getFile("/"+currentFolder+"/"+filename, null,
				    outputStream);
			} catch (DbxException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
        } finally {
            try {
				outputStream.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
        }
        FileInputStream fileInputStream=null;
		byte[] bFile = new byte[ (int) downloadedFile.numBytes];
		try {
			fileInputStream = new FileInputStream(filename);
			fileInputStream.read(bFile);
			fileInputStream.close();
		}catch(Exception e){
			e.printStackTrace();
		}
		return bFile;
	}

	/*
	 * @param client The dropbox client 
	 * @param filename The name of the folder to delete from dropbox
	 */
	public void deleteFolder(String name, DbxClient client)
	{
		try {
			client.delete(name);
		} catch (DbxException e) {
			e.printStackTrace();
		}
	}
	
	/*
	 * @param name Name of user
	 * Deletes the private key pertaining to the user matching name
	 */
	public void removePrivateKey(String name)
	{
		storePrivateKey.remove(name);
	}
	
}
