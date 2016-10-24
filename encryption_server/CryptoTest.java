import com.dropbox.core.*;
import java.awt.Color;
import java.awt.Desktop;
import java.awt.Font;
import java.awt.Image;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.Locale;
import java.util.Scanner;
import javax.swing.DefaultListModel;
import javax.swing.ImageIcon;
import javax.swing.JFrame;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.UIManager;
import javax.swing.plaf.FontUIResource;
public class CryptoTest {

	//private static ArrayList<String> users = new ArrayList<String>();
	static ArrayList<String> listOfNames = new ArrayList<String>();
	private static final String APP_KEY = "u4jbimr0r3uaxfm";
	private static final String APP_SECRET = "4th3cecydz0q7cd";
	private static Hashtable<String, String> authenticatedUsers = new Hashtable<String, String>(); //name and pin
	private static ArrayList<String> communicatedWith = new ArrayList<String>(); //name
	public static void main(String[] args) {
		Crypto crypto = new Crypto();
		UIManager.put("OptionPane.messageFont", new FontUIResource(new Font("Century Gothic", Font.PLAIN, 11)));
		// -------- establish connection with dropbox --------------
		DbxAppInfo appInfo = new DbxAppInfo(APP_KEY, APP_SECRET);

		DbxRequestConfig config = new DbxRequestConfig("JavaTutorial/1.0",
				Locale.getDefault().toString());
		DbxWebAuthNoRedirect webAuth = new DbxWebAuthNoRedirect(config, appInfo);

		// Have the user sign in and authorize your app.
		String authorizeUrl = webAuth.start();
		try {
			Desktop desktop = java.awt.Desktop.getDesktop();
			URI oURL = new URI(authorizeUrl);
			desktop.browse(oURL);
		} catch (Exception e) {
			e.printStackTrace();
		}
		System.out.println("2. Click \"Allow\"");
		System.out.println("3. Enter the authorization code:");
		String code="";
		try {
			code = new BufferedReader(new InputStreamReader(System.in)).readLine().trim();
		} catch (IOException e) {
			e.printStackTrace();
		}
		DbxAuthFinish authFinish = null;
		try {
			authFinish = webAuth.finish(code);
		} catch (DbxException e) {
			e.printStackTrace();
		}
		String accessToken = authFinish.accessToken;
		DbxClient client = new DbxClient(config, accessToken);
		String admin = "";
		try {
			admin = client.getAccountInfo().displayName;
			System.out.println("Account admin: " + admin);
		} catch (DbxException e) {
			e.printStackTrace();
		}
		
		Color dropboxBlue = new Color(39, 155, 253);
		UIManager.put("OptionPane.messageFont", new FontUIResource(new Font("Gotham Bold", Font.PLAIN, 17)));
		UIManager.put("OptionPane.buttonFont", new FontUIResource(new Font("Gotham Bold", Font.PLAIN, 14)));
		UIManager.put("OptionPane.background", Color.white);
		UIManager.put("OptionPane.messageForeground", dropboxBlue);
		UIManager.put("Panel.background", Color.white);
		
		JFrame frame = new JFrame();
		ImageIcon safetyimage = new ImageIcon("dropbox.png");
		Image img = safetyimage.getImage();
		Image newimg = img.getScaledInstance(150, 150,  java.awt.Image.SCALE_SMOOTH);
		ImageIcon newIcon = new ImageIcon(newimg);
		Object[] homePageOptions = {"Add a user", "Encrypt a file", "Remove a user", "View authorised users"};
		
		
		
		DefaultListModel<String> modelUsers = new DefaultListModel<String>();
		JList<String> memberList = new JList<String>(modelUsers);
		JScrollPane panelOfUsers=new JScrollPane(memberList);
		JList<String> fileList;
		JScrollPane panelOfFiles;
		DefaultListModel<String> modelFiles = new DefaultListModel<String>();
		
		Scanner scanInput = new Scanner(System.in);
		String pin, encryptionFileName, user, encryptedFile, pinInput, symmetricKey, delete="";
		int adminChoice, password;
		while(true)
		{
			adminChoice = JOptionPane.showOptionDialog(frame, "Please select an option:", "DropboxSecure",
					JOptionPane.YES_NO_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE, newIcon, homePageOptions, null);
			switch(adminChoice)
			{
			case 0: // add user
				user = (String) JOptionPane.showInputDialog(frame, panelOfUsers,
						null, JOptionPane.OK_CANCEL_OPTION, newIcon, null, null);
				modelUsers.addElement(user);
				password = (int)(Math.random()*9000)+1000;
				pin = String.valueOf(password);
				authenticatedUsers.put(user, pin);
				listOfNames.add(user);
				System.out.println(authenticatedUsers);
				break;

			case 1: //encrypt a file
				if(authenticatedUsers.size() > 0)
				{
					File folder = new File("filesToSend");
					File[] listOfFiles = folder.listFiles();
					
					ArrayList<String> test = new ArrayList<String>();
					for (int i = 0; i < listOfFiles.length; i++) {
						if (listOfFiles[i].isFile()) 
						{
							test.add(listOfFiles[i].getName());
						}
					}
					modelFiles = new DefaultListModel<String>();
					for(String s:test){
						modelFiles.addElement(s);
					}
					fileList = new JList<String>(modelFiles);
					panelOfFiles = new JScrollPane(fileList); 
					
					Object array[] = {panelOfFiles, panelOfUsers};
					JOptionPane.showOptionDialog(frame, array, "DropboxSecure",
							JOptionPane.YES_NO_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE, newIcon, null, null);
					
					String receiverName = memberList.getSelectedValue();
					System.out.println(fileList.getSelectedValue());
					// generate pub key
					System.out.println(" ---------- GUEST MODE SIMULATION -----------");
					System.out.println(receiverName + ", " + admin + " would like to send you a file. Please enter your pin: ");
					pinInput = scanInput.nextLine();
					if(authenticatedUsers.get(receiverName).equals(pinInput)) // user has logged in correctly
					{
						crypto.createNewUserFolder(receiverName);
						//guest uploads their public key as their name.txt
						crypto.createPublicKey(receiverName + ".txt", client);
						encryptionFileName = fileList.getSelectedValue();
						System.out.println("Encryption in process...");
						crypto.beginEncryption(encryptionFileName, receiverName+".txt", client);
						System.out.println("Encryption complete!\nSource file to decrypt:");
						encryptedFile = scanInput.nextLine();
						System.out.println("Key file to decrypt:");
						symmetricKey = scanInput.nextLine();
						crypto.beginDecryption(encryptedFile, symmetricKey, client);
						System.out.println("Decryption complete.");
						communicatedWith.add(receiverName);
					}
					else
					{
						System.out.println("Incorrect name/pin. Failed to log in.");
					}
				}
				else
				{
					JOptionPane.showMessageDialog(null, "There are no users to communicate with.");
				}
				break;

			case 2: //remove a user
				JOptionPane.showOptionDialog(frame, panelOfUsers, "DropboxSecure",
						JOptionPane.YES_NO_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE, newIcon, null, null);
				delete = memberList.getSelectedValue();
				authenticatedUsers.remove(delete);
				listOfNames.remove(delete);
				if(communicatedWith.contains(delete))
				{
					crypto.deleteFolder("/"+delete, client);
					crypto.removePrivateKey(delete);
				}
				modelUsers.removeElement(delete);
				JOptionPane.showMessageDialog(null, "Deleted: " + delete, "DropboxSecure", JOptionPane.PLAIN_MESSAGE);
				break;
			case 3: //view current users
				JOptionPane.showOptionDialog(frame, panelOfUsers, "DropboxSecure",
						JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE, newIcon, null, null);
				break;
			case -1:
				System.exit(0);
				break;
			}
		}
	}
	
	
	
}