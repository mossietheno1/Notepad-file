import java.awt.Container;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.Key;
//import java.security.NoSuchAlgorithmException;
//import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Base64;

import javax.crypto.Cipher;
//import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Notepad extends JFrame implements ActionListener {
static final String UNTITLED="Untitled";
	final JFileChooser dialog=new JFileChooser();
	final JMenuBar menubar=new JMenuBar();
	final JMenu file=new JMenu("File");
	final JMenuItem newfile=new JMenuItem("New");
	final JMenuItem openfile=new JMenuItem("Open");
	final JMenuItem savefile=new JMenuItem("Save");
	final JMenuItem exit=new JMenuItem("Exit");
	final JTextArea textArea=new JTextArea();
	final JScrollPane scrollPane;
	boolean modified = false;
	String key;
	String ciphertext;
	String plaintext;
	Cipher c;
	Key k;

	public Notepad() {
		Security.addProvider(new BouncyCastleProvider());
		textArea.addKeyListener(new KeyAdapter() {
			@Override
			public void keyTyped(KeyEvent e) {
				modified = true;
			}
		});
		scrollPane = new JScrollPane(textArea);
		newfile.addActionListener(this);
		openfile.addActionListener(this);
		savefile.addActionListener(this);
		exit.addActionListener(this);
		file.add(newfile);
		file.add(openfile);
		file.add(savefile);
		file.addSeparator();
		file.add(exit);
		menubar.add(file);
		Container ca = getContentPane();
		getRootPane().setJMenuBar(menubar);
		ca.add(scrollPane);
		setTitle(UNTITLED);
		setPreferredSize(new Dimension(600, 400));
	}

	public void actionPerformed(ActionEvent ae) {
		if (ae.getSource() == newfile) {
			System.out.println("NEW FILE");
			if (modified) {
				int ca = checkModified();
				if (ca == JOptionPane.YES_OPTION) {
					saveFile();
				} else if (ca == JOptionPane.NO_OPTION) {
					newFile();
				}
			} else {
				newFile();
			}
		} else if (ae.getSource() == openfile) {
			if (modified) {
				int ca = checkModified();
				if (ca == JOptionPane.YES_OPTION) {
					saveFile();
					openFile();
				} else if (ca == JOptionPane.NO_OPTION) {
					openFile();
				}
			} else {
				openFile();
			}
		} else if (ae.getSource() == savefile) {
			saveFile();
		} else if (ae.getSource() == exit) {
			if (modified) {
				int ca = checkModified();
				if (ca == JOptionPane.YES_OPTION) {
					saveFile();
				} else if (ca == JOptionPane.NO_OPTION) {
					System.exit(0);
				}
			} else {
				System.exit(0);
			}
		}
	}

	public void newFile() {
		textArea.setText("");
		setTitle(UNTITLED);
		modified = false;
	}

	public void openFile() {
			try {
				int ca = dialog.showOpenDialog(this);
				if (ca == JFileChooser.APPROVE_OPTION) {
					enterPassword();
					if(key != null && !key.isEmpty()) 
					{
					File f = dialog.getSelectedFile();
					FileInputStream fis = new FileInputStream(f);
					textArea.setText("");
					BufferedReader br = new BufferedReader(new InputStreamReader(fis));
					String str;
					str = decrypt(c, k, ciphertext);
					while ((str = br.readLine()) != null)
						textArea.append(str + "\n");
					setTitle(f.getPath());
					modified = false;
					}
					else{
						JOptionPane.showMessageDialog(this, "please enter a password to save the file");
					}
				}
			}
		catch (IOException e) {
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}


	public void saveFile() {
		try {
			File f = null;
			if (getTitle().equals(UNTITLED)) {
				int ca = dialog.showSaveDialog(this);
				if (ca == JFileChooser.APPROVE_OPTION) {
					f = dialog.getSelectedFile();
				}
			} else {
				f = new File(getTitle());
			}
			enterPassword();
			if(key != null && !key.isEmpty()) 
			{
			Cipher c = Cipher.getInstance("AES", "BC");
			Key k = new SecretKeySpec(key.getBytes(), "AES"); 
			String ciphertext = encrypt(c, k, plaintext);
			FileOutputStream fos = new FileOutputStream(f);
			byte[] textInBytes = textArea.getText().getBytes();
			fos.write(textInBytes);
			fos.close();
			setTitle(f.getPath());
			modified = false;
			}
			else {
				JOptionPane.showMessageDialog(this, "pleae enter a password to save the file");
			}
		} catch (IOException e) {
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

public int checkModified() {
return JOptionPane.showConfirmDialog(this,
"The text in the " + getTitle() + " has changed\nDo you want to save it", "Notepad",
JOptionPane.YES_NO_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
}

public String enterPassword()	{
			key = JOptionPane.showInputDialog(this,"Please enter the password you would like to use");
			return key;
}
	public static void main(String[] args) {
		SwingUtilities.invokeLater(new Runnable() {
			public void run() {
				Notepad notepad = new Notepad();
				notepad.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
				notepad.pack();
				notepad.setVisible(true);
			}
		});
	}
	public static String encrypt(Cipher c, Key k, String data) throws
	Exception {
	c.init(Cipher.ENCRYPT_MODE, k);
	byte[] encryptedData = c.doFinal(data.getBytes());
	String encodedData = Base64.getEncoder().encodeToString(encryptedData);
	return encodedData;
	}
	public static String decrypt(Cipher c, Key k, String data) throws
	Exception {
	c.init(Cipher.DECRYPT_MODE, k);
	byte[] decodedData = Base64.getDecoder().decode(data);
	byte[] decryptedData = c.doFinal(decodedData);
	return new String(decryptedData);
	}
}

