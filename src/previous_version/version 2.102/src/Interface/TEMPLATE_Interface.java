/**
 * @author Solomon Sonya
 */


package Interface;

import java.io.*;
import java.awt.*;
import java.awt.event.*;
import java.net.*;
import java.security.*;
import java.util.*;

import javax.imageio.ImageIO;
import javax.swing.*;
import javax.swing.border.BevelBorder;
import javax.swing.border.TitledBorder;
import Driver.*;
//import Sound.ThreadSound;


public class TEMPLATE_Interface extends Thread implements Runnable, ActionListener
{
	public static final String myClassName = "Interface";
	public static volatile Driver driver = new Driver();

	public static volatile JFrame jfrm = null;
	public static volatile JMenuBar menu_bar = null;
	public static volatile JMenu jmnuFile = null;
		public static volatile JMenuItem jmnuitm_Close = null;
		public static volatile JMenu jmnuEncryption = null;
			public static volatile ButtonGroup bgEncryption = null;
			public static volatile JRadioButtonMenuItem jrbEncryptionEnabled = null;
			public static volatile JRadioButtonMenuItem jrbEncryptionDisabled = null;
			public static volatile JMenuItem jmnuitm_Import = null;
			
	public JPanel jpnlMain = null;
	
	public JPanel jpnlNORTH = null;
	public JPanel jpnlCENTER = null;
	public JPanel jpnlSOUTH = null;
	
	public JPanelHeap jpnlHeap = null;
	public JPanelTime jpnlTime = null;
	
	public JSplitPane_Solomon jsplitpane_MAIN = null;
	public JTabbedPane jtabbedPane_MAIN  = null;
	public JTabbedPane jtabbedPane_CONSOLE  = null;
	
	public volatile JTextArea_Solomon jpnlConsole = null;
	
	
	
	
	public TEMPLATE_Interface()
	{
		try
		{
			this.start();
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
		
	}
	
	public void run()
	{
		try
		{
			initialize_component();
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "run", e);
		}
	}
	
	public boolean initialize_component()
	{
		try
		{
			driver.setLookAndFeel();
			try 		 {				 UIManager.setLookAndFeel("com.sun.java.swing.plaf.windows.WindowsLookAndFeel");				 SwingUtilities.updateComponentTreeUI(jfrm);				 /*updateComponentTreeUI(this);	*/	    }	catch (Exception e) 	    {	    }
			
			jfrm = new JFrame();			
			jfrm.setTitle(Driver.FULL_NAME);
			jfrm.setSize(new Dimension(1100,800));
			jfrm.setVisible(true);
			jfrm.setLayout(new BorderLayout());
			
			try
			{
				jfrm.setLocationRelativeTo(null);
			}
			catch(Exception e)
			{
				Dimension dim = Toolkit.getDefaultToolkit().getScreenSize();
				jfrm.setLocation(dim.width/2-jfrm.getSize().width/2, dim.height/2-jfrm.getSize().height/2);
			}
			
			//
			//menu
			//
			menu_bar = new JMenuBar();
			
			//file
			this.jmnuFile = new JMenu("File");
			jmnuFile.setMnemonic(KeyEvent.VK_F);
			menu_bar.add(jmnuFile);
			
			jmnuitm_Import = new JMenuItem("Import");
			jmnuitm_Close = new JMenuItem("Close");
			jmnuEncryption = new JMenu("Encryption");
				jrbEncryptionEnabled = new JRadioButtonMenuItem("Encryption Enabled");
				jrbEncryptionDisabled = new JRadioButtonMenuItem("Encryption Disabled", true);
				bgEncryption = new ButtonGroup();
				bgEncryption.add(this.jrbEncryptionEnabled);
				bgEncryption.add(this.jrbEncryptionDisabled);
				jmnuEncryption.add(this.jrbEncryptionEnabled);
				jmnuEncryption.add(this.jrbEncryptionDisabled);
			
			jmnuFile.add(jmnuEncryption);
			jmnuFile.add(jmnuitm_Import);
			jmnuFile.add(jmnuitm_Close);
			
			this.jrbEncryptionDisabled.addActionListener(this);
			this.jrbEncryptionEnabled.addActionListener(this);
			this.jmnuitm_Close.addActionListener(this);
			this.jmnuitm_Import.addActionListener(this);
			
			this.jfrm.setJMenuBar(menu_bar);
			
			jpnlMain = new JPanel(new BorderLayout());
				jfrm.add(BorderLayout.CENTER, jpnlMain);
			
			jpnlNORTH = new JPanel(new BorderLayout());
			jpnlCENTER = new JPanel(new BorderLayout());
			jpnlSOUTH = new JPanel(new BorderLayout());
			
			jpnlMain.add(BorderLayout.NORTH, jpnlNORTH);
			jpnlMain.add(BorderLayout.CENTER, jpnlCENTER);
			jpnlMain.add(BorderLayout.SOUTH, jpnlSOUTH);
			
			
			//
			//SPECIAL PANELS
			//
			jpnlTime = new JPanelTime();
				jpnlNORTH.add(BorderLayout.CENTER, jpnlTime);
				jpnlNORTH.setBorder(BorderFactory.createBevelBorder(BevelBorder.LOWERED));
				
				
				
				
				
			jpnlHeap = new JPanelHeap();				
				jpnlSOUTH.add(BorderLayout.CENTER, jpnlHeap);
				jpnlSOUTH.setBorder(BorderFactory.createBevelBorder(BevelBorder.LOWERED));
												
			
				
			//
			//JTABBED PANE
			//
			jtabbedPane_MAIN = new JTabbedPane(JTabbedPane.TOP);
			jtabbedPane_CONSOLE = new JTabbedPane(JTabbedPane.TOP);
			jsplitpane_MAIN = new JSplitPane_Solomon(JSplitPane.VERTICAL_SPLIT, jtabbedPane_MAIN, jtabbedPane_CONSOLE, 500);
				jpnlCENTER.add(BorderLayout.CENTER, jsplitpane_MAIN);
			
			
			//
			jpnlConsole = new JTextArea_Solomon("", true, "Command Transmission", true);			
			jtabbedPane_CONSOLE.addTab("Console", jpnlConsole);
			
			jtabbedPane_MAIN.addTab("Main", new JPanel());
			
			
			
			
			
			
			
			
			
			
			jfrm.addWindowListener(new java.awt.event.WindowAdapter()
			{
				public void windowClosing(java.awt.event.WindowEvent e)
				{
					close();
				}
			});
			
			jfrm.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
			
			jfrm.validate();
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "initialize_component", e);
		}
		
		return false;
	}
	
	public boolean close()
	{
		try
		{
			if(driver.query_user("Close " + Driver.NAME, "Exit?") == JOptionPane.YES_OPTION)
			{
				driver.directive("Program Terminated.");
				System.exit(0);
			}
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "close", e);
		}
		
		return false;
	}
	
	public void actionPerformed(ActionEvent ae)
	{
		try
		{
			if(ae.getSource() == jmnuitm_Close)
			{
				close();
			}
			
			else if(ae.getSource() == this.jmnuitm_Import)
			{
				//try{	ThreadSound.play(ThreadSound.url_note_beep);	}	catch(Exception ee){}
				
				File fle = driver.querySelectFile(true, "Please select file to import", JFileChooser.FILES_ONLY, false, false);
				
				if(fle == null || !fle.exists() || !fle.isFile())
				{
					driver.directive("\nPUNT! No valid file selected!");
					driver.jop_Error("PUNT! No valid file selected!", true);
				}
				
				else
					StandardInListener.import_file(fle);
			}
			
			else if(ae.getSource() == this.jrbEncryptionDisabled)
			{
				StandardInListener.set_encryption(null);				
			}
			
			else if(ae.getSource() == this.jrbEncryptionEnabled)
			{
				String key = driver.jop_Query("Please specify encryption key", "Enter Encryption Key");
				
				if(key == null || key.trim().equals("") || key.equalsIgnoreCase("null"))
				{
					jrbEncryptionDisabled.setSelected(true);
					StandardInListener.set_encryption(null);
				}
				else
				{
					StandardInListener.set_encryption(key);	
				}
				
				
				
			}
			
			this.jfrm.validate();
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "ae", e);
		}
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
