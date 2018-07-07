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
import org.apache.commons.io.LineIterator;
import javax.imageio.ImageIO;
import javax.swing.*;
import javax.swing.border.BevelBorder;
import javax.swing.border.TitledBorder;
import Driver.*;
import java.util.*;
import Plugin.*;
//import Sound.ThreadSound;
import SearchImage.SearchImage;


public class Interface extends Thread implements Runnable, ActionListener
{
	public static final String myClassName = "Interface";
	public static volatile Driver driver = new Driver();

	public static volatile JFrame jfrm = null;
	public static volatile JMenuBar menu_bar = null;
	public static volatile JMenu jmnuFile = null;
	public static volatile JMenu jmnuHelp = null;
		public static volatile JMenuItem jmnuitm_Close = null;
		public static volatile JMenu jmnuEncryption = null;
			public static volatile ButtonGroup bgEncryption = null;
			public static volatile JRadioButtonMenuItem jrbEncryptionEnabled = null;
			public static volatile JRadioButtonMenuItem jrbEncryptionDisabled = null;
			public static volatile JMenuItem jmnuitm_Import = null;
			
			public static volatile JMenuItem jmnuitm_About = null;
			
			public static volatile JMenuItem jmnuitm_Specify_Volatility_Executable = null;
			public static volatile JMenuItem jmnuitm_Specify_Memory_Image_For_Analysis = null;
			public static volatile JMenuItem jmnuitm_Specify_Profile = null;
			public static volatile JMenuItem jmnuitm_Specify_Investigator_Name = null;
			public static volatile JMenuItem jmnuitm_Specify_Investigation_Details = null;
			
	public JPanel jpnlMain = null;
	
	public JPanel jpnlNORTH = null;
		public JPanel jpnlNORTH_SOUTH = null;
		public JLabel jlbl_volatility_path = new JLabel("  Volatility Path not yet set...");
		public JLabel jlbl_memory_image_path = new JLabel("  Memory Dump/Image Path not yet set...");
		public JLabel jlblProfile = new JLabel("  Memory Image Profile not yet set...");
		public JLabel jlbl_memory_image_attributes = new JLabel("  Memory Image Attributes not available yet set...");
		public JLabel jlblInvestigationDetails = new JLabel("  Investigation details not specified yet...");
		
	public JPanel jpnlCENTER = null;
	public JPanel jpnlSOUTH = null;
	
	public JPanel jpnlPlugin_CONTAINER = null;
	public JPanel jpnlPluginButtons = null;
	public JButton jbtnAnalyse = new JButton("Analyze");
	public JButton jbtnSelectFavorites = new JButton("Select Favorites");
	public JButton jbtnHailMary = new JButton("Hail Mary");
	public JButton jbtnDeselectAllPlugins = new JButton("Deselect All Plugins");
	public JButton jbtnPreview = new JButton("Preview");
	public JButton jbtnSearchImage = new JButton("Add Search Image Tab");
	public JScrollPane jscrlpne_jpnlPlugins = null;
	public JPanel jpnlPlugins = null;
	public static final int num_plugin_cols = 2;
	
	public JPanelHeap jpnlHeap = null;
	public JPanelTime jpnlTime = null;
	
	public JSplitPane_Solomon jsplitpane_MAIN = null;
	public static JTabbedPane jtabbedPane_MAIN  = null;
	public static JTabbedPane jtabbedPane_CONSOLE  = null;
	public static JTabbedPane jtabbedPane_CONFIGURATION  = null;
	public static JTabbedPane jtabbedPane_ANALYSIS  = null;
	/**Specific data/time for all of these analysis for this current instance*/
	public JTabbedPane jtabbedPane_ANALYSIS_DATE_TIME  = null;
	
	public static volatile JTextArea_Solomon jpnlConsole = null;
	
	public volatile boolean supported_plugins_found = false;
	public static volatile JTextArea_Solomon jpnlVolatilityOptions = null;
	public static volatile JTextArea_Solomon jpnlVolatilitySupportedPlugins = null;
	
	public static volatile LinkedList<String> list_volatility_help_configuration_OPTIONS = new LinkedList<String>();
	public static volatile LinkedList<String> list_volatility_help_configuration_SUPPORTED_PLUGINS = new LinkedList<String>();
	
	public volatile boolean profiles_found = true;
	public volatile boolean address_spaces_found = false;
	public volatile boolean plugins_found = false;
	public volatile boolean scanner_checks_found = false;
	
	

	public static volatile LinkedList<String> list_volatility_info_configuration_PROFILES = new LinkedList<String>();
	public static volatile LinkedList<String> list_volatility_info_configuration_ADDRESS_SPACES = new LinkedList<String>();
	public static volatile LinkedList<String> list_volatility_info_configuration_PLUGINS = new LinkedList<String>();
	public static volatile LinkedList<String> list_volatility_info_configuration_SCANNER_CHECKS = new LinkedList<String>();
	
	public static volatile JTextArea_Solomon jpnlVolatilityInfo_Profiles = null;
	public static volatile JTextArea_Solomon jpnlVolatilityInfo_Address_Spaces = null;
	public static volatile JTextArea_Solomon jpnlVolatilityInfo_Plugins = null;
	public static volatile JTextArea_Solomon jpnlVolatilityInfo_Scanner_Checks = null;
	
	public static volatile File fle_analysis_directory = null;
	public static volatile String path_fle_analysis_directory = "";
	
	public static volatile File fle_volatility = null;
	public static volatile FileAttributeData file_attr_volatility = null;
	public static volatile String hash_volatility_md5 = null;
	public static volatile String hash_volatility_sha256 = null;
	
	public static volatile LinkedList<String> list_image_files = new LinkedList<String>();
	
	public static volatile File fle_memory_image = null;
	public static volatile FileAttributeData file_attr_memory_image = null; 
	public static volatile String hash_memory_image_md5 = null;
	public static volatile String hash_memory_image_sha256 = null;
	
	public static volatile File fle_procdump = null;
	
	public static volatile String investigator_name = null;
	public static volatile String investigation_description = null;
	
	
	public volatile static String PROFILE = "Win7SP1x64";
	
	public static final String analysis_time_stamp = driver.get_time_stamp("_");
	public static final String EXECUTION_TIME_STAMP = driver.getTime_Specified_Hyphenated_with_seconds_using_colon(System.currentTimeMillis());
	
	public static final String select_image_from_location_text = "Select image from location...";
	
	public Interface()
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
			
			System.gc();
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
			
			//hELP
			this.jmnuHelp = new JMenu("Help");
			jmnuHelp.setMnemonic(KeyEvent.VK_H);
			menu_bar.add(jmnuHelp);
			jmnuitm_About = new JMenuItem("About");
			jmnuHelp.add(jmnuitm_About);
			jmnuitm_About.addActionListener(this);
			
			jmnuitm_Import = new JMenuItem("Import");
			
			jmnuitm_Specify_Volatility_Executable = new JMenuItem("Specify Volatility Executable");
			jmnuitm_Specify_Memory_Image_For_Analysis = new JMenuItem("Specify Memory Image for Analysis");
			jmnuitm_Specify_Profile = new JMenuItem("Specify Profile for Memory Image Analysis");
			jmnuitm_Specify_Investigator_Name = new JMenuItem("Specify Investigator Name");
			jmnuitm_Specify_Investigation_Details = new JMenuItem("Specify Investigation Details");
			
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
			jmnuFile.add(jmnuitm_Specify_Volatility_Executable);
			jmnuFile.add(jmnuitm_Specify_Profile);
			jmnuFile.add(this.jmnuitm_Specify_Memory_Image_For_Analysis);
			jmnuFile.add(jmnuitm_Specify_Investigator_Name);
			jmnuFile.add(jmnuitm_Specify_Investigation_Details);
			
			jmnuFile.add(jmnuitm_Close);
			
			this.jrbEncryptionDisabled.addActionListener(this);
			this.jrbEncryptionEnabled.addActionListener(this);
			this.jmnuitm_Close.addActionListener(this);
			this.jmnuitm_Import.addActionListener(this);
			this.jmnuitm_Specify_Profile.addActionListener(this);
			jmnuitm_Specify_Investigator_Name.addActionListener(this);
			jmnuitm_Specify_Investigation_Details.addActionListener(this);
			
			
			this.jmnuitm_Specify_Volatility_Executable.addActionListener(this);
			this.jmnuitm_Specify_Memory_Image_For_Analysis.addActionListener(this);
			
			
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
				
				jpnlNORTH_SOUTH = new JPanel(new GridLayout(5,1,5,5));
				jpnlNORTH_SOUTH.add(jlbl_volatility_path);
				jpnlNORTH_SOUTH.add(jlblProfile);
				jpnlNORTH_SOUTH.add(jlbl_memory_image_path);
				jpnlNORTH_SOUTH.add(jlbl_memory_image_attributes);
				jpnlNORTH_SOUTH.add(jlblInvestigationDetails);
					jpnlNORTH.add(BorderLayout.SOUTH, jpnlNORTH_SOUTH);
				
				
				
				
				
			jpnlHeap = new JPanelHeap();				
				jpnlSOUTH.add(BorderLayout.CENTER, jpnlHeap);
				jpnlSOUTH.setBorder(BorderFactory.createBevelBorder(BevelBorder.LOWERED));
												
			
				
			//
			//JTABBED PANE
			//
			jtabbedPane_MAIN = new JTabbedPane(JTabbedPane.TOP);
			jtabbedPane_CONSOLE = new JTabbedPane(JTabbedPane.TOP);
			jsplitpane_MAIN = new JSplitPane_Solomon(JSplitPane.VERTICAL_SPLIT, jtabbedPane_MAIN, jtabbedPane_CONSOLE, 100);
				jpnlCENTER.add(BorderLayout.CENTER, jsplitpane_MAIN);
			
				
			
			//
			jpnlConsole = new JTextArea_Solomon("", true, "Command Transmission", true);			
			jtabbedPane_CONSOLE.addTab("Console", jpnlConsole);
			
			this.jpnlPlugins = new JPanel(new GridLayout(20, 3, 5,5));
			jscrlpne_jpnlPlugins = new JScrollPane(this.jpnlPlugins, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
			
			jpnlPluginButtons = new JPanel(new GridLayout(1,6, 5, 5));
			
			jpnlPluginButtons.add(this.jbtnSelectFavorites);
			jbtnSelectFavorites.addActionListener(this);
			
			jpnlPluginButtons.add(jbtnPreview);
			jbtnPreview.addActionListener(this);
			
			jpnlPluginButtons.add(jbtnAnalyse);
			jbtnAnalyse.addActionListener(this);
			
			jpnlPluginButtons.add(jbtnHailMary);
			jbtnHailMary.addActionListener(this);
			
			jpnlPluginButtons.add(jbtnDeselectAllPlugins);
			jbtnDeselectAllPlugins.addActionListener(this);
			
			jpnlPluginButtons.add(jbtnSearchImage);
			jbtnSearchImage.addActionListener(this);
			
			
			
			jpnlPlugin_CONTAINER = new JPanel(new BorderLayout());
			jpnlPlugin_CONTAINER.add(BorderLayout.CENTER, this.jscrlpne_jpnlPlugins);
			jpnlPlugin_CONTAINER.add(BorderLayout.SOUTH, jpnlPluginButtons);
			
			jtabbedPane_MAIN.addTab("Plugins", jpnlPlugin_CONTAINER);
			
			
			jtabbedPane_CONFIGURATION = new JTabbedPane(JTabbedPane.TOP);
			jtabbedPane_ANALYSIS = new JTabbedPane(JTabbedPane.TOP);
				jtabbedPane_CONSOLE.addTab("Volatility Configuration", jtabbedPane_CONFIGURATION);
				jtabbedPane_CONSOLE.addTab("Memory Analysis", jtabbedPane_ANALYSIS);
				
			jtabbedPane_ANALYSIS_DATE_TIME = new JTabbedPane(JTabbedPane.TOP);
				jtabbedPane_ANALYSIS.addTab("Analysis Timestamp - " + analysis_time_stamp, jtabbedPane_ANALYSIS_DATE_TIME);
			
			fle_analysis_directory = new File(Driver.NAME_LOWERCASE + File.separator + "export" + File.separator + "memory_analysis" + File.separator + analysis_time_stamp);
			
			try	{	fle_analysis_directory.mkdirs(); } catch(Exception e){}
			
			if(fle_analysis_directory.getCanonicalPath().trim().endsWith(File.separator))
				path_fle_analysis_directory = fle_analysis_directory.getCanonicalPath().trim();
			else
				path_fle_analysis_directory = fle_analysis_directory.getCanonicalPath().trim() + File.separator;
			
			//procdump directory
			fle_procdump = new File(path_fle_analysis_directory + "procdump");
			
			//
			//NOTIFY USER
			//
			driver.directive("///////////////////////////////////////////////////////////////////////////////////");
			driver.directive("// Welcome to " + Driver.FULL_NAME + " by Solomon Sonya @Carpenter1010\t//");
			driver.directive("/////////////////////////////////////////////////////////////////////////////////\n");
			
			jbtnSearchImage.setToolTipText("<html>Enter specific keywords to search for hits through a specified image. <br>A new Tab will appear to allow you to select an image and enter keywords to search for hits.</html>");
			this.jbtnHailMary.setToolTipText("<html><b>Proceed with caution on this one.</b> <br>Selecting this will enable every applicable plugin for analysis.<br>After selecting, click on Analyze to begin analysis.</html>");
			this.jbtnPreview.setToolTipText("Populate new tabs based on the selected plugins. This allows you to modify the commands before execution. Click on Analyze when ready to begin analysis.");
			this.jbtnSelectFavorites.setToolTipText("Quickly enable a few plugins useful in many investigations. Click on Analyze to begin analysis.");
			this.jbtnAnalyse.setToolTipText("Begin analysis on the selected plugins");
			this.jbtnDeselectAllPlugins.setToolTipText("Unselect all selected plugins");
			
			//
			//check if we have a config file or import files already completed
			//
			initialize_framework_volatility_executable();
						
			//
			//set volatility path
			//
			if(this.fle_volatility == null || !this.fle_volatility.exists() || !this.fle_volatility.isFile())
				this.specify_volatility_executable();
			
			
			//
			//set memory image path
			//
			initialize_framework_import_memory_image();
						
			if(this.fle_memory_image == null || !this.fle_memory_image.exists() || !this.fle_memory_image.isFile())
				specify_memory_image(fle_volatility);
			
			//
			//specify profile
			//
			specify_profile();
			
			
			//
			//Investigation Details
			//
			specify_investigation_details();
			
			
			driver.directive("\nInitial Configuration Complete.");			
	        driver.directive("\tPlease refer to the Volatility Configuration tab to view various options and plugins supported by this sample.");
	        driver.directive("\tWhen you are ready, please enable one or more plugins from the top Plugins tab. ");
	        driver.directive("\tPress Preview after making you selection(s) to load your selected plugins as well as view applicable parameters in the Memory Analysis tab.");
	        driver.directive("\tFinally, press Analyze to run the analysis process for all selected plugins. Alternatively, you can select Execute from each plugin tab to run the analysis commands individually.");
	        driver.directive("\tYou may also search through an image (e.g. hibernation file or pagefile) for specific keyword hits. You can click on the Search Image button for individual keyword searches.");
	        driver.directive("\tHappy Hunting! - Solomon Sonya @Carpenter1010");
			
			
			
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
	
	public boolean initialize_framework_volatility_executable()
	{
		try
		{
			//
			//Check if volatility is included in the import directory
			//
			LinkedList<File> list = new LinkedList<File>();
			list = driver.getFileListing(Start.fleImportMemoryAnalysisDirectory, true, null, list);
			boolean volatility_name_found = false;
			
			if(list != null && !list.isEmpty())
			{
				//at least there are files, iterate through to select the first one that has volatility
				for(File fle : list)
				{
					if(fle == null || !fle.exists() || !fle.isFile())
						continue;
					
					if(fle.getCanonicalPath().toLowerCase().contains("volatility"))
					{
						Interface.fle_volatility = fle;
						volatility_name_found = true;
						break;
					}
				}
				
				//check if nothing with "volatility" in its name was found
				if(!volatility_name_found)
				{
					for(File fle : list)
					{
						if(fle == null || !fle.exists() || !fle.isFile())
							continue;
						
						//take the first file found
						Interface.fle_volatility = fle;
						driver.directive("NOTE: I could not specifically find a volatility binary file at framework import directory: \n--> " + Start.fleImportMemoryAnalysisDirectory.getCanonicalPath() + "\n");
						driver.directive("I have selected the following memory analysis executable --> " + Interface.fle_volatility.getCanonicalPath());
						driver.directive("If this is not acceptable, remove this file from the import directory and select \"File --> Specify Volatility Executable\" to update the framework.\n");
						break;
					}										
					
				}
				
				
				//
				//review file
				//
				if(Interface.fle_volatility != null && Interface.fle_volatility.exists() && Interface.fle_volatility.isFile())
				{
					driver.directive("I am configuring interface to work with volatility binary at path --> " + Interface.fle_volatility.getCanonicalPath() + "\n");
					file_attr_volatility = new FileAttributeData(fle_volatility, true, true);
					set_jlabel_text(this.jlbl_volatility_path, "  Path to Volatility: " + this.fle_volatility.getCanonicalPath());
					populate_volatility_HELP(fle_volatility);
					
					return true;
				}
				
			}
				
			//
			//File not found, notify user
			//
			driver.directive("NOTE: I could not locate volatility in my import path. \nIn the future, you can speed up the configuration process if you place the volatility executable binary file at\n--> " + Start.fleImportMemoryAnalysisDirectory.getCanonicalPath());
			
			
			return true;
		}
		catch(Exception e)
		{
			//driver.eop(myClassName, "initialize_framework_volatility_executable", e);
		}
		
		return false;
	}
	
	public boolean close()
	{
		try
		{
			if(driver.query_user("Close " + Driver.NAME + "?", "Exit?") == JOptionPane.YES_OPTION)
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
	
	public boolean initialize_framework_import_memory_image()
	{
		try
		{
			//
			//Check if volatility is included in the import directory
			//
			LinkedList<File> list = new LinkedList<File>();
			list = driver.getFileListing(Start.fleImportMemoryImageDirectory, true, null, list);
			boolean import_image = false;
			
			if(list != null && !list.isEmpty())
			{
				//at least there are files, iterate through to select the first one that has volatility
				for(File fle : list)
				{
					if(fle == null || !fle.exists() || !fle.isFile())
						continue;
					
					//take the first file found
					Interface.fle_memory_image = fle;
					
					if(!list_image_files.contains(fle.getCanonicalPath()))
						list_image_files.add(fle.getCanonicalPath())	;
					
					break;
				}	
				
				
				//
				//review file
				//
				if(Interface.fle_memory_image != null && Interface.fle_memory_image.exists() && Interface.fle_memory_image.isFile())
				{
					driver.directive("\nI am configuring interface to work with import memory image at path --> " + Interface.fle_memory_image.getCanonicalPath() + "\n");
					file_attr_memory_image = new FileAttributeData(fle_memory_image, true, true);
					
					this.set_jlabel_text(jlbl_memory_image_path, "  Path to Memory Image: " + fle_memory_image.getCanonicalPath());				
					this.set_jlabel_text(this.jlbl_memory_image_attributes, "  Memory Image Attributes: " + file_attr_memory_image.get_attributes("   "));
					
					return true;
				}
				
			}
				
			//
			//File not found, notify user
			//
			driver.directive("\nNOTE: I could not locate a memory image in my import path. \nIn the future, you can speed up the configuration process if you place the import memory image at\n--> " + Start.fleImportMemoryImageDirectory.getCanonicalPath());
			
			
			return true;
		}
		catch(Exception e)
		{
			//driver.eop(myClassName, "initialize_framework_import_memory_image", e);
		}
		
		return false;
	}
	
	public boolean specify_profile()
	{
		try
		{
			LinkedList<String> list_profiles = new LinkedList<String>();
			
			if(this.list_volatility_info_configuration_PROFILES == null || list_volatility_info_configuration_PROFILES.isEmpty())
				list_profiles = null;
			else
			{
				for(String plugin : list_volatility_info_configuration_PROFILES)
				{
					plugin = plugin.trim();
					
					if(plugin == null || plugin.trim().equals(""))
						continue;
						
					if(plugin.toLowerCase().startsWith("volatility foundation"))
						continue;
					
					if(plugin.equalsIgnoreCase("profiles"))
						continue;
					
					if(plugin.startsWith("---"))
						continue;
					
					list_profiles.add("  " + plugin);
				}
			}
			
			String profile = null;
			
			if(list_profiles == null || list_profiles.isEmpty())
			{
				if(Interface.fle_memory_image != null && Interface.fle_memory_image.exists() && Interface.fle_memory_image.isFile())
					profile = driver.jop_Query("Please specify profile to load for this analysis:", "* Specify Profile for Image [" + Interface.fle_memory_image.getName() + "]");
				else
					profile = driver.jop_Query("Please specify profile to load for this analysis:", "* Specify Profile *");
			}
			
			else
			{
				String [] array = new String[list_profiles.size()];
				
				for(int i = 0; i < list_profiles.size(); i++)
				{
					array[i] = list_profiles.get(i);
				}
				
				if(Interface.fle_memory_image != null && Interface.fle_memory_image.exists() && Interface.fle_memory_image.isFile())
					profile = ""+ driver.jop_queryJComboBox("Please specify profile to load for this analysis:", "Specify Profile for Image [" + Interface.fle_memory_image.getName() + "]", array);
				else
					profile = ""+ driver.jop_queryJComboBox("Please specify profile to load for this analysis:", "Specify Profile", array);
			}
			
			if(profile == null || profile.trim().equals("") || profile.equalsIgnoreCase("null"))
				profile = driver.jop_Query("No profile has been entered. \nPlease specify profile to load for this analysis:", "Specify Profile");
			
			if(profile == null)
			{
				driver.jop_Error("NOTE: No valid profile has been specified. This could contaminate results of our analysis...");
				return false;
			}
			
			profile = profile.trim();
			
			String [] array = profile.split(" ");
			
			if(array == null || array.length < 1)
				array = profile.split("\t");
			
			if(array == null || array.length < 1)
				array = profile.split("-");
			
			if(array != null && array.length > 0)
				profile = array[0].trim();
									
			PROFILE = profile;
			
			this.jlblProfile.setText("  Profile: " + PROFILE);
			this.jlblProfile.setToolTipText("  Profile: " + PROFILE);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "specify_profile", e);
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
			
			else if(ae.getSource() == jmnuitm_Specify_Volatility_Executable)
			{
				this.specify_volatility_executable();
			}
			
			else if(ae.getSource() == jmnuitm_About)
			{
				show_about_dialog();
			}
			
			else if(ae.getSource() == this.jmnuitm_Specify_Memory_Image_For_Analysis)
			{
				this.specify_memory_image(this.fle_volatility);
			}
			
			else if(ae.getSource() == jbtnSearchImage)
			{
				add_search_image();
			}
			
			else if(ae.getSource() == jbtnAnalyse)
			{
				update_interface();
				
				Plugin.analyze_image();
				
				//
		        //request focus
		        //
		        //try	{	Interface.jtabbedPane_CONSOLE.setSelectedComponent(Interface.jtabbedPane_ANALYSIS);} catch(Exception e){}
			}
			
			else if(ae.getSource() == jbtnSelectFavorites)
			{
				Plugin.selectFavorites();
			}
			
			else if(ae.getSource() == jbtnDeselectAllPlugins)
			{
				deselect_all_plugins();
			}
			
			else if(ae.getSource() == jbtnHailMary)
			{
				selectHailMary();
			}
			
			else if(ae.getSource() == jbtnPreview)
			{
				Plugin.preview();
				
				//
		        //request focus
		        //
		        //try	{	Interface.jtabbedPane_CONSOLE.setSelectedComponent(Interface.jtabbedPane_ANALYSIS);} catch(Exception e){}
			}
			
			else if(ae.getSource() == this.jmnuitm_Specify_Profile)
			{
				this.specify_profile();
			}
			
			else if(ae.getSource() == jmnuitm_Specify_Investigator_Name)
			{
				this.specify_investigator_name();
			}
			
			else if(ae.getSource() == jmnuitm_Specify_Investigation_Details)
			{
				this.specify_investigation_description();
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
	
	public static boolean deselect_all_plugins()
	{
		try
		{
			if(Plugin.tree_plugins == null || Plugin.tree_plugins.isEmpty())
			{
				driver.jop_Error("Punt! No plugins have been loaded yet!", false);
				return false;
			}
			
			if(driver.jop_Confirm("Confirm you wish to deselect all applicable plugins?", "Deselect All Plugins") == JOptionPane.YES_OPTION)
			{
				for(Plugin plugin : Plugin.tree_plugins.values())
				{
					try//some plugins are not actually populated which would throw a nullpointerexception e.g. ifyou are on a windows machine and loaded hail mary. then the linux modules would not be loaded full yet, however this function would try to clear a textfield that has yet to be instantiated
					{
						if(plugin == null)
							continue;
						
						plugin.jcb.setSelected(false);
						
						//need to disable previous text that might have been set from the Hail Mary
						plugin.jtaConsole.jtf.setText("");							
					}
					catch(Exception e)
					{
						continue;
					}
					
				}
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "deselect_all_plugins", e, true);
		}
		
		return false;
	}
	
	public boolean selectHailMary()
	{
		try
		{
			if(Plugin.tree_plugins == null || Plugin.tree_plugins.isEmpty())
			{
				driver.jop_Error("No plugins have been loaded yet!", false);
				return false;
			}
			
			if(driver.jop_Confirm("You have selected Hail Mary!\nConfirm you wish to execute all applicable plugins for this analysis?", "Hail Mary! --> Confirm Select All Plugins...") == JOptionPane.YES_OPTION)
			{
				//
				//select plugins
				//
				for(Plugin plugin : Plugin.tree_plugins.values())
				{
					//DISMISS CERTAIN PLUGINS
					if(driver.isWindows)
					{
						if(plugin.plugin_name.toLowerCase().trim().startsWith("linux_"))
							continue;
						if(plugin.plugin_name.toLowerCase().trim().startsWith("mac_"))
							continue;
					}
					else if(driver.isLinux && !plugin.plugin_name.toLowerCase().trim().startsWith("linux_"))
					{
						continue;
					}
					else if(driver.isMac && !plugin.plugin_name.toLowerCase().trim().startsWith("mac_"))
					{
						continue;
					}
					
					if(plugin != null)
						plugin.jcb.setSelected(true);						
				}
				
				//
				//EXECUTE!
				//
				update_interface();				
				//Plugin.analyze_image();
				
				driver.jop_Message("All applicable plugins have been selected.\nPlease review as necessary and click on Analyze to begin execution", "Reveiw before continuing...");
			}
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "selectHailMary", e);			
		}
		
		return false;
	}
	
	public boolean update_interface()
	{
		try
		{
			if(this.file_attr_memory_image != null && hash_volatility_md5 == null && hash_volatility_sha256 == null && this.file_attr_volatility.hash_md5 != null && this.file_attr_volatility.hash_sha256 != null)
			{
				hash_volatility_md5 = file_attr_volatility.hash_md5;
				hash_volatility_sha256 = file_attr_volatility.hash_sha256;
				
				set_jlabel_text(this.jlbl_volatility_path, "  Path to Volatility: " + this.fle_volatility.getCanonicalPath() + "         MD5: " + hash_volatility_md5 + "   SHA-256: " + hash_volatility_sha256 + "  " + "Last Modified: " + this.file_attr_memory_image.last_modified);
			}
			
			
			if(this.file_attr_memory_image != null && this.hash_memory_image_md5 == null && hash_memory_image_sha256 == null && this.file_attr_memory_image.hash_md5 != null && this.file_attr_memory_image.hash_sha256 != null)
			{
				hash_memory_image_md5 = file_attr_memory_image.hash_md5;
				hash_memory_image_sha256 = file_attr_memory_image.hash_sha256;
				
				this.set_jlabel_text(this.jlbl_memory_image_attributes, "  Memory Image Attributes: " + file_attr_memory_image.get_attributes("   "));
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "update_interface", e);
		}
		
		return false;
	}
	
	public File specify_volatility_executable()
	{
		try
		{
			File fle = driver.querySelectFile(true, "Please select Volatility Executable", JFileChooser.FILES_ONLY, false, false);
			
			if(fle == null || !fle.exists() || !fle.isFile())
			{
				driver.jop_Error("Invalid file specified. \nYou must specify Volatility Executable before proceeding further...", false);
				return null;
			}			
			
			if(fle != null && fle.exists() && fle.isFile())
			{
				fle_volatility = fle;
				set_jlabel_text(this.jlbl_volatility_path, "  Path to Volatility: " + this.fle_volatility.getCanonicalPath());
				
				file_attr_volatility = new FileAttributeData(fle_volatility, true, true);
				//file_attr_volatility.get_hash(true);
			}
			
			populate_volatility_HELP(fle);
			
			return fle;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "specify_volatility_executable", e);
		}
		
		return null;
	}
	
	public boolean populate_volatility_HELP(File fle)
	{
		try
		{
			jpnlConsole.append("Please standby. I will attempt to populate Volatility's help configuration information now...");
			
			ProcessBuilder process_builder = null;
			
			if(driver.isWindows)
				process_builder = new ProcessBuilder("cmd.exe", "/C", fle.getCanonicalPath(), "-h");
			
			else if(driver.isLinux)
				process_builder = new ProcessBuilder("/bin/bash", "-c", fle.getCanonicalPath(), "-h");
			
			//
			//redirect error stream
			//
			process_builder.redirectErrorStream(true); 
						
			//
			//setup
			//
			//instantiate new process
			Process process = process_builder.start();
			
			//this.fleLog_Whois = new File(this.pathTopFolder_whois + DOMAIN_NAME + "_" + driver.get_time_stamp("_") + ".txt");
			File fleHelp = new File(Driver.NAME_LOWERCASE + File.separator + "log" + File.separator + "help.txt");
			
			try	{	if(!fleHelp.getParentFile().exists() || !fleHelp.getParentFile().isDirectory())
				fleHelp.getParentFile().mkdirs();	
			}	 catch(Exception e){}
			
			PrintWriter pw = new PrintWriter(new FileWriter(fleHelp), true);
			
			BufferedReader brIn = new BufferedReader(new InputStreamReader(process.getInputStream()));
							
			try	{list_volatility_help_configuration_OPTIONS.clear();} catch(Exception e){list_volatility_help_configuration_OPTIONS = new LinkedList<String>();}
			try	{list_volatility_help_configuration_SUPPORTED_PLUGINS.clear();} catch(Exception e){list_volatility_help_configuration_SUPPORTED_PLUGINS = new LinkedList<String>();}
			
			supported_plugins_found = false;
			
			LineIterator line_iterator = new LineIterator(brIn);
			String line = "";
		    try 
		    {
		        while (line_iterator.hasNext()) 
		        {		        	
		        	line = line_iterator.nextLine();
		        	
		        	if(line == null)
		        		continue;

		        	
		        	if(line.toLowerCase().contains("supported plugin"))
		        		supported_plugins_found = true;
		        	
		        	if(supported_plugins_found)
		        		this.list_volatility_help_configuration_SUPPORTED_PLUGINS.add(line);
		        	
		        	else
		        		list_volatility_help_configuration_OPTIONS.add(line);

		        	//log
		        	pw.println(line);
		        }
		        
		        //
		        //update GUI
		        //
		        if(!supported_plugins_found)
		        {
		        	driver.jop_Error("Error! It doesn't look a valid Volatility executable was selected...", false);
		        	return false;
		        }
		        
		        if(this.jpnlVolatilityOptions == null)
		        {
		        	jpnlVolatilityOptions = new JTextArea_Solomon("", true, "Volatility Options", false);
		        	try	{	jpnlVolatilityOptions.jcbAutoScroll.setSelected(false);	}	catch(Exception e){}
		        	jtabbedPane_CONFIGURATION.addTab("Volatility Options", jpnlVolatilityOptions);
		        	
		        	populate_export_btn(jpnlVolatilityOptions);
		        }
		        
		        if(this.jpnlVolatilitySupportedPlugins == null)
		        {
		        	jpnlVolatilitySupportedPlugins = new JTextArea_Solomon("", false, "Volatility Supported Plugin Commands", false);		
		        	try	{	jpnlVolatilitySupportedPlugins.jcbAutoScroll.setSelected(false);	}	catch(Exception e){}
		        	jtabbedPane_CONFIGURATION.addTab("Volatility Supported Plugins", jpnlVolatilitySupportedPlugins);
		        	
		        	populate_export_btn(jpnlVolatilitySupportedPlugins);
		        }
		        
		        jpnlVolatilityOptions.clear();
		        jpnlVolatilitySupportedPlugins.clear();
		        
		        for(String s : list_volatility_help_configuration_OPTIONS)
		        {
		        	jpnlVolatilityOptions.append(s);
		        }
		        
		        for(String s : list_volatility_help_configuration_SUPPORTED_PLUGINS)
		        {
		        	jpnlVolatilitySupportedPlugins.append(s);
		        }
		        
		        populate_volatility_info(fle);
		        
		        //
		        //request focus
		        //
		       //try	{	jtabbedPane_CONSOLE.setSelectedComponent(jtabbedPane_CONFIGURATION);} catch(Exception e){}
		        
		        
		    }
		    catch(Exception e)
		    {
		    	driver.sop("check " + myClassName);
		    }
		        
		      
		   //clean up
		    try	{ 	brIn.close();       		}	catch(Exception e){}
		    try	{	process.destroy();			}	catch(Exception e){}
		    try	{ 	line_iterator.close();      }	catch(Exception e){}
		    
		    try	{	pw.flush();} catch(Exception e){}
			try	{	pw.close();} catch(Exception e){}
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "populate_volatility_plugins", e);
		}
		
		return false;
	}
	
	public boolean populate_export_btn(JTextArea_Solomon jpnl)
	{
		try
		{
			jpnl.jpnlSouth.add(BorderLayout.CENTER, jpnl.jbtnExportData);
        	try	{	jpnl.jpnlSouth.setBorder(new TitledBorder("Options"));	}	catch(Exception e){}					
        	jpnl.add(BorderLayout.SOUTH, jpnl.jpnlSouth);
        	jpnl.validate();
        	jpnl.repaint();
			
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "populate_export_btn", e);
		}
		
		return false;
	}
	
	public static boolean add_search_image()
	{
		try
		{
			String image_path = ""; 
			String image_name = "";
			File fle = null;
			if(list_image_files == null || list_image_files.isEmpty())
			{
				fle = driver.querySelectFile(true, "Select Image to Search...", JFileChooser.FILES_ONLY, null);
				
				if(fle == null || !fle.exists() || !fle.isFile())
				{
					//driver.directive("Action canceled... no valid file was selected.");
					return false;
				}
				
				image_path = fle.getCanonicalPath();
				
				if(!list_image_files.contains(fle.getCanonicalPath()))
					list_image_files.add(fle.getCanonicalPath());
				
				image_name = fle.getName();
			}
			else
			{
				String []arrElements = new String[list_image_files.size() +1];
				
				int i = 0;
				for(String path : list_image_files)
				{
					if(path == null || path.trim().equals(""))
						continue;
					
					arrElements[i++] = path;
				}
				
				arrElements[i] = select_image_from_location_text;
				
				String selection = ""+driver.jop_queryJComboBox("Please select image to analyze:", "Specify Image", arrElements);
				
				if(selection == null || selection.trim().equalsIgnoreCase("null"))
				{
					//driver.directive("Action canceled. No valid file selected...");
					return false;
				}
				
				if(selection.equalsIgnoreCase(select_image_from_location_text))
				{
					fle = driver.querySelectFile(true, "Select Image to Search...", JFileChooser.FILES_ONLY, null);
				}
				else				
					fle = new File(selection.trim());
				
				if(fle == null || !fle.exists() || !fle.isFile())
				{
					//driver.directive("* Action canceled... no valid file was selected.");
					return false;
				}
				
				image_path = fle.getCanonicalPath();
				
				if(!list_image_files.contains(fle.getCanonicalPath()))
					list_image_files.add(fle.getCanonicalPath());
				
				image_name = fle.getName();
				
			}
			
			SearchImage search = new SearchImage(fle, image_path, image_name);
			
			jtabbedPane_MAIN.addTab("Image Search - " + image_name, search);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "add_search_image", e);
		}
		
		return false;
	}
	
	public File specify_memory_image(File fle_volatility)
	{
		try
		{
			File fle = driver.querySelectFile(true, "Please select Memory Image to Analyze...", JFileChooser.FILES_ONLY, fle_volatility);
			
			if(fle == null || !fle.exists() || !fle.isFile())
			{
				driver.jop_Error("Invalid file specified. \nYou must specify a memory image for analysis before proceeding further...", false);
				return null;
			}			
			
			if(fle != null && fle.exists() && fle.isFile())
			{
				fle_memory_image = fle;
				file_attr_memory_image = new FileAttributeData(fle_memory_image, true, true);
				
				if(!list_image_files.contains(fle.getCanonicalPath()))
					list_image_files.add(fle.getCanonicalPath())	;
				
				//file_attr_memory_image.get_hash(true);
				
				this.set_jlabel_text(jlbl_memory_image_path, "  Path to Memory Image: " + fle.getCanonicalPath());				
				this.set_jlabel_text(this.jlbl_memory_image_attributes, "  Memory Image Attributes: " + file_attr_memory_image.get_attributes("   "));
										
			}
			
			return fle;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "specify_memory_image", e);
		}
		
		return null;
	}
	
	
	public boolean populate_volatility_info(File fle)
	{
		try
		{
			jpnlConsole.append("Please standby. I will attempt to populate Volatility's info configuration settings now...");
			
			ProcessBuilder process_builder = null;
			
			if(driver.isWindows)
				process_builder = new ProcessBuilder("cmd.exe", "/C", fle.getCanonicalPath(), "--info");
			
			else if(driver.isLinux)
				process_builder = new ProcessBuilder("/bin/bash", "-c", fle.getCanonicalPath(), "--info");
			
			//
			//redirect error stream
			//
			process_builder.redirectErrorStream(true); 
						
			//
			//setup
			//
			//instantiate new process
			Process process = process_builder.start();
			
			//this.fleLog_Whois = new File(this.pathTopFolder_whois + DOMAIN_NAME + "_" + driver.get_time_stamp("_") + ".txt");
			File fleHelp = new File(Driver.NAME_LOWERCASE + File.separator + "log" + File.separator + "info.txt");
			
			try	{	if(!fleHelp.getParentFile().exists() || !fleHelp.getParentFile().isDirectory())
				fleHelp.getParentFile().mkdirs();	
			}	 catch(Exception e){}
			
			PrintWriter pw = new PrintWriter(new FileWriter(fleHelp), true);
			
			BufferedReader brIn = new BufferedReader(new InputStreamReader(process.getInputStream()));
					
			
			try	{this.list_volatility_info_configuration_PROFILES.clear();} catch(Exception e){list_volatility_info_configuration_PROFILES = new LinkedList<String>();}
			try	{list_volatility_info_configuration_ADDRESS_SPACES.clear();} catch(Exception e){list_volatility_info_configuration_ADDRESS_SPACES = new LinkedList<String>();}
			try	{list_volatility_info_configuration_PLUGINS.clear();} catch(Exception e){list_volatility_info_configuration_PLUGINS = new LinkedList<String>();}
			try	{list_volatility_info_configuration_SCANNER_CHECKS.clear();} catch(Exception e){list_volatility_info_configuration_SCANNER_CHECKS = new LinkedList<String>();}

			
			supported_plugins_found = false;
			
			LineIterator line_iterator = new LineIterator(brIn);
			String line = "";
		    try 
		    {
		        while (line_iterator.hasNext()) 
		        {
		        	line = line_iterator.nextLine();
		        	
		        	//log
		        	pw.println(line);
		        	
		        	//skip
		        	if(line == null || line.trim().equals(""))
		        		continue;
		        	
		        	//process
		        	line = line.trim();
		        			        	
		        	if(line.equalsIgnoreCase("profiles"))
		        	{
		        		profiles_found = true;
		        		address_spaces_found = false;
		        		plugins_found = false;
		        		scanner_checks_found = false;			        		
		        	}
		        	
		        	else if(line.equalsIgnoreCase("address spaces"))
		        	{
		        		profiles_found = false;
		        		address_spaces_found = true;
		        		plugins_found = false;
		        		scanner_checks_found = false;				        		
		        	}
		        	
		        	else if(line.equalsIgnoreCase("plugins"))
		        	{
		        		profiles_found = false;
		        		address_spaces_found = false;
		        		plugins_found = true;
		        		scanner_checks_found = false;				        		
		        	}
		        	
		        	else if(line.equalsIgnoreCase("scanner checks"))
		        	{
		        		profiles_found = false;
		        		address_spaces_found = false;
		        		plugins_found = false;
		        		scanner_checks_found = true;				        		
		        	}
		        	
		        	
		        	if(profiles_found)
		        		this.list_volatility_info_configuration_PROFILES.add(line);
		        	else if(address_spaces_found)
		        		this.list_volatility_info_configuration_ADDRESS_SPACES.add(line);
		        	else if(plugins_found)
		        		this.list_volatility_info_configuration_PLUGINS.add(line);
		        	else if(scanner_checks_found)
		        		this.list_volatility_info_configuration_SCANNER_CHECKS.add(line);
		        	
		        	
		        }
		        
		        //
		        //update GUI
		        //
		        if(list_volatility_info_configuration_PROFILES == null || list_volatility_info_configuration_PROFILES.isEmpty())
		        {
		        	driver.jop_Error("Error!!! It doesn't look a valid Volatility executable was selected...", false);
		        	return false;
		        }
		        
		        
		    	
		    	
		    	
		        
		        if(this.jpnlVolatilityInfo_Profiles == null)
		        {
		        	jpnlVolatilityInfo_Profiles = new JTextArea_Solomon("", false, "Volatility Profiles", false);		
		        	try	{	jpnlVolatilityInfo_Profiles.jcbAutoScroll.setSelected(false);	}	catch(Exception e){}
		        	jtabbedPane_CONFIGURATION.addTab("Volatility Profiles", jpnlVolatilityInfo_Profiles);
		        	
		        	populate_export_btn(jpnlVolatilityInfo_Profiles);
		        }
		    	
		    	if(this.jpnlVolatilityInfo_Address_Spaces == null)
		    	{
		    		jpnlVolatilityInfo_Address_Spaces = new JTextArea_Solomon("", false, "Volatility Address Spaces", false);
		    		try	{	jpnlVolatilityInfo_Address_Spaces.jcbAutoScroll.setSelected(false);	}	catch(Exception e){}		
		    		jtabbedPane_CONFIGURATION.addTab("Volatility Address Spaces", jpnlVolatilityInfo_Address_Spaces);
		    		
		    		populate_export_btn(jpnlVolatilityInfo_Address_Spaces);
		    	}
		    	
		    	if(this.jpnlVolatilityInfo_Plugins == null)
		    	{
		    		jpnlVolatilityInfo_Plugins = new JTextArea_Solomon("", false, "Volatility Plugins", false);
		    		try	{	jpnlVolatilityInfo_Plugins.jcbAutoScroll.setSelected(false);	}	catch(Exception e){}
		    		jtabbedPane_CONFIGURATION.addTab("Volatility Plugins", jpnlVolatilityInfo_Plugins);
		    		
		    		populate_export_btn(jpnlVolatilityInfo_Plugins);
		    	}
		    	
		    	if(this.jpnlVolatilityInfo_Scanner_Checks == null)
		    	{
		    		jpnlVolatilityInfo_Scanner_Checks = new JTextArea_Solomon("", false, "Volatility Scanner Checks", false);
		    		try	{	jpnlVolatilityInfo_Scanner_Checks.jcbAutoScroll.setSelected(false);	}	catch(Exception e){}
		    		jtabbedPane_CONFIGURATION.addTab("Volatility Scanner Checks", jpnlVolatilityInfo_Scanner_Checks);
		    		
		    		populate_export_btn(jpnlVolatilityInfo_Scanner_Checks);
		    	}
		        

		        
		    	jpnlVolatilityInfo_Profiles.clear();
		    	jpnlVolatilityInfo_Address_Spaces.clear();
		    	jpnlVolatilityInfo_Plugins.clear();
		    	jpnlVolatilityInfo_Scanner_Checks.clear();
		        
		    	for(String s : this.list_volatility_info_configuration_PROFILES)
		        {
		    		jpnlVolatilityInfo_Profiles.append(s);
		        }
		    	
		    	for(String s : this.list_volatility_info_configuration_ADDRESS_SPACES)
		        {
		    		jpnlVolatilityInfo_Address_Spaces.append(s);
		        }
		    	
		    	for(String s : this.list_volatility_info_configuration_PLUGINS)
		        {
		        	jpnlVolatilityInfo_Plugins.append(s);
		        }
		    	
		    	for(String s : this.list_volatility_info_configuration_SCANNER_CHECKS)
		        {
		    		jpnlVolatilityInfo_Scanner_Checks.append(s);
		        }
		        
		       
		        //populate plugins
		    	populate_volatility_plugins(list_volatility_info_configuration_PLUGINS);
		        
		        
		        
		    }
		    catch(Exception e)
		    {
		    	driver.sop("check " + myClassName);
		    }
		        
		      
		   //clean up
		    try	{ 	brIn.close();       		}	catch(Exception e){}
		    try	{	process.destroy();			}	catch(Exception e){}
		    try	{ 	line_iterator.close();      }	catch(Exception e){}
		    
		    try	{	pw.flush();} catch(Exception e){}
			try	{	pw.close();} catch(Exception e){}
			
			
//			driver.directive("\nComplete.");
//	        driver.directive("\tPlease refer to the Volatility Configuration tab to view various options and plugins supported by this sample.");
//	        driver.directive("\tWhen you are ready, please enable one or more plugins from the top Plugins tab. ");
//	        driver.directive("\tPress Preview after making you selection(s) to load your selected plugins as well as view applicable parameters in the Memory Analysis tab.");
//	        driver.directive("\tFinally, press Analyze to run the analysis process for all selected plugins. Alternatively, you can select Execute from each plugin tab to run the analysis commands individually.");
//	        driver.directive("\tHappy Hunting! - Solomon Sonya @Carpenter1010");
//			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "populate_volatility_info", e);
		}
		
		return false;
	}
	
	
	public boolean populate_volatility_plugins(LinkedList<String> list_plugins)
	{
		try
		{
			if(list_plugins == null || list_plugins.isEmpty())
			{
				driver.jop_Error("Error! List of Plugins appears to be empty!\nDid you select the correct Volatility executable binary file?");
				return false;
			}
			
			try	{	 Plugin.tree_plugins.clear();	}	catch(Exception e){Plugin.tree_plugins = new TreeMap<String, Plugin>(); }
			
			//init jpanel			
			
			try	{	this.jpnlPlugins.removeAll();}	catch(Exception e){}
			
			jpnlPlugins.setLayout(new GridLayout((int)Math.ceil(list_plugins.size()/num_plugin_cols), num_plugin_cols, 5, 5));
			
			//init plugins
			for(String tuple : list_plugins)
			{
				if(tuple == null || tuple.trim().equals(""))
					continue;
				
				tuple = tuple.trim();
						
				if(tuple.equalsIgnoreCase("plugins"))
					continue;
				
				if(tuple.startsWith("---"))
					continue;
				
				int line_count = 0;
				if(tuple.contains("-"))
				{
					try
					{
						line_count++;
						
						String [] array = tuple.split("-");
						
						if(array == null || array.length < 2)
							continue;
						
						Plugin plugin = new Plugin(array[0], array[1], this.jpnlPlugins, this.jtabbedPane_ANALYSIS_DATE_TIME);
					}
					catch(Exception e)
					{
						driver.directive("Check Plugin around index [" + line_count + "]");
						continue;
					}
					
				}
				
				/*Plugins
				-------
				amcache                    - Print AmCache information
				apihooks                   - Detect API hooks in process and kernel memory
				atoms                      - Print session and window station atom tables
				atomscan                   - Pool scanner for atom tables
				auditpol                   - Prints out the Audit Policies from HKLM\SECURITY\Policy\PolAdtEv
				bigpools                   - Dump the big page pools using BigPagePoolScanner
				bioskbd                    - Reads the keyboard buffer from Real Mode memory*/
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "populate_volatility_plugins", e);
		}
		
		return false;
	}
	
	
	public boolean set_jlabel_text(JLabel jlbl, String text)
	{
		try
		{
			if(jlbl == null)
				return false;
			
			jlbl.setText(text);
			jlbl.setToolTipText(text);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "set_jlabel_text", e);
		}
		
		return false;
	}
	
	
	
	
	
	
	public boolean specify_investigation_details()
	{
		try
		{
			this.investigator_name = driver.jop_Query("Please specify investigator name:", "Enter investigator Name");
			this.investigation_description = driver.jop_Query("Please specify investigation description:\ne.g. Description or address of image machine ==> Captured using Magnet RAM Capture v1:", "Enter investigation description");
			
			if(investigator_name != null && investigator_name.trim().length() > 0)
			{
				if(investigation_description != null && investigation_description.trim().length() > 0)
				{
					investigator_name = investigator_name.trim();
					investigation_description = investigation_description.trim();
					
					this.set_jlabel_text(this.jlblInvestigationDetails, "  Investigator: " + investigator_name + "  Investigation Description: " + investigation_description);
				}
				
				else
				{
					investigator_name = investigator_name.trim();

					this.set_jlabel_text(this.jlblInvestigationDetails, "  Investigator: " + investigator_name);
				}
			}
			
			else if(investigation_description != null && investigation_description.trim().length() > 0)
			{
				investigation_description = investigation_description.trim();
				
				this.set_jlabel_text(this.jlblInvestigationDetails, "  Investigation Details: " + investigation_description);
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "specify_investigation_details", e);
		}
		
		return false;
	}
	
	
	public boolean specify_investigator_name()
	{
		try
		{
			String entry = driver.jop_Query("Please specify investigator name:", "Enter investigator Name");
			
			if(entry == null || entry.trim().length() < 1)
				return false;
			
			investigator_name = entry.trim();
			
			if(investigator_name != null && investigator_name.trim().length() > 0)
			{
				if(investigation_description != null && investigation_description.trim().length() > 0)
					this.set_jlabel_text(this.jlblInvestigationDetails, "  Investigator: " + investigator_name + "  Investigation Details: " + investigation_description);
				
				else
					this.set_jlabel_text(this.jlblInvestigationDetails, "  Investigator: " + investigator_name);
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "specify_investigator_name", e);
		}
		
		return false;
	}
	
	public boolean specify_investigation_description()
	{
		try
		{
			String entry = driver.jop_Query("Please specify investigation description:\ne.g. Description or address of image machine ==> Captured using Magnet RAM Capture v1:", "Enter investigation description");
			
			if(entry == null || entry.trim().length() < 1)
				return false;
			
			investigation_description = entry.trim();
			
			if(investigation_description != null && investigation_description.trim().length() > 0)
			{
				if(investigator_name != null && investigator_name.trim().length() > 0)
					this.set_jlabel_text(this.jlblInvestigationDetails, "  Investigator: " + investigator_name + "  Investigation Description: " + investigation_description);
				
				else
					this.set_jlabel_text(this.jlblInvestigationDetails, "  Investigation Description: " + investigation_description);
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "specify_investigation_description", e);
		}
		
		return false;
	}
	
	
	
	public static boolean show_about_dialog()
	{
		try
		{
			String underline = "\n=====================================================\n"; 
			JTextArea jta = new JTextArea();
			 jta.setEditable(false);
			 
			 jta.append("\n");
			 jta.append(Driver.FULL_NAME + " is a user interface wrapper built on top of the Volatility(c) memory forensics framework.");
			 
			 jta.append("\n\nGetting Started" + underline);
			 jta.append("The latest version of Volatility can be downloaded from https://www.volatilityfoundation.org/releases");
			 
			 jta.append("\n\nMemory Acquisition" + underline);
			 jta.append("There are multiple programs useful for acquiring a memory image for analysis."); 
			 jta.append("\nThe following tools were very effective to acquire a memory image:");
			 jta.append("\n\tDumpIt - https://www.aldeid.com/wiki/Dumpit");
			 jta.append("\n\tMandiant's Memoryze - https://www.fireeye.com/services/freeware/memoryze.html");
			 jta.append("\n\tWInpmem - https://github.com/google/rekall/releases?after=v1.4.1");
			 jta.append("\n\tBelkasoft's RAM Capture - https://belkasoft.com/ram-capturer");
			 jta.append("\n\tMagnet RAM Capture - https://www.magnetforensics.com/free-tool-magnet-ram-capture/");
			 jta.append("\n\tMandiant's Redline - https://www.fireeye.com/services/freeware/redline.html");
			 jta.append("\n\tFTK Imager - https://accessdata.com/product-download/ftk-imager-version-4.2.0");


			 jta.append("\n\nMemory Analysis" + underline);
			 jta.append("Once you have a memory image, you can perform analysis using Xavier (that scripts commands to Volatility)\nand helps to provide additional analysis for the investigator.");
			 jta.append(" From Xavier, executing each plugin creates \na separate tab to view the analysis results. An output file is also created to reference output at a later date.");
			
			 jta.append("\n\nAdditional Memory Analysis Tools Include:" + underline);
			 jta.append("Volatility");
			 jta.append(", Mandiant's Redline");
			 jta.append(", Rekall");
			 jta.append(", Autopsy");
			 jta.append(", FTK Imager");
			 jta.append(", OSForensics");
			 
			 jta.append("\n\nQuestions/Updates?"+underline);
			 jta.append("If you have any questions or update suggestions, please feel free to contact me.\n-Solomon Sonya @Carpenter1010");
			 jta.append("\n");
			 
			 driver.jop_TextArea("About", jta);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "show_about_dialog", e);
		}
		
		return false;
		
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
