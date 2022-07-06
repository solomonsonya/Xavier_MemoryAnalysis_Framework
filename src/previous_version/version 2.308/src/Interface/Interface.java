/**
 * @author Solomon Sonya
 * 
 * Known issues: Using volatility creates files similar to _MEI85162 at %temp%.  The prolonged running of volatility can eventually lead to significant space utilization on the hard drive.
 * User must be aware of this temp file creation
 * 
 * dependenc: readpe: download from https://sourceforge.net/projects/pev/
 * 
 * @author Solomon Sonya
 */

//LiME - Linux Memory dump
//winpmem_1.4 imagedump.raw 
//winpmem_v3.3.rc3.exe -e */PhysicalMemory -D mem.dump mem.dump <mem.raw path>

package Interface;

import java.io.*;
import java.awt.*;
import java.awt.event.*;
import java.net.*;
import java.security.*;
import java.util.*;
import org.apache.commons.io.LineIterator;

import Advanced_Analysis.Advanced_Analysis_Director;
import Advanced_Analysis.Node_Generic;
import Advanced_Analysis.Snapshot_Manifest_Analysis;
import Advanced_Analysis.Analysis_Plugin.Analysis_Plugin_DumpFiles;
import Advanced_Analysis.Analysis_Plugin.Analysis_Plugin_EXECUTION;
import Advanced_Analysis.Analysis_Plugin.Analysis_Plugin_memdump;
import Advanced_Analysis.Analysis_Report.*;
import javax.imageio.ImageIO;
import javax.swing.*;
import javax.swing.border.BevelBorder;
import javax.swing.border.TitledBorder;
import Driver.*;
import java.util.*;
import Plugin.*;
//import Sound.ThreadSound;
import SearchImage.SearchImage;
import Snapshot.Snapshot_Driver;


public class Interface extends Thread implements Runnable, ActionListener, KeyListener
{
	public static volatile boolean AUTO_START_ADVANCED_ANALYSIS = false;
	
	public static volatile boolean IMPORT_SYSTEM_MANIFEST_RUN_AT_LEAST_ONCE = false;
	
	public volatile Advanced_Analysis_Director advanced_analysis_director_snapshot_1 = null;
	public volatile Advanced_Analysis_Director advanced_analysis_director_snapshot_2 = null;
	
	public volatile Advanced_Analysis_Director advanced_analysis_director_MEMORY_IMAGES = null;
	
	public volatile boolean launching_auto_advanced_analysis = false;
	
	
	public volatile FileAttributeData file_attr_manifest_snapshot_1 = null;
	public volatile FileAttributeData file_attr_manifest_snapshot_2 = null;
	public volatile File fleSnapshotManifest_1 = null;
	public volatile File fleSnapshotManifest_2 = null;
	public volatile Snapshot_Manifest_Analysis snapshot_manifest_analysis = null;
	
	public volatile File_XREF file_xref = null;
	
	public static final String myClassName = "Interface";
	public static volatile Driver driver = new Driver();
	
	public static volatile File fle_yara_signature_file = null;
	
	public static volatile LinkedList<String> list_profiles = null;
	
	public static volatile TreeMap<String, String> tree_PLUGIN_AND_DESCRIPTION = new TreeMap<String, String>();
	
	public static volatile Advanced_Analysis_Director advanced_analysis_director = null;
	public static volatile Advanced_Analysis_Director advanced_analysis_AUTO_RUN_INSTANTIATION = null;
	public static volatile Advanced_Analysis_Director advanced_analysis_director_SECOND_SNAPSHOT = null;

	/**Hold over in case XREF was needed, advanced analysis is started, and then when complete, return to complete XREF*/
	public static volatile boolean AUTOMATE_XREF_SEARCH = false;
	public static volatile String XREF_SEARCH_STRING = null;
	public static volatile boolean configure_processlist_for_xref = false;
	public static volatile boolean execute_xref_search_plugins_if_import_files_are_missing = false;
	
	public static volatile JFrame jfrm = null;
	public static volatile JMenuBar menu_bar = null;
	public static volatile JMenu jmnuFile = null;
	public static volatile JMenu jmnuOptions = null;
	public static volatile JMenu jmnuHelp = null;
		public static volatile JMenuItem jmnuitm_Close = null;
		public static volatile JMenu jmnuEncryption = null;
			public static volatile ButtonGroup bgEncryption = null;
			public static volatile JRadioButtonMenuItem jrbEncryptionEnabled = null;
			public static volatile JRadioButtonMenuItem jrbEncryptionDisabled = null;
			public static volatile JMenuItem jmnuitm_Import = null;
			
			public static volatile JMenuItem jmnuitm_About = null;
			public static volatile JMenuItem jmnuitm_Import_Directory = null;
			public static volatile JMenuItem jmnuitm_Initiate_Advanced_Analysis_SingleFile = null;
			public static volatile JMenuItem jmnuitm_Initiate_Advanced_Analysis_Entire_Directory = null;
			
			public static volatile JMenuItem jmnuitm_Specify_Volatility_Executable = null;
			public static volatile JMenuItem jmnuitm_Specify_Memory_Image_For_Analysis = null;
			public static volatile JMenuItem jmnuitm_Specify_Profile = null;
			public static volatile JMenuItem jmnuitm_Specify_Investigator_Name = null;
			public static volatile JMenuItem jmnuitm_Specify_Investigation_Details = null;
			public static volatile JMenuItem jmnuitm_Specify_Investigation_Output_Directory = null;
			public static volatile JMenuItem jmnuitm_Enable_Search_TF_XREF = null;
			
			public static volatile JMenuItem jmnuitm_SpecifyTimeZone = null;
			
	public static volatile JMenu jmnuDataXREF = null;
		public static volatile JMenuItem jmnuitm_DataXREF_Specify_YARA_Signature_File = null;
			
	public static volatile JMenu jmnuAdvancedAnalysis = null;
	public static volatile JMenu jmnuInitiateAdvancedAnalysis = null;
	public static volatile JMenu jmnuAnalysisReport = null;
	public static volatile JMenu jmnuSystemManifest = null;
	
	public static volatile JMenu jmnuSnapshotAnalysis = null;
		public static volatile JMenuItem jmnuitm_InitiateSnapshotAnalysis = null;
	
	public static volatile JMenu jmnuImport = null;
	public static volatile JMenu jmnuSpecify = null;
		public static volatile JMenuItem jmnuitm_ExportSystemManifest = null;
		public static volatile JMenuItem jmnuitm_ImportSystemManifest = null;
		public static volatile JMenuItem jmnuitm_ImportSystemManifest_from_file_menu = null;
		public static volatile JMenuItem jmnuitm_AnalyseUserAssist = null;
	public static volatile JMenu jmnuAnalysisReportProcessTree = null;
	public static volatile JMenu jmnuAnalysisReportProcessInformationTree = null;
		public static volatile JMenuItem jmnuitm_Set_Node_Length_PROCESS_TREE = null;
		public static volatile JMenuItem jmnuitm_Set_Div_Height_PROCESS_TREE = null;
		public static volatile JMenuItem jmnuitm_Set_Div_Width_PROCESS_TREE  = null;
		
		public static volatile JMenuItem jmnuitm_Set_Node_Length_PROCESS_INFORMATION_TREE = null;
		public static volatile JMenuItem jmnuitm_Set_Div_Height_PROCESS_INFORMATION_TREE = null;
		public static volatile JMenuItem jmnuitm_Set_Div_Width_PROCESS_INFORMATION_TREE  = null;
		
		public static volatile JMenu jmnuAnalysisReport_Execution_Plugin = null;
			public static volatile JMenuItem jmnuitm_Only_Show_Button_If_Execution_Plugins_Detected  = null;
			public static volatile JMenuItem jmnuitm_Always_Show_Button_Even_If_Execution_Plugins_Not_Detected  = null;
		
		public static volatile JMenu jmnuAnalysisReport_ProcessInformationTree_ProduceChildProcessTree = null;
		public static volatile ButtonGroup bgAnalysisReport_ProcessInformationTree_ProduceChildProcessTree = null;
		public static volatile JRadioButtonMenuItem jrbAnalysisReport_ProcessInformationTree_ProduceChildProcessTree_Enabled = null;
		public static volatile JRadioButtonMenuItem jrbAnalysisReport_ProcessInformationTree_ProduceChildProcessTree_Disabled = null;
		
		public static volatile JMenu jmnuAnalysis_Report_Handles = null;
		public static volatile ButtonGroup bgAnalysisReport_Handles = null;
		public static volatile JRadioButtonMenuItem jrbAnalysisReport_Handles_BifurcateIntoMultipleSubTypes = null;
		public static volatile JRadioButtonMenuItem jrbAnalysisReport_Handles_ProduceOutputInSingleType = null;
		
		
		public static volatile JMenuItem jmnuitm_ReDraw_Report  = null;
		public static volatile JMenuItem jmnuitm_Open_Report  = null;
			
	public static volatile long IMAGE_SEARCH_INDEX = 0;
	public static volatile long SNAPSHOT_SEARCH_INDEX = 0;
			
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
	
	public JButton jbtnInitiateAdvancedAnalysis_AdvancedAnalysis = new JButton("Initiate Advanced Analysis");
	public JPanel jpnlAdvancedAnalysis_Center = null;
	public JTabbedPane jtabbedpane_AdvancedAnalysis = null;
	public JTabbedPane jtabbedpane_SnapshotAnalysis_1 = null;
	public JTabbedPane jtabbedpane_SnapshotAnalysis_2 = null;
	
	public static volatile JTextArea_Solomon jpnlAdvancedAnalysisConsole = null;
	public static volatile JTextArea_Solomon jta_advanced_analysis = null;
	
	public JPanel jpnlPlugin_Options = null;
	public JPanel jpnlPluginSearch = null;
	public JLabel jlblPluginSearch = null;
	public JTextField jtfPluginSearch = null;
	
	public JPanel jpnlSearchPlugin_jcbs = null;
	public JCheckBox jcbPluginSearch_SearchPluginName = null;
	public JCheckBox jcbPluginSearch_SearchPluginDescription = null;
	
	public JPanel jpnlPlugin_CONTAINER = null;
	public JPanel jpnlAdvancedAnalysisAutomation_CONTAINER = null;
	public JPanel jpnlPluginButtons = null;
	public JButton jbtnAnalyse = new JButton("Analyze");
	public JButton jbtnSelectFavorites = new JButton("Select Favorites");
	public JButton jbtnHailMary = new JButton("Hail Mary");
	public JButton jbtnDeselectAllPlugins = new JButton("Deselect All Plugins");
	public JButton jbtnPreview = new JButton("Preview");
	public JButton jbtnSearchImage = new JButton("Add Search Image Tab");
	public JButton jbtnSnapshotAnalysis = new JButton("Snapshot Analysis");
	public JButton jbtnAnalysisReport = new JButton("Analysis Report");
	
	public JScrollPane jscrlpne_jpnlPlugins = null;
	public JPanel jpnlPlugins = null;
	public static final int num_plugin_cols = 2;
	
	public JPanelHeap jpnlHeap = null;
	public JPanelTime jpnlTime = null;
	
	public static JPanel jpnlTabbedPane_and_Messages = null;
	public static JLabel jlblStatusMessage = null;
	public static final String num_plugins_in_execution = "Number plugins in execution: "; 
	
	public JSplitPane_Solomon jsplitpane_MAIN = null;
	public static JTabbedPane jtabbedPane_MAIN  = null;
	public static JTabbedPane jtabbedPane_CONSOLE  = null;
	public static JTabbedPane jtabbedPane_CONFIGURATION  = null;
	public static JTabbedPane jtabbedPane_ANALYSIS  = null;
	/**Specific data/time for all of these analysis for this current instance*/
	public static JTabbedPane jtabbedPane_ANALYSIS_DATE_TIME  = null;
	
	
	public JSplitPane_Solomon jsplitpane_File_XREF = null;
	public static JPanel jpnlFile_XREF_MAIN = null;
		public static JPanel jpnlFile_XREF_Search_String_NORTH_Container = null;
			public static JLabel jlblFile_XREF_SearchString = null;
			public static JPanel jpnlSearchString_jtf_Container = null;
			public static JTextField jtfFile_XREF_SearchString = null;
			public static JPanel jpnlCheckBox_Enable_YARA_Search = null;
			public static JCheckBox jcb_IncludeYaraStringScan = null;
			public static JCheckBox jcb_IncludeYaraSignatureFile = null;
			public static JCheckBox jcb_RestrictSearch_to_Core_XREF_Plugins = null;
			public static JButton jbtnSpecifySearchDirectory = null;
			public static JButton jbtnSpecifyYaraSignatureFile = null;
			public JPanel jpnl_jcb_search_string_options = null;
		public static JTabbedPane jtabbedPane_File_XREF_SEARCH  = null;
		public static JTabbedPane jtabbedPane_File_XREF_FILE_SCAN  = null;
		
		public static JTextArea_Solomon jtaFile_XREF_Search_Results = null;
		public static JTextArea_Solomon jtaSnapshotAnalysisConsole = null;
	
		public static JLabel jlblNum_Dump_Files = null;
		public static JLabel jlblNum_Container_Files = null;
		
		
		public static JPanel jpnlDumpFiles_MAIN = null;
		public static JScrollPane jscrlpne_DumpFiles = null;
		public static JPanel jpnlDumpFilesEntries = null;
		public static JPanel jpnlButtons_DumpFiles = null;
		public static JButton jbtnDumpSelectedFiles = null;
		public static JButton jbtnSelectAllFiles_DumpFiles = null;
		public static JButton jbtnDeSelectAllFiles_DumpFiles = null;
		public static JButton jbtnDumpFiles_Open_Working_Directory = null;
		
		public static JPanel jpnlContainerFiles_MAIN = null;
		public static JScrollPane jscrlpne_ContainerFiles = null;
		public static JPanel jpnlContainerFilesEntries = null;
		public static JButton jbtnOpenSelectedFiles = null;
		public static JButton jbtnSelectAllFiles_ContainerFiles = null;
		public static JButton jbtnDeSelectAllFiles_ContainerFiles = null;
		public static JPanel jpnlButtons_ContainerFiles = null;
		
		
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
	
	public static volatile File fle_config_file = null;
	public static volatile String path_fle_config = null;
	
	public static volatile File fle_volatility = null;
	public static volatile FileAttributeData file_attr_volatility = null;
	public static volatile String hash_volatility_md5 = null;
	public static volatile String hash_volatility_sha256 = null;
	
	public static volatile LinkedList<String> list_image_files = new LinkedList<String>();
	
	public static volatile File fle_memory_image = null;
	public static volatile File automate_advanced_analysis_fle_memory_image = null;
	public static volatile FileAttributeData file_attr_memory_image = null; 
	public static volatile String hash_memory_image_md5 = null;
	public static volatile String hash_memory_image_sha256 = null;
	
	public static volatile File fle_procdump = null;
	
	public static volatile String investigator_name = null;
	public static volatile String investigation_description = null;
	
	
	public volatile static String PROFILE = null;
	
	public static final String analysis_time_stamp = driver.get_time_stamp("_");
	public static final String EXECUTION_TIME_STAMP = driver.getTime_Specified_Hyphenated_with_seconds_using_colon(System.currentTimeMillis());
	
	public volatile int plugin_add_index = 0;
	
	public static final String select_image_from_location_text = "Select image from location...";
	
	public static final String num_plugin_displayed_text = "Num Plugins Displayed: ";
	public JLabel jlblNumPluginsDisplayed = null;
	
	public volatile LinkedList<String> list_plugin_autorun = new LinkedList<String>();
	
	public static volatile LinkedList<String> list_omit_plugins = new LinkedList();
	
	public volatile JButton jbtn_open_advanced_analysis_open_working_directory = null;
	
	public volatile boolean self_terminate_upon_execution = true;
	
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
	
	public Interface(File volatility, File setup, File image, boolean Self_terminate_upon_execution)
	{
		try
		{
			//advanced_analysis_director = new Advanced_Analysis_Director(fle_volatility, fle_memory_image, PROFILE, path_fle_analysis_directory, file_attr_volatility, file_attr_memory_image, investigator_name, investigation_description, true, true);
			
			Interface.fle_volatility = volatility;
			Interface.fle_config_file = setup;
			Interface.fle_memory_image = image;
			Interface.automate_advanced_analysis_fle_memory_image = image;
			self_terminate_upon_execution = Self_terminate_upon_execution;
			
			launching_auto_advanced_analysis = true;
			
			this.start();
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 2", e);
		}
		
	}
	
	public void run()
	{
		try
		{
			initialize_component();
									
			if(launching_auto_advanced_analysis)
			{								
				jpnlAdvancedAnalysisConsole.jta.append("Instantiating Advanced Analysis on [" + fle_memory_image.getName() + "]\nProfile: " + PROFILE + "\nPath to image: " + fle_memory_image.getCanonicalPath() + "\nPath to setup.conf: " + Interface.path_fle_config + "\n" + Driver.UNDERLINE + "\n\n");								

				try	{	Start.intface.jtabbedPane_MAIN.setSelectedIndex(1); } catch(Exception e){}
				
				advanced_analysis_director = new Advanced_Analysis_Director(fle_volatility, fle_memory_image, PROFILE, path_fle_analysis_directory, file_attr_volatility, file_attr_memory_image, investigator_name, investigation_description, true, true);
			}
				
			
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
			
			list_omit_plugins.add("volshell");
			list_omit_plugins.add("servicediff");
			list_omit_plugins.add("amcache");
			list_omit_plugins.add("poolpeek");
			list_omit_plugins.add("hivedump");
			list_omit_plugins.add("machoinfo");
			list_omit_plugins.add("cachedump");
			list_omit_plugins.add("hpakinfo");
			list_omit_plugins.add("qemuinfo");
			list_omit_plugins.add("limeinfo");
			list_omit_plugins.add("raw2dmp");
			list_omit_plugins.add("strings");
			list_omit_plugins.add("imagecopy");
			list_omit_plugins.add("yarascan");
			list_omit_plugins.add("hpakextract");
			list_omit_plugins.add("patcher");			
			list_omit_plugins.add("crashinfo");
			list_omit_plugins.add("pooltracker");
			
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
			
			this.jmnuOptions = new JMenu("Options");
			jmnuOptions.setMnemonic(KeyEvent.VK_O);
			
			this.jmnuImport = new JMenu("Import");
			jmnuFile.setMnemonic(KeyEvent.VK_I);
			jmnuFile.add(jmnuImport);
			
			this.jmnuSpecify = new JMenu("Specify");
			jmnuFile.setMnemonic(KeyEvent.VK_S);
			jmnuFile.add(jmnuSpecify);
			
			
						
			//hELP
			this.jmnuHelp = new JMenu("Help");
			jmnuHelp.setMnemonic(KeyEvent.VK_H);
			
			jmnuitm_About = new JMenuItem("About");
			jmnuHelp.add(jmnuitm_About);
			jmnuitm_About.addActionListener(this);
			
			jmnuitm_Import = new JMenuItem("Import");
			jmnuitm_Import_Directory = new JMenuItem("Import Analysis Directory");
			jmnuitm_Import_Directory.setToolTipText("Specify this option to analyze export directory from previous Advanced Analysis");
			
			jmnuitm_Specify_Volatility_Executable = new JMenuItem("Specify Volatility Executable");
			jmnuitm_Specify_Memory_Image_For_Analysis = new JMenuItem("Specify Memory Image for Analysis");
			jmnuitm_Specify_Profile = new JMenuItem("Specify Profile for Memory Image Analysis");
			jmnuitm_Specify_Investigator_Name = new JMenuItem("Specify Investigator Name");
			jmnuitm_Specify_Investigation_Details = new JMenuItem("Specify Investigation Details");
			jmnuitm_Specify_Investigation_Output_Directory = new JMenuItem("Specify Investigation Output Directory");
			jmnuitm_SpecifyTimeZone = new JMenuItem("Specify TimeZone");
			
			jmnuitm_Enable_Search_TF_XREF = new JMenuItem("Enable XREF Search TextField");
			jmnuitm_Enable_Search_TF_XREF.setToolTipText("Select this option in case XREF search text field is disabled");
			jmnuitm_Enable_Search_TF_XREF.addActionListener(this);
			
			jmnuitm_Close = new JMenuItem("Close");
			jmnuEncryption = new JMenu("Encryption");
				jrbEncryptionEnabled = new JRadioButtonMenuItem("Encryption Enabled");
				jrbEncryptionDisabled = new JRadioButtonMenuItem("Encryption Disabled", true);
				bgEncryption = new ButtonGroup();
				bgEncryption.add(this.jrbEncryptionEnabled);
				bgEncryption.add(this.jrbEncryptionDisabled);
				jmnuEncryption.add(this.jrbEncryptionEnabled);
				jmnuEncryption.add(this.jrbEncryptionDisabled);
			
			
				
				
				
				
				
			//jmnuFile.add(jmnuitm_Import);
			jmnuImport.add(jmnuitm_Import_Directory);	jmnuitm_Import_Directory.setEnabled(false);			
			jmnuSpecify.add(jmnuitm_Specify_Volatility_Executable);
			jmnuSpecify.add(jmnuitm_Specify_Profile);
			jmnuSpecify.add(this.jmnuitm_Specify_Memory_Image_For_Analysis);
			jmnuSpecify.add(jmnuitm_Specify_Investigator_Name);
			jmnuSpecify.add(jmnuitm_Specify_Investigation_Details);
			jmnuSpecify.add(jmnuitm_SpecifyTimeZone);
			jmnuSpecify.add(jmnuitm_Specify_Investigation_Output_Directory);
			jmnuOptions.add(jmnuitm_Enable_Search_TF_XREF);
			
			this.jmnuOptions.add(jmnuEncryption); jmnuEncryption.setEnabled(false);
			jmnuFile.add(jmnuitm_Close);
			
			this.jrbEncryptionDisabled.addActionListener(this);
			this.jrbEncryptionEnabled.addActionListener(this);
			this.jmnuitm_Close.addActionListener(this);
			this.jmnuitm_Import.addActionListener(this);
			this.jmnuitm_Import_Directory.addActionListener(this);
			this.jmnuitm_Specify_Profile.addActionListener(this);
			jmnuitm_Specify_Investigator_Name.addActionListener(this);
			jmnuitm_Specify_Investigation_Details.addActionListener(this);
			jmnuitm_SpecifyTimeZone.addActionListener(this);
			jmnuitm_Specify_Investigation_Output_Directory.addActionListener(this);
			
			
			this.jmnuitm_Specify_Volatility_Executable.addActionListener(this);
			this.jmnuitm_Specify_Memory_Image_For_Analysis.addActionListener(this);
			
			//
			//Data XREF
			//
			jmnuDataXREF = new JMenu("Data XREF");			jmnuDataXREF.setMnemonic(KeyEvent.VK_D);
			jmnuDataXREF.setToolTipText("Data Cross Reference");
				jmnuitm_DataXREF_Specify_YARA_Signature_File = new JMenuItem("Specify YARA Signature File");
				jmnuitm_DataXREF_Specify_YARA_Signature_File.addActionListener(this);
				jmnuDataXREF.add(jmnuitm_DataXREF_Specify_YARA_Signature_File);
			
			//
			//Advanced Analysis
			//
				
				

			jmnuAdvancedAnalysis = new JMenu("Advanced Analysis");
				jmnuAdvancedAnalysis.setMnemonic(KeyEvent.VK_A);	
				jmnuAnalysisReport = new JMenu("Analysis Report");
				jmnuSystemManifest = new JMenu("System Manifest");
					jmnuitm_ImportSystemManifest_from_file_menu = new JMenuItem("Import System Manifest");	jmnuImport.add(jmnuitm_ImportSystemManifest_from_file_menu);	jmnuitm_ImportSystemManifest_from_file_menu.addActionListener(this);  jmnuitm_ImportSystemManifest_from_file_menu.setEnabled(false);  jmnuitm_ImportSystemManifest_from_file_menu.setMnemonic(KeyEvent.VK_I);
					jmnuitm_ImportSystemManifest = new JMenuItem("Import System Manifest");	jmnuSystemManifest.add(jmnuitm_ImportSystemManifest);	jmnuitm_ImportSystemManifest.addActionListener(this);  jmnuitm_ImportSystemManifest.setEnabled(false);
					jmnuitm_ExportSystemManifest = new JMenuItem("Export System Manifest");	jmnuSystemManifest.add(jmnuitm_ExportSystemManifest);	jmnuitm_ExportSystemManifest.addActionListener(this);  jmnuitm_ExportSystemManifest.setEnabled(false);
					
					
					
					
					
				jmnuAnalysisReportProcessTree = new JMenu("Process Tree");
				jmnuAnalysisReportProcessInformationTree = new JMenu("Process Information Tree");
				
				menu_bar.add(jmnuAdvancedAnalysis);
				
				menu_bar.add(jmnuDataXREF);
				menu_bar.add(jmnuOptions);
				
				
				jmnuitm_Initiate_Advanced_Analysis_SingleFile = new JMenuItem("Execute Advanced Analysis on Single Memory Image");	jmnuitm_Initiate_Advanced_Analysis_SingleFile.addActionListener(this);	jmnuitm_Initiate_Advanced_Analysis_SingleFile.setEnabled(false);  
				jmnuitm_Initiate_Advanced_Analysis_SingleFile.setToolTipText("<html>Select this option to execute advanced analysis actions on the single memory image loaded<br>If in doubt, select this option first.</html>");
				
				jmnuitm_Initiate_Advanced_Analysis_Entire_Directory = new JMenuItem("Execute Advanced Analysis on all memory images under specified directory");	jmnuitm_Initiate_Advanced_Analysis_Entire_Directory.addActionListener(this);	
				jmnuitm_Initiate_Advanced_Analysis_Entire_Directory.setToolTipText("<html>Select this option to automate analysis of several memory images under a specified top folder<br><b><u>NOTE:</b></u> Each directory must a memory image and a setup.conf file present in order to instantiate the advanced analysis directors.</html>");
				
				jmnuInitiateAdvancedAnalysis = new JMenu("Initiate Advanced Analysis");
				jmnuInitiateAdvancedAnalysis.add(jmnuitm_Initiate_Advanced_Analysis_SingleFile);
				jmnuInitiateAdvancedAnalysis.add(jmnuitm_Initiate_Advanced_Analysis_Entire_Directory);
				jmnuAdvancedAnalysis.add(jmnuInitiateAdvancedAnalysis);
				
				jmnuAdvancedAnalysis.add(jmnuAnalysisReport);
												
				jmnuAdvancedAnalysis.add(jmnuSystemManifest);
				
				jmnuSnapshotAnalysis = new JMenu("Snapshot Analysis");
				jmnuitm_InitiateSnapshotAnalysis = new JMenuItem("Initiate Snapshot Analysis");	jmnuSnapshotAnalysis.add(jmnuitm_InitiateSnapshotAnalysis);	jmnuitm_InitiateSnapshotAnalysis.addActionListener(this);  jmnuitm_InitiateSnapshotAnalysis.setEnabled(false);  jmnuitm_InitiateSnapshotAnalysis.setMnemonic(KeyEvent.VK_S);	
				jmnuAdvancedAnalysis.add(jmnuSnapshotAnalysis);
				
				
				
				jmnuAnalysisReport.add(jmnuAnalysisReportProcessTree);
				
				
				
				
				
				jmnuAnalysisReport.add(jmnuAnalysisReportProcessInformationTree);
				
				jmnuitm_AnalyseUserAssist = new JMenuItem("Analyze User Assist");	jmnuitm_AnalyseUserAssist.addActionListener(this);	jmnuitm_AnalyseUserAssist.setEnabled(false);
				jmnuAdvancedAnalysis.add(jmnuitm_AnalyseUserAssist);
				
				
				jmnuitm_Set_Node_Length_PROCESS_TREE =  new JMenuItem("Set Node Length");
				jmnuitm_Set_Div_Height_PROCESS_TREE =  new JMenuItem("Set HTML Div Height");
				jmnuitm_Set_Div_Width_PROCESS_TREE =  new JMenuItem("Set HTML Div Width");
				
				jmnuitm_Set_Node_Length_PROCESS_INFORMATION_TREE =  new JMenuItem("Set Node Length");
				jmnuitm_Set_Div_Height_PROCESS_INFORMATION_TREE =  new JMenuItem("Set HTML Div Height");
				jmnuitm_Set_Div_Width_PROCESS_INFORMATION_TREE =  new JMenuItem("Set HTML Div Width");
				
				jmnuitm_ReDraw_Report =  new JMenuItem("Redraw Report");
				jmnuitm_Open_Report =  new JMenuItem("Open Report"); 
				jmnuitm_Open_Report.setToolTipText("Open previous analysis file present in html directory");
					jmnuAnalysisReportProcessTree.add(jmnuitm_Set_Node_Length_PROCESS_TREE);
					jmnuAnalysisReportProcessTree.add(jmnuitm_Set_Div_Height_PROCESS_TREE);
					jmnuAnalysisReportProcessTree.add(jmnuitm_Set_Div_Width_PROCESS_TREE);
					
					jmnuAnalysisReportProcessInformationTree.add(jmnuitm_Set_Node_Length_PROCESS_INFORMATION_TREE);
					jmnuAnalysisReportProcessInformationTree.add(jmnuitm_Set_Div_Height_PROCESS_INFORMATION_TREE);
					jmnuAnalysisReportProcessInformationTree.add(jmnuitm_Set_Div_Width_PROCESS_INFORMATION_TREE);
					
					
			jmnuAnalysisReport_ProcessInformationTree_ProduceChildProcessTree = new JMenu("Produce Child Process Call Tree");
			bgAnalysisReport_ProcessInformationTree_ProduceChildProcessTree = new ButtonGroup();
			jrbAnalysisReport_ProcessInformationTree_ProduceChildProcessTree_Enabled = new JRadioButtonMenuItem("Enable Recursion to Produce Child Process Call Tree", true);
			jrbAnalysisReport_ProcessInformationTree_ProduceChildProcessTree_Disabled = new JRadioButtonMenuItem("Do not Child Process Call Tree");
			bgAnalysisReport_ProcessInformationTree_ProduceChildProcessTree.add(jrbAnalysisReport_ProcessInformationTree_ProduceChildProcessTree_Enabled);
			bgAnalysisReport_ProcessInformationTree_ProduceChildProcessTree.add(jrbAnalysisReport_ProcessInformationTree_ProduceChildProcessTree_Disabled);
					
			jmnuAnalysisReportProcessInformationTree.add(jmnuAnalysisReport_ProcessInformationTree_ProduceChildProcessTree);
			jmnuAnalysisReport_ProcessInformationTree_ProduceChildProcessTree.add(jrbAnalysisReport_ProcessInformationTree_ProduceChildProcessTree_Enabled);
			jmnuAnalysisReport_ProcessInformationTree_ProduceChildProcessTree.add(jrbAnalysisReport_ProcessInformationTree_ProduceChildProcessTree_Disabled);
			
			jrbAnalysisReport_ProcessInformationTree_ProduceChildProcessTree_Enabled.setToolTipText("This option directs Xavier to use recursion to include the process call tree within the Process Informaiton Tree section of the output page.");
			jrbAnalysisReport_ProcessInformationTree_ProduceChildProcessTree_Disabled.setToolTipText("Use this option to disable production of Child Processes call tree under Process Informaiton Tree section of html analysis report.");
			
			jrbAnalysisReport_ProcessInformationTree_ProduceChildProcessTree_Enabled.addActionListener(this);
			jrbAnalysisReport_ProcessInformationTree_ProduceChildProcessTree_Disabled.addActionListener(this);
			
			jmnuAnalysis_Report_Handles = new JMenu("Handles");
			bgAnalysisReport_Handles = new ButtonGroup();
			jrbAnalysisReport_Handles_BifurcateIntoMultipleSubTypes = new JRadioButtonMenuItem("Bifurcate Handle Output into Multiple SubTypes", true);
			jrbAnalysisReport_Handles_ProduceOutputInSingleType = new JRadioButtonMenuItem("Produce Handle in Single Type");		
			jmnuAnalysisReportProcessInformationTree.add(jmnuAnalysis_Report_Handles);
			jmnuAnalysis_Report_Handles.add(jrbAnalysisReport_Handles_BifurcateIntoMultipleSubTypes);
			jmnuAnalysis_Report_Handles.add(jrbAnalysisReport_Handles_ProduceOutputInSingleType);
			
			jrbAnalysisReport_Handles_BifurcateIntoMultipleSubTypes.addActionListener(this);
			jrbAnalysisReport_Handles_ProduceOutputInSingleType.addActionListener(this);
			
			jrbAnalysisReport_Handles_BifurcateIntoMultipleSubTypes.setToolTipText("<html>Handles can come in multiple types e.g., Process, Thread, Key, Event, etc. <br>Enable this option to write the Handles output in sub types.</html>" );
			jrbAnalysisReport_Handles_ProduceOutputInSingleType.setToolTipText("<html>Although handles can come in multiple subtypes, enable this option to write as a single type.</html>" );
			
				
			jmnuAnalysisReport_Execution_Plugin = new JMenu("Execution Plugins");
			jmnuitm_Only_Show_Button_If_Execution_Plugins_Detected = new JMenuItem("Only show Execution Plugins Button if advanced analysis plugins were auto-executed");	jmnuAnalysisReport_Execution_Plugin.add(jmnuitm_Only_Show_Button_If_Execution_Plugins_Detected);	jmnuitm_Only_Show_Button_If_Execution_Plugins_Detected.addActionListener(this);  //jmnuitm_Only_Show_Button_If_Execution_Plugins_Detected.setEnabled(false);
			jmnuitm_Always_Show_Button_Even_If_Execution_Plugins_Not_Detected = new JMenuItem("Always show Executeion Plugins even if advanced analysis plugins were NOT detected");	jmnuAnalysisReport_Execution_Plugin.add(jmnuitm_Always_Show_Button_Even_If_Execution_Plugins_Not_Detected);	jmnuitm_Always_Show_Button_Even_If_Execution_Plugins_Not_Detected.addActionListener(this);  //jmnuitm_Always_Show_Button_Even_If_Execution_Plugins_Not_Detected.setEnabled(false);
			jmnuAnalysisReport.add(jmnuAnalysisReport_Execution_Plugin);	
			
			jmnuAnalysisReport.add(jmnuitm_Open_Report);
			jmnuAnalysisReport.add(jmnuitm_ReDraw_Report);
					
					jmnuitm_Open_Report.addActionListener(this);
					jmnuitm_Set_Node_Length_PROCESS_TREE.addActionListener(this);
					jmnuitm_Set_Div_Height_PROCESS_TREE.addActionListener(this);
					jmnuitm_Set_Div_Width_PROCESS_TREE.addActionListener(this);
					
					jmnuitm_Set_Node_Length_PROCESS_INFORMATION_TREE.addActionListener(this);
					jmnuitm_Set_Div_Height_PROCESS_INFORMATION_TREE.addActionListener(this);
					jmnuitm_Set_Div_Width_PROCESS_INFORMATION_TREE.addActionListener(this);
					
					jmnuitm_ReDraw_Report.addActionListener(this);
					
					jmnuitm_Set_Node_Length_PROCESS_TREE.setToolTipText("<html>Set the initial length between each node in analysis report html file. <br>Right now, length is set to <b>" + Analysis_Report_Container_Writer.tree_length_to_each_node_PROCESS_TREE  + "</b></html>");
					jmnuitm_Set_Div_Height_PROCESS_TREE.setToolTipText("<html>Set the initial height of the html file that is added as a frame into the main Analysis Report container html file. <br>Right now, initial height is set to <b>" + Analysis_Report_Container_Writer.tree_div_height_PROCESS_TREE  + "</b></html>");
					jmnuitm_Set_Div_Width_PROCESS_TREE.setToolTipText("<html>Set the initial width of the html file that is added as a frame into the main Analysis Report container html file. <br>Right now, initial width is set to <b>" + Analysis_Report_Container_Writer.tree_div_width_PROCESS_TREE  + "</b></html>");
					jmnuitm_ReDraw_Report.setToolTipText("Redraw Analysis Report... say we just made a configuration change. This redraws the analysis report to reflect recent updates.");
					jmnuitm_ReDraw_Report.setEnabled(false);
					
					jmnuitm_Set_Node_Length_PROCESS_INFORMATION_TREE.setToolTipText("<html>Set the initial length between each node in analysis report html file. <br>Right now, length is set to <b>" + Analysis_Report_Container_Writer.tree_length_to_each_node_PROCESS_INFORMATION_TREE  + "</b></html>");
					jmnuitm_Set_Div_Height_PROCESS_INFORMATION_TREE.setToolTipText("<html>Set the initial height of the html file that is added as a frame into the main Analysis Report container html file. <br>Right now, initial height is set to <b>" + Analysis_Report_Container_Writer.tree_div_height_PROCESS_INFORMATION_TREE  + "</b></html>");
					jmnuitm_Set_Div_Width_PROCESS_INFORMATION_TREE.setToolTipText("<html>Set the initial width of the html file that is added as a frame into the main Analysis Report container html file. <br>Right now, initial width is set to <b>" + Analysis_Report_Container_Writer.tree_div_width_PROCESS_INFORMATION_TREE  + "</b></html>");
					
					
					
					
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
			
			jpnlTabbedPane_and_Messages = new JPanel(new BorderLayout());
			jlblStatusMessage = new JLabel(num_plugins_in_execution + "[0]", JLabel.CENTER);
			try	{	jlblStatusMessage.setFont(new Font("Helvetica", Font.PLAIN, 16));} catch(Exception e){}
			jlblStatusMessage.setBorder(BorderFactory.createBevelBorder(BevelBorder.LOWERED));
			jlblStatusMessage.setOpaque(true);
			jlblStatusMessage.setBackground(Color.yellow);
			jlblStatusMessage.setForeground(Color.blue);
			jlblStatusMessage.setVisible(false);
			
			
			jsplitpane_MAIN = new JSplitPane_Solomon(JSplitPane.VERTICAL_SPLIT, jtabbedPane_MAIN, jtabbedPane_CONSOLE, 270);
				//jpnlCENTER.add(BorderLayout.CENTER, jsplitpane_MAIN);
			
			
			jpnlTabbedPane_and_Messages.add(BorderLayout.CENTER, jsplitpane_MAIN);
			jpnlTabbedPane_and_Messages.add(BorderLayout.NORTH, jlblStatusMessage);
			jpnlCENTER.add(BorderLayout.CENTER, jpnlTabbedPane_and_Messages);
			
				
			
			//
			jpnlConsole = new JTextArea_Solomon("", true, "Command Transmission", true);			
			jtabbedPane_CONSOLE.addTab("Console", jpnlConsole);
			
			this.jpnlPlugins = new JPanel(new GridLayout(20, 3, 5,5));
			jscrlpne_jpnlPlugins = new JScrollPane(this.jpnlPlugins, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
			
			jlblNumPluginsDisplayed = new JLabel(this.num_plugin_displayed_text + "[0]", JLabel.RIGHT);
			
			jpnlSearchPlugin_jcbs = new JPanel(new GridLayout(1,3,0,0));
			this.jcbPluginSearch_SearchPluginDescription = new JCheckBox("Search Plugin Description");
			this.jcbPluginSearch_SearchPluginName = new JCheckBox("Search Plugin Name", true);
			jpnlSearchPlugin_jcbs.add(jcbPluginSearch_SearchPluginName);
			jpnlSearchPlugin_jcbs.add(jcbPluginSearch_SearchPluginDescription);
			jpnlSearchPlugin_jcbs.add(jlblNumPluginsDisplayed);
			
			jpnlConsole.jtf.setEditable(false);
			
			jtfPluginSearch = new JTextField(12);
			jlblPluginSearch = new JLabel("  Plugin Search: ");
			jtfPluginSearch.setEditable(false);
			jtfPluginSearch.validate();
			jpnlPlugin_Options = new JPanel(new BorderLayout());
			
			jpnlPluginSearch = new JPanel(new BorderLayout());
			jpnlPluginSearch.setBorder(new TitledBorder("Search"));
			jpnlPluginSearch.add(BorderLayout.WEST, jlblPluginSearch);
			jpnlPluginSearch.add(BorderLayout.CENTER, jtfPluginSearch);
			jpnlPluginSearch.add(BorderLayout.EAST, jpnlSearchPlugin_jcbs);
			jtfPluginSearch.addActionListener(this);
			
			jpnlPluginButtons = new JPanel(new GridLayout(1,8, 2, 2));
			jpnlPluginButtons.setBorder(new TitledBorder("Execution Options"));	
			
			jpnlPluginButtons.add(this.jbtnSelectFavorites);
			jbtnSelectFavorites.addActionListener(this);
			
			jpnlPluginButtons.add(jbtnPreview);
			jbtnPreview.addActionListener(this);
			
			jpnlPluginButtons.add(jbtnAnalyse);
			jbtnAnalyse.addActionListener(this);
			jbtnAnalyse.setBackground(Color.red);
			
			jbtnInitiateAdvancedAnalysis_AdvancedAnalysis.addActionListener(this);
			
			
			jpnlPluginButtons.add(jbtnHailMary);
			jbtnHailMary.addActionListener(this);
			
			jpnlPluginButtons.add(jbtnDeselectAllPlugins);
			jbtnDeselectAllPlugins.addActionListener(this);
			
			jpnlPluginButtons.add(jbtnSearchImage);
			jbtnSearchImage.addActionListener(this);
			
			jpnlPluginButtons.add(jbtnAnalysisReport);
			jbtnAnalysisReport.addActionListener(this);
			jbtnAnalysisReport.setToolTipText("<html>Enable this option to automate running multiple plugins and consolidate summary into a single report. </html>");
			
			
			jpnlPluginButtons.add(jbtnSnapshotAnalysis);
			jbtnSnapshotAnalysis.addActionListener(this);
			jbtnSnapshotAnalysis.setToolTipText("<html>Enable this option to automate snapshot analysis on 2 memory images.<br>First, selection the pre-host-infection image, <br>then select the memory image taken after a host system has been compromised for instance with malware.<br>This option will analyze both memory images and provide a summary of the relevant changes discovered between the 2 memory images. </html>");
			
			
			jpnlPlugin_Options.add(BorderLayout.NORTH, jpnlPluginSearch);
			jpnlPlugin_Options.add(BorderLayout.SOUTH, jpnlPluginButtons);
			
			jpnlPlugin_CONTAINER = new JPanel(new BorderLayout());
			jpnlPlugin_CONTAINER.add(BorderLayout.CENTER, this.jscrlpne_jpnlPlugins);
			//jpnlPlugin_CONTAINER.add(BorderLayout.SOUTH, jpnlPluginButtons);
			jpnlPlugin_CONTAINER.add(BorderLayout.SOUTH, jpnlPlugin_Options);
			
			jpnlAdvancedAnalysisAutomation_CONTAINER = new JPanel(new BorderLayout());
			jpnlAdvancedAnalysisAutomation_CONTAINER.add(BorderLayout.NORTH, jbtnInitiateAdvancedAnalysis_AdvancedAnalysis);
			jbtnInitiateAdvancedAnalysis_AdvancedAnalysis.setEnabled(false);
			jbtnInitiateAdvancedAnalysis_AdvancedAnalysis.setBackground(Color.blue.darker());
			
			jpnlAdvancedAnalysis_Center = new JPanel(new BorderLayout());
				jtabbedpane_AdvancedAnalysis = new JTabbedPane(JTabbedPane.TOP);
				jpnlAdvancedAnalysisConsole = new JTextArea_Solomon("", true, "Advanced Analysis Options", false);
				jta_advanced_analysis  = jpnlAdvancedAnalysisConsole;
				jtabbedpane_AdvancedAnalysis.addTab("Analysis Console", jpnlAdvancedAnalysisConsole);
				jpnlAdvancedAnalysis_Center.add(BorderLayout.CENTER, jtabbedpane_AdvancedAnalysis);
				jpnlAdvancedAnalysisAutomation_CONTAINER.add(BorderLayout.CENTER, jpnlAdvancedAnalysis_Center);
				jpnlAdvancedAnalysisConsole.jtf.setEditable(false);
				jpnlAdvancedAnalysisConsole.restrict_data_entries = false;
				
				//update gui
				jbtn_open_advanced_analysis_open_working_directory = new JButton("Open Working Directory");
				update_jtf_panel(jpnlAdvancedAnalysisConsole);
				
			
			jtabbedPane_MAIN.addTab("Plugins", jpnlPlugin_CONTAINER);
			jtabbedPane_MAIN.addTab("Advanced Analysis Automation", jpnlAdvancedAnalysisAutomation_CONTAINER);
			
			//
			//JTabbedPane File XREF
			//
			
			this.jpnlFile_XREF_Search_String_NORTH_Container = new JPanel(new BorderLayout());
			this.jlblFile_XREF_SearchString = new JLabel("   Search String:   ");
			this.jpnlSearchString_jtf_Container = new JPanel(new BorderLayout());
				this.jtfFile_XREF_SearchString = new JTextField(7);
				jtfFile_XREF_SearchString.addActionListener(this);
				jpnlSearchString_jtf_Container.add(BorderLayout.SOUTH, jtfFile_XREF_SearchString);
				jtfFile_XREF_SearchString.setEditable(false);
				
			jpnlFile_XREF_Search_String_NORTH_Container.add(BorderLayout.WEST, jlblFile_XREF_SearchString);
			jpnlFile_XREF_Search_String_NORTH_Container.add(BorderLayout.CENTER, jpnlSearchString_jtf_Container);
					
			this.jpnlCheckBox_Enable_YARA_Search = new JPanel();
			this.jcb_IncludeYaraStringScan = new JCheckBox("Include YARA String Search", false);
			jcb_IncludeYaraSignatureFile = new JCheckBox("Include YARA Signature File");
			jbtnSpecifyYaraSignatureFile = new JButton("Include YARA Signature File");
			jbtnSpecifyYaraSignatureFile.addActionListener(this);
			
			this.jcb_RestrictSearch_to_Core_XREF_Plugins = new JCheckBox("Only search core XREF plugins", false);
			jpnl_jcb_search_string_options = new JPanel(new GridLayout(1,3,5,5));
			jpnl_jcb_search_string_options.add(jcb_IncludeYaraStringScan);
			jpnl_jcb_search_string_options.add(jcb_IncludeYaraSignatureFile);
			//jpnl_jcb_search_string_options.add(jbtnSpecifyYaraSignatureFile);
			
			
			
			//this.jtaFile_XREF_Search_Results.jpnlcheckBox.add(jcb_RestrictSearch_to_Core_XREF_Plugins);
			jpnlFile_XREF_Search_String_NORTH_Container.add(BorderLayout.EAST, jpnl_jcb_search_string_options);
			
			this.jpnlFile_XREF_MAIN = new JPanel(new BorderLayout());
			jpnlFile_XREF_MAIN.add(BorderLayout.NORTH, jpnlFile_XREF_Search_String_NORTH_Container);	
			
			this.jtabbedPane_File_XREF_SEARCH = new JTabbedPane(JTabbedPane.TOP);
			this.jtabbedPane_File_XREF_FILE_SCAN = new JTabbedPane(JTabbedPane.TOP);
			this.jsplitpane_File_XREF = new JSplitPane_Solomon(JSplitPane.HORIZONTAL_SPLIT, jpnlFile_XREF_MAIN, jtabbedPane_File_XREF_FILE_SCAN, 900);
			jtabbedPane_MAIN.addTab("Data XREF", jsplitpane_File_XREF);			
			
			jtaFile_XREF_Search_Results = new JTextArea_Solomon("", true, "Command Transmission", true);
			jtaFile_XREF_Search_Results.restrict_data_entries = false;
			//jtabbedPane_File_XREF_SEARCH.addTab("Search Results", jtaFile_XREF_Search_Results); //uncomment if you wish to add tabs
			jpnlFile_XREF_MAIN.add(BorderLayout.CENTER, jtaFile_XREF_Search_Results);
			try	{	this.jtaFile_XREF_Search_Results.setBorder(new TitledBorder("Search Results"));	}	catch(Exception e){}
			jtaFile_XREF_Search_Results.jtf.setEditable(false);
			jtaFile_XREF_Search_Results.jbtnSend.setEnabled(false);
			
			jbtnSpecifySearchDirectory = new JButton("Specify Search Directory");
			jbtnSpecifySearchDirectory.addActionListener(this);
			
			
			
			
			
			try
			{
				jtaFile_XREF_Search_Results.jpnlSouth.removeAll();			
				jtaFile_XREF_Search_Results.jpnlSouth.setLayout(new GridLayout(1,5,5,5));
				jtaFile_XREF_Search_Results.jpnlSouth.add(jtaFile_XREF_Search_Results.jbtnClear);					
				jtaFile_XREF_Search_Results.jpnlSouth.add(jtaFile_XREF_Search_Results.jbtnExportData);
				jtaFile_XREF_Search_Results.jpnlSouth.add(jbtnSpecifySearchDirectory);
				
				JPanel jpnl_restrict_alignment = new JPanel(new BorderLayout());
				jpnl_restrict_alignment.add(BorderLayout.EAST, jcb_RestrictSearch_to_Core_XREF_Plugins);
				//jcb_RestrictSearch_to_Core_XREF_Plugins.setEnabled(false);
				this.jcb_RestrictSearch_to_Core_XREF_Plugins.setToolTipText("<html> Use this option if you selected to \"Proceed here to enable execution of specific analysis plugins required for XREF search\" <br> to reduce the number of plugins that are initially executed to search for XREF.<br> It'll be best for you to initiate full Advanced Analysis, and then return here or specify the export directory to expand your search results </html>");
				
				JPanel jpnl_autoscroll_alignment = new JPanel(new BorderLayout());
				jpnl_autoscroll_alignment.add(BorderLayout.EAST, jtaFile_XREF_Search_Results.jcbAutoScroll);
				
				jtaFile_XREF_Search_Results.jpnlSouth.add(jpnl_autoscroll_alignment);
				jtaFile_XREF_Search_Results.jpnlSouth.add(jpnl_restrict_alignment);
					
			
			}catch(Exception e){}
			
			
			
			jpnlDumpFiles_MAIN = new JPanel(new BorderLayout());
			jpnlDumpFilesEntries = new JPanel(new GridLayout(5,1));
			//jpnlFileScanEntries.setBorder(BorderFactory.createBevelBorder(BevelBorder.RAISED));
				
			jscrlpne_DumpFiles = new JScrollPane(this.jpnlDumpFilesEntries, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
			
			
			
			jpnlDumpFiles_MAIN.add(BorderLayout.CENTER, jscrlpne_DumpFiles);
			
			jbtnDumpSelectedFiles = new JButton("Dump Selected File(s)");
			jbtnDumpSelectedFiles.addActionListener(this);
			
			jbtnDumpSelectedFiles.setToolTipText("Dump Selected File(s)");
			this.jbtnSelectAllFiles_DumpFiles = new JButton("Select All File(s)");
			this.jbtnSelectAllFiles_DumpFiles.setToolTipText("Select All File(s)");
			jbtnSelectAllFiles_DumpFiles.addActionListener(this);
			
			this.jbtnDumpFiles_Open_Working_Directory = new JButton("Open Working Directory");
			this.jbtnDumpFiles_Open_Working_Directory.setToolTipText("Open Working Directory");
			jbtnDumpFiles_Open_Working_Directory.addActionListener(this);
			
			this.jbtnDeSelectAllFiles_DumpFiles = new JButton("Deselect All File(s)");
			this.jbtnDeSelectAllFiles_DumpFiles.setToolTipText("Deelect All File(s)");
			jbtnDeSelectAllFiles_DumpFiles.addActionListener(this);
			
			jpnlButtons_DumpFiles = new JPanel(new GridLayout(4,1,3,3));
			jpnlButtons_DumpFiles.add(jbtnSelectAllFiles_DumpFiles);
			jpnlButtons_DumpFiles.add(jbtnDeSelectAllFiles_DumpFiles);
			jpnlButtons_DumpFiles.add(jbtnDumpSelectedFiles);
			jpnlButtons_DumpFiles.add(jbtnDumpFiles_Open_Working_Directory);
			
			jpnlDumpFiles_MAIN.add(BorderLayout.SOUTH, this.jpnlButtons_DumpFiles);
			
			jlblNum_Dump_Files = new JLabel("No Files Loaded", JLabel.CENTER);
			jlblNum_Container_Files = new JLabel("No Files Loaded", JLabel.CENTER);
			
			jpnlDumpFiles_MAIN.add(BorderLayout.NORTH, jlblNum_Dump_Files);
			
			
			jtabbedPane_File_XREF_FILE_SCAN.addTab("Dump Files", jpnlDumpFiles_MAIN);
			
			
			jpnlContainerFiles_MAIN = new JPanel(new BorderLayout());
			jpnlContainerFilesEntries = new JPanel(new GridLayout(5,1));
			
			jscrlpne_ContainerFiles = new JScrollPane(this.jpnlContainerFilesEntries, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
			
			jpnlContainerFiles_MAIN.add(BorderLayout.CENTER, jscrlpne_ContainerFiles);
			
			jpnlButtons_ContainerFiles = new JPanel(new GridLayout(3,1,3,3));
				jbtnOpenSelectedFiles = new JButton("Open Selected File(s)");
				jbtnOpenSelectedFiles.addActionListener(this);
				jbtnOpenSelectedFiles.setToolTipText("Open Selected File(s)");
				
				jbtnSelectAllFiles_ContainerFiles = new JButton("Select All File(s)");
				jbtnSelectAllFiles_ContainerFiles.addActionListener(this);
				jbtnSelectAllFiles_ContainerFiles.setToolTipText("Select All File(s)");
				
				jbtnDeSelectAllFiles_ContainerFiles = new JButton("Deselect All File(s)");
				jbtnDeSelectAllFiles_ContainerFiles.addActionListener(this);
				jbtnDeSelectAllFiles_ContainerFiles.setToolTipText("Deselect All File(s)");
				
				
				jpnlButtons_ContainerFiles.add(jbtnSelectAllFiles_ContainerFiles);
				jpnlButtons_ContainerFiles.add(jbtnDeSelectAllFiles_ContainerFiles);
				jpnlButtons_ContainerFiles.add(jbtnOpenSelectedFiles);
				
				jpnlContainerFiles_MAIN.add(BorderLayout.SOUTH, jpnlButtons_ContainerFiles);
				
				jtabbedPane_File_XREF_FILE_SCAN.addTab("Container Files", jpnlContainerFiles_MAIN);
			
				try	{	jtabbedPane_File_XREF_FILE_SCAN.setToolTipTextAt(0, "<html>Dump each file matching your search string found from <b>filescan</b> plugin</html>");	} catch(Exception e){}
				try	{	jtabbedPane_File_XREF_FILE_SCAN.setToolTipTextAt(1, "<html>Open container file (from respective plugin's output) where your search string was found</html>");	} catch(Exception e){}
			
			//jtabbedPane_CONSOLE.addTab("Console", jpnlConsole);
			
				this.jpnlContainerFiles_MAIN.add(BorderLayout.NORTH, jlblNum_Container_Files);
			
			//
			//continue with GUI
			//
			
			
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
			driver.directive("///////////////////////////////////////////////////////////////////////////////");
			driver.directive("// Welcome to " + Driver.FULL_NAME + " by Solomon Sonya @Carpenter1010    //");
			driver.directive("/////////////////////////////////////////////////////////////////////////////\n");
			
			jbtnSearchImage.setToolTipText("<html>Enter specific keywords to search for hits through a specified image. <br>A new Tab will appear to allow you to select an image and enter keywords to search for hits.</html>");
			this.jbtnHailMary.setToolTipText("<html><b>Proceed with caution on this one.</b> <br>Selecting this will enable every applicable plugin for analysis.<br>After selecting, click on Analyze to begin analysis.</html>");
			this.jbtnPreview.setToolTipText("Populate new tabs based on the selected plugins. This allows you to modify the commands before execution. Click on Analyze when ready to begin analysis.");
			this.jbtnSelectFavorites.setToolTipText("Quickly enable a few plugins useful in many investigations. Click on Analyze to begin analysis.");
			this.jbtnAnalyse.setToolTipText("Begin analysis on the selected plugins");
			this.jbtnDeselectAllPlugins.setToolTipText("Unselect all selected plugins");
			
			
			menu_bar.add(jmnuHelp);
			
			//
			//initialize dependencies
			//
			initialize_dependencies();
			
			
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
			driver.eop(myClassName, "initialize_component", e, true);
		}
		
		return false;
	}
	
	
	/**
	 * continuation mtd
	 * @return
	 */
	public boolean initialize_dependencies()
	{
		try
		{
			//
			//check if we have a config file or import files already completed
			//
			initialize_framework_volatility_executable();
			
			//
			//check for graphviz
			//
			initialize_graphviz();
			
			//
			//check for readpe
			//
			//initialize_readpe();
			
			//initialize_dependencies_file();
			
			if(Start.fleImportDirectory == null || !Start.fleImportDirectory.exists() || !Start.fleImportDirectory.isDirectory())
			{
				sop("NOTE: I am terminating enumeration for readpe.exe, import directory does not appear to be established...") ;
				return false;
			}
			else
			{
				Start.fle_dependencies = driver.get_file(Start.fleImportDirectory, "dependencies.exe");
				Start.fle_whois = driver.get_file(Start.fleImportDirectory, "whois.exe");
				
				if(Start.fle_whois == null && driver.isWindows)
				{
					Start.fle_whois = driver.get_file(Start.fleImportDirectory, "whois64.exe");					
				}
				
				if(Start.fle_whois != null)
					driver.directive("setting location of whois --> " + Start.fle_whois.getCanonicalPath());
				
			}
			
			
			
						
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
			//read config file
			//
			import_config_file();
			
			//
			//specify profile
			//
			specify_profile(false);
			
			
			//
			//Investigation Details
			//
			specify_investigation_details(false);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "initialize_dependencies", e);
		}
		
		return false;
	}
	
	public boolean update_jtf_panel(JTextArea_Solomon jpnl)
	{
		try
		{
			try	{	jpnl.jtf.removeActionListener(jpnl); } catch(Exception e){}
			try	{	jpnl.jbtnSend.removeActionListener(jpnl); } catch(Exception e){}
			
			jpnl.jtf.addActionListener(this);
			jbtn_open_advanced_analysis_open_working_directory.addActionListener(this);
			
			
			jbtn_open_advanced_analysis_open_working_directory.addActionListener(this);			
			jpnl.jpnlcheckBox.add(this.jbtn_open_advanced_analysis_open_working_directory);
			
			
			try	{	jfrm.validate();} catch(Exception e){}
			try	{	jpnl.validate();} catch(Exception e){}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "update_jtf_panel", e);
		}
		
		return false;
	}
	
	public boolean import_config_file()
	{
		try
		{
			File fleConf = Interface.fle_config_file;
			
			String path = Interface.path_fle_config;
			String line = "";
			String lower = "";
			String plugin_autorun = "";
			boolean i_read_config_file = false;
			
			if(fleConf == null)
			{
				LinkedList<File> list = new LinkedList<File>();
				list = driver.getFileListing(Start.fleImportMemoryImageDirectory, true, null, list);
				
				if(list == null || list.size() < 0)
				{
					driver.sop("Note: I could not find setup.conf file at " + Start.fleImportMemoryImageDirectory);
					return false;
				}								
				
				try	{list_plugin_autorun.clear();} catch(Exception e){ list_plugin_autorun = new LinkedList<String>();}		
								
				for(File fle : list)
				{
					if(fle == null || i_read_config_file)
						continue;
					
					path = fle.getCanonicalPath().trim();
					
					if(!path.toLowerCase().trim().contains(".conf"))
						continue;
					
					fleConf = fle;
					
					break;
				}
			}
			
			
			
			if(fleConf == null || !fleConf.isFile())
				return false;
			
			sop("Analyzing config file --> " + path);
			
			BufferedReader br = new BufferedReader(new FileReader(fleConf));
			
			
			
			while((line = br.readLine()) != null)
			{
				line = line.replace("\"", "").trim();
				
				if(line.startsWith("#"))
					continue;
				
				lower = line.toLowerCase().trim();
				
				//
				//investigator_name
				//
				if(lower.startsWith("investigator_name"))
				{
					investigator_name = line.substring(17).trim();
					
					if(investigator_name.startsWith("="))
						investigator_name = investigator_name.substring(1).trim();
					
					if(investigator_name.startsWith(":"))
						investigator_name = investigator_name.substring(1).trim();
					
					if(investigator_name.startsWith("-"))
						investigator_name = investigator_name.substring(1).trim();
					
					sop("Setting investigator_name= \"" + investigator_name + "\"");
				}
				
				//
				//investigation_description
				//
				else if(lower.startsWith("investigation_description"))
				{
					investigation_description = line.substring(25).trim();
					
					if(investigation_description.startsWith("="))
						investigation_description = investigation_description.substring(1).trim();
					
					if(investigation_description.startsWith(":"))
						investigation_description = investigation_description.substring(1).trim();
					
					if(investigation_description.startsWith("-"))
						investigation_description = investigation_description.substring(1).trim();
					
					sop("Setting investigation_description= \"" + investigation_description + "\"");
				}
				
				//
				//profile
				//
				else if(lower.startsWith("profile"))
				{
					PROFILE = line.substring(7).trim();
					
					if(PROFILE.startsWith("="))
						PROFILE = PROFILE.substring(1).trim();
					
					if(PROFILE.startsWith(":"))
						PROFILE = PROFILE.substring(1).trim();
					
					if(PROFILE.startsWith("-"))
						PROFILE = PROFILE.substring(1).trim();
					
					sop("Setting profile= \"" + PROFILE + "\"");
				}
				
				//
				//plugin_autorun
				//
				else if(lower.startsWith("plugin_autorun"))
				{
					plugin_autorun = line.substring(14).trim();
					
					if(plugin_autorun.startsWith("="))
						plugin_autorun = plugin_autorun.substring(1).trim();
					
					if(plugin_autorun.startsWith(":"))
						plugin_autorun = plugin_autorun.substring(1).trim();
					
					if(plugin_autorun.startsWith("-"))
						plugin_autorun = plugin_autorun.substring(1).trim();
					
					if(!list_plugin_autorun.contains(plugin_autorun))
						list_plugin_autorun.add(plugin_autorun);
				}
				
			}//end while
			
			i_read_config_file = true;
			
			//
			//close file
			//
			br.close();
			
			//
			//Profile Autorun
			//
			if(list_plugin_autorun != null && list_plugin_autorun.size() > 0)
			{
				if(list_plugin_autorun.size() == 1)
					Start.intface.jpnlAdvancedAnalysisConsole.append_sp("Only 1 specified plugin to autorun: " + list_plugin_autorun.getFirst());
				else
					Start.intface.jpnlAdvancedAnalysisConsole.append_sp("[" + list_plugin_autorun.size() + "] Specified plugins to autorun: " + list_plugin_autorun.getFirst());
														
				for(int i = 1; i < list_plugin_autorun.size(); i++)
					Start.intface.jpnlAdvancedAnalysisConsole.append_sp(", " + list_plugin_autorun.get(i));
				
				Start.intface.jpnlAdvancedAnalysisConsole.append_sp("\n");					
				
				
				this.advanced_analysis_director = new Advanced_Analysis_Director(list_plugin_autorun, fle_volatility, fle_memory_image, PROFILE, path_fle_analysis_directory, file_attr_volatility, file_attr_memory_image, investigator_name, investigation_description, true, true);
				
			}
				
				
				
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "import_config_file", e);
		}
		
		return false;
	}
	
	public boolean sop(String out)
	{
		try
		{
			Interface.jpnlConsole.append(out);
						
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "sop", e);
		}
		
		return false;
	}
	
	public boolean sp(String out)
	{
		try
		{
			Interface.jpnlConsole.append_sp(out);			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "sop", e);
		}
		
		return false;
	}
	
	
	public boolean initialize_readpe()
	{
		try
		{
			//
			//WINDOWS
			//
			if(driver.isWindows)
			{
				
				if(Start.fleImportDirectory == null || !Start.fleImportDirectory.exists() || !Start.fleImportDirectory.isDirectory())
				{
					driver.sop("NOTE: I am terminating enumeration for readpe.exe, import directory does not appear to be established...") ;
					return false;
				}
				
				Thread thd = new Thread(new Runnable() 
				{
				    @Override
				    public void run() 
				    {
				    	try
				    	{
				    		LinkedList<File> list = new LinkedList<File>();
							list = driver.getFileListing(Start.fleImportDirectory, true, null, list);
							
							if(list != null && list.size() > 0)
							{
								//iterate to find dot.exe
								for(int i = 0; i < list.size() && Start.fle_readPe == null; i++)
								{
									try
									{
										if(list.get(i) == null)
											continue;
										
										if(list.get(i).getCanonicalPath().toLowerCase().trim().endsWith("readpe.exe"))
										{
											Start.fle_readPe = list.get(i);
											break;
										}
									}
									catch(Exception e)
									{
										continue;
									}
								}																
							}
							
							
							
				    	}
						catch(Exception e)
				    	{
							driver.eop(myClassName, "initialize_readpe thread", e);
				    	}
				    }
				});  
				thd.start();

			}
			else
			{
				//need to return to perform which cmd for Unix machine. 
			}
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "initialize_readpe", e);
		}
		
		return false;
	}
	
	
	
	public boolean initialize_dependencies_file()
	{
		try
		{
			//
			//WINDOWS
			//
			if(driver.isWindows)
			{
				
				if(Start.fleImportDirectory == null || !Start.fleImportDirectory.exists() || !Start.fleImportDirectory.isDirectory())
				{
					driver.sop("NOTE: I am terminating enumeration for readpe.exe, import directory does not appear to be established...") ;
					return false;
				}
				
				Thread thd = new Thread(new Runnable() 
				{
				    @Override
				    public void run() 
				    {
				    	try
				    	{
				    		LinkedList<File> list = new LinkedList<File>();
							list = driver.getFileListing(Start.fleImportDirectory, true, null, list);
							
							if(list != null && list.size() > 0)
							{
								//iterate to find dot.exe
								for(int i = 0; i < list.size() && Start.fle_readPe == null; i++)
								{
									try
									{
										if(list.get(i) == null)
											continue;
										
										if(list.get(i).getCanonicalPath().toLowerCase().trim().endsWith("dependencies.exe"))
										{
											Start.fle_dependencies = list.get(i);
											break;
										}
									}
									catch(Exception e)
									{
										continue;
									}
								}																
							}
							
							
							
				    	}
						catch(Exception e)
				    	{
							driver.eop(myClassName, "initialize_dependencies thread", e);
				    	}
				    }
				});  
				thd.start();

			}
			else
			{
				//need to return to perform which cmd for Unix machine. 
			}
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "initialize_dependencies", e);
		}
		
		return false;
	}
	
	public boolean initialize_graphviz()
	{
		try
		{
			//
			//WINDOWS
			//
			if(driver.isWindows)
			{
				
				if(Start.fleImportDirectory == null || !Start.fleImportDirectory.exists() || !Start.fleImportDirectory.isDirectory())
				{
					driver.sop("NOTE: I am terminating enumeration for graphviz dot.exe, import directory does not appear to be established...") ;
					return false;
				}
				
				Thread thd = new Thread(new Runnable() 
				{
				    @Override
				    public void run() 
				    {
				    	try
				    	{
				    		LinkedList<File> list = new LinkedList<File>();
							list = driver.getFileListing(Start.fleImportDirectory, true, null, list);
							
							if(list != null && list.size() > 0)
							{
								//iterate to find dot.exe
								for(int i = 0; i < list.size() && Start.fle_graphviz_dot == null; i++)
								{
									try
									{
										if(list.get(i) == null)
											continue;
										
										if(list.get(i).getCanonicalPath().toLowerCase().trim().endsWith(File.separator + "dot.exe"))
											Start.fle_graphviz_dot = list.get(i);
									}
									catch(Exception e)
									{
										continue;
									}
								}
								
								
							}
							
				    	}
						catch(Exception e)
				    	{
							driver.eop(myClassName, "initialize_graphviz thread", e);
				    	}
				    }
				});  
				thd.start();

			}
			else
			{
				//need to return to perform which cmd for Unix machine. 
			}
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "initialize_graphviz", e);
		}
		
		return false;
	}
	
	public boolean initialize_framework_volatility_executable()
	{
		try
		{
			if(Interface.fle_volatility == null)
			{
				//
				//Check if volatility is included in the import directory
				//
				LinkedList<File> list = new LinkedList<File>();
				list = driver.getFileListing(Start.fleImportMemoryAnalysisDirectory, true, null, list);
				boolean volatility_name_found = false;

				String file_name = "";

				if(list != null && !list.isEmpty())
				{
					//at least there are files, iterate through to select the first one that has volatility
					for(File fle : list)
					{
						if(fle == null || !fle.exists() || !fle.isFile() || !fle.getCanonicalPath().toLowerCase().trim().endsWith("exe"))
							continue;

						file_name = fle.getName().toLowerCase().trim();

						if(file_name.startsWith("volatility") || file_name.startsWith("vol"))
						{
							Interface.fle_volatility = fle;
							volatility_name_found = true;
							break;
						}
					}

					//check if anything with "volatility" in its name was found
					if(!volatility_name_found)
					{
						driver.directive("NOTE: I could not find volatility named executable, I'm searching for next executable to use in my analysis");

						for(File fle : list)
						{
							if(fle == null || !fle.exists() || !fle.isFile() || !fle.getCanonicalPath().toLowerCase().trim().endsWith(".exe"))
								continue;

							//take the first file found
							Interface.fle_volatility = fle;
							driver.directive("NOTE: I could not specifically find a volatility binary file at framework import directory: \n--> " + Start.fleImportMemoryAnalysisDirectory.getCanonicalPath() + "\n");
							driver.directive("I have selected the following memory analysis executable --> " + Interface.fle_volatility.getCanonicalPath());
							driver.directive("If this is not acceptable, remove this file from the import directory and select \"File --> Specify Volatility Executable\" to update the framework.\n");
							break;
						}										

					}
				}
			}//end if volatility == null
			
				
				
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
				
			
				
			//
			//File not found, notify user
			//
			driver.directive("NOTE: I could not locate volatility in my import path. \nIn the future, you can speed up the configuration process if you place the volatility executable binary file at:\n--> " + Start.fleImportMemoryAnalysisDirectory.getCanonicalPath());
			
			
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
			
			String file_name = "";
			
			if(list != null && !list.isEmpty())
			{
				//at least there are files, iterate through to select the first one that has volatility
				for(File fle : list)
				{
					if(fle == null || !fle.exists() || !fle.isFile())
						continue;
					
					file_name = fle.getName().toLowerCase().trim();
					
					//
					//omit config file
					//
					if(file_name.endsWith(".conf"))
						continue;
					
					//take the first file found
					Interface.fle_memory_image = fle;
					
					if(!list_image_files.contains(fle.getCanonicalPath()))
						list_image_files.add(fle.getCanonicalPath())	;
					
					break;
				}	
				
				//check if we are launching from automation
				if(Interface.automate_advanced_analysis_fle_memory_image != null && Interface.automate_advanced_analysis_fle_memory_image.isFile())
				{
					try
					{
						list_image_files.remove(Interface.fle_memory_image.getCanonicalPath());
					}
					catch(Exception e){}
					
					sop("Updating import file to file specified from advanced analysis automation --> " + Interface.automate_advanced_analysis_fle_memory_image.getName());
					Interface.fle_memory_image = Interface.automate_advanced_analysis_fle_memory_image;
					
					//add the new name
					if(!list_image_files.contains(Interface.fle_memory_image.getCanonicalPath()))
						list_image_files.add(Interface.fle_memory_image.getCanonicalPath())	;
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
	
	public boolean initial_configuration_complete_enable_gui()
	{
		try
		{
			this.jtfPluginSearch.setEditable(true);
			this.jtfPluginSearch.validate();
			
			jmnuitm_ReDraw_Report.setEnabled(true);
			jbtnInitiateAdvancedAnalysis_AdvancedAnalysis.setEnabled(true);
			this.jtfFile_XREF_SearchString.setEditable(true);
			jmnuitm_Import_Directory.setEnabled(true);
			this.jmnuitm_ExportSystemManifest.setEnabled(true);
			jmnuitm_AnalyseUserAssist.setEnabled(true);
			jmnuitm_ImportSystemManifest.setEnabled(true);
			jmnuitm_ImportSystemManifest_from_file_menu.setEnabled(true);
			jmnuitm_Initiate_Advanced_Analysis_SingleFile.setEnabled(true);
			jmnuitm_InitiateSnapshotAnalysis.setEnabled(true);
			
			if(AUTO_START_ADVANCED_ANALYSIS)
			{
				driver.directive("Initiating Auto Start of Advanced Analysis...\n\n");
				this.execute_advanced_analysis();
			}
			
			//
			//driver.directive("AUTO_START SNAPSHOT ANALYSIS in " + myClassName + " initial_configuration_complete_enable_gui mtd");
			//AUTO_INITIATE_SNAPSHOT_ANALYSIS();
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "initial_configuration_complete_enable_gui", e);
		}
		
		return false;
	}
	
	public boolean AUTO_INITIATE_SNAPSHOT_ANALYSIS()
	{
		try
		{
			if(jtaSnapshotAnalysisConsole == null)
			{								
				jtaSnapshotAnalysisConsole = new JTextArea_Solomon("", true, "Snapshot Analysls", false);				
				Start.intface.populate_export_btn(jtaSnapshotAnalysisConsole);
				Start.intface.jtabbedPane_MAIN.addTab("Snapshot Analysis", jtaSnapshotAnalysisConsole);								
			}
			else
				jtaSnapshotAnalysisConsole.clear();
			
			//get focus
			try	{	Start.intface.jtabbedPane_MAIN.setSelectedComponent(jtaSnapshotAnalysisConsole);}catch(Exception e){}
			
			fleSnapshotManifest_1 = new File("C:\\Users\\Solomon Sonya\\Desktop\\_manifest.txt");
			fleSnapshotManifest_2 = new File("C:\\Users\\Solomon Sonya\\Desktop\\_manifest2.txt");
			
			file_attr_manifest_snapshot_1 = new FileAttributeData(fleSnapshotManifest_1, true, true);
			file_attr_manifest_snapshot_2 = new FileAttributeData(fleSnapshotManifest_2, true, true);
			
			jtaSnapshotAnalysisConsole.append("Manifest File Snapshot Analysis initialized.\n" + driver.UNDERLINE);
			jtaSnapshotAnalysisConsole.append("Manifest Snapshot File [1]: " + fleSnapshotManifest_1);
			jtaSnapshotAnalysisConsole.append("Manifest Snapshot File [2]: " + fleSnapshotManifest_2);
			
			
			if(file_attr_manifest_snapshot_1.is_hashing_complete)
				jtaSnapshotAnalysisConsole.append("Manifest Snapshot File [1] Particulars: " + file_attr_manifest_snapshot_1.toString("\n"));
			if(file_attr_manifest_snapshot_2.is_hashing_complete)
				jtaSnapshotAnalysisConsole.append("Manifest Snapshot File [2] Particulars: " + file_attr_manifest_snapshot_2.toString("\n"));
			
			
			jtaSnapshotAnalysisConsole.append("\nImporting manifest [1]: " + fleSnapshotManifest_1.getName() + ". Please standby...");
			
			configure_gui_for_snapshot_analysis();
			
			//only execute 1st snapshot import. when finished, trigger to call the next one
			advanced_analysis_director_snapshot_1 = new Advanced_Analysis_Director(fleSnapshotManifest_1, 1, this);
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "AUTO_INITIATE_SNAPSHOT_ANALYSIS", e);
		}
		
		return false;
	}
	
	public boolean specify_profile(boolean override_to_query_user)
	{
		try
		{			
			list_profiles = new LinkedList<String>();
			
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
			
			
			//
			//determine if we have profile
			//
			if(PROFILE == null || PROFILE.length() < 2 || override_to_query_user)
			{
				if(list_profiles == null || list_profiles.isEmpty())
				{
					if(Interface.fle_memory_image != null && Interface.fle_memory_image.exists() && Interface.fle_memory_image.isFile())
						PROFILE = driver.jop_Query("Please specify profile to load for this analysis:", "* Specify Profile for Image [" + Interface.fle_memory_image.getName() + "]");
					else
						PROFILE = driver.jop_Query("* * * Please specify profile to load for this analysis:", "* Specify Profile *");
				}
				else
				{
					//otw, convert list of plugins to array to send to the JOP query message
					String [] array = new String[list_profiles.size()];
					
					for(int i = 0; i < list_profiles.size(); i++)
					{
						array[i] = list_profiles.get(i);
					}
					
					if(Interface.fle_memory_image != null && Interface.fle_memory_image.exists() && Interface.fle_memory_image.isFile())
						PROFILE = ""+ driver.jop_queryJComboBox("* Please specify profile to load for this analysis:", "Specify Profile for Image [" + Interface.fle_memory_image.getName() + "]", array);
					else
						PROFILE = ""+ driver.jop_queryJComboBox("* * Please specify profile to load for this analysis:", "Specify Profile", array);
				}
			}
						
			
//			
//			//MANUAL ENTRY IF LIST FAILED ABOVE
//			if(profile == null || profile.trim().equals("") || profile.equalsIgnoreCase("null"))
//				profile = driver.jop_Query("No profile has been entered. \nPlease specify profile to load for this analysis:", "Specify Profile");
//			
//			if(profile == null)
//			{
//				driver.jop_Error("NOTE: No valid profile has been specified. This could contaminate results of our analysis...");
//				return false;
//			}
			
			if(PROFILE == null)
				PROFILE = "";
			
			//normalize profile (remove white spaces and description
			String profile = PROFILE;

			profile = profile.trim();
			
			String [] array = profile.split(" ");
			
			if(array == null || array.length < 1)
				array = profile.split("\t");
			
			if(array == null || array.length < 1)
				array = profile.split("-");
			
			if(array != null && array.length > 0)
				profile = array[0].trim();
									
			PROFILE = profile.trim();
			
			
			
			initial_configuration_complete_enable_gui();
			
			if(Plugin.list_plugins == null)
				this.jlblNumPluginsDisplayed.setText(num_plugin_displayed_text + "[0]");
			else
				this.jlblNumPluginsDisplayed.setText(num_plugin_displayed_text + "[" + Plugin.list_plugins.size() + "]");
			
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
	
	public static String querySelectProfile(File fleMemoryImage, String default_profile)
	{
		try
		{
			String profile = null;
			
			if(list_profiles == null || list_profiles.isEmpty())
			{
				if(fleMemoryImage != null && fleMemoryImage.exists() && fleMemoryImage.isFile())
					profile = driver.jop_Query("Please specify profile to load for this analysis:", "* Specify Profile for Image [" + fleMemoryImage.getName() + "]");
				else
					profile = driver.jop_Query("Please specify profile to load for this analysis:", "* Specify Profile *");
				
				if(profile == null)
				{
					profile = default_profile;
					
					if(profile != null)
					{
						driver.jop_Message("No valid profile was specified. I am going to load with this profile [" + profile + "]");
					}
				}
			}
			
			else
			{
				//otw, convert list of plugins to array to send to the JOP query message
				String [] array = new String[list_profiles.size()];
				
				for(int i = 0; i < list_profiles.size(); i++)
				{
					array[i] = list_profiles.get(i);
				}
				
				if(fleMemoryImage != null && fleMemoryImage.exists() && fleMemoryImage.isFile())
					profile = ""+ driver.jop_queryJComboBox("Please specify profile to load for this analysis:", "Specify Profile for Image [" + fleMemoryImage.getName() + "]", array);
				else
					profile = ""+ driver.jop_queryJComboBox("Please specify profile to load for this analysis:", "Specify Profile", array);
			}
			
			if(profile == null || profile.trim().equals("") || profile.equalsIgnoreCase("null"))
				profile = driver.jop_Query("No profile has been entered. \nPlease specify profile to load for this analysis:", "Specify Profile");
			
			if(profile == null)
			{
				
				profile = default_profile;
				
				if(profile != null)
					driver.jop_Message("No valid profile was specified. I am going to load with this profile [" + profile + "]");
				
				else
					driver.jop_Error("NOTE: No valid profile has been specified. This could contaminate results of our analysis...");
				
				return profile;
			}
			
			//normalize
			profile = profile.trim();
			
			String [] array = profile.split(" ");
			
			if(array == null || array.length < 1)
				array = profile.split("\t");
			
			if(array == null || array.length < 1)
				array = profile.split("-");
			
			if(array != null && array.length > 0)
				profile = array[0].trim();
									
			
			
			return profile;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "querySelectProfile", e);
		}
		
		return null;
	}
	
	public boolean update_visible_plugins()
	{
		try
		{
			String text = this.jtfPluginSearch.getText().toLowerCase().trim();
			
			if(text.equals("") || text.equals("*"))
			{
				//repopulate all
				this.jpnlPlugins.removeAll();
				
				jpnlPlugins.setLayout(new GridLayout((int)Math.ceil((Plugin.list_plugins.size() + 0.0)/num_plugin_cols), num_plugin_cols, 5, 5));
				
				for(Plugin plugin : Plugin.list_plugins)
					jpnlPlugins.add(plugin);
				
				
				if(Plugin.list_plugins == null)
					this.jlblNumPluginsDisplayed.setText(num_plugin_displayed_text + "[0]");
				else
					this.jlblNumPluginsDisplayed.setText(num_plugin_displayed_text + "[" + Plugin.list_plugins.size() + "]");
				
				this.jpnlPlugin_CONTAINER.repaint();
				this.jpnlPlugin_CONTAINER.validate();		
				
				return true;
			}
			
			LinkedList<Plugin> list = new LinkedList<Plugin>();
			
			boolean starts_with = false;
			boolean ends_with = false;
			
			if(!this.jcbPluginSearch_SearchPluginDescription.isSelected() && !this.jcbPluginSearch_SearchPluginName.isSelected())
				this.jcbPluginSearch_SearchPluginName.setSelected(true);
			
			if(text.startsWith("*") && text.endsWith("*"))
			{
				text = text.replace("*", "");
				//do nothing else, bcs this is just a "contains"
			}
			
			else if(text.startsWith("*"))
			{
				text = text.replace("*", "");
				ends_with = true;
			}
			
			else if(text.endsWith("*"))
			{
				text = text.replace("*", "");
				starts_with = true;
			}
							
			boolean search_plugin_name = this.jcbPluginSearch_SearchPluginName.isSelected();
			boolean search_plugin_description = this.jcbPluginSearch_SearchPluginDescription.isSelected();
			
			String plugin_name = "";
			String plugin_description = "";
			
			//search for plugins
			for(Plugin plugin : Plugin.list_plugins)
			{
				try
				{
					if(plugin == null)
						continue; 
					
					plugin_name = plugin.plugin_name.toLowerCase().trim();
					plugin_description = plugin.plugin_description.toLowerCase().trim(); 
					
					if(search_plugin_name)
					{
						if(starts_with)
						{
							if(plugin_name.startsWith(text) && !list.contains(plugin))
								list.add(plugin);
						}
						else if(ends_with)
						{
							if(plugin_name.endsWith(text) && !list.contains(plugin))
								list.add(plugin);
						}
						else if(plugin_name.contains(text) && !list.contains(plugin))
							list.add(plugin);										
					}
					
					//
					//plugin description
					//
					if(search_plugin_description)
					{
						if(starts_with)
						{
							if(plugin_description.startsWith(text) && !list.contains(plugin))
								list.add(plugin);
						}
						else if(ends_with)
						{
							if(plugin_description.endsWith(text) && !list.contains(plugin))
								list.add(plugin);
						}
						else if(plugin_description.contains(text) && !list.contains(plugin))
							list.add(plugin);										
					}
				}
				catch(Exception e)
				{
					driver.directive("check plugin search description...");					
				}
				
			}
			
			
			if(list == null)
				this.jlblNumPluginsDisplayed.setText(num_plugin_displayed_text + "[0]");
			else
				this.jlblNumPluginsDisplayed.setText(num_plugin_displayed_text + "[" + list.size() + "]");
			
			//repopulate all
			this.jpnlPlugins.removeAll();
			this.jpnlPlugin_CONTAINER.repaint();
			this.jpnlPlugin_CONTAINER.validate();		
			
			//
			//verify we have at least 1 entry
			//
			if(list == null || list.size() < 1)
			{
				driver.jop_Error("No results returned from selected query!", false);
				return false;
			}
			
			//repopulate all
			this.jpnlPlugins.removeAll();
			
			jpnlPlugins.setLayout(new GridLayout((int)Math.ceil((list.size() + 0.0)/num_plugin_cols), num_plugin_cols, 5, 5));
			
			for(Plugin plugin : list)
				jpnlPlugins.add(plugin);
				
			
			this.jpnlPlugin_CONTAINER.repaint();
			this.jpnlPlugin_CONTAINER.validate();			
			
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "update_visible_plugins", e);
		}
		
		return false;
	}
	
	public boolean specify_timezone()
	{
		try
		{
			String time_zone_country =  ""+ driver.jop_queryJComboBox("Please TimeZone Country:", "Specify TimeZone Country", driver.array_timezone_countries);
			
			if(time_zone_country == null || time_zone_country.toLowerCase().trim().equals("null"))
				return false;
			
			LinkedList<String> list = new LinkedList<String>();
			String zone_lower = null;
			String country_lower = time_zone_country.toLowerCase().trim();
			for(String zone : driver.array_timezones)
			{
				zone_lower = zone.toLowerCase().trim();
				
				if(zone_lower.startsWith(country_lower))
					list.add(zone);
			}
			
			if(list.size() == 1)
			{
				driver.TIME_ZONE = list.removeFirst().trim();
				driver.jop_Warning("TimeZone has been set to: [" + driver.TIME_ZONE + "]", "Set TimeZone");
				return true;
			}
			else
			{
				String [] array = new String[list.size()];
				
				for(int i = 0; i < list.size(); i++)
				{
					array[i] = list.get(i);
				}
				
				String selected_time_zone =  ""+ driver.jop_queryJComboBox("Please Select TimeZone:", "Specify TimeZone", array);
				
				if(selected_time_zone == null || selected_time_zone.toLowerCase().equals("null"))
					return false;
				
				//otw
				driver.TIME_ZONE = selected_time_zone.trim();
				
				driver.jop_Warning("TimeZone has been set to: [" + driver.TIME_ZONE + "]", "Set TimeZone");
			}
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "specify_timezone" ,e);
		}
		
		return false;
	}
	
	public boolean open_selected_container_files()
	{
		try
		{
			if(File_XREF.tree_container_files_with_search_hits_for_Container_JTAB == null || File_XREF.tree_container_files_with_search_hits_for_Container_JTAB.isEmpty())
			{
				driver.jop("Punt! There are no container files to open! Please retry your xref search...");
				return false;
			}
			
			boolean at_least_one_file_selected = false;
			
			for(Node_Generic node : File_XREF.tree_container_files_with_search_hits_for_Container_JTAB.values())
			{
				try
				{
					if(node == null || node.fle == null || !node.fle.isFile() || !node.fle.exists() || node.fle.length() < 1 || node.jcb == null || !node.jcb.isSelected())
						continue;
					
					//try to open output directory
					try	{	driver.open_file(node.fle);	}	catch(Exception e){}
					
					at_least_one_file_selected = true;
					
				}
				catch(Exception e)
				{
					continue;
				}
			}
			
			if(!at_least_one_file_selected)
			{
				driver.jop("NOTE: You need to select at least one file to open!");
				return false;
			}
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "open_selected_container_files", e);
		}
		
		return false;
	}
	
	public boolean set_jcheckbox_selection_state(TreeMap<String, Node_Generic> tree, boolean set_state_selected)
	{
		try
		{
			if(tree == null || tree.size() < 1)
				return false;
			
			for(Node_Generic node : tree.values())
			{
				node.jcb.setSelected(set_state_selected);
				node.jcb.validate();
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "set_jcheckbox_selection_state", e);
		}
		
		return false;
	}
	
	public boolean dump_selected_files_XREF()
	{
		try
		{
			if(File_XREF.tree_dump_file_entries_FILEDUMP_XREF == null || File_XREF.tree_dump_file_entries_FILEDUMP_XREF.isEmpty())
			{
				
				driver.jop("Punt! There are no filescan entries to dump! Please retry your xref search...");
				return false;
			}
			
			
			boolean at_least_one_file_selected = false;
			Node_Generic node_last_to_start_execution = null;
			boolean process_memdump = false;
			
			for(Node_Generic node : File_XREF.tree_dump_file_entries_FILEDUMP_XREF.values())
			{
				try
				{
					process_memdump = false;
					if(node != null && node.plugin_name != null && node.pid != null && node.pid.length() > 0 && node.jcb != null && node.jcb.isSelected())
					{
						process_memdump = true;
					}
					else if(node == null || !node.jcb.isSelected())
						continue;
					
					//ensure advanced analysis instance exists...
					if(advanced_analysis_director == null)
						advanced_analysis_director = new Advanced_Analysis_Director(fle_volatility, fle_memory_image, PROFILE, path_fle_analysis_directory, file_attr_volatility, file_attr_memory_image, investigator_name, investigation_description, false, false);
					
					//
					//determine dump type
					//
					
					if(process_memdump)
					{
						node.plugin_execution =  new Analysis_Plugin_memdump(null, advanced_analysis_director, "memdump", "Dump the addressable memory for a process", true, Start.intface.jpnlConsole, node.pid);
					}
					else	//else, FILESCAN dump file!
					{
						node.plugin_dumpfile = new Analysis_Plugin_DumpFiles(null, advanced_analysis_director, "dumpfiles -Q " + node.offset_p, "Dump Windows Event Logs ", true, Start.intface.jpnlConsole, node.file_name, node.offset_p);
					}
				
					node_last_to_start_execution = node;
					
					at_least_one_file_selected = true;
					
				}
				catch(Exception e)
				{
					continue;
				}
			}
			
			if(!at_least_one_file_selected)
			{
				driver.jop("NOTE: You need to select at least one file to dump!");
				return false;
			}
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "dump_selected_files_XREF", e);
		}
		
		return false;
	}
	
	public boolean import_advanced_analysis_directory(File_XREF xref, boolean execute_manifest_export)
	{
		try
		{
			
			File import_directory = driver.querySelectFile(true, "Please select advanced analysis directory to import", JFileChooser.DIRECTORIES_ONLY, null);
			
			if(import_directory == null)
				return false;
			
			//remove prev tabs if present
			//remove consoles if preloaded
			try	
			{	
				int count = 0;
				while(this.jtabbedpane_AdvancedAnalysis.getTabCount() > 1 && ++count < 100)
				{					
					try
					{
						jtabbedpane_AdvancedAnalysis.remove(1);
					}catch(Exception ee){}
				}
				
				jtabbedpane_AdvancedAnalysis.validate();
			}
			catch(Exception e){}
			
			
			//inventory directory for files
			LinkedList<File> list = new LinkedList<File>();
			
			list = driver.getFileListing(import_directory, true, null, list);
			
			if(list != null && list.size() > 0)
			{
				advanced_analysis_director = new Advanced_Analysis_Director(list, import_directory, fle_volatility, fle_memory_image, PROFILE, path_fle_analysis_directory, file_attr_volatility, file_attr_memory_image, investigator_name, investigation_description, true, xref);
				advanced_analysis_director.EXECUTE_EXPORT_MANIFEST = execute_manifest_export;
			}
			
			return true;			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "import_advanced_analysis_directory", e);
		}
		
		return false;
	}
	
	public boolean open_html_analysis_file()
	{
		try
		{
			File analysis_html = null;
			
			if(fle_analysis_directory == null || !fle_analysis_directory.exists() || !fle_analysis_directory.isDirectory())
			{
				driver.jop("Output directory has not been established yet! \nPlease either Initiate Advanced Analysis or Import Analysis Directory.");
				return false;
			}
			
			LinkedList<File> list = new LinkedList<File>();
			list = driver.getFileListing(fle_analysis_directory, true, null, list);
			String file_name = null;
			//iterate through and look for analysis file
			for(File fle : list)
			{
				if(fle == null)
					continue;
				
				file_name = fle.getName().toLowerCase().trim();
				
				if(file_name.startsWith("analysis_report_") && file_name.endsWith(".html"))
				{
					analysis_html = fle;
					break;
				}
			}
			
			if(analysis_html != null && analysis_html.exists() && analysis_html.isFile())
				driver.open_file(analysis_html);
			
			else
			{
				driver.jop("I was not able to find analysis_html file to open from current working directory!");
				return false;
			}
			
			
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "open_html_analysis_file", e, true);
		}
		
		return false;
	}
	
	public boolean specify_yara_signature_file()
	{
		try
		{
			File fle = driver.querySelectFile(true, "Please select File containing YARA signatures to import", JFileChooser.FILES_ONLY, null);
			
			if(fle == null || !fle.isFile() || !fle.exists())
				return false;
			
			fle_yara_signature_file = fle;
			
			sop("YARA signature file has been set to " + fle.getCanonicalPath());
			
			try	{ this.jcb_IncludeYaraSignatureFile.setSelected(true);} catch(Exception e){}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "specify_yara_signature_file", e);
		}
		
		return false;
	}
	
	public boolean export_system_manifest()
	{
		try
		{
			if(advanced_analysis_director == null || advanced_analysis_director.tree_PROCESS == null || advanced_analysis_director.tree_PROCESS.isEmpty())
			{								
				Object [] buttons = new Object[] {"Initiate Advanced Analysis", "Import Advanced Analysis Directory", "Canel"};
				int selection = driver.jop_custom_buttons("It looks like you have not executed Advanced Analysis or imported results from a previous analysis directory. \n\nPlease choose how to proceed:\n", "Advanced Analysis Required Before Continuing...", buttons);
			
				if(selection == 0)
				{
					try	{	jtabbedPane_MAIN.setSelectedIndex(1);	}	catch(Exception e){}
					advanced_analysis_director = new Advanced_Analysis_Director(fle_volatility, fle_memory_image, PROFILE, path_fle_analysis_directory, file_attr_volatility, file_attr_memory_image, investigator_name, investigation_description, true, true);					
					return true;
				}
				
				else if(selection == 1)
				{
					return import_advanced_analysis_directory(null, true);
				}
			}
			
			//otw, import/load was successful, export manifest file
			advanced_analysis_director.write_manifest(Advanced_Analysis_Director.WRITE_MANIFEST_DELIMITER);
			
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "export_system_manifest", e);
		}
		
		return false;
	}
	
	public boolean analyze_user_assist()
	{
		try
		{
			//this.advanced_analysis_director = new Advanced_Analysis_Director(list_plugin_autorun, fle_volatility, fle_memory_image, PROFILE, path_fle_analysis_directory, file_attr_volatility, file_attr_memory_image, investigator_name, investigation_description, true);
			
			if(advanced_analysis_director == null || advanced_analysis_director.plugin_userassist == null || advanced_analysis_director.tree_user_assist_linked_by_time_focused == null || advanced_analysis_director.tree_user_assist_linked_by_time_focused.isEmpty())
			{
				LinkedList<String> list = new LinkedList<String>();
				list.add("userassist");
				
				//autorun userassist
				this.advanced_analysis_director = new Advanced_Analysis_Director(list, fle_volatility, fle_memory_image, PROFILE, path_fle_analysis_directory, file_attr_volatility, file_attr_memory_image, investigator_name, investigation_description, true, true);				
			}
			else
			{
				driver.jop("User Assist is already visible! \nNo further action is necessary...");
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_user_assist", e);
		}
		
		return false;
	}
	
	public boolean import_system_manifest()
	{
		try
		{
			File fle = driver.querySelectFile(true, "Please select Manifest File", JFileChooser.FILES_ONLY, null);
			
			if(fle != null && fle.exists() && fle.isFile())
			{
				advanced_analysis_director = new Advanced_Analysis_Director(fle, -1, null);
				
				IMPORT_SYSTEM_MANIFEST_RUN_AT_LEAST_ONCE = true;
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "import_system_manifest", e);
		}
		
		return false;
	}
	
	
	public boolean initiate_snapshot_analysis()
	{
		try
		{
			if(jtaSnapshotAnalysisConsole == null)
			{								
				jtaSnapshotAnalysisConsole = new JTextArea_Solomon("", true, "Snapshot Analysls", false);				
				Start.intface.populate_export_btn(jtaSnapshotAnalysisConsole);
				Start.intface.jtabbedPane_MAIN.addTab("Snapshot Analysis", jtaSnapshotAnalysisConsole);								
			}
			else
				jtaSnapshotAnalysisConsole.clear();
			
			//get focus
			try	{	Start.intface.jtabbedPane_MAIN.setSelectedComponent(jtaSnapshotAnalysisConsole);}catch(Exception e){}
			
			fleSnapshotManifest_1 = driver.querySelectFile(true, "Please select snapshot manifest file 1", JFileChooser.FILES_ONLY, driver.LAST_FILE_SELECTED);
			
			if(fleSnapshotManifest_1 == null)
				return false;
			
			if(!fleSnapshotManifest_1.exists() || !fleSnapshotManifest_1.isFile() || fleSnapshotManifest_1.length() < 10)
			{
				driver.jop_Error("It appears an invalid file was selected.\nPlease try again if necessary...");
				return false;
			}
			
			fleSnapshotManifest_2 = driver.querySelectFile(true, "Please select snapshot manifest file 2", JFileChooser.FILES_ONLY, driver.LAST_FILE_SELECTED);
			
			if(fleSnapshotManifest_2 == null || !fleSnapshotManifest_2.exists() || !fleSnapshotManifest_2.isFile() || fleSnapshotManifest_2.length() < 10)
			{
				driver.jop_Error("It appears an invalid snapshot manifest 2 file was selected.\nI cannot initiate snapshot analysis if one of the manifest input files are invalid.\nPlease try again if necessary...");
				return false;
			}
			
			if(fleSnapshotManifest_1.getCanonicalPath().equals(fleSnapshotManifest_2.getCanonicalPath()))
			{
				driver.jop_Error("Punt!!! System Manifest Snapshot File [1] must be different than System Manifest Snapshot File [2]");
				return false;
			}
			
			file_attr_manifest_snapshot_1 = new FileAttributeData(fleSnapshotManifest_1, true, true);
			file_attr_manifest_snapshot_2 = new FileAttributeData(fleSnapshotManifest_2, true, true);
			
			jtaSnapshotAnalysisConsole.append("Manifest File Snapshot Analysis initialized.\n" + driver.UNDERLINE);
			jtaSnapshotAnalysisConsole.append("Manifest Snapshot File [1]: " + fleSnapshotManifest_1);
			jtaSnapshotAnalysisConsole.append("Manifest Snapshot File [2]: " + fleSnapshotManifest_2);
			
			
			if(file_attr_manifest_snapshot_1.is_hashing_complete)
				jtaSnapshotAnalysisConsole.append("Manifest Snapshot File [1] Particulars: " + file_attr_manifest_snapshot_1.toString("\n"));
			if(file_attr_manifest_snapshot_2.is_hashing_complete)
				jtaSnapshotAnalysisConsole.append("Manifest Snapshot File [2] Particulars: " + file_attr_manifest_snapshot_2.toString("\n"));
			
			
			jtaSnapshotAnalysisConsole.append("\nImporting manifest [1]: " + fleSnapshotManifest_1.getName() + ". Please standby...");
			
			configure_gui_for_snapshot_analysis();
			
			//only execute 1st snapshot import. when finished, trigger to call the next one
			advanced_analysis_director_snapshot_1 = new Advanced_Analysis_Director(fleSnapshotManifest_1, 1, this);
			
			//wait to trigger by completion of the first snapshot to commence snapshot number 2
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "initiate_snapshot_analysis", e);
		}
		
		return false;
	}
	
	public boolean configure_gui_for_snapshot_analysis()
	{
		try
		{
			this.jtabbedpane_SnapshotAnalysis_1 = new JTabbedPane(JTabbedPane.LEFT);
			this.jtabbedpane_SnapshotAnalysis_2 = new JTabbedPane(JTabbedPane.LEFT);
			
			jtabbedpane_AdvancedAnalysis.addTab("Snapshot Manifest Analysis 1 [" + this.fleSnapshotManifest_1.getName() + "]", jtabbedpane_SnapshotAnalysis_1);
			jtabbedpane_AdvancedAnalysis.addTab("Snapshot Manifest Analysis 2 [" + this.fleSnapshotManifest_2.getName() + "]", jtabbedpane_SnapshotAnalysis_2);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "configure_gui_for_snapshot_analysis", e);
		}
		
		return false;
	}
	
	/**
	 * continuation mtd from initiate_snapshot_analysis
	 * @return
	 */
	public boolean trigger_commence_snspshot_analysis_SNAPSHOT_2()
	{
		try
		{
			jtaSnapshotAnalysisConsole.append("DONE! Importing manifest [2]: " + fleSnapshotManifest_2.getName() + ". Please standby...");
			advanced_analysis_director_snapshot_2 = new Advanced_Analysis_Director(fleSnapshotManifest_2, 2, this);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "trigger_commence_snspshot_analysis_SNAPSHOT_2", e);
		}
		
		return false;
		
	}
	
	public boolean trigger_execute_snspshot_analysis()
	{
		try
		{
			jtaSnapshotAnalysisConsole.append("DONE! Import complete. Starting comparison analysis.");
			
			//
			//Phase 1: Search for added artifacts
			//
			snapshot_manifest_analysis = new Snapshot_Manifest_Analysis(this, this.advanced_analysis_director_snapshot_1, this.advanced_analysis_director_snapshot_2);
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "trigger_execute_snspshot_analysis", e);
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
			
			else if(ae.getSource() == jmnuitm_Initiate_Advanced_Analysis_Entire_Directory)
			{
				advanced_analysis_director_MEMORY_IMAGES = new Advanced_Analysis_Director(this, null);
			}
			
			else if(ae.getSource() == jmnuitm_InitiateSnapshotAnalysis)
			{
				initiate_snapshot_analysis();
			}
			
			else if(ae.getSource() == jmnuitm_Only_Show_Button_If_Execution_Plugins_Detected)
			{
				Analysis_Report_Container_Writer.ONLY_PRINT_EXECUTION_PLUGINS_IF_ADVANCED_ANALYSIS_INITIATED = true;
				this.sop("Only print Execution Plugins button in Advanced Analysis HTML Report is set to " + Analysis_Report_Container_Writer.ONLY_PRINT_EXECUTION_PLUGINS_IF_ADVANCED_ANALYSIS_INITIATED);
			}
			
			else if(ae.getSource() == jmnuitm_Always_Show_Button_Even_If_Execution_Plugins_Not_Detected)
			{
				Analysis_Report_Container_Writer.ONLY_PRINT_EXECUTION_PLUGINS_IF_ADVANCED_ANALYSIS_INITIATED = false;
				this.sop("Only print Execution Plugins button in Advanced Analysis HTML Report is set to " + Analysis_Report_Container_Writer.ONLY_PRINT_EXECUTION_PLUGINS_IF_ADVANCED_ANALYSIS_INITIATED + ". I will always display Execution Plugins option in the export Analysis Report.");
			}
			
			else if (ae.getSource() == jmnuitm_ImportSystemManifest_from_file_menu)
			{
				
				if(IMPORT_SYSTEM_MANIFEST_RUN_AT_LEAST_ONCE)
				{
					String prompt = "At this time, only one system load snapshot action should be executed per program instantiation. \n\nIt is recommended to restart the program in order to re-import a new system snapshot.\n\nProceeding (without program restart) may cause unexpected results. \n\nDo you wish to continue?";
					
					if(driver.jop_Confirm(prompt, "It is not recommended to proceed without restarting " + driver.NAME) == JOptionPane.YES_OPTION)
					{
						driver.sop("User has been warned but selected to override. Proceeding to import manifest without program restart. System may cause unexpected results...");
						import_system_manifest();
					}
				}
				else
					import_system_manifest();
			}
			
			else if(ae.getSource() == jmnuitm_ImportSystemManifest)
			{
				if(IMPORT_SYSTEM_MANIFEST_RUN_AT_LEAST_ONCE)
				{
					String prompt = "At this time, only one system load snapshot action should be executed per program instantiation. \n\nIt is recommended to restart the program in order to re-import a new system snapshot.\n\nProceeding (without program restart) may cause unexpected results. \n\nDo you wish to continue?";
					
					if(driver.jop_Confirm(prompt, "It is not recommended to proceed without restarting " + driver.NAME) == JOptionPane.YES_OPTION)
					{
						driver.sop("User has been warned but selected to override. \nProceeding to import manifest without program restart. \n * * * Program execution may cause unexpected results * * * ");
						import_system_manifest();
					}
				}
				else
					import_system_manifest();
			}
			
			else if(ae.getSource() == jmnuitm_Initiate_Advanced_Analysis_SingleFile)
			{
				execute_advanced_analysis();
				
				try	{ this.jtabbedPane_MAIN.setSelectedIndex(1); } catch(Exception e){}
			}
			
			else if(ae.getSource() == this.jmnuitm_AnalyseUserAssist)
			{
				//prevent additional executions of this action since it is automatic from here on (i.e., after this class is called to execute the function
				try	{	jmnuitm_AnalyseUserAssist.setEnabled(false);} catch(Exception e){}
				
				analyze_user_assist();
			}
			
			else if(ae.getSource() == jmnuitm_ExportSystemManifest)
			{
				export_system_manifest();
			}
			
			else if(ae.getSource() == this.jmnuitm_DataXREF_Specify_YARA_Signature_File)
			{
				specify_yara_signature_file();
			}
			
			else if(ae.getSource() == jmnuitm_Open_Report)
			{
				open_html_analysis_file();
			}
			
			else if(ae.getSource() == jbtnSpecifySearchDirectory)
			{
				specify_investigation_output_directory(2);
			}
			
			else if (ae.getSource() == jmnuitm_Import_Directory)
			{
				import_advanced_analysis_directory(null, false);
			}
			
			else if(ae.getSource() == this.jbtnOpenSelectedFiles)
			{
				open_selected_container_files();
			}
			
			else if(ae.getSource() == this.jbtnDumpFiles_Open_Working_Directory)
			{
				//try to open output directory
				try	{	driver.open_file(new File(advanced_analysis_director.path_fle_analysis_directory));	}	catch(Exception e){}
			}
			
			else if(ae.getSource() == this.jbtnDumpSelectedFiles)
			{
				dump_selected_files_XREF();
			}
			
			else if(ae.getSource() == this.jbtnSelectAllFiles_DumpFiles)
			{
				set_jcheckbox_selection_state(File_XREF.tree_dump_file_entries_FILEDUMP_XREF, true);
			}
			else if(ae.getSource() == this.jbtnDeSelectAllFiles_DumpFiles)
			{
				set_jcheckbox_selection_state(File_XREF.tree_dump_file_entries_FILEDUMP_XREF, false);
			}
			
			else if(ae.getSource() == this.jbtnSelectAllFiles_ContainerFiles)
			{
				set_jcheckbox_selection_state(File_XREF.tree_container_files_with_search_hits_for_Container_JTAB, true);
			}
			
			else if(ae.getSource() == this.jbtnDeSelectAllFiles_ContainerFiles)
			{
				set_jcheckbox_selection_state(File_XREF.tree_container_files_with_search_hits_for_Container_JTAB, false);
			}
			
			else if(ae.getSource() == this.jtfFile_XREF_SearchString && !this.jtfFile_XREF_SearchString.getText().trim().equals(""))
			{
				this.jtfFile_XREF_SearchString.setEditable(false);
				file_xref = new File_XREF(this);
			}
			
			else if(ae.getSource() == this.jbtn_open_advanced_analysis_open_working_directory)
			{
				driver.open_file(fle_analysis_directory);
			}
			
			else if(this.jpnlAdvancedAnalysisConsole != null && ae.getSource() == this.jpnlAdvancedAnalysisConsole.jtf)
			{
				driver.directive("ready to process instruction from user");
			}
			
			else if(ae.getSource() == jrbAnalysisReport_ProcessInformationTree_ProduceChildProcessTree_Enabled)
			{
				Dependency_File_Writer_Tree.use_recursion_to_produce_process_call_tree = true;
				sop("Recursion is enabled to produce process call tree.");
			}
			
			else if(ae.getSource() == jrbAnalysisReport_Handles_BifurcateIntoMultipleSubTypes)
			{
				Dependency_File_Writer_Tree.handles_bifurcate_output_into_multiple_subtypes = true;
				sop("Handles output bifurcation into multiple subtypes is enabled");
			}
			
			else if(ae.getSource() == jrbAnalysisReport_Handles_ProduceOutputInSingleType)
			{
				Dependency_File_Writer_Tree.handles_bifurcate_output_into_multiple_subtypes = false;
				sop("Handles output bifurcation into multiple subtypes is disabled");
			}
			
			else if(ae.getSource() == jrbAnalysisReport_ProcessInformationTree_ProduceChildProcessTree_Disabled)
			{
				Dependency_File_Writer_Tree.use_recursion_to_produce_process_call_tree = false;
				sop("Recursion is disabled to produce process call tree.");
			}
			
			else if(ae.getSource() == jmnuitm_Set_Node_Length_PROCESS_TREE)
			{
				Analysis_Report_Container_Writer.set_node_length_PROCESS_TREE(-1);
			}
			
			else if(ae.getSource() == jmnuitm_Set_Div_Height_PROCESS_TREE)
			{
				Analysis_Report_Container_Writer.set_initial_div_height_PROCESS_TREE(-1);
			}
			
			else if(ae.getSource() == jmnuitm_Set_Div_Width_PROCESS_TREE)
			{
				Analysis_Report_Container_Writer.set_initial_div_width_PROCESS_TREE(-1);
			}
			
			else if(ae.getSource() == this.jmnuitm_ReDraw_Report)
			{
				redraw_advanced_analysis_report();
			}
			
			else if(ae.getSource() == jtfPluginSearch)
			{
				update_visible_plugins();
			}
			
			else if(ae.getSource() == jmnuitm_Set_Node_Length_PROCESS_INFORMATION_TREE)
			{
				Analysis_Report_Container_Writer.set_node_length_PROCESS_INFORMATION_TREE(-1);
			}
			
			else if(ae.getSource() == jmnuitm_Set_Div_Height_PROCESS_INFORMATION_TREE)
			{
				Analysis_Report_Container_Writer.set_initial_div_height_PROCESS_INFORMATION_TREE(-1);
			}
			
			else if(ae.getSource() == jmnuitm_Set_Div_Width_PROCESS_INFORMATION_TREE)
			{
				Analysis_Report_Container_Writer.set_initial_div_width_PROCESS_INFORMATION_TREE(-1);
			}
			
			else if(ae.getSource() == jbtnInitiateAdvancedAnalysis_AdvancedAnalysis)
			{
				execute_advanced_analysis();
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
			
			else if(ae.getSource() == jbtnSnapshotAnalysis)
			{
				commence_snapshot_analysis();
			}
			
			else if(ae.getSource() == jbtnAnalysisReport)
			{
				launch_plugin_analysis_report();
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
			
			else if(ae.getSource() == jmnuitm_Enable_Search_TF_XREF)
			{
				try	{	this.jtfFile_XREF_SearchString.setEditable(true); } catch(Exception e){}
			}
			
			else if(ae.getSource() == jmnuitm_Specify_Investigation_Output_Directory)
			{
				specify_investigation_output_directory(0);
			}
			
			else if(ae.getSource() == jmnuitm_SpecifyTimeZone)
			{
				specify_timezone();
			}
			
			else if(ae.getSource() == this.jmnuitm_Specify_Profile)
			{
				this.specify_profile(true);
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
	
	public File specify_investigation_output_directory(int message_type)
	{
		try
		{
			
			String message = "";
			switch(message_type)
			{
				case 0: //default, state output directory
				{
					message = "Please specify output directory";
					break;
				}
				case 1: //specify output directory, but used to import XREF search first
				{
					message = "Specify import working directory";
					break;
				}
				case 2: //specify output directory, but used to import XREF search first
				{
					message = "Specify Search Directory";
					break;
				}
			}
			
			File directory = driver.querySelectFile(true, message, JFileChooser.DIRECTORIES_ONLY, false, false);
			
			if(directory == null || !directory.exists())
			{
				sop("User declined input to select output directory");
				return null;
			}
			
			if(directory.exists() && directory.isDirectory())
			{
				this.set_output_directory(directory);
				driver.directive("output directory has been set to " + directory.getCanonicalPath());
				return directory;
			}			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "specify_investigation_output_directory", e);
		}
		
		return null;
	}
	
	public boolean redraw_advanced_analysis_report()
	{
		try
		{
			if(advanced_analysis_director == null)
			{
				driver.jop_Error("It doesn't look like you have executed Advanced Analysis. \nPlease do that first before being able to redraw analysis report.");
				return false;							
			}
			else if(advanced_analysis_director.analysis_report == null)
			{
				if(advanced_analysis_director.tree_ORPHAN_process == null || advanced_analysis_director.tree_ORPHAN_process.size() < 1)
					advanced_analysis_director.create_tree_structure(advanced_analysis_director.tree_PROCESS);
				
				
				boolean prev = Analysis_Report_Container_Writer.open_file_when_complete;
				Analysis_Report_Container_Writer.open_file_when_complete = true;
				
				advanced_analysis_director.analysis_report = new Analysis_Report_Container_Writer(advanced_analysis_director);				
				advanced_analysis_director.print_file_attributes();
				
				Analysis_Report_Container_Writer.open_file_when_complete = prev;
			}
			else
			{			
				boolean prev = Analysis_Report_Container_Writer.open_file_when_complete;
				Analysis_Report_Container_Writer.open_file_when_complete = true;
				
				//otw
				advanced_analysis_director.analysis_report.commence_action();
				driver.jop_Message("Process complete! Please refresh output file");
				
				Analysis_Report_Container_Writer.open_file_when_complete = prev;
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "redraw_advanced_analysis_report", e);
		}
		
		return false;
	}
	
	public boolean execute_advanced_analysis()
	{
		try
		{
			if(advanced_analysis_director != null)
			{
				if(driver.jop_Confirm("Advanced Analysis has been instantiated previously. Do you wish to start new Advanced Analysis?", "Restart Advanced Analysis?") != JOptionPane.YES_OPTION)
				{
					driver.sop("Advanced Analysis confirm option rejected");
					return false;
				}
			}
			
			advanced_analysis_director = new Advanced_Analysis_Director(fle_volatility, fle_memory_image, PROFILE, path_fle_analysis_directory, file_attr_volatility, file_attr_memory_image, investigator_name, investigation_description, true, true);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "execute_advanced_analysis", e);
		}
		
		return false;
	}
	
	public boolean launch_plugin_analysis_report()
	{
		try
		{
			if(Plugin.list_plugins == null || Plugin.list_plugins.isEmpty())
			{
				driver.jop_Error("Error! I couldn't detect plugins yet... \nPlease ensure plugins have been imported into the framework before continuing...", false);
				return false;
			}
			
			JDialog_Report_Plugin jdialog = new JDialog_Report_Plugin(this);
			
			
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "launch_plugin_analysis_report", e);
		}
		
		return false;
	}
	
	public static boolean commence_snapshot_analysis()
	{
		try
		{
			//procure snapshot memory images
			File fleImage1 = driver.querySelectFile(true, "Please select snapshot memory image 1 [PRE]", JFileChooser.OPEN_DIALOG, fle_memory_image);
			
			if(fleImage1 == null || !fleImage1.exists() || !fleImage1.isFile())
			{
				driver.jop_Error("Halting Snapshot Analysis - no valid file was received for Snapshot 1 [PRE]");
				return false;
			}
			
			String profile1 = querySelectProfile(fleImage1, PROFILE);
			
			File fleImage2 = driver.querySelectFile(true, "Please select snapshot memory image 2 [POST]", JFileChooser.OPEN_DIALOG, fleImage1);
			
			if(fleImage2 == null || !fleImage2.exists() || !fleImage2.isFile())
			{
				driver.jop_Error("Halting Snapshot Analysis - no valid file was received for Snapshot 2 [POST]");
				return false;
			}
			
			String profile2 = querySelectProfile(fleImage2, profile1);
			
			//commence process!
			Snapshot_Driver snapshot = new Snapshot_Driver(fleImage1, profile1, fleImage2, profile2);
			
			//create jtab						
			jtabbedPane_ANALYSIS_DATE_TIME.addTab(snapshot.snapshot_name, snapshot.jtaConsole);
			
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "commence_snapshot_analysis", e);
		}
		
		return false;
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
				String profile_lower = this.PROFILE.toLowerCase().trim();
				
				boolean select_win_plugins = false;
				boolean select_unix_plugins = false;
				boolean select_mac_plugins = false;
				
				if(profile_lower.startsWith("win") || profile_lower.startsWith("vista"))
				{
					select_win_plugins = true;
				}
				
				
				if(!select_win_plugins && !select_unix_plugins && !select_mac_plugins)				
				{
					int selection = driver.jop_custom_buttons("I could not determine OS type for selected profile. \nPlease select appropraiate Profile OS below:\n", "Specify Profile OS", new Object[]{"Unix OS Profile", "Mac OS Profile", "Windows OS Profile", "Cancel"});
					
					if(selection == 0)
						select_unix_plugins = true;
					else if(selection == 1)
						select_mac_plugins = true;
					else if(selection == 2)
						select_win_plugins = true;
					else
					{
						System.out.println("No appliable Profile OS was selected");
						return false;
					}										
				}
				
				if(!select_win_plugins && !select_unix_plugins && !select_mac_plugins)				
				{
					driver.jop_Message("I can not determine OS for this profile.");
					return false;
				}
				
				
				for(Plugin plugin : Plugin.tree_plugins.values())
				{
					//DISMISS CERTAIN PLUGINS
					if(select_win_plugins)
					{
						if(list_omit_plugins.contains(plugin.plugin_name.toLowerCase().trim()))
							continue;
												
						if(plugin.plugin_name.toLowerCase().trim().startsWith("lin"))
							continue;
						
						if(plugin.plugin_name.toLowerCase().trim().startsWith("mac"))
							continue;
						
												
						if(plugin != null)
							plugin.jcb.setSelected(true);	
						
					}
					
					else if(select_unix_plugins)
					{
						if(plugin.plugin_name.toLowerCase().trim().startsWith("lin"))
						{
							if(plugin != null)
								plugin.jcb.setSelected(true); 
						}																							
					}
					
					else if(select_mac_plugins)
					{
						if(plugin.plugin_name.toLowerCase().trim().startsWith("mac"))
						{
							if(plugin != null)
								plugin.jcb.setSelected(true); 
						}																							
					}														
					
										
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
			
			//configure environment to have the executable moved into the import folder
			driver.copy_file(fle_volatility, Start.fleImportMemoryAnalysisDirectory);

			
			File fle_config_stub = write_setup_config_file(Start.fleImportMemoryAnalysisDirectory);
			
			if(fle_config_stub != null && fle_config_stub.exists() && fle_config_stub.isFile())			
				jpnlConsole.append("\nNOTE: I have written a setup config file for you at " + fle_config_stub.getCanonicalPath() + " \nIn the future, please modify this config file and place at the same path of the memory image to analyze to speed up your analysis\n"); 
									
			//continue
			populate_volatility_HELP(fle);
			
			return fle;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "specify_volatility_executable", e);
		}
		
		return null;
	}
	
	public File write_setup_config_file(File fle_path)
	{
		File fle_config = null;
		
		try
		{
			if(fle_path == null || !fle_path.isDirectory())
			{
				jpnlConsole.append("\nNOTE: I am not able to write setup config helper file - import path appears to be invalid");
				return null;
			}
			
			String path = fle_path.getCanonicalPath().trim();
			
			if(!path.endsWith(File.separator))
				path = path + File.separator;
			
			fle_config = new File(path + "setup.conf");
			
			PrintWriter pw = new PrintWriter(new FileWriter(fle_config));
			
			pw.println("#Xavier Memory Analysis Framework by Solomon Sonya @Carpenter1010");
			pw.println("#Uncomment and modify feature directives below that you would like to use in this analysis");
			pw.println("");
			pw.println("#investigator_name=");
			pw.println("#investigation_description=");
			pw.println("#profile=");
			pw.println("");
			pw.println("#use the following to indicate plugins to run automatically");
			pw.println("#plugin_autorun=amcache");
			pw.println("#plugin_autorun=apihooks");
			pw.println("#plugin_autorun=atoms");
			pw.println("#plugin_autorun=atomscan");
			pw.println("#plugin_autorun=auditpol");
			pw.println("#plugin_autorun=bigpools");
			pw.println("#plugin_autorun=bioskbd");
			pw.println("#plugin_autorun=cachedump");
			pw.println("#plugin_autorun=callbacks");
			pw.println("#plugin_autorun=clipboard");
			pw.println("#plugin_autorun=cmdline");
			pw.println("#plugin_autorun=cmdscan");
			pw.println("#plugin_autorun=connections");
			pw.println("#plugin_autorun=connscan");
			pw.println("#plugin_autorun=consoles");
			pw.println("#plugin_autorun=crashinfo");
			pw.println("#plugin_autorun=deskscan");
			pw.println("#plugin_autorun=devicetree");
			pw.println("#plugin_autorun=dlldump");
			pw.println("#plugin_autorun=dlllist");
			pw.println("#plugin_autorun=driverirp");
			pw.println("#plugin_autorun=drivermodule");
			pw.println("#plugin_autorun=driverscan");
			pw.println("#plugin_autorun=dumpcerts");
			pw.println("#plugin_autorun=dumpfiles");
			pw.println("#plugin_autorun=dumpregistry");
			pw.println("#plugin_autorun=editbox");
			pw.println("#plugin_autorun=envars");
			pw.println("#plugin_autorun=eventhooks");
			pw.println("#plugin_autorun=evtlogs");
			pw.println("#plugin_autorun=filescan");
			pw.println("#plugin_autorun=gahti");
			pw.println("#plugin_autorun=gditimers");
			pw.println("#plugin_autorun=gdt");
			pw.println("#plugin_autorun=getservicesids");
			pw.println("#plugin_autorun=getsids");
			pw.println("#plugin_autorun=handles");
			pw.println("#plugin_autorun=hashdump");
			pw.println("#plugin_autorun=hibinfo");
			pw.println("#plugin_autorun=hivedump");
			pw.println("#plugin_autorun=hivelist");
			pw.println("#plugin_autorun=hivescan");
			pw.println("#plugin_autorun=hpakextract");
			pw.println("#plugin_autorun=hpakinfo");
			pw.println("#plugin_autorun=idt");
			pw.println("#plugin_autorun=iehistory");
			pw.println("#plugin_autorun=imagecopy");
			pw.println("#plugin_autorun=imageinfo");
			pw.println("#plugin_autorun=impscan");
			pw.println("#plugin_autorun=joblinks");
			pw.println("#plugin_autorun=kdbgscan");
			pw.println("#plugin_autorun=kpcrscan");
			pw.println("#plugin_autorun=ldrmodules");
			pw.println("#plugin_autorun=limeinfo");
			pw.println("#plugin_autorun=linux_apihooks");
			pw.println("#plugin_autorun=linux_arp");
			pw.println("#plugin_autorun=linux_aslr_shift");
			pw.println("#plugin_autorun=linux_banner");
			pw.println("#plugin_autorun=linux_bash");
			pw.println("#plugin_autorun=linux_bash_env");
			pw.println("#plugin_autorun=linux_bash_hash");
			pw.println("#plugin_autorun=linux_check_afinfo");
			pw.println("#plugin_autorun=linux_check_creds");
			pw.println("#plugin_autorun=linux_check_evt_arm");
			pw.println("#plugin_autorun=linux_check_fop");
			pw.println("#plugin_autorun=linux_check_idt");
			pw.println("#plugin_autorun=linux_check_inline_kernel");
			pw.println("#plugin_autorun=linux_check_modules");
			pw.println("#plugin_autorun=linux_check_syscall");
			pw.println("#plugin_autorun=linux_check_syscall_arm");
			pw.println("#plugin_autorun=linux_check_tty");
			pw.println("#plugin_autorun=linux_cpuinfo");
			pw.println("#plugin_autorun=linux_dentry_cache");
			pw.println("#plugin_autorun=linux_dmesg");
			pw.println("#plugin_autorun=linux_dump_map");
			pw.println("#plugin_autorun=linux_dynamic_env");
			pw.println("#plugin_autorun=linux_elfs");
			pw.println("#plugin_autorun=linux_enumerate_files");
			pw.println("#plugin_autorun=linux_find_file");
			pw.println("#plugin_autorun=linux_getcwd");
			pw.println("#plugin_autorun=linux_hidden_modules");
			pw.println("#plugin_autorun=linux_ifconfig");
			pw.println("#plugin_autorun=linux_info_regs");
			pw.println("#plugin_autorun=linux_iomem");
			pw.println("#plugin_autorun=linux_kernel_opened_files");
			pw.println("#plugin_autorun=linux_keyboard_notifiers");
			pw.println("#plugin_autorun=linux_ldrmodules");
			pw.println("#plugin_autorun=linux_library_list");
			pw.println("#plugin_autorun=linux_librarydump");
			pw.println("#plugin_autorun=linux_list_raw");
			pw.println("#plugin_autorun=linux_lsmod");
			pw.println("#plugin_autorun=linux_lsof");
			pw.println("#plugin_autorun=linux_malfind");
			pw.println("#plugin_autorun=linux_memmap");
			pw.println("#plugin_autorun=linux_moddump");
			pw.println("#plugin_autorun=linux_mount");
			pw.println("#plugin_autorun=linux_mount_cache");
			pw.println("#plugin_autorun=linux_netfilter");
			pw.println("#plugin_autorun=linux_netscan");
			pw.println("#plugin_autorun=linux_netstat");
			pw.println("#plugin_autorun=linux_pidhashtable");
			pw.println("#plugin_autorun=linux_pkt_queues");
			pw.println("#plugin_autorun=linux_plthook");
			pw.println("#plugin_autorun=linux_proc_maps");
			pw.println("#plugin_autorun=linux_proc_maps_rb");
			pw.println("#plugin_autorun=linux_procdump");
			pw.println("#plugin_autorun=linux_process_hollow");
			pw.println("#plugin_autorun=linux_psaux");
			pw.println("#plugin_autorun=linux_psenv");
			pw.println("#plugin_autorun=linux_pslist");
			pw.println("#plugin_autorun=linux_pslist_cache");
			pw.println("#plugin_autorun=linux_psscan");
			pw.println("#plugin_autorun=linux_pstree");
			pw.println("#plugin_autorun=linux_psxview");
			pw.println("#plugin_autorun=linux_recover_filesystem");
			pw.println("#plugin_autorun=linux_route_cache");
			pw.println("#plugin_autorun=linux_sk_buff_cache");
			pw.println("#plugin_autorun=linux_slabinfo");
			pw.println("#plugin_autorun=linux_strings");
			pw.println("#plugin_autorun=linux_threads");
			pw.println("#plugin_autorun=linux_tmpfs");
			pw.println("#plugin_autorun=linux_truecrypt_passphrase");
			pw.println("#plugin_autorun=linux_vma_cache");
			pw.println("#plugin_autorun=linux_volshell");
			pw.println("#plugin_autorun=linux_yarascan");
			pw.println("#plugin_autorun=lsadump");
			pw.println("#plugin_autorun=mac_adium");
			pw.println("#plugin_autorun=mac_apihooks");
			pw.println("#plugin_autorun=mac_apihooks_kernel");
			pw.println("#plugin_autorun=mac_arp");
			pw.println("#plugin_autorun=mac_bash");
			pw.println("#plugin_autorun=mac_bash_env");
			pw.println("#plugin_autorun=mac_bash_hash");
			pw.println("#plugin_autorun=mac_calendar");
			pw.println("#plugin_autorun=mac_check_fop");
			pw.println("#plugin_autorun=mac_check_mig_table");
			pw.println("#plugin_autorun=mac_check_syscall_shadow");
			pw.println("#plugin_autorun=mac_check_syscalls");
			pw.println("#plugin_autorun=mac_check_sysctl");
			pw.println("#plugin_autorun=mac_check_trap_table");
			pw.println("#plugin_autorun=mac_compressed_swap");
			pw.println("#plugin_autorun=mac_contacts");
			pw.println("#plugin_autorun=mac_dead_procs");
			pw.println("#plugin_autorun=mac_dead_sockets");
			pw.println("#plugin_autorun=mac_dead_vnodes");
			pw.println("#plugin_autorun=mac_devfs");
			pw.println("#plugin_autorun=mac_dmesg");
			pw.println("#plugin_autorun=mac_dump_file");
			pw.println("#plugin_autorun=mac_dump_maps");
			pw.println("#plugin_autorun=mac_dyld_maps");
			pw.println("#plugin_autorun=mac_find_aslr_shift");
			pw.println("#plugin_autorun=mac_get_profile");
			pw.println("#plugin_autorun=mac_ifconfig");
			pw.println("#plugin_autorun=mac_interest_handlers");
			pw.println("#plugin_autorun=mac_ip_filters");
			pw.println("#plugin_autorun=mac_kernel_classes");
			pw.println("#plugin_autorun=mac_kevents");
			pw.println("#plugin_autorun=mac_keychaindump");
			pw.println("#plugin_autorun=mac_ldrmodules");
			pw.println("#plugin_autorun=mac_librarydump");
			pw.println("#plugin_autorun=mac_list_files");
			pw.println("#plugin_autorun=mac_list_kauth_listeners");
			pw.println("#plugin_autorun=mac_list_kauth_scopes");
			pw.println("#plugin_autorun=mac_list_raw");
			pw.println("#plugin_autorun=mac_list_sessions");
			pw.println("#plugin_autorun=mac_list_zones");
			pw.println("#plugin_autorun=mac_lsmod");
			pw.println("#plugin_autorun=mac_lsmod_iokit");
			pw.println("#plugin_autorun=mac_lsmod_kext_map");
			pw.println("#plugin_autorun=mac_lsof");
			pw.println("#plugin_autorun=mac_machine_info");
			pw.println("#plugin_autorun=mac_malfind");
			pw.println("#plugin_autorun=mac_memdump");
			pw.println("#plugin_autorun=mac_moddump");
			pw.println("#plugin_autorun=mac_mount");
			pw.println("#plugin_autorun=mac_netstat");
			pw.println("#plugin_autorun=mac_network_conns");
			pw.println("#plugin_autorun=mac_notesapp");
			pw.println("#plugin_autorun=mac_notifiers");
			pw.println("#plugin_autorun=mac_orphan_threads");
			pw.println("#plugin_autorun=mac_pgrp_hash_table");
			pw.println("#plugin_autorun=mac_pid_hash_table");
			pw.println("#plugin_autorun=mac_print_boot_cmdline");
			pw.println("#plugin_autorun=mac_proc_maps");
			pw.println("#plugin_autorun=mac_procdump");
			pw.println("#plugin_autorun=mac_psaux");
			pw.println("#plugin_autorun=mac_psenv");
			pw.println("#plugin_autorun=mac_pslist");
			pw.println("#plugin_autorun=mac_pstree");
			pw.println("#plugin_autorun=mac_psxview");
			pw.println("#plugin_autorun=mac_recover_filesystem");
			pw.println("#plugin_autorun=mac_route");
			pw.println("#plugin_autorun=mac_socket_filters");
			pw.println("#plugin_autorun=mac_strings");
			pw.println("#plugin_autorun=mac_tasks");
			pw.println("#plugin_autorun=mac_threads");
			pw.println("#plugin_autorun=mac_threads_simple");
			pw.println("#plugin_autorun=mac_timers");
			pw.println("#plugin_autorun=mac_trustedbsd");
			pw.println("#plugin_autorun=mac_version");
			pw.println("#plugin_autorun=mac_vfsevents");
			pw.println("#plugin_autorun=mac_volshell");
			pw.println("#plugin_autorun=mac_yarascan");
			pw.println("#plugin_autorun=machoinfo");
			pw.println("#plugin_autorun=malfind");
			pw.println("#plugin_autorun=mbrparser");
			pw.println("#plugin_autorun=memdump");
			pw.println("#plugin_autorun=memmap");
			pw.println("#plugin_autorun=messagehooks");
			pw.println("#plugin_autorun=mftparser");
			pw.println("#plugin_autorun=moddump");
			pw.println("#plugin_autorun=modscan");
			pw.println("#plugin_autorun=modules");
			pw.println("#plugin_autorun=multiscan");
			pw.println("#plugin_autorun=mutantscan");
			pw.println("#plugin_autorun=netscan");
			pw.println("#plugin_autorun=notepad");
			pw.println("#plugin_autorun=objtypescan");
			pw.println("#plugin_autorun=patcher");
			pw.println("#plugin_autorun=poolpeek");
			pw.println("#plugin_autorun=pooltracker");
			pw.println("#plugin_autorun=printkey");
			pw.println("#plugin_autorun=privs");
			pw.println("#plugin_autorun=procdump");
			pw.println("#plugin_autorun=pslist");
			pw.println("#plugin_autorun=psscan");
			pw.println("#plugin_autorun=pstree");
			pw.println("#plugin_autorun=psxview");
			pw.println("#plugin_autorun=qemuinfo");
			pw.println("#plugin_autorun=raw2dmp");
			pw.println("#plugin_autorun=screenshot");
			pw.println("#plugin_autorun=servicediff");
			pw.println("#plugin_autorun=sessions");
			pw.println("#plugin_autorun=shellbags");
			pw.println("#plugin_autorun=shimcache");
			pw.println("#plugin_autorun=shutdowntime");
			pw.println("#plugin_autorun=sockets");
			pw.println("#plugin_autorun=sockscan");
			pw.println("#plugin_autorun=ssdt");
			pw.println("#plugin_autorun=strings");
			pw.println("#plugin_autorun=svcscan");
			pw.println("#plugin_autorun=symlinkscan");
			pw.println("#plugin_autorun=thrdscan");
			pw.println("#plugin_autorun=threads");
			pw.println("#plugin_autorun=timeliner");
			pw.println("#plugin_autorun=timers");
			pw.println("#plugin_autorun=truecryptmaster");
			pw.println("#plugin_autorun=truecryptpassphrase");
			pw.println("#plugin_autorun=truecryptsummary");
			pw.println("#plugin_autorun=unloadedmodules");
			pw.println("#plugin_autorun=userassist");
			pw.println("#plugin_autorun=userhandles");
			pw.println("#plugin_autorun=vaddump");
			pw.println("#plugin_autorun=vadinfo");
			pw.println("#plugin_autorun=vadtree");
			pw.println("#plugin_autorun=vadwalk");
			pw.println("#plugin_autorun=vboxinfo");
			pw.println("#plugin_autorun=verinfo");
			pw.println("#plugin_autorun=vmwareinfo");
			pw.println("#plugin_autorun=volshell");
			pw.println("#plugin_autorun=win10cookie");
			pw.println("#plugin_autorun=windows");
			pw.println("#plugin_autorun=wintree");
			pw.println("#plugin_autorun=wndscan");
			pw.println("#plugin_autorun=yarascan");

			pw.flush();
			pw.close();
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_setup_config_file", e);
		}
		
		return fle_config;
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
			String lower = "";
		    try 
		    {
		        while (line_iterator.hasNext()) 
		        {		        	
		        	line = line_iterator.nextLine();
		        	
		        	if(line == null)
		        		continue;
		        	
		        	lower = line.toLowerCase().trim();

		        	//On Windows, ensure x86 or x64 is the binary in use
		        	if(lower.contains("is not compatible with the version of Windows") && lower.contains("check your computer's system information to see whether you need a x86 (32-bit) or x64 (64-bit) version of the program"))
		        		driver.jop_Error("it is you are attempting to run an incompatible volatility version on this OS.\nCheck that your OS is compatible with x86 or x64 version of volatility and try again...", "* * ERROR * * Possible Incompatible volatility selected!!!");
		        	
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
			
			jtabbedPane_MAIN.addTab("Image Search [" + IMAGE_SEARCH_INDEX++ + "] - " + image_name, search);
			
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
		        	{
		        		this.list_volatility_info_configuration_PLUGINS.add(line);
		        		
		        		//bifurcate plugin from description
		        		try
		        		{
		        			if(!line.contains("-"))
		        				continue;
		        			
		        			String plugin = line.toLowerCase().substring(0, line.indexOf("-")).trim(), description = line.substring(line.indexOf("-")+1).trim();
		        			
		        			tree_PLUGIN_AND_DESCRIPTION.put(plugin,  description);	        					        			
		        		}
		        		catch(Exception e)
		        		{		        			
		        			continue;
		        		}
		        		
		        	}
		        	else if(scanner_checks_found)
		        		this.list_volatility_info_configuration_SCANNER_CHECKS.add(line);
		        	
		        	
		        }
		        
		        //
		        //update GUI
		        //
		        if(list_volatility_info_configuration_PROFILES == null || list_volatility_info_configuration_PROFILES.isEmpty())
		        {
		        	driver.jop_Error("Error!!! It doesn't look like a valid Volatility executable was selected...", false);
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
						plugin.original_index = plugin_add_index++;
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
	
	
	
	
	
	
	public boolean specify_investigation_details(boolean override_to_query_user)
	{
		try
		{
			if(override_to_query_user || investigator_name == null)			
				this.investigator_name = driver.jop_Query("Please specify investigator name:", "Enter investigator Name");
			
			if(override_to_query_user || investigation_description == null)
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
	
	
	
	public static boolean ensure_volatility_and_memory_image_are_configured()
	{
		try
		{						
			if(fle_volatility == null || !fle_volatility.exists() || !fle_volatility.isFile())
			{
				driver.sop("* * - ERROR! Valid volatility executable binary has not been set. I cannot proceed yet... * * ");
				return false;
			}
			
			if(fle_memory_image == null || !fle_memory_image.exists() || !fle_memory_image.isFile())
			{
				driver.sop("* * - ERROR! Valid valid image to analyze not been set. I cannot proceed yet... * * ");				
				return false;
			}
			
			
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "ensure_volatility_and_image_are_configured", e);
		}
		
		return false;
	}
	
	
	
	public boolean is_valid_file(File fle)
	{
		try
		{
			if(fle != null && fle.isFile() && fle.exists() && fle.length() > 1)
				return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "is_valid_file", e);
		}
		
		return false;
	}
	
	public boolean populate_container_files_FILE_XREF(TreeMap<String, Node_Generic> tree)
	{
		try
		{
			if(tree == null || tree.isEmpty())
			{
				try	{	this.jpnlContainerFilesEntries.removeAll();} catch(Exception e){}
				
				jpnlContainerFilesEntries.setLayout(new GridLayout(1,1));
				
				jpnlContainerFilesEntries.validate();
				
				try	{	this.jlblNum_Dump_Files.setText("No Files Loaded: ");	}	catch(Exception e){}
				
				return true;
			}
			
			try	{	this.jpnlContainerFilesEntries.removeAll();} catch(Exception e){}
			
			jpnlContainerFilesEntries.setLayout(new GridLayout(tree.size(),1, 5, 5));
			
			try	{	this.jlblNum_Container_Files.setText("Num Files Loaded: " + tree.size());	}	catch(Exception e){}
			
			for(Node_Generic node : tree.values())
			{
				if(node.fle == null || !node.fle.isFile() || !node.fle.exists() || node.fle.length() < 1)
					continue;
												
				jpnlContainerFilesEntries.add(node.jcb);				
			}
			
			jpnlContainerFilesEntries.validate();
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "populate_container_files_FILE_XREF", e, true);
		}
		
		return false;
	}
	
	public boolean set_output_directory(File directory)
	{
		try
		{
			if(directory == null || !directory.exists() || !directory.isDirectory())
			{
				driver.directive("\nI am unable to continue with directory set action. Directory appears to be invalid...");
				return false;
			}
			
			String initial_path = directory.getCanonicalPath().trim();
			
			if(!initial_path.endsWith(File.separator))
				initial_path = initial_path.trim() + File.separator;
			
			//fle_analysis_directory = new File(initial_path + Driver.NAME_LOWERCASE + File.separator + "export" + File.separator + "memory_analysis" + File.separator + analysis_time_stamp);
			
			fle_analysis_directory = new File(directory.getCanonicalPath().trim());
			
			try	{	fle_analysis_directory.mkdirs(); } catch(Exception e){}
			
			if(fle_analysis_directory.getCanonicalPath().trim().endsWith(File.separator))
				path_fle_analysis_directory = fle_analysis_directory.getCanonicalPath().trim();
			else
				path_fle_analysis_directory = fle_analysis_directory.getCanonicalPath().trim() + File.separator;
			
			//procdump directory
			fle_procdump = new File(path_fle_analysis_directory + "procdump");
			
			if(this.advanced_analysis_director != null)
				this.advanced_analysis_director.path_fle_analysis_directory = path_fle_analysis_directory;
			
			advanced_analysis_director.relative_path_to_file_analysis_directory = driver.get_relative_path(fle_analysis_directory);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "set_output_directory", e);
		}
		
		return false;
	}
	
	public boolean populate_dump_files_FILESCAN_XREF(TreeMap<String, Node_Generic> tree)
	{
		try
		{
			if(tree == null || tree.isEmpty())
			{
				try	{	this.jpnlDumpFilesEntries.removeAll();} catch(Exception e){}
				
				jpnlDumpFilesEntries.setLayout(new GridLayout(1,1));
				
				jpnlDumpFilesEntries.validate();
				
				try	{	this.jlblNum_Dump_Files.setText("No Files Loaded");	}	catch(Exception e){}								
				
				return true;
			}
			
			jpnlDumpFilesEntries.setLayout(new GridLayout(tree.size(),1, 5, 5));
			
			try	{	this.jlblNum_Dump_Files.setText("Num Files Loaded: " + tree.size());	}	catch(Exception e){}
			
			for(Node_Generic node : tree.values())
			{
				try
				{
//					if(node.plugin_name != null && node.plugin_name.equalsIgnoreCase("yarascan") && node.jcb != null)
//					{
//						//do n/t
//					}
//					
//					else if(node.offset_p == null)
//						continue;
					
					if(node.plugin_name == null || node.jcb == null)
						continue;
													
					jpnlDumpFilesEntries.add(node.jcb);
				}
				
				catch(Exception e){continue;}				
			}
			jpnlDumpFilesEntries.validate();
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "populate_dump_files_FILESCAN", e, true);
		}
		
		return false;
	}
	
	public boolean is_memory_image_WINDOWS()
	{
		try
		{
			if(PROFILE == null)
				return false;
			
			String lower = PROFILE.toLowerCase().trim();
			
			if(lower.startsWith("win") || lower.startsWith("vista"))
				return true;					
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "is_memory_image_WINDOWS", e);
		}
		
		return false;
	}

	@Override
	public void keyPressed(KeyEvent ke) 
	{
		try
		{
			if(ke.getKeyCode() == KeyEvent.VK_I)
				import_system_manifest();
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "keyPresed", e);
		}		
	}

	@Override
	public void keyReleased(KeyEvent ke) 
	{
		try
		{
						
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "keyReleased", e);
		}		
	}

	@Override
	public void keyTyped(KeyEvent ke) 
	{
		try
		{
						
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "keyTyped", e);
		}		
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
