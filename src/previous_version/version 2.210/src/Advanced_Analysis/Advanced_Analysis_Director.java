/**
 * 
 * @author Solomon Sonya
 * 
 * 
 * 		
 * 	Future Works:
 * 	- strings: memdump --> strings and include strings in Data XREF
 *  - STORE_REGISTRY_RAW_DATA: add entry in .conf file to indicate if we want to store all raw data from registry e.g. userassist. it is not stored att to reduce RAM utilization
 *  - complete compatibility XREF search add File_XREF functions for tree_hivelist and tree_get_service_sids  
 *  - ensure registry_startup folder is compatible with Xavier System Information report tree and works for manifest baseline/snapshot comparisons
 *  - ssdt and use in manifest/snapshot comparison
 *  - incorporate threads plugin data into in each process
 *  - incorporate timers plugin into driver data 
 *  - distill shimcache, shellbags, timeliner, mft into manifest file
 * 
 * 
 * 
 * System Manifest:
 * 	Intentionally not printing separately - I'll have to come back and verify outliers if necessary similar to printing_vad_node_called_by_process in Node_process to prevent duplication of VAD entries when printed by this director class:
 * 		- assuming all entries are printed under respective Node_Process:
 * 			-- tree_NETSTAT 
 * 			-- tree_ENVIRONMENT_VARS  
 * 			-- tree_API_HOOK
 * 			-- tree_PRIVS_PROCESSES
 * 			-- tree_SERVICES_SVCSCAN
 * 			-- tree_MALFIND
 * 			-- tree_GDI_TIMERS
 * 			-- tree_VAD_INFO
 * 		- assuming all entries are printed under respective Node_Driver:
 * 			-- tree_CALLBACKS
 * 			-- tree_UNLOADED_MODULES
 * 			-- tree_TIMERS
 * 			-- tree_DRIVER_IRP_HOOK
 * 
 *  Special NOTES:
 *  	- User_Assist: we only store the first string of raw data for now to reduce amount of RAM used for this data. If needed, I may come back here and store the contents to the list details
 *  
 *  Awaiting Update Features
 *  	- print malfind file_attribute data if present under each node (i.e., add file_attr tree nodes to the html file read in from manifest) 
 * 
 * 	*/

//

package Advanced_Analysis;

import java.io.*;
import java.util.*;

import javax.swing.JOptionPane;

import org.apache.commons.io.LineIterator;

import Advanced_Analysis.Analysis_Report.Analysis_Report_Container_Writer;
import Advanced_Analysis.Analysis_Plugin.*;
import Advanced_Analysis.*;
import Driver.*;
import Interface.Interface;
import Interface.JTextArea_Solomon;
import Plugin.Plugin;
import Plugin.Process_Plugin;


public class Advanced_Analysis_Director extends Thread implements Runnable 
{
	public static final String myClassName = "Advanced_Analysis_Director";	
	public static volatile Driver driver = new Driver();
	
	public volatile boolean AUTOMATED_ANALYSIS_STARTED = false;
	public volatile boolean AUTOMATED_ANALYSIS_COMPLETE = false;
	public volatile boolean EXECUTE_EXPORT_MANIFEST = false;
	public static volatile boolean DO_NOT_INCLUDE_TIME_STAMP_IN_FILE_NAME = true;

	public static volatile JTextArea_Solomon jtaUserAssistConsole = null;
	
	/**add */
	public static volatile boolean STORE_REGISTRY_RAW_DATA = false; 
	
	public static volatile boolean PROCESS_IMPSCAN = true;
	
	public volatile File_XREF XREF = null;
	
	public volatile File fle_manifest_IMPORT = null;
	
	public static boolean processling_process_list = false;
	
	public static final int new_line_separator_count = 2000;
	public static final String import_complete_separator = " ";
	
	public static final int MAX_TREE_NODE_COUNT = 20;
	public static volatile String WRITE_MANIFEST_DELIMITER = "\t";
	
	public volatile Analysis_Report_Container_Writer analysis_report = null;
	
	public static volatile boolean DEBUG = false;
	
	public String EXECUTION_TIME_STAMP = driver.getTime_Specified_Hyphenated_with_seconds_using_colon(System.currentTimeMillis());
	public volatile String MFTPARSER_EXECUTION_TIME_STAMP_FROM_RELOAD_EXPORT_DIRECTORY = null;
	
	/**all processes*/
	public volatile TreeMap<Integer, Node_Process> tree_PROCESS = new TreeMap<Integer, Node_Process>();
	
	/**Null Process - used for every process with PID -1 and when there is no process identified e.g. svcscan with Process ID == "-"*/
	public volatile Node_Process NULL_PROCESS = new Node_Process(this, -1, "Null Process");
	
	/**all processes with offset from pslist as the key*/
	public volatile TreeMap<String, Node_Process> tree_PROCESS_linked_by_pslist_EPROCESS_base_address = new TreeMap<String, Node_Process>();
	
	/**only orphaned processes*/
	public volatile TreeMap<Integer, Node_Process> tree_ORPHAN_process = new TreeMap<Integer, Node_Process>();
	
	/**when in doubt, use this tree*/
	public volatile TreeMap<String, Node_DLL> tree_DLL_by_path = new TreeMap<String, Node_DLL>();
		
	/**unique modules stored by base address*/
	public volatile TreeMap<String, LinkedList<Node_DLL>> tree_DLL_MODULES_linked_by_VAD_base_start_address = new TreeMap<String, LinkedList<Node_DLL>>();
	
	/**e.g. given DLLDump line: 0xfffffa800148f040 smss1.exe             0x0000000047ef0000 smss2.exe             OK: module.248.3f68f040.47ef0000.dll, provide key of 0x0000000047ef0000 as key, tree will store smss2.exe as module name from DLLDump line */
	public volatile TreeMap<String, String> tree_Module_Name_from_base_address_as_key = new TreeMap<String, String>();	
	/**e.g. given DLLDump line: 0xfffffa800148f040 smss1.exe             0x0000000047ef0000 smss2.exe             OK: module.248.3f68f040.47ef0000.dll, provide key of 47ef0000 as key, tree will store smss2exe as module name from DLLDump line */
	public volatile TreeMap<String, String> tree_Module_Name_from_base_address_trimmed_as_key = new TreeMap<String, String>();
	/**e.g. given DLLDump line: 0xfffffa800148f040 smss1.exe             0x0000000047ef0000 smss2.exe             OK: module.248.3f68f040.47ef0000.dll, provide key of 0xfffffa800148f040 as key, tree will store smss1.exe as module name from DLLDump line */
	public volatile TreeMap<String, String> tree_Process_Name_from_process_offset_V = new TreeMap<String, String>();
	/**e.g. given DLLDump line: 0xfffffa800148f040 smss1.exe             0x0000000047ef0000 smss2.exe             OK: module.248.3f68f040.47ef0000.dll, provide key of 3f68f040 as key, tree will store smss1.exe as module name from DLLDump line */
	public volatile TreeMap<String, String> tree_Process_Name_from_process_offset_P_trimmed = new TreeMap<String, String>();
	
	public volatile TreeMap<String, Node_Process> tree_Process_from_offset_P_trimmed = new TreeMap<String, Node_Process>();
	public volatile TreeMap<String, Node_Process> tree_Process_from_offset_V = new TreeMap<String, Node_Process>();
	public volatile TreeMap<String, Node_Process> tree_Process_from_module_base_address = new TreeMap<String, Node_Process>();
	public volatile TreeMap<String, Node_Process> tree_Process_from_module_base_address_trimmed = new TreeMap<String, Node_Process>();
	
	
	public volatile TreeMap<Integer, Node_Process> tree_NETSTAT = new TreeMap<Integer, Node_Process>();
	
	/**Stores the last environment variable*/
	public volatile TreeMap<String, Node_Envar> tree_ENVIRONMENT_VARS = new TreeMap<String, Node_Envar>();
	
	/** stores entries e.g. TMP	C:\DOCUME~1\Adham\LOCALS~1\Temp	 in all lowercase*/
	public volatile TreeMap<String, Node_Envar> tree_ENVIRONMENT_TEMP = new TreeMap<String, Node_Envar>();
	
	/**stores all API Hook at address*/
	public volatile TreeMap<String, Node_ApiHook> tree_API_HOOK = new TreeMap<String, Node_ApiHook>();
	
	/**API Hooks where first disassembly line contained an unconditional JMP to another location*/
	public volatile LinkedList<Node_DLL> list_API_HOOKS_WITH_HEAD_TRAMPOLINE_PRESENT = new LinkedList<Node_DLL>();	
	public volatile LinkedList<Node_DLL> list_API_HOOKS_WITH_MZ_PRESENT = new LinkedList<Node_DLL>();
	
	public volatile TreeMap<String, TreeMap<Integer, Node_Process>> tree_PRIVS_PROCESSES = new TreeMap<String, TreeMap<Integer, Node_Process>>();
	public volatile TreeMap<String, Node_svcscan> tree_SERVICES_SVCSCAN = new TreeMap<String, Node_svcscan>();
	/**use this to better organize service print outs*/
	public volatile TreeMap<String, String> tree_SERVICES_START_TYPE_only = new TreeMap<String, String>(); 
	public volatile TreeMap<String, String> tree_hashdump = new TreeMap<String, String>();
	public volatile TreeMap<String, Node_hivelist> tree_hivelist = new TreeMap<String, Node_hivelist>();
	public volatile TreeMap<String, Node_get_service_sid> tree_get_service_sids = new TreeMap<String, Node_get_service_sid>();
	public volatile TreeMap<String, String> tree_SIDS = new TreeMap<String, String>();
	
	public volatile TreeMap<Integer, Node_Process> tree_MALFIND = new TreeMap<Integer, Node_Process>();
	public volatile TreeMap<String, String> tree_MALFIND_PAGE_PROTECTION_TYPES = new TreeMap<String, String>();
	public volatile TreeMap<String, Node_Driver> tree_DRIVERS = new TreeMap<String, Node_Driver>();
	public volatile TreeMap<String, Node_Driver> tree_DRIVER_IRP_HOOK = new TreeMap<String, Node_Driver>();	
	public volatile TreeMap<String, LinkedList<String>> tree_session_entries = new TreeMap<String, LinkedList<String>>();
	
	public volatile TreeMap<Integer, Node_Process> tree_GDI_TIMERS = new TreeMap<Integer, Node_Process>();
	public volatile TreeMap<String, Node_Driver> tree_CALLBACKS = new TreeMap<String, Node_Driver>();
	public volatile TreeMap<String, Node_Driver> tree_UNLOADED_MODULES = new TreeMap<String, Node_Driver>();
	public volatile TreeMap<String, Node_Driver> tree_TIMERS = new TreeMap<String, Node_Driver>();
	public volatile TreeMap<String, Node_Registry_Hive> tree_REGISTRY_HIVE_USER_ASSIST = new TreeMap<String, Node_Registry_Hive>();
	public volatile TreeMap<String, Node_Registry_Hive> tree_REGISTRY_HIVE_PRINTKEY = new TreeMap<String, Node_Registry_Hive>();
	public volatile TreeMap<Integer, Node_Process> tree_VAD_INFO = new TreeMap<Integer, Node_Process>();
	
	/**focussed time is they key, each registry node that has the focussed time is stored in the LL. This way, we can reverse search by the user assist keys that took the longest time... these may be processes that are more important to the user that the analyst may wish to review*/
	public volatile TreeMap<String, LinkedList<Node_Generic>> tree_user_assist_linked_by_time_focused = new TreeMap<String, LinkedList<Node_Generic>>();
	
	public volatile TreeMap<String, Node_Generic> tree_DESKSCAN = new TreeMap<String, Node_Generic>();
	
	/**Link each process that has VAD entry for PAGE_EXECUTE_WRITECOPY, PAGE_READWRITE, etc*/
	public volatile TreeMap<String, TreeMap<Integer, Node_Process>> tree_VAD_PAGE_PROTECTION = new TreeMap<String, TreeMap<Integer, Node_Process>>();
	
	public volatile TreeMap<String, String> tree_malfind_dump_name_conversion_table = new TreeMap<String, String>();
	public volatile TreeMap<String, Node_Process> tree_malfind_original_dump_name_to_process = new TreeMap<String, Node_Process>();
	
	/**Analyze cmdscan first, identify processes with command history. First - output */
	public volatile TreeMap<Integer, Node_Process> tree_process_to_link_cmdline_cmdscan_consoles = new TreeMap<Integer, Node_Process>();
	
	public volatile TreeMap<String, Node_Generic> tree_AUDIT_POLICY = new TreeMap<String, Node_Generic>();
	
	public volatile String relative_path_to_converted_dot_process_image = "";
	
	public volatile String analysis_framework_export_name = null;
	public volatile String analysis_framework_export_version = null;
	
	public volatile File fle_volatility = null;
	public volatile File fle_memory_image = null;
	public volatile String PROFILE = Interface.PROFILE;
	public volatile String profile_lower = ""; 
	public volatile String path_fle_analysis_directory = "";
	public volatile String relative_path_to_file_analysis_directory = "";
	public volatile FileAttributeData file_attr_volatility = null;  
	public volatile FileAttributeData file_attr_memory_image = null;
	public volatile String investigator_name = "";
	public volatile String investigation_description = "";
	
	public volatile File fle_manifest_EXPORT = null;
	
	public volatile Analysis_Plugin_dlllist plugin_dlllist = null;
	public volatile Analysis_Plugin_ldrmodules plugin_ldrmodules = null;
	public volatile Analysis_Plugin_connections plugin_connections = null;
	public volatile Analysis_Plugin_connscan plugin_connscan = null;
	public volatile Analysis_Plugin_sockets plugin_sockets = null;
	public volatile Analysis_Plugin_sockscan plugin_sockscan = null;
	public volatile Analysis_Plugin_netscan plugin_netscan = null;
	public volatile Analysis_Plugin_verinfo plugin_verinfo = null;
	public volatile Analysis_Plugin_handles plugin_handles = null;
	public volatile Analysis_Plugin_cmdline plugin_cmdline = null;
	public volatile Analysis_Plugin_envars plugin_envars = null;
	public volatile Analysis_Plugin_apihooks plugin_apihooks = null;
	public volatile Analysis_Plugin_cmdscan plugin_cmdscan = null;
	public volatile Analysis_Plugin_svcscan plugin_svcscan = null;
	public volatile Analysis_Plugin_malfind plugin_malfind = null;
	public volatile Analysis_Plugin_Threads plugin_threads = null;
	
	public volatile Analysis_Plugin_Auditpolicy plugin_audit_policies = null;
	public volatile Analysis_Plugin_hashdump plugin_hashdump = null;
	public volatile Analysis_Plugin_SUPER_MODULES plugin_moddump = null;
	public volatile Analysis_Plugin_Callbacks plugin_callbacks = null;
	
	public volatile Analysis_Plugin_Unloaded_Modules plugin_unloaded_modules = null;
	public volatile Analysis_Plugin_Timers plugin_timers = null;	
	public volatile Analysis_Plugin_modules plugin_modules = null;
	public volatile Analysis_Plugin_EXECUTION plugin_regdump = null;  
	public volatile Analysis_Plugin_consoles plugin_consoles = null;  
	public volatile Analysis_Plugin_Deskscan plugin_deskscan = null;
	//public volatile Analysis_Plugin_EXECUTION plugin_drivermodule = null;  
	//public volatile Analysis_Plugin_EXECUTION plugin_driverscan = null;  
	public volatile Analysis_Plugin_EXECUTION plugin_evtlogs = null;
	public volatile Analysis_Plugin_EXECUTION plugin_filescan = null;  
	
	public volatile Analysis_Plugin_Dump procdump = null;
	public volatile Analysis_Plugin_Dump dlldump = null;
	
	public volatile Analysis_Plugin_GDI_Timers plugin_gditimers = null;
	public volatile Analysis_Plugin_EXECUTION plugin_imageinfo = null;
	public volatile Analysis_Plugin_EXECUTION plugin_kdbgscan = null;
	public volatile Analysis_Plugin_EXECUTION plugin_kpcrscan = null;
	public volatile Analysis_Plugin_EXECUTION plugin_lsadump = null;
	public volatile Analysis_Plugin_EXECUTION plugin_memmap = null;
	public volatile Analysis_Plugin_EXECUTION plugin_messagehooks = null;
	 
	public volatile Analysis_Plugin_EXECUTION plugin_impscan = null;
	public volatile Analysis_Plugin_EXECUTION plugin_joblinks = null;
	public volatile Analysis_Plugin_EXECUTION plugin_notepad = null;
	public volatile Analysis_Plugin_sessions plugin_sessions = null;
	public volatile Analysis_Plugin_EXECUTION plugin_shellbags = null;
	public volatile Analysis_Plugin_EXECUTION plugin_shimcache = null;
	public volatile Analysis_Plugin_ShutdownTime plugin_shutdowntime = null;
	public volatile Analysis_Plugin_EXECUTION plugin_ssdt = null;
	
	public volatile Analysis_Plugin_EXECUTION plugin_symlinkscan = null;
	public volatile Analysis_Plugin_EXECUTION plugin_thrdscan = null;
	public volatile Analysis_Plugin_EXECUTION plugin_timeliner = null;
	public volatile Analysis_Plugin_EXECUTION plugin_unloadedmodules = null;
	public volatile Analysis_Plugin_user_assist plugin_userassist = null;
	public volatile Analysis_Plugin_EXECUTION plugin_userhandles = null;
	public volatile Analysis_Plugin_VAD_INFO plugin_vadinfo = null;
	public volatile Analysis_Plugin_EXECUTION plugin_vadwalk = null;
	public volatile Analysis_Plugin_EXECUTION plugin_win10cookie = null;
	public volatile Analysis_Plugin_EXECUTION plugin_windows = null;
	public volatile Analysis_Plugin_EXECUTION plugin_wintree = null;
	public volatile Analysis_Plugin_EXECUTION plugin_wndscan = null;
	
	public volatile Analysis_Plugin_vadtree plugin_vadtree = null;
	
	public Analysis_Plugin_modscan plugin_modscan = null;
	public Analysis_Plugin_driverscan plugin_driverscan = null;
	public Analysis_Plugin_drivermodule plugin_drivermodule = null;
	public Analysis_Plugin_driverirp plugin_driverirp = null;
	public volatile Analysis_Plugin_get_service_sids plugin_get_service_sids = null;
	public volatile Analysis_Plugin_getsids plugin_getsids = null;
	public volatile Analysis_Plugin_hivelist plugin_hivelist = null;
	public volatile Analysis_Plugin_EXECUTION plugin_hivescan = null;
	public volatile Analysis_Plugin_print_key plugin_printkey = null;
	public volatile Analysis_Plugin_Privs plugin_privs = null;

	public volatile Node_Generic node_shutdown_time = null;
	public volatile Node_Generic node_audit_policy = null;
	
	public volatile Process_Plugin plugin_mftparser = null;
	
	public volatile Analysis_Plugin_Registry_Startup_Apps plugin_registry_startup = null;
	
	/**e.g., C:*/
	public volatile String system_drive = null;
	/**e.g., C:\WINDOWS*/
	public volatile String system_root = null;
	public volatile String computer_name = "SYSTEM";
	public volatile String PROCESSOR_IDENTIFIER = "unknown";
	public volatile String PROCESSOR_ARCHITECTURE = "unknown";
	
	public static volatile boolean INOCULATE_FILE_EXECUTABLE_EXTENSION = true;
	
	public static volatile LinkedList<String> list_plugins_in_execution = new LinkedList<String>();
	
	public volatile TreeMap<String, _Analysis_Plugin_Super_Class> tree_advanced_analysis_threads = new TreeMap<String, _Analysis_Plugin_Super_Class>();

	
	public volatile File fle_pslist = null;
	public volatile File fle_psscan = null;
	public volatile File fle_pstree = null;
	public volatile File fle_psxview = null;
	
	public volatile boolean process_in_execution_PSLIST = false;
	public volatile boolean process_in_execution_PSSCAN = false;
	public volatile boolean process_in_execution_PSTREE = false;
	public volatile boolean process_in_execution_PSXVIEW = false;
	
//public volatile TreeMap<String, Analysis_Plugin_impscan> tree_executed_imports = new TreeMap<String, Analysis_Plugin_impscan>();
	
	public volatile LinkedList<String> list_auto_plugins_execution = null;
	public volatile LinkedList<File> list_import_files = null;
	public volatile File fle_import_directory = null;
	
	public volatile JTextArea_Solomon jta = Interface.jpnlAdvancedAnalysisConsole;
	
	public volatile boolean executed_create_tree_structure = false;
	
	public volatile LinkedList<String> list_import_manifest_file_error_message = new LinkedList<String>();
	public volatile Node_Process node_process_import_manifest = null;
	public volatile Node_Process node_process_malfind_import_manifest = null;
	public volatile Node_Threads node_threads_import_manifest = null;
	public volatile Node_Generic node_vad_import_manifest = null;
	public volatile Node_Malfind node_malfind_import_manifest = null;
	public volatile Node_DLL node_dll_import_manifest = null;
	public volatile String base_addresses_import_manifest = null;
	public volatile Node_Generic node_generic_import_manifest = null;
	public volatile Node_Driver node_driver_import_manifest = null;
	public volatile Node_Registry_Hive node_registry_hive_import_manifest = null;
	public volatile Node_CmdScan node_cmdscan_import_manifest = null; 
	
	/**Import Advanced analysis Directory:
	 * Load previously completed advanced analysis output files
	 * not compatible yet: /malfind/malfind_dump directory
	 * */
	public Advanced_Analysis_Director(LinkedList<File> list, File import_directory, File file_volatily, File file_memory_image, String profile, String PATH_fle_analysis_directory, FileAttributeData fle_attr_volatility, FileAttributeData fle_attr_memory_image, String investigator_NAME, String investigation_DESCRIPTION, boolean initiate_analysis_upon_instantiation, File_XREF xref)
	{
		try
		{	
			if(list != null && list.size() > 0)
			{
				list_import_files = list;
				fle_import_directory = import_directory;
				
				fle_volatility = file_volatily;
				fle_memory_image = file_memory_image;
				PROFILE = profile;
				profile_lower = PROFILE.toLowerCase().trim();
				path_fle_analysis_directory = PATH_fle_analysis_directory;
				file_attr_volatility = fle_attr_volatility;
				file_attr_memory_image = fle_attr_memory_image;
				investigator_name = investigator_NAME;
				investigation_description = investigation_DESCRIPTION;
				XREF = xref;
				
				//we have good import list, update working directory to this location
				if(import_directory != null && import_directory.isDirectory() && import_directory.exists())
				{
					//try to delete the old directory
					try	
					{	
						File fle = new File(path_fle_analysis_directory); 
						
						LinkedList<File> listing = new LinkedList<File>();
						listing = driver.getFileListing(fle, true, null, listing);
						
						if(listing == null || listing.size() < 1)						
							fle.delete();	
						
					}	catch(Exception e){}
					
					path_fle_analysis_directory = import_directory.getCanonicalPath().trim();
					
					if(!path_fle_analysis_directory.endsWith(File.separator))
						path_fle_analysis_directory = path_fle_analysis_directory + File.separator;	
					
					Interface.fle_analysis_directory = import_directory;
					Interface.path_fle_analysis_directory = path_fle_analysis_directory;
				}
								
				
				if(initiate_analysis_upon_instantiation)
					this.start();
			}
			
			else
			{
				driver.jop("Empty listing was received! Please select a different import folder if necessary...");
			}
			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
	}
	
	/**Initiate Advanced Analysis execution plugins*/
	public Advanced_Analysis_Director(File file_volatily, File file_memory_image, String profile, String PATH_fle_analysis_directory, FileAttributeData fle_attr_volatility, FileAttributeData fle_attr_memory_image, String investigator_NAME, String investigation_DESCRIPTION, boolean initiate_analysis_upon_instantiation, boolean explort_manifest_when_complete)
	{
		try
		{		
			fle_volatility = file_volatily;
			fle_memory_image = file_memory_image;
			PROFILE = profile;
			profile_lower = PROFILE.toLowerCase().trim();
			path_fle_analysis_directory = PATH_fle_analysis_directory;
			file_attr_volatility = fle_attr_volatility;
			file_attr_memory_image = fle_attr_memory_image;
			investigator_name = investigator_NAME;
			investigation_description = investigation_DESCRIPTION;
			
			EXECUTE_EXPORT_MANIFEST = explort_manifest_when_complete;
			
			if(initiate_analysis_upon_instantiation)
				this.start();
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 2", e);
		}
	}
	
	/**Load auto plugins to execute */
	public Advanced_Analysis_Director(LinkedList<String> list, File file_volatily, File file_memory_image, String profile, String PATH_fle_analysis_directory, FileAttributeData fle_attr_volatility, FileAttributeData fle_attr_memory_image, String investigator_NAME, String investigation_DESCRIPTION, boolean initiate_analysis_upon_instantiation, boolean explort_manifest_when_complete)
	{
		try
		{	
			if(list != null && list.size() > 0)
			{
				list_auto_plugins_execution = list;
				
				fle_volatility = file_volatily;
				fle_memory_image = file_memory_image;
				PROFILE = profile;
				profile_lower = PROFILE.toLowerCase().trim();
				path_fle_analysis_directory = PATH_fle_analysis_directory;
				file_attr_volatility = fle_attr_volatility;
				file_attr_memory_image = fle_attr_memory_image;
				investigator_name = investigator_NAME;
				investigation_description = investigation_DESCRIPTION;
				
				EXECUTE_EXPORT_MANIFEST = explort_manifest_when_complete;
																			
				if(initiate_analysis_upon_instantiation)
					this.start();
			}
			
			else
			{
				driver.jop("Empty listing was received! Please select a different import folder if necessary...");
			}
			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 3", e);
		}
	}
	
	/** Import Manifest*/
	public Advanced_Analysis_Director(File fle_IMPORT_MANIFEST)
	{
		try
		{	
			fle_manifest_IMPORT = fle_IMPORT_MANIFEST;
			
			if(fle_manifest_IMPORT != null && fle_manifest_IMPORT.exists() && fle_manifest_IMPORT.isFile() && fle_manifest_IMPORT.length() > 0 && fle_manifest_IMPORT.getCanonicalPath().toLowerCase().trim().endsWith(".lnk"))
			{
				String error = "\n\n* * * * ERROR! It looks like you selected a shortcutlink. At this time, I cannot follow Windows shortcut links to files.\nPlease select actual file to import...";
				//Start.intface.sop(error);
				driver.directive(error);
			}
			else if(fle_manifest_IMPORT != null && fle_manifest_IMPORT.exists() && fle_manifest_IMPORT.isFile() && fle_manifest_IMPORT.length() > 0)
			{
				
				//try to delete the old directory
				try	
				{	
					File fle = new File(Interface.path_fle_analysis_directory); 
					
					LinkedList<File> listing = new LinkedList<File>();
					listing = driver.getFileListing(fle, true, null, listing);
					
					if(listing == null || listing.size() < 1)						
						fle.delete();	
					
				}	catch(Exception e){}
				
				path_fle_analysis_directory = fle_manifest_IMPORT.getParentFile().getCanonicalPath().trim();
				
				if(!path_fle_analysis_directory.endsWith(File.separator))
					path_fle_analysis_directory = path_fle_analysis_directory + File.separator;	
				
				Interface.fle_analysis_directory = fle_manifest_IMPORT.getParentFile();
				Interface.path_fle_analysis_directory = path_fle_analysis_directory;
			
				
				
				this.start();
			}
			else
			{
				driver.directive("PUNT!!! No valid system manifest import file was received for analysis!");
			}			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 4", e);
		}
	}
	
	
	public void run()
	{
		try
		{
			commence_action();
			driver.open_file(Interface.fle_analysis_directory);
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "run", e);
		}
	}
	
	public boolean launch_report_terminate_system(boolean terminate_program)
	{
		try
		{
			create_tree_structure(this.tree_PROCESS);
			
			analysis_report = new Analysis_Report_Container_Writer(this);		
			
			AUTOMATED_ANALYSIS_COMPLETE = true;
			
			driver.pause();
			
			if(Interface.AUTOMATE_XREF_SEARCH)
			{
				try	{	Start.intface.jtabbedPane_MAIN.setSelectedIndex(2);	} catch(Exception e){}


				if(!Start.intface.jtfFile_XREF_SearchString.getText().trim().equals(""))
				{
					Start.intface.file_xref = new File_XREF(Start.intface);
				}
			}
			
			
			if(terminate_program)
				System.exit(0);
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "launch_report_terminate_system", e);
		}
		
		return false;
	}
	
	public boolean process_list(boolean dump_processes, boolean execute_abbreviated_processlist)
	{
		try
		{
			driver.directive("\nExecuting Process list plugins...");
			
			LinkedList<String> list_output = new LinkedList<String>();
			
			try	{	Advanced_Analysis_Director.list_plugins_in_execution.add("pslist");	} catch(Exception e){}

			fle_pslist = execute_plugin("pslist", "Print all running processes by following the EPROCESS lists", null, "", list_output, true);			
			process_pslist(list_output);
			try	{	Advanced_Analysis_Director.list_plugins_in_execution.remove("pslist");	} catch(Exception e){}

			//
			//psscan - scan for processes via pool-scanning
			//
			try	{	Advanced_Analysis_Director.list_plugins_in_execution.add("psscan");	} catch(Exception e){}

			fle_psscan = execute_plugin("psscan", "Pool scanner for process objects", null, "", list_output, true);			
			process_psscan(list_output);
						
			//
			//dot file; then on linux: dot -Tjpg psscan.dot -o <path>.jpg  or dot -Tpng <path>.dot -o <path>.png
			//
			create_psscan_dot_file();
			try	{	Advanced_Analysis_Director.list_plugins_in_execution.remove("psscan");	} catch(Exception e){}
			
			if(!execute_abbreviated_processlist)
			{
				//
				//pstree
				//
				try	{	Advanced_Analysis_Director.list_plugins_in_execution.add("pstree");	} catch(Exception e){}
				fle_pstree = execute_plugin("pstree", "Print process list as a tree", null, "", list_output, true);			
				process_pstree(list_output);
				try	{	Advanced_Analysis_Director.list_plugins_in_execution.remove("pstree");	} catch(Exception e){}
				//
				//psxview
				//
				try	{	Advanced_Analysis_Director.list_plugins_in_execution.add("psxview");	} catch(Exception e){}
				fle_psxview = execute_plugin("psxview", "Find hidden processes with various process listings", null, "", list_output, true);			
				process_psxview(list_output);
				try	{	Advanced_Analysis_Director.list_plugins_in_execution.remove("psxview");	} catch(Exception e){}
			}
			

			if(dump_processes)
				procdump = new Analysis_Plugin_Dump(null, this, "procdump", "Dump a process to an executable file sample", true, jta, false);
			
			//recurse process tree structure
			create_tree_structure(this.tree_PROCESS);
			
			driver.directive("\nProcess list plugin execution complete...");
			return true;		
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_list");
		}
		
		driver.directive("\nProcess list plugin execution complete...");
		return false;
	}
	
	
	/**
	 * return process from file name input where the PID is the second token from underline delimiters e.g. vadtree_4_MemoryDump_Lab1.raw.png
	 * @param file_name
	 * @return
	 */
	public Node_Process get_process_from_file_name(String file_name, String delimiter, int index_to_locate_pid)
	{
		try
		{
			if(file_name == null || file_name.trim().equals("") || file_name.length() < index_to_locate_pid)
				return null;
			
			if(this.tree_PROCESS == null || this.tree_PROCESS.size() < 1)
			{
				driver.sop("NOTE: Node_Process tree is empty! I was not able to extract PID from input: " + file_name + " in class: " + this.myClassName);
				return null;
			}
			
			String [] arr = file_name.split(delimiter);							
			int PID = Integer.parseInt(arr[index_to_locate_pid].trim());
			
			return this.tree_PROCESS.get(PID);			
		}
		catch(Exception e)
		{
			driver.sop("* * NOTE: I was not able to extract PID from input: " + file_name + " in class: " + this.myClassName);
		}
		
		return null;
	}
	
	public boolean import_advanced_analysis(LinkedList<File> list, File directory)
	{
		boolean prev_enable_impscan = PROCESS_IMPSCAN;
		
		try
		{
			if(list == null || list.isEmpty())
			{
				driver.jop("Received list is empty! Please try again if necessary...");
				return false;
			}
			
			AUTOMATED_ANALYSIS_STARTED = true;
			AUTOMATED_ANALYSIS_COMPLETE = false;
						
			PROCESS_IMPSCAN = false;
			
			String fle_name = "";
			String fle_path = "";
			String plugin_name = "";
			
			Start.intface.sop("\nCommencing import action on directory --> " + directory);
			

			///////////////////////////////////////////////////////////////////////////
			//
			// Rebuild Process tree
			//
			///////////////////////////////////////////////////////////////////////////				
			Start.intface.sop("Building process tree now...");
			
			for(File fle : list)
			{
				if(fle == null || !fle.exists() || !fle.isFile())
					continue;
				
				fle_path = fle.getCanonicalPath().trim();
				fle_name = fle.getName().toLowerCase().trim();
				
				if(fle_name.startsWith("_"))
					fle_name = fle_name.substring(1).trim();
				
				if(fle_name.equals(""))
					continue;
															
				if(fle_name.startsWith("psscan") && fle_name.endsWith(".png"))
					relative_path_to_converted_dot_process_image = fle.getParentFile().getName() + "/" + fle.getName();				
				
				//filter only to text files
				if(!fle_name.endsWith(".txt"))
					continue;

				//////////////////////////////////////////////////////////////////////
				// Build process list
				/////////////////////////////////////////////////////////////////////	
				
				//pslist
				if(fle_name.startsWith("pslist"))
				{
					plugin_name = "pslist";
					
					this.fle_pslist = fle;
					LinkedList<String> list_output = new LinkedList<String>();
					driver.load_file(fle, list_output, true);					
					this.process_pslist(list_output);
					Start.intface.sop("\t[" + plugin_name + "] Import complete for file --> " + fle);
				}
				
				//psscan
				else if(fle_name.startsWith("psscan"))
				{
					plugin_name = "psscan";
					
					this.fle_psscan = fle;
					LinkedList<String> list_output = new LinkedList<String>();
					driver.load_file(fle, list_output, true);					
					this.process_psscan(list_output);
					Start.intface.sop("\t[" + plugin_name + "] Import complete for file --> " + fle);					
				}
				
				//psscan
				else if(fle_name.startsWith("pstree"))
				{
					plugin_name = "pstree";
					
					this.fle_pstree = fle;
					LinkedList<String> list_output = new LinkedList<String>();
					driver.load_file(fle, list_output, true);					
					this.process_pstree(list_output);
					Start.intface.sop("\t[" + plugin_name + "] Import complete for file --> " + fle);
				}
				
				//psscan
				else if(fle_name.startsWith("psxview"))
				{
					plugin_name = "psxview";
					
					this.fle_psxview = fle;
					LinkedList<String> list_output = new LinkedList<String>();
					driver.load_file(fle, list_output, true);					
					this.process_psxview(list_output);
					Start.intface.sop("\t[" + plugin_name + "] Import complete for file --> " + fle);
				}										
				
			}// end for
			
			///////////////////////////////////////////////////////////////////////////
			//
			// Load envars
			//
			///////////////////////////////////////////////////////////////////////////
			Start.intface.sop("\nDone. Building Environment Variables list now...");

			for(File fle : list)
			{
				if(fle == null || !fle.exists() || !fle.isFile())
					continue;

				fle_path = fle.getCanonicalPath().trim();
				fle_name = fle.getName().toLowerCase().trim();

				if(fle_name.startsWith("_"))
					fle_name = fle_name.substring(1).trim();

				if(fle_name.equals(""))
					continue;

				//filter only to text files
				if(!fle_name.endsWith(".txt"))
					continue;

				if(fle_name.startsWith("envars"))
				{
					plugin_envars = new Analysis_Plugin_envars(fle, this, "envars", "Display process environment variables", false, jta);
					initialize_computer_name();
				}	

			}
						
			
			///////////////////////////////////////////////////////////////////////////
			//
			// Load DLL modules
			//
			///////////////////////////////////////////////////////////////////////////
			Start.intface.sop("\nDone. Building DLL modules tree now...");
			
			for(File fle : list)
			{
				if(fle == null || !fle.exists() || !fle.isFile())
					continue;
				
				fle_path = fle.getCanonicalPath().trim();
				fle_name = fle.getName().toLowerCase().trim();
				
				if(fle_name.startsWith("_"))
					fle_name = fle_name.substring(1).trim();
				
				if(fle_name.equals(""))
					continue;
																					
				//filter only to text files
				if(!fle_name.endsWith(".txt"))
					continue;
				
				 if(fle_name.startsWith("dlllist"))
					plugin_dlllist = new Analysis_Plugin_dlllist(fle,this, "dlllist", "Print list of loaded dlls for each process", false, jta);
				 
				//else if(fle_name.startsWith("moddump"))
					//plugin_moddump = new Analysis_Plugin_SUPER_MODULES(fle,this, "moddump", "Dump a kernel driver to an executable file sample", false, jta); //runs modules and modscan within moddump!
					
				else if(fle_name.startsWith("modules"))
					plugin_modules = new Analysis_Plugin_modules(fle, this, "modules", "Print list of loaded modules", false, jta); //run modules and modscan within moddump!
				
				else if(fle_name.startsWith("modscan"))
					plugin_modscan = new Analysis_Plugin_modscan(fle, this, "modscan", "Pool scanner for kernel modules", false, jta); 
				
				else if(fle_name.startsWith("drivermodule"))
					plugin_drivermodule = new Analysis_Plugin_drivermodule(fle, this, "drivermodule", "Associate driver objects to kernel modules", false, jta);
				
				else if(fle_name.startsWith("driverscan"))
					plugin_driverscan = new Analysis_Plugin_driverscan(fle, this, "driverscan", "Pool scanner for driver objects", false, jta);
							
				else if(fle_name.startsWith("driverirp"))
					plugin_driverirp = new Analysis_Plugin_driverirp(fle, this, "driverirp", "Driver IRP hook detection", false, jta);
												
				else if(fle_name.startsWith("timers"))
					plugin_timers  = new Analysis_Plugin_Timers(fle, this, "timers", "Print kernel timers and associated module DPCs", false, jta);				 
					
				else if(fle_name.startsWith("ldrmodules"))
					plugin_ldrmodules = new Analysis_Plugin_ldrmodules(fle,this, "ldrmodules", "Detect unlinked DLLs", false, jta);				

			}//end for
									
			///////////////////////////////////////////////////////////////////////////
			//
			// Load all other files
			//
			///////////////////////////////////////////////////////////////////////////
			Start.intface.sop("\nDone. Importing plugin output files now...");
			
			for(File fle : list)
			{
				
				
				if(fle == null || !fle.exists() || !fle.isFile())
					continue;
				
				fle_path = fle.getCanonicalPath().trim();
				fle_name = fle.getName().toLowerCase().trim();
				
				if(fle_name.startsWith("_"))
					fle_name = fle_name.substring(1).trim();
				
				if(fle_name.equals(""))
					continue;
				
				///////////////////////////////////////////////////////////////////////////
				// process images
				///////////////////////////////////////////////////////////////////////////
				if(fle_name.endsWith(".png"))
				{
					try
					{
						//
						//vadtree
						//
						if(fle_name.startsWith("vadtree_"))
						{
							//vadtree_4_MemoryDump_Lab1.raw.png
							Node_Process process = this.get_process_from_file_name(fle_name, "_", 1);
							
							if(process == null)
								continue;
							
							//save path
							process.fle_vadtree_output_image = fle;							
							process.relative_path_vadtree_image = fle.getParentFile().getParentFile().getName() + File.separator + fle.getParentFile().getName() + File.separator + fle.getName(); 
						}
					}
					catch(Exception e)
					{
						continue;
					}										
				}
						
				
				///////////////////////////////////////////////////////////////////////////
				// process dot files
				///////////////////////////////////////////////////////////////////////////
				else if(fle_name.endsWith(".dot"))
				{
					try
					{
						//
						//vadtree
						//
						if(fle_name.startsWith("vadtree_"))
						{
							//vadtree_4_MemoryDump_Lab1.raw.png
							Node_Process process = this.get_process_from_file_name(fle_name, "_", 1);
							
							if(process == null)
								continue;
							
							//save path
							process.fle_vadtree_output_data = fle;												 
						}
					}
					catch(Exception e)
					{
						continue;
					}										
				}
				
				
				///////////////////////////////////////////////////////////////////////////
				// process text files
				///////////////////////////////////////////////////////////////////////////
				else if(!fle_name.endsWith(".txt"))
					continue;
				
				///////////////////////////////////////////////////////////////////////////
				// procdump output file
				///////////////////////////////////////////////////////////////////////////
				if(fle_name.startsWith("procdump_"))
				{
					try
					{
						plugin_name = "procdump";						
						BufferedReader br = new BufferedReader(new FileReader(fle));
						
						String line = "";
						while((line = br.readLine()) != null)
						{
							try
							{
								line = line.trim();
								
								if(line.equals(""))
									continue;
								
								if(line.startsWith("#"))
									continue;
								
								if(!line.contains("	"))
									continue;
								
								//File Name: svchost_1044_exe	  File Size: 27.14 KBs	  Creation Date: 2021-10-26-1104:16	  Last Accessed: 2021-10-26-1104:16	  Last Modified: 2021-10-26-1104:16	  MD5: 2d4caec773108a32313681cee8f2a514	  SHA-256: ac9df0d3cae01e00598d71962865802276d9d6afd798448b63cbb784ea986ced
								String [] arr = line.split("	");
								
								String name = arr[0].substring(arr[0].indexOf(":")+1).trim();
								String file_size = arr[1].substring(arr[1].indexOf(":")+1).trim();
								String creation_date = arr[2].substring(arr[2].indexOf(":")+1).trim();
								String last_accessed = arr[3].substring(arr[3].indexOf(":")+1).trim();
								String last_modified = arr[4].substring(arr[4].indexOf(":")+1).trim();
								String md5 = arr[5].substring(arr[5].indexOf(":")+1).trim();
								String sha_256 = arr[6].substring(arr[6].indexOf(":")+1).trim();								
								String extension = null;
									try	{	extension = name.substring(name.lastIndexOf(".")+1).trim();	}	catch(Exception e){}
										
								Node_Process process = this.get_process_from_file_name(name, "_", 1);
								
								process.fle_attributes = new FileAttributeData(process);
								
								process.fle_attributes.file_name = name;
								process.fle_attributes.size = file_size;
								process.fle_attributes.creation_date = creation_date;
								process.fle_attributes.last_accessed = last_accessed;
								process.fle_attributes.last_modified = last_modified;
								process.fle_attributes.hash_md5 = md5;
								process.fle_attributes.hash_sha256 = sha_256;
								process.fle_attributes.extension = extension;
								
								try	{	FileAttributeData.tree_file_attributes.put(name, process.fle_attributes);	} catch(Exception e){}
							}
							catch(Exception e)
							{
								continue;
							}
						}
						
					}
					catch(Exception e)
					{
						continue;
					}
				}//end if for procdump
				
			
				
				///////////////////////////////////////////////////////////////////////////
				// dlldump output file
				///////////////////////////////////////////////////////////////////////////
				if(fle_name.startsWith("dlldump_"))
				{
					try
					{
						plugin_name = "dlldump";						
						BufferedReader br = new BufferedReader(new FileReader(fle));
						
						String line = "";
						while((line = br.readLine()) != null)
						{
							try
							{
								line = line.trim();
								
								if(line.equals(""))
									continue;
								
								if(line.startsWith("#"))
									continue;
								
								if(!line.contains("	"))
									continue;
								
								//File Name: svchost.exe_1044_kernel32.dll_3ec50b30_77a70000	 File Size: 1.16 MBs	 Creation Date: 2021-10-31-2110:31	 Last Accessed: 2021-10-31-2110:31	 Last Modified: 2021-10-31-2110:31	 MD5: 1607b73ac661d46249f649bbf2a90f22	 SHA-256: a018753453f794663922cb88fcba5895d31090ab3543e40f0512017528db9fca	 
								String [] arr = line.split("	");
								String name = arr[0].substring(arr[0].indexOf(":")+1).trim(); //svchost.exe_1044_kernel32.dll_3ec50b30_77a70000
								String file_size = arr[1].substring(arr[1].indexOf(":")+1).trim();
								String creation_date = arr[2].substring(arr[2].indexOf(":")+1).trim();
								String last_accessed = arr[3].substring(arr[3].indexOf(":")+1).trim();
								String last_modified = arr[4].substring(arr[4].indexOf(":")+1).trim();
								String md5 = arr[5].substring(arr[5].indexOf(":")+1).trim();
								String sha_256 = arr[6].substring(arr[6].indexOf(":")+1).trim();								
								
								//bifurcate name
								String [] arrName = name.split("_");
								String process_name = arrName[0].trim();
								String pid = arrName[1].trim();
								String dll_name = arrName[2].trim();
								String process_offset_P_trimmed = arrName[3].trim();
								String module_base_address_trimemd = arrName[4].trim();
								int PID = -1;	try	{ PID = Integer.parseInt(pid.trim());	} catch(Exception e){PID = -1;}
								
								
								//expand to create full module base address
								String module_base_address = driver.expand_base_address(module_base_address_trimemd);
								
								
								String extension = null;
									try	{	extension = dll_name.substring(dll_name.lastIndexOf(".")+1).trim();	}	catch(Exception e){}
										
								Node_Process process = null;
								Node_DLL DLL = null;
								
								try	{	process = this.tree_PROCESS.get(Integer.parseInt(pid));	} catch(Exception e){}
								try	{	DLL = tree_DLL_MODULES_linked_by_VAD_base_start_address.get(module_base_address.toLowerCase().trim()).getFirst();	} catch(Exception e){}
								
									
								if(process != null && process.fle_attributes == null)
								{
									process.fle_attributes = new FileAttributeData(process);								
									process.fle_attributes.file_name = name;
									process.fle_attributes.size = file_size;
									process.fle_attributes.creation_date = creation_date;
									process.fle_attributes.last_accessed = last_accessed;
									process.fle_attributes.last_modified = last_modified;
									process.fle_attributes.hash_md5 = md5;
									process.fle_attributes.hash_sha256 = sha_256;
									process.fle_attributes.extension = extension;	
									
									try	{	FileAttributeData.tree_file_attributes.put(name, process.fle_attributes);	} catch(Exception e){}
								}
								
								if(DLL != null && DLL.fle_attributes == null)
								{
									DLL.fle_attributes = new FileAttributeData(process);								
									DLL.fle_attributes.file_name = name;
									DLL.fle_attributes.size = file_size;
									DLL.fle_attributes.creation_date = creation_date;
									DLL.fle_attributes.last_accessed = last_accessed;
									DLL.fle_attributes.last_modified = last_modified;
									DLL.fle_attributes.hash_md5 = md5;
									DLL.fle_attributes.hash_sha256 = sha_256;
									DLL.fle_attributes.extension = extension;
									
									if(process != null && process.tree_dll_VAD_base_start_address != null && !process.tree_dll_VAD_base_start_address.containsKey(module_base_address))
										process.tree_dll_VAD_base_start_address.put(module_base_address,  DLL);
									
									if(DLL.tree_process != null && !DLL.tree_process.containsKey(module_base_address))
											DLL.tree_process.put(PID,  process);
									if(process != null)
										DLL.store_dll_base(module_base_address, process, this);
									
									try	{	FileAttributeData.tree_file_attributes.put(name, DLL.fle_attributes);	} catch(Exception e){}
								}
								
								
																							
							}
							catch(Exception e)
							{
								continue;
							}
						}
						
					}
					catch(Exception e)
					{
						continue;
					}
				}//end if for dlldump

				

				///////////////////////////////////////////////////////////////////////////
				// moddump output file
				///////////////////////////////////////////////////////////////////////////
				else if(fle_name.startsWith("moddump_"))
				{
					try
					{
						plugin_name = "moddump";						
						BufferedReader br = new BufferedReader(new FileReader(fle));
						
						String line = "";
						while((line = br.readLine()) != null)
						{
							try
							{
								line = line.trim();
								
								if(line.equals(""))
									continue;
								
								if(line.startsWith("#"))
									continue;
								
								if(!line.contains("	"))
									continue;
								
								//File Name: kdcom.dll_driver.fffff80000bc2000.sys	 File Size: 10.75 KBs	 Creation Date: 2021-10-31-2352:01	 Last Accessed: 2021-10-31-2352:01	 Last Modified: 2021-10-31-2352:01	 MD5: 7e6364b55777f1f88782e83cee2b05db	 SHA-256: 38d41cf69ee3472c9f009e9ccb22aad21085d2c2013cc398298ef4a72bc0de50	 	 
								String [] arr = line.split("	");
								String name = arr[0].substring(arr[0].indexOf(":")+1).trim(); //kdcom.dll_driver.fffff80000bc2000.sys
								String file_size = arr[1].substring(arr[1].indexOf(":")+1).trim();
								String creation_date = arr[2].substring(arr[2].indexOf(":")+1).trim();
								String last_accessed = arr[3].substring(arr[3].indexOf(":")+1).trim();
								String last_modified = arr[4].substring(arr[4].indexOf(":")+1).trim();
								String md5 = arr[5].substring(arr[5].indexOf(":")+1).trim();
								String sha_256 = arr[6].substring(arr[6].indexOf(":")+1).trim();								
								
								//bifurcate name
								String [] arrName = name.split("_");
								String module_name = arrName[0].trim();
																							
								Node_Driver module = null;
								
								try	{ module = this.tree_DRIVERS.get(module_name);	}	catch(Exception e){}
								
								if(module == null)
									try	{ module = this.tree_DRIVERS.get(module_name.toLowerCase().trim());	}	catch(Exception e){}
																							
								if(module != null && module.fle_attributes == null)
								{
									String extension = "";
									
									try	{ extension = module_name.substring(module_name.lastIndexOf(".")+1).trim();	} catch(Exception e){}
									
									module.fle_attributes = new FileAttributeData(module);								
									module.fle_attributes.file_name = name;
									module.fle_attributes.size = file_size;
									module.fle_attributes.creation_date = creation_date;
									module.fle_attributes.last_accessed = last_accessed;
									module.fle_attributes.last_modified = last_modified;
									module.fle_attributes.hash_md5 = md5;
									module.fle_attributes.hash_sha256 = sha_256;
									module.fle_attributes.extension = extension;	
								}
								
							}
							catch(Exception e)
							{
								driver.directive("[" + plugin_name + "] NOTE: I was unable to process line --> " + line);
								continue;
							}
						}
						
					}
					catch(Exception e)
					{
						continue;
					}
				}//end if for moddump
				
				///////////////////////////////////////////////////////////////////////////
				// impscan
				///////////////////////////////////////////////////////////////////////////
				else if(fle_name.startsWith("impscan_"))
				{
					try
					{
						//bifurcate process name and PID
						String []arr = fle_name.split("_");
						String process_name = arr[1].trim();
						String pid = arr[2].trim();
						
						if(pid.contains("."))
							pid = pid.substring(0, pid.indexOf(".")).trim();
						
						Node_Process process = this.tree_PROCESS.get(Integer.parseInt(pid));
						
						if(process == null)
						{
							driver.directive("[impscan] I could not locate PID from " + fle_name);
							continue;
						}
						
						if(process.impscan == null && process.PID > -1)
						{
							process.impscan = new Analysis_Plugin_impscan(fle, this, "impscan", "Scan for calls to imported functions", Analysis_Plugin_impscan.EXECUTE_VIA_THREAD, jta, process);
						}
					}
					catch(Exception e)
					{
						continue;
					}
				}
				
				

				///////////////////////////////////////////////////////////////////////////
				// remaining plugin output files
				///////////////////////////////////////////////////////////////////////////
				
				else if(fle_name.startsWith("callbacks"))
					plugin_callbacks  = new Analysis_Plugin_Callbacks(fle, this, "callbacks", "Print system-wide notification routines", false, jta); 
				
				else if(fle_name.startsWith("unloadedmodules"))
					plugin_unloaded_modules  = new Analysis_Plugin_Unloaded_Modules(fle, this, "unloadedmodules", "Print list of unloaded modules", false, jta); 
				
				else if(fle_name.startsWith("hashdump"))				
					plugin_hashdump = new Analysis_Plugin_hashdump(fle, this, "hashdump", "Dumps passwords hashes (LM/NTLM) from memory", false, jta);				
				
				else if(fle_name.startsWith("getservicesids"))
					plugin_get_service_sids = new Analysis_Plugin_get_service_sids(fle, this, "getservicesids", "Get the names of services in the Registry and return Calculated SID", false, jta);
				
				else if(fle_name.startsWith("mftparser_"))
				{
					plugin_mftparser = new Process_Plugin(null, "mftparser", "Scans for and parses potential MFT entries");
					plugin_mftparser.fleOutput = fle;
					
					//set import timestamp
					if(this.MFTPARSER_EXECUTION_TIME_STAMP_FROM_RELOAD_EXPORT_DIRECTORY == null)	{	try	{	this.MFTPARSER_EXECUTION_TIME_STAMP_FROM_RELOAD_EXPORT_DIRECTORY = fle_name.substring(fle_name.indexOf("_")+1, fle_name.indexOf(".")).trim();	}		catch(Exception e){}}		
				
															
					plugin_mftparser.path_to_output_directory = fle.getParentFile().getCanonicalPath().trim();
					
					if(!plugin_mftparser.path_to_output_directory.endsWith(File.separator))
						plugin_mftparser.path_to_output_directory = plugin_mftparser.path_to_output_directory + File.separator;
					
					plugin_mftparser.path_to_output_directory = plugin_mftparser.path_to_output_directory + "_mftparser_" + MFTPARSER_EXECUTION_TIME_STAMP_FROM_RELOAD_EXPORT_DIRECTORY + File.separator;
				}

//else if(fle_name.startsWith("mftparser"))
	//plugin_mftparser = new Process_Plugin(fle, "mftparser", "Scans for and parses potential MFT entries", null, null, this.fle_volatility.getName() + " -f " + this.fle_memory_image.getName() + " mftparser --profile=" + this.PROFILE, true, false, "", false, jta);
	
				//else if(fle_name.startsWith("registry_startup"))
				//	plugin_registry_startup = new Analysis_Plugin_Registry_Startup_Apps(fle,this, "registry_startup", "Print Subkeys of Registry Startup Locations", false, jta);
					
				else if(fle_name.startsWith("svcscan"))
					plugin_svcscan = new Analysis_Plugin_svcscan(fle,this, "svcscan", "Scan for Windows services", false, jta);
				
				else if(fle_name.startsWith("threads"))
					plugin_threads = new Analysis_Plugin_Threads(fle,this, "threads", "Investigate _ETHREAD and _KTHREADs", false, jta);	
					
				else if(fle_name.startsWith("apihooks"))
					plugin_apihooks = new Analysis_Plugin_apihooks(fle,this, "apihooks", "Detect API hooks in process and kernel memory", false, jta);
				
				else if(fle_name.startsWith("privs"))
					plugin_privs = new Analysis_Plugin_Privs(fle,this, "privs", "Display process privileges", false, jta);
											

					
//else if(fle_name.startsWith("procdump"))
//	procdump = new Analysis_Plugin_Dump(fle,this, "procdump", "Dump a process to an executable file sample", true, false);
	
//else if(fle_name.startsWith("dlldump"))
	//dlldump = new Analysis_Plugin_Dump(fle,this, "dlldump", "Dump DLLs from a process address space", true, false);
					
				else if(fle_name.startsWith("cmdscan"))
					plugin_cmdscan = new Analysis_Plugin_cmdscan(fle,this, "cmdscan", "Extract command history by scanning for _COMMAND_HISTORY", false, jta);
			 				 
				else if(fle_name.startsWith("malfind"))
					plugin_malfind = new Analysis_Plugin_malfind(fle,this, "malfind", "Find hidden and injected code", false, jta);
					
				else if(fle_name.startsWith("getsids"))
					plugin_getsids = new Analysis_Plugin_getsids(fle,this, "getsids", "Print the SIDs owning each process", false, jta);
					
				else if(fle_name.startsWith("hivelist"))
					plugin_hivelist = new Analysis_Plugin_hivelist(fle,this, "hivelist", "Print list of registry hives", false, jta);
					
				else if(fle_name.startsWith("hivescan"))
					plugin_hivescan = new Analysis_Plugin_EXECUTION(fle,this, "hivescan", "Pool scanner for registry hives", false, jta);
					
				else if(fle_name.startsWith("dumpregistry"))
					plugin_regdump = new Analysis_Plugin_EXECUTION(fle,this, "dumpregistry", "Dumps registry files out to disk", false, jta);
					
				else if(fle_name.startsWith("deskscan"))
					plugin_deskscan = new Analysis_Plugin_Deskscan(fle,this, "deskscan", "Poolscaner for tagDESKTOP (desktops)", false, jta);
					
				else if(fle_name.startsWith("evtlogs"))
					plugin_evtlogs = new Analysis_Plugin_EXECUTION(fle,this, "evtlogs", "Extract Windows Event Logs (XP/2003 only)", false, jta);
					
				else if(fle_name.startsWith("dumpfiles --regex"))
					plugin_evtlogs = new Analysis_Plugin_EXECUTION(fle,this, "dumpfiles - event logs", "Dump Windows Event Logs ", false, jta);
					
				else if(fle_name.startsWith("filescan"))
					plugin_filescan = new Analysis_Plugin_EXECUTION(fle,this, "filescan", "Pool scanner for file objects", false, jta);
					
				else if(fle_name.startsWith("gditimers"))
					plugin_gditimers = new Analysis_Plugin_GDI_Timers(fle,this, "gditimers", "Print installed GDI timers and callbacks", false, jta);
					
				else if(fle_name.startsWith("imageinfo"))
					plugin_imageinfo = new Analysis_Plugin_EXECUTION(fle,this, "imageinfo", "Identify information for the image", false, jta);
					
				else if(fle_name.startsWith("kdbgscan"))
					plugin_kdbgscan = new Analysis_Plugin_EXECUTION(fle,this, "kdbgscan", "Search for and dump potential KDBG values", false, jta);
					
				else if(fle_name.startsWith("lsadump"))
					plugin_lsadump = new Analysis_Plugin_EXECUTION(fle,this, "lsadump", "Dump (decrypted) LSA secrets from the registry", false, jta);
					
				else if(fle_name.startsWith("messagehooks"))
					plugin_messagehooks = new Analysis_Plugin_EXECUTION(fle,this, "messagehooks", "List desktop and thread window message hooks", false, jta);
					
				else if(fle_name.startsWith("joblinks"))
					plugin_joblinks = new Analysis_Plugin_EXECUTION(fle,this, "joblinks", "Print process job link information", false, jta);
				
				else if(fle_name.startsWith("notepad"))
					plugin_notepad = new Analysis_Plugin_EXECUTION(fle,this, "notepad", "List currently displayed notepad text", false, jta);
					
				else if(fle_name.startsWith("sessions"))
					plugin_sessions = new Analysis_Plugin_sessions(fle,this, "sessions", "List details on _MM_SESSION_SPACE (user logon sessions)", false, jta);
					
				else if(fle_name.startsWith("ssdt"))
					plugin_ssdt = new Analysis_Plugin_EXECUTION(fle,this, "ssdt", "Display SSDT entries", false, jta);
					
				else if(fle_name.startsWith("symlinkscan"))
					plugin_symlinkscan = new Analysis_Plugin_EXECUTION(fle,this, "symlinkscan", "Pool scanner for symlink objects", false, jta);
					
				else if(fle_name.startsWith("thrdscan"))
					plugin_thrdscan = new Analysis_Plugin_EXECUTION(fle,this, "thrdscan", "Pool scanner for thread objects", false, jta);
					
				else if(fle_name.startsWith("userassist"))
					plugin_userassist = new Analysis_Plugin_user_assist(fle,this, "userassist", "Print userassist registry keys and information", false, jta);
					
				else if(fle_name.startsWith("printkey"))
					plugin_printkey = new Analysis_Plugin_print_key(fle,this, "printkey", "Print a registry key, and its subkeys and values", false, jta);
					
				else if(fle_name.startsWith("userhandles"))
					plugin_userhandles = new Analysis_Plugin_EXECUTION(fle,this, "userhandles", "Dump the USER handle tables", false, jta);
					
				else if(fle_name.startsWith("vadinfo"))
					plugin_vadinfo = new Analysis_Plugin_VAD_INFO(fle,this, "vadinfo", "Dump the VAD info", false, jta);
					
				else if(fle_name.startsWith("vadtree") && fle_name.endsWith(".txt"))
					plugin_vadtree = new Analysis_Plugin_vadtree(fle,this, "vadtree", "vadtree", false, jta);
					
				else if(fle_name.startsWith("vadwalk"))
					plugin_vadwalk = new Analysis_Plugin_EXECUTION(fle,this, "vadwalk", "Walk the VAD tree", false, jta);
					
				else if(fle_name.startsWith("win10cookie"))
					plugin_win10cookie = new Analysis_Plugin_EXECUTION(fle,this, "win10cookie", "Find the ObHeaderCookie value for Windows 10", false, jta);
					
				else if(fle_name.startsWith("windows_"))
					plugin_windows = new Analysis_Plugin_EXECUTION(fle,this, "windows", "Print Desktop Windows (verbose details)", false, jta);
										
				else if(fle_name.startsWith("wintree"))
					plugin_wintree = new Analysis_Plugin_EXECUTION(fle,this, "wintree", "Print Z", false, jta);
					
				else if(fle_name.startsWith("wndscan"))
					plugin_wndscan = new Analysis_Plugin_EXECUTION(fle,this, "wndscan", "Pool scanner for window stations", false, jta);
					
				else if(fle_name.startsWith("shellbags"))
					plugin_shellbags = new Analysis_Plugin_EXECUTION(fle,this, "shellbags", "Prints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags info", false, jta);
					
				else if(fle_name.startsWith("shimcache"))
					plugin_shimcache = new Analysis_Plugin_EXECUTION(fle,this, "shimcache", "Parses the Application Compatibility Shim Cache registry key", false, jta);
					
				else if(fle_name.startsWith("timeliner"))
					plugin_timeliner = new Analysis_Plugin_EXECUTION(fle,this, "timeliner", "Creates a timeline from various artifacts in memory", false, jta);

					
				else if(fle_name.startsWith("verinfo"))
					plugin_verinfo = new Analysis_Plugin_verinfo(fle,this, "verinfo", "Prints out the version information from PE images", false, jta);
					
				else if(fle_name.startsWith("cmdline"))
					plugin_cmdline = new Analysis_Plugin_cmdline(fle,this, "cmdline", "Display process command", false, jta);
					
				else if(fle_name.startsWith("consoles"))
					plugin_consoles = new Analysis_Plugin_consoles(fle,this, "consoles", "Extract command history by scanning for _CONSOLE_INFORMATION", false, jta);
					
				else if(fle_name.startsWith("connections"))
					plugin_connections = new Analysis_Plugin_connections(fle,this, "connections", "Print list of open connections [Windows XP and 2003 Only]", false, jta);
					
				else if(fle_name.startsWith("connscan"))
					plugin_connscan = new Analysis_Plugin_connscan(fle,this, "connscan", "Pool scanner for tcp connections", false, jta);
					
				else if(fle_name.startsWith("sockets"))
					plugin_sockets = new Analysis_Plugin_sockets(fle,this, "sockets", "Print list of open sockets", false, jta);
					
				else if(fle_name.startsWith("sockscan"))
					plugin_sockscan = new Analysis_Plugin_sockscan(fle,this, "sockscan", "Pool scanner for tcp socket objects", false, jta);
					
				else if(fle_name.startsWith("netscan"))
					plugin_netscan = new Analysis_Plugin_netscan(fle,this, "netscan", "Scan a Vista (or later) image for connections and sockets", false, jta);
					
				else if(fle_name.startsWith("handles"))
					plugin_handles = new Analysis_Plugin_handles(fle,this, "handles", "Print list of open handles for each process", false, jta);
					
				else if(fle_name.startsWith("auditpol"))
					plugin_audit_policies = new Analysis_Plugin_Auditpolicy(fle, this, "auditpol", "Prints out the Audit Policies from HKLM\\SECURITY\\Policy\\PolAdtEv", false, jta);
				
				else if(fle_name.startsWith("shutdowntime"))
					plugin_shutdowntime = new Analysis_Plugin_ShutdownTime(fle, this, "shutdowntime", "Print ShutdownTime of machine from registry", false, jta);
				
			
				
			}
				
			//////////////////////////////////////////////////////////////////////
			// Create Tree Structure - including building parent, child trees
			/////////////////////////////////////////////////////////////////////
			create_tree_structure(this.tree_PROCESS);
			
			Start.intface.sop("\n\nImport process complete!");
			
			analyze_display_consoles();
			

			
			PROCESS_IMPSCAN = prev_enable_impscan;
			AUTOMATED_ANALYSIS_COMPLETE = true;
			
			//check if xref search initiated this process
			if(XREF != null)
				XREF.process_search_File_XREF();
			
			if(EXECUTE_EXPORT_MANIFEST)
				this.write_manifest(WRITE_MANIFEST_DELIMITER);
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "import_advanced_analysis", e);
		}
		
		PROCESS_IMPSCAN = prev_enable_impscan;
		AUTOMATED_ANALYSIS_COMPLETE = true;
		return false;
	}
	
	public boolean plugin_autorun_setup_conf()
	{
		boolean prev_enable_impscan = PROCESS_IMPSCAN;
		PROCESS_IMPSCAN = false;
		
		try
		{
			
			
			if(this.list_auto_plugins_execution == null || this.list_auto_plugins_execution.size() < 1)
			{
				driver.jop("Empty Plugins to execute!");
				AUTOMATED_ANALYSIS_COMPLETE = true;
				return false;
			}
			
			AUTOMATED_ANALYSIS_STARTED = true;
			AUTOMATED_ANALYSIS_COMPLETE = false;
			
			//profile is the main item required for volatility 2.6 and older
			String plugin_lower = "";
			String description = "";
			
			//set focus
			try	{ Start.intface.jtabbedPane_MAIN.setSelectedIndex(1);} catch(Exception e){}
			
			//driver.sop("Initiating autorun actions - building proces and dll lists first...");
			
			Start.intface.jpnlAdvancedAnalysisConsole.append("Initiating autorun actions - building proces and dll lists first...");
			
			//run processlists
			process_list(false, true);
			
			//dlllist
			plugin_dlllist = new Analysis_Plugin_dlllist(null, this, "dlllist", "Print list of loaded dlls for each process", false, Start.intface.jpnlAdvancedAnalysisConsole);
			sp("Done! Instantiating autorun plugins now...");
			for(String plugin : this.list_auto_plugins_execution)
			{
				try
				{
					if(plugin == null)
						continue;
																			
					plugin_lower = plugin.toLowerCase().trim();

					if(plugin_lower.equals(""))
						continue;
					
					if(plugin_lower.equals("pslist") || plugin_lower.equals("psscann") || plugin_lower.equals("dlllist"))
						continue;
					
					description  = Interface.tree_PLUGIN_AND_DESCRIPTION.get(plugin_lower);
					
					if(description == null || description.trim().equals(""))
					{
						sop("I could not find plugin [" + plugin + "] in the main plugin inventory.");
						driver.jop_Message("I could not find plugin [" + plugin + "] in the main plugin inventory.");
						description = "-";
					}
					
					driver.sop("Instantiating Autoplugin --> " + plugin);
					
					if(plugin_lower.equals("userassist"))
						plugin_userassist = new Analysis_Plugin_user_assist(null, this, "userassist", "Print userassist registry keys and information", false, jta);
					else					
					{
						//handle specific plugins differently
											
						//instantiate plugin
						Analysis_Plugin_EXECUTION PLUGIN = new Analysis_Plugin_EXECUTION(null, this, plugin, description, true, Start.intface.jpnlAdvancedAnalysisConsole);
					}
				}
				
				catch(Exception e)
				{
					sop("I could not properly execute autoplugin entry [" + plugin + "]\nPlease check this entry and try again if necessary...");
					driver.jop("I could not properly execute autoplugin entry [" + plugin + "]\nPlease check this entry and try again if necessary...");
					continue;
				}								
			}
			
						
			
			PROCESS_IMPSCAN = prev_enable_impscan;
			//execute_completion_actions();
			AUTOMATED_ANALYSIS_COMPLETE = true;
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "plugin_autorun_setup_conf", e);
		}
		
		
		PROCESS_IMPSCAN = prev_enable_impscan;
		//execute_completion_actions();
		AUTOMATED_ANALYSIS_COMPLETE = true;
		return false;
	}
	
	
	
	public boolean import_manifest(File fle)
	{
		long line_num = 0;
		BufferedReader br = null;
		 
		boolean prev_PROCESS_IMPSCAN = PROCESS_IMPSCAN;		
		PROCESS_IMPSCAN = false;
		
		try
		{
			
			if(fle == null || !fle.isFile())
			{
				driver.directive("PUNT!!! Invalid manifest import file received!!!!!!\nI am halting actions here...");
				return false;
			}
			
			br = new BufferedReader(new FileReader(fle));
			
			String line = "";						
			String lower = "", key = "", value = "";
			String arr[] = null;
			
			driver.directive("\ncomencing import manifest on file " + fle.getCanonicalPath());
			
			try	{	list_import_manifest_file_error_message.clear(); } catch(Exception e){ list_import_manifest_file_error_message = new LinkedList<String>();}
			
			while((line = br.readLine()) != null)
			{								
				++line_num;
				
				if(line_num % 100 == 0)
					driver.sp(".");
				
				if(line_num % 10000 == 0)
					driver.sp("\n");
				
				line = line.trim();
				
				if(line.startsWith("#") || line.equals(""))
					continue;
				
				if(line.startsWith("*"))
					continue;
				
				if(line.startsWith("-"))
					continue;
				
				if(line.startsWith("~"))
					continue;
				
				lower = line.toLowerCase().trim();
				
				//
				//bifurcate key and value
				//
				arr = line.split("\t");
				key = arr[0].toLowerCase().trim();
				value = driver.trim_key(key, line, true);
												
				////////////////////////////////////////////////////////////
				//
				// investigation_particulars
				//
				//////////////////////////////////////////////////////////
				if(lower.startsWith("investigation_particulars"))
					process_import_manifest_investigation_particulars(line, lower, "investigation_particulars", line_num, br, 25, true);
				
				
								
				////////////////////////////////////////////////////////////
				//
				// PROCESS
				//
				//////////////////////////////////////////////////////////				
				else if(lower.startsWith("pid")) 									process_import_manifest_PROCESS(line, lower, "PROCESS", line_num, br, 0, true);
				else if(lower.startsWith("process_name")) 							process_import_manifest_PROCESS(line, lower, "PROCESS", line_num, br, 0, true);				
				else if(lower.startsWith("ppid")) 									process_import_manifest_PROCESS(line, lower, "PROCESS", line_num, br, 0, true);
				else if(lower.startsWith("command_line")) 							process_import_manifest_PROCESS(line, lower, "PROCESS", line_num, br, 0, true);

				else if(lower.startsWith("file_name")) 								process_import_manifest_PROCESS(line, lower, "PROCESS", line_num, br, 0, true);
				else if(lower.startsWith("extension")) 								process_import_manifest_PROCESS(line, lower, "PROCESS", line_num, br, 0, true);

				//
				//my_module_description
				//
				else if(lower.startsWith("my_module_description"))					process_import_manifest_PROCESS(line, lower, "PROCESS", line_num, br, 0, true);
				
				//
				//process\tfile_attr
				//
				else if(lower.startsWith("process\tfile_attr"))						process_import_manifest_PROCESS(line.substring(7).trim(), lower, "PROCESS", line_num, br, 0, true);
								
				//						
				//pslist		
				//						
				else if(lower.startsWith("thread_count")) 							process_import_manifest_PROCESS(line, lower, "PROCESS", line_num, br, 0, true);
				else if(lower.startsWith("handle_count")) 							process_import_manifest_PROCESS(line, lower, "PROCESS", line_num, br, 0, true);
				else if(lower.startsWith("wow64")) 									process_import_manifest_PROCESS(line, lower, "PROCESS", line_num, br, 0, true);
				else if(key.equals("session")) 										process_import_manifest_PROCESS(line, lower, "PROCESS", line_num, br, 0, true);
				else if(lower.startsWith("offset_pslist")) 							process_import_manifest_PROCESS(line, lower, "PROCESS", line_num, br, 0, true);

				//						
				//psscan		
				//						
				else if(lower.startsWith("pdb")) 									process_import_manifest_PROCESS(line, lower, "PROCESS", line_num, br, 0, true);
				else if(lower.startsWith("time_created_date")) 						process_import_manifest_PROCESS(line, lower, "PROCESS", line_num, br, 0, true);
				else if(lower.startsWith("time_created_time")) 						process_import_manifest_PROCESS(line, lower, "PROCESS", line_num, br, 0, true);
				else if(lower.startsWith("time_created_utc")) 						process_import_manifest_PROCESS(line, lower, "PROCESS", line_num, br, 0, true);
				else if(lower.startsWith("time_exited_date")) 						process_import_manifest_PROCESS(line, lower, "PROCESS", line_num, br, 0, true);
				else if(lower.startsWith("time_exited_time")) 						process_import_manifest_PROCESS(line, lower, "PROCESS", line_num, br, 0, true);
				else if(lower.startsWith("time_exited_utc")) 						process_import_manifest_PROCESS(line, lower, "PROCESS", line_num, br, 0, true);
				else if(lower.startsWith("offset_psscan")) 							process_import_manifest_PROCESS(line, lower, "PROCESS", line_num, br, 0, true);

				//						
				//pstree		
				//						
				else if(lower.startsWith("offset_pstree")) 							process_import_manifest_PROCESS(line, lower, "PROCESS", line_num, br, 0, true);

				//						
				//psxview		
				//						
				else if(lower.startsWith("offset_psxview")) 						process_import_manifest_PROCESS(line, lower, "PROCESS", line_num, br, 0, true);
				else if(lower.startsWith("psxview_pslist")) 						process_import_manifest_PROCESS(line, lower, "PROCESS", line_num, br, 0, true);
				else if(lower.startsWith("psxview_psscan")) 						process_import_manifest_PROCESS(line, lower, "PROCESS", line_num, br, 0, true);
				else if(lower.startsWith("psxview_thrdproc")) 						process_import_manifest_PROCESS(line, lower, "PROCESS", line_num, br, 0, true);
				else if(lower.startsWith("psxview_pspcid")) 						process_import_manifest_PROCESS(line, lower, "PROCESS", line_num, br, 0, true);
				else if(lower.startsWith("psxview_csrss")) 							process_import_manifest_PROCESS(line, lower, "PROCESS", line_num, br, 0, true);
				else if(lower.startsWith("psxview_session")) 						process_import_manifest_PROCESS(line, lower, "PROCESS", line_num, br, 0, true);
				else if(lower.startsWith("psxview_deskthrd")) 						process_import_manifest_PROCESS(line, lower, "PROCESS", line_num, br, 0, true);
													
				//						
				//dlldump		
				//						
				else if(lower.startsWith("offset_v_dlldump")) 						process_import_manifest_PROCESS(line, lower, "PROCESS", line_num, br, 0, true);
				else if(lower.startsWith("offset_p_dlldump_trimmed")) 				process_import_manifest_PROCESS(line, lower, "PROCESS", line_num, br, 0, true);
				else if(lower.startsWith("module_base_address_dlldump")) 			process_import_manifest_PROCESS(line, lower, "PROCESS", line_num, br, 0, true);
				else if(lower.startsWith("module_base_address_dlldump_trimmed")) 	process_import_manifest_PROCESS(line, lower, "PROCESS", line_num, br, 0, true);

				//						
				//dlllist		
				//						
				else if(lower.startsWith("path")) 									process_import_manifest_PROCESS(line, lower, "PROCESS", line_num, br, 0, true);

				//						
				//other		
				//						
				else if(lower.startsWith("found_in_pslist")) 						process_import_manifest_PROCESS(line, lower, "PROCESS", line_num, br, 0, true);
				else if(lower.startsWith("found_in_psscan")) 						process_import_manifest_PROCESS(line, lower, "PROCESS", line_num, br, 0, true);
				else if(lower.startsWith("relative_path_vadtree_image")) 			process_import_manifest_PROCESS(line, lower, "PROCESS", line_num, br, 0, true);


				
				
				////////////////////////////////////////////////////////////
				//
				// my_vad_info
				//
				//////////////////////////////////////////////////////////
				else if(lower.startsWith("my_vad_info")) 			process_import_manifest_my_vad_info(line, lower, "my_vad_info", line_num, br, 11, true);
				
				
				
				////////////////////////////////////////////////////////////
				//
				// netstat
				//
				//////////////////////////////////////////////////////////
				else if(key.equals("netstat")) 			Node_Netstat_Entry.import_manifest_line_entry(key, line, this, node_process_import_manifest);
				
				
				
				////////////////////////////////////////////////////////////
				//
				// handle
				//
				//////////////////////////////////////////////////////////
				else if(key.equals("handle")) 			Node_Handle.import_manifest_line_entry(key, line, this, node_process_import_manifest);
				
				
				
				////////////////////////////////////////////////////////////
				//
				// privilege
				//
				//////////////////////////////////////////////////////////
				else if(key.equals("privilege")) 			Node_Privs.import_manifest_line_entry(key, line, this, node_process_import_manifest);
				
				
				////////////////////////////////////////////////////////////
				//
				// svcscan
				//
				//////////////////////////////////////////////////////////
				else if(key.equals("svcscan")) 			Node_svcscan.import_manifest_line_entry(key, line, this, node_process_import_manifest);
				
				
				////////////////////////////////////////////////////////////
				//
				// sids
				//
				//////////////////////////////////////////////////////////
				else if(lower.startsWith("sids")) 			process_import_manifest_sids(line, lower, "sids", line_num, br, 4, false);
				
				
				////////////////////////////////////////////////////////////
				//
				// malfind
				//
				//////////////////////////////////////////////////////////
				else if(lower.startsWith("malfind")) 			process_import_manifest_malfind(line, lower, "malfind", line_num, br, 7, true);
				
				
				////////////////////////////////////////////////////////////
				//
				// threads
				//
				//////////////////////////////////////////////////////////
				else if(lower.startsWith("threads")) 			process_import_manifest_thread(line, lower, "threads", line_num, br, 7, true);
				
				
				////////////////////////////////////////////////////////////
				//
				// gdi_timers
				//
				//////////////////////////////////////////////////////////
				else if(key.equals("gdi_timers") && node_process_import_manifest!= null) 			Node_Generic.import_manifest_line_entry_NODE_IS_ENTIRE_LINE(key, line, this, node_process_import_manifest, Node_Generic.INDEX_KEY_GDI_TIMERS); 
				
				
				////////////////////////////////////////////////////////////
				//
				// api_hooks - not done here, bcs imported in process
				//
				//////////////////////////////////////////////////////////
				else if(lower.startsWith("api_hooks")) 			;//process_import_manifest_api_hooks(line, lower, "api_hooks", line_num, br, 9, true);
				
				
				////////////////////////////////////////////////////////////
				//
				// vad_info
				//
				//////////////////////////////////////////////////////////
				else if(lower.startsWith("vad_info")) 			process_import_manifest_vad_info(line, lower, "vad_info", line_num, br, 9, true);
				
								
				////////////////////////////////////////////////////////////
				//
				// cmdscan_consoles - deprecated - handled by process_import_manifest_cmdscan
				//
				//////////////////////////////////////////////////////////
				else if(lower.startsWith("cmdscan_consoles")) 			;//process_import_manifest_cmdscan_consoles(line, lower, "cmdscan_consoles", line_num, br, 16, true);
				
								
				////////////////////////////////////////////////////////////
				//
				// cmdscan
				//
				//////////////////////////////////////////////////////////
				else if(lower.startsWith("cmdscan")) 			process_import_manifest_cmdscan(line, lower, "cmdscan", line_num, br, 7, true);
								
				
				////////////////////////////////////////////////////////////
				//
				// envars
				//
				//////////////////////////////////////////////////////////
				else if(key.equals("envars")) 			Node_Envar.import_manifest_line_entry_NODE_IS_ENTIRE_LINE(key, line, this, node_process_import_manifest);
				
															
				////////////////////////////////////////////////////////////
				//
				// impscan
				//
				//////////////////////////////////////////////////////////
				else if(key.equals("impscan")) 			Node_DLL_Container_Impscan.import_manifest_line_entry_NODE_IS_ENTIRE_LINE(key, line, this, node_process_import_manifest);

				
				
				////////////////////////////////////////////////////////////
				//
				// child_process @Carpenter1010 - don't need. already done by analyze_tree fcs
				//
				//////////////////////////////////////////////////////////
				else if(lower.startsWith("child_process")) 			;//process_import_manifest_child_process(line, lower, "child_process", line_num, br, 14, false);
				
				
				////////////////////////////////////////////////////////////
				//
				// orphaned_process_list - don't need. already done by analyze_tree fcn
				//
				//////////////////////////////////////////////////////////
				else if(lower.startsWith("orphaned_process_list")) 			;//process_import_manifest_orphaned_process_list(line, lower, "orphaned_process_list", line_num, br, 21, false);
				
				
				
				////////////////////////////////////////////////////////////
				//
				// processes_linked_to_cmdline_cmdscan_consoles - don't need. already done withing import cmdscan fcn
				//
				//////////////////////////////////////////////////////////
				else if(lower.startsWith("processes_linked_to_cmdline_cmdscan_consoles")) 			;//process_import_manifest_processes_linked_to_cmdline_cmdscan_consoles(line, lower, "processes_linked_to_cmdline_cmdscan_consoles", line_num, br, 44, false);
				
				
				////////////////////////////////////////////////////////////
				//
				// dll
				//
				//////////////////////////////////////////////////////////
				else if(lower.startsWith("dll")) 			process_import_manifest_dll(line, lower, "dll", line_num, br, 3, true);
				
				
				
				
				////////////////////////////////////////////////////////////
				//
				// driver_module
				//
				//////////////////////////////////////////////////////////
				else if(lower.startsWith("driver_module")) 			process_import_manifest_driver_module(line, lower, "driver_module", line_num, br, 13, true);
				
				
				////////////////////////////////////////////////////////////
				//
				// sessions
				//
				//////////////////////////////////////////////////////////
				else if(lower.startsWith("sessions")) 			process_import_manifest_sessions(line, lower, "sessions", line_num, br, 8, true);
				
				
				////////////////////////////////////////////////////////////
				//
				// deskscan
				//
				//////////////////////////////////////////////////////////
				else if(lower.startsWith("deskscan")) 			process_import_manifest_deskscan(line, lower, "deskscan", line_num, br, 8, true);
				
				

				////////////////////////////////////////////////////////////
				//
				// print_key
				//
				//////////////////////////////////////////////////////////
				else if(lower.startsWith("print_key")) 			process_import_manifest_REGISTRY_HIVE(line, lower, "print_key", line_num, br, 9, true, this.tree_REGISTRY_HIVE_PRINTKEY);

				////////////////////////////////////////////////////////////
				//
				// user_assist
				//
				//////////////////////////////////////////////////////////
				else if(lower.startsWith("user_assist")) 		process_import_manifest_REGISTRY_HIVE(line, lower, "user_assist", line_num, br,12, true, this.tree_REGISTRY_HIVE_USER_ASSIST);

				
				
				////////////////////////////////////////////////////////////
				//
				// hashdump
				//
				//////////////////////////////////////////////////////////
				else if(lower.startsWith("hashdump")) 			process_import_manifest_hashdump(line, lower, "hashdump", line_num, br, 8, false);
				
				
				////////////////////////////////////////////////////////////
				//
				// hivelist
				//
				//////////////////////////////////////////////////////////
				else if(key.equals("hivelist")) 			Node_hivelist.import_manifest_line_entry_NODE_IS_ENTIRE_LINE(key, line, this, node_process_import_manifest);
				
				
				////////////////////////////////////////////////////////////
				//
				// getsids - don't need. alread implemented by "sids" fcs in process
				//
				//////////////////////////////////////////////////////////
				else if(lower.startsWith("getsids")) 			;//process_import_manifest_getsids(line, lower, "getsids", line_num, br, 7, false);
				
				
				////////////////////////////////////////////////////////////
				//
				// getservicesid
				//
				//////////////////////////////////////////////////////////
				else if(lower.startsWith("getservicesid")) 			Node_get_service_sid.import_manifest_line_entry_NODE_IS_ENTIRE_LINE(key, line, this, node_process_import_manifest);
				
				
				////////////////////////////////////////////////////////////
				//
				// auditpol
				//
				//////////////////////////////////////////////////////////
				else if(lower.startsWith("auditpol")) 			process_import_manifest_auditpol(line, lower, "auditpol", line_num, br, 8, true);
				
				
				////////////////////////////////////////////////////////////
				//
				// shutdown time
				//
				//////////////////////////////////////////////////////////
				else if(lower.startsWith("shutdown_time")) 			process_import_manifest_shutdown_time(line, lower, "shutdown_time", line_num, br, 13, true);



				
				
				
																			
				else
					list_import_manifest_file_error_message.add("Unknown manifest directive at line [" + line_num + "] -->" + line);
			}
			
			try	{	br.close();}catch(Exception eee){}
			
			if(line_num > 0)
				driver.directive("\nComplete! [" + line_num + "] lines read on file " + fle.getCanonicalPath());
			else
				driver.directive("\nDone! It appears I was not able to read a line on your import file " + fle.getCanonicalPath());
			
			//
			//note errors
			//
			if(list_import_manifest_file_error_message != null && list_import_manifest_file_error_message.size() > 0)
				driver.print_linked_list("\n\n*\nERROR! It looks like there was at least [" + list_import_manifest_file_error_message.size() + "] error(s) detected on this manifest import:", list_import_manifest_file_error_message);
			else
				driver.directive("0 errors found while processing import file.");
			
			PROCESS_IMPSCAN = prev_PROCESS_IMPSCAN;
			
			boolean status = analyze_user_assist();
			
			if(status)
				sop("\nUser Assist entries were detected. I have created a new tab for you copy these entries and paste into a spreadsheet to analyze and sort for artifacts");
			
			analyze_display_consoles();
			
			this.create_tree_structure(tree_PROCESS);
			
			
			/*	driver.directive("\n\n DEBUG: printing manifest!");
				DEBUG = true;								
				this.write_manifest("\t");
				execute_completion_actions();
				driver.directive("\n\ndebug message print complete!");
				//pw.println(Driver.END_OF_ENTRY_MINOR);
				
			*/	
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "import_manifest last line read: [" + line_num + "]", e);
		}
		
		try	{	br.close();}catch(Exception eee){}
		
		driver.directive("\n* * * Complete with errors! [" + line_num + "] line(s) read on import file");
		
		PROCESS_IMPSCAN = prev_PROCESS_IMPSCAN;
		
		return false;
	}
	
	
	/**
	 * continuation mtd
	 * @param key
	 * @param arr
	 * @param line
	 * @param lower
	 * @param mtd_designator
	 * @param line_num
	 * @param br
	 * @param designator_len
	 * @param multi_lines_used_to_describe_single_node
	 * @return
	 */
	public boolean process_import_manifest_analysis_toolkit(String key, String [] arr, int starting_index, String line, String lower, String mtd_designator, Long line_num, BufferedReader br, int designator_len, boolean multi_lines_used_to_describe_single_node)
	{
		try
		{
			if(key == null || key.trim().equals("") || arr == null || arr.length < 1)
				return this.unknown_import_manifest_line(mtd_designator, key, line_num, line);
			
			this.file_attr_volatility = new FileAttributeData(arr, starting_index);
			
			return true;
		}
		catch(Exception e)
		{
			return this.unknown_import_manifest_line(mtd_designator + " EXCEPTION HANDLER", key, line_num, line);
		}
		
		//return false;
	}
	
	/**
	 * continuation mtd
	 * @param key
	 * @param arr
	 * @param line
	 * @param lower
	 * @param mtd_designator
	 * @param line_num
	 * @param br
	 * @param designator_len
	 * @param multi_lines_used_to_describe_single_node
	 * @return
	 */
	public boolean process_import_manifest_analysis_memory_image(String key, String [] arr, int starting_index, String line, String lower, String mtd_designator, Long line_num, BufferedReader br, int designator_len, boolean multi_lines_used_to_describe_single_node)
	{
		try
		{
			if(key == null || key.trim().equals("") || arr == null || arr.length < 1)
				return this.unknown_import_manifest_line(mtd_designator, key, line_num, line);
			
			file_attr_memory_image = new FileAttributeData(arr, starting_index);
			
			return true;
		}
		catch(Exception e)
		{
			return this.unknown_import_manifest_line(mtd_designator + " EXCEPTION HANDLER", key, line_num, line);
		}
		
		//return false;
	}
	
	
	/**
	 * continuation mtd. assumes line and lower are valid
	 * @param line
	 * @param lower
	 * @param mtd_designator
	 * @return
	 */
	public boolean process_import_manifest_investigation_particulars(String line, String lower, String mtd_designator, Long line_num, BufferedReader br, int designator_len, boolean multi_lines_used_to_describe_single_node)
	{
		try
		{
			if(line == null || line.trim().equals("") || lower == null || lower.trim().equals(""))
				return false;
			
			if(!lower.startsWith(mtd_designator))
			{
				driver.directive("Unknown import at line [" + line_num + "] --> " + line);
				return false;
			}
			
			//
			//remove designator header
			//
			String line_entry = line.substring(designator_len).trim();
			
			//
			//split by "\t"
			//
			String [] arr = null;

			try
			{
				arr = line_entry.split("\t");
			}
			catch(Exception ee)
			{
				arr = null;
			}
			
			//
			//validate
			//
			if(arr == null || arr.length < 2)
			{
				driver.directive("I was unable to parse manifest line [" + line_num + "] --> " + line);
				return false;
			}
			
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			//process entry where EACH LINE DESCRIBES A DIFFERENT, INDIVIDUAL TOKEN ABOUT THE SAME NODE e.g. process node, dll node, and thread node descriptions
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			if(multi_lines_used_to_describe_single_node) 
			{
				String key = arr[0].toLowerCase().trim();
				String value = arr[1].trim();
												
				//
				//value_to_check
				//
				if(key.equals("investigator_name"))								investigator_name = value;
				else if(key.equals("investigation_description"))				investigation_description = value;
				else if(key.equals("execution_time_stamp"))						EXECUTION_TIME_STAMP = value;
				else if(key.equals("profile"))									PROFILE= value;
				else if(key.equals("profile_lower"))							profile_lower = value;
				else if(key.equals("relative_path_to_file_analysis_directory"))	relative_path_to_file_analysis_directory= value;
				else if(key.equals("analysis_framework"))	
				{
					analysis_framework_export_name = value;
					analysis_framework_export_version = arr[2].trim();
					
				}
				
				else if(key.equals("analysis_kit"))								process_import_manifest_analysis_toolkit(key, arr, 1, line, lower, "investigation_particulars", line_num, br, 25, true);
				else if(key.equals("analysis_image"))							process_import_manifest_analysis_memory_image(key, arr, 1, line, lower, "investigation_particulars", line_num, br, 25, true);
				else if(key.equals("memory_image_system_drive"))				system_drive			= value;
				else if(key.equals("memory_image_system_root"))					system_root				= value;
				else if(key.equals("memory_image_computer_name"))				computer_name			= value;
				else if(key.equals("memory_image_processor_identifier"))		PROCESSOR_IDENTIFIER	= value;
				else if(key.equals("memory_image_processor_architecture"))		PROCESSOR_ARCHITECTURE	= value;
				
				else	
				{	
					list_import_manifest_file_error_message.add("Unknown manifest directive key [" + key + "] at mtd_designator [" + mtd_designator + "] at line [" + line_num + "] -->" + line);
				}
				
			}//end if
			
			else
			{
				list_import_manifest_file_error_message.add("Invalid parsing parameters received in process_import_manifest_" + mtd_designator + "\t line_num[" + line_num + "] --> " + line);
			}
			
			
			//
			//notify
			//
//			if(this.file_attr_memory_image != null)
//			{
//				driver.directive("\nImport Manifest Particulars complete:");
//				driver.directive("\t investigator_name: " + investigator_name);
//				driver.directive("\t investigation_description: " + investigation_description);
//				driver.directive("\t execution_time_stamp: " + EXECUTION_TIME_STAMP);
//				driver.directive("\t profile: " + PROFILE);
//				driver.directive("\t relative_path_to_file_analysis_directory: " + relative_path_to_file_analysis_directory);
//				if(this.file_attr_volatility != null)	driver.directive("\t analysis_toolkit: " + file_attr_volatility.get_attributes("\t"));
//				if(this.file_attr_memory_image != null)	driver.directive("\t memory_image: " + file_attr_memory_image.get_attributes("\t"));
//				driver.directive("\t system_drive: " + system_drive);
//				driver.directive("\t system_root: " + system_root);
//				driver.directive("\t computer_name: " + computer_name);
//				driver.directive("\t processor_identifier: " + PROCESSOR_IDENTIFIER);
//				driver.directive("\t processor_architecture: " + PROCESSOR_ARCHITECTURE);
//			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_import_manifest_" + mtd_designator);
		}
		
		return false;
	}
	
	public boolean unknown_import_manifest_line(String mtd_designator, String key, long line_num, String line)
	{
		try
		{
			driver.directive("in process_import_manifest [" + mtd_designator + "] unknown key [" + key + "] found at line [" + line_num + "] - I am unable to process this line entry --> " + line);
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "unknown_import_manifest_line", e);
		}
		
		return false;
	}
		
	/**
	 * continuation mtd. assumes line and lower are valid
	 * @param line
	 * @param lower
	 * @param mtd_designator
	 * @return
	 */
	public boolean process_import_manifest_PROCESS(String line, String lower, String mtd_designator, Long line_num, BufferedReader br, int designator_len, boolean multi_lines_used_to_describe_single_node)
	{
		try
		{
			if(line == null || line.trim().equals("") || lower == null || lower.trim().equals(""))
				return false;
			

			String line_entry = line.trim();
			
			//
			//split by "\t"
			//
			String [] arr = null;

			try
			{
				arr = line_entry.split("\t");
			}
			catch(Exception ee)
			{
				arr = null;
			}
			
			//
			//validate
			//
			if(arr == null || arr.length < 2)
			{
				driver.directive("I was unable to parse manifest line [" + line_num + "] --> " + line);
				return false;
			}
			
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			//process entry where EACH LINE DESCRIBES A DIFFERENT, INDIVIDUAL TOKEN ABOUT THE SAME NODE e.g. process node, dll node, and thread node descriptions
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			if(multi_lines_used_to_describe_single_node) 
			{
				String key = arr[0].toLowerCase().trim();
				String value = arr[1].trim();
												
				//
				//value_to_check
				//
				if(key.equals("pid")) 
				{
					int PID = Integer.parseInt(value);
					
					node_process_import_manifest = new Node_Process(this, PID, "unknown");
					
					node_process_import_manifest.PID  = Integer.parseInt(value);
					
					if(tree_PROCESS == null)
						tree_PROCESS = new TreeMap<Integer, Node_Process>();
					
					this.tree_PROCESS.put(node_process_import_manifest.PID, node_process_import_manifest);
				}
				
				
				else if(key.equals("process_name")) 		node_process_import_manifest.process_name  = value;
				else if(key.equals("ppid")) 				node_process_import_manifest.PPID  = Integer.parseInt(value);
				else if(key.equals("command_line")) 		node_process_import_manifest.command_line  = value;

				else if(key.equals("file_name")) 			node_process_import_manifest.file_name  = value;
				else if(key.equals("extension")) 			node_process_import_manifest.extension  = value;

				//
				//my_module_description
				//
				else if(key.equals("my_module_description")) node_process_import_manifest.process_import_manifest_my_module_description(1, arr[1].toLowerCase().trim(), arr[2].trim(), arr, line, lower, mtd_designator, line_num, br, designator_len, multi_lines_used_to_describe_single_node);

				//
				//process file_attr
				//
				else if(key.equals("file_attr")) 	
				{
					if(node_process_import_manifest.fle_attributes == null)
						node_process_import_manifest.fle_attributes = new FileAttributeData(node_process_import_manifest);
										
						node_process_import_manifest.fle_attributes.import_manifest_entry(arr[1], arr[2], line);
				}

				//
				//pslist
				//
				else if(key.equals("thread_count"))			node_process_import_manifest.threads  = value;
				else if(key.equals("handle_count")) 		node_process_import_manifest.handles  = value;
				else if(key.equals("wow64")) 				node_process_import_manifest.wow64  = value;
				else if(key.equals("session")) 				{node_process_import_manifest.session  = value;  /*driver.directive("session: " + node_process_import_manifest.session);*/ }
				else if(key.equals("offset_pslist")) 		node_process_import_manifest.offset_pslist  = value;

				//
				//psscan
				//
				else if(key.equals("pdb")) 					node_process_import_manifest.PDB  = value;
				else if(key.equals("time_created_date")) 	node_process_import_manifest.time_created_date  = value;
				else if(key.equals("time_created_time")) 	node_process_import_manifest.time_created_time  = value;
				else if(key.equals("time_created_utc")) 	node_process_import_manifest.time_created_UTC  = value;
				else if(key.equals("time_exited_date")) 	node_process_import_manifest.time_exited_date  = value;
				else if(key.equals("time_exited_time")) 	node_process_import_manifest.time_exited_time  = value;
				else if(key.equals("time_exited_utc")) 		node_process_import_manifest.time_exited_UTC  = value;
				else if(key.equals("offset_psscan")) 		node_process_import_manifest.offset_psscan  = value;

				//
				//pstree
				//
				else if(key.equals("offset_pstree")) 		node_process_import_manifest.offset_pstree  = value;

				//
				//psxview
				//
				else if(key.equals("offset_psxview")) 		node_process_import_manifest.offset_psxview  = value;
				else if(key.equals("psxview_pslist")) 		node_process_import_manifest.psxview_pslist  = value;
				else if(key.equals("psxview_psscan")) 		node_process_import_manifest.psxview_psscan  = value;
				else if(key.equals("psxview_thrdproc")) 	node_process_import_manifest.psxview_thrdproc  = value;
				else if(key.equals("psxview_pspcid")) 		node_process_import_manifest.psxview_pspcid  = value;
				else if(key.equals("psxview_csrss")) 		node_process_import_manifest.psxview_csrss  = value;
				else if(key.equals("psxview_session")) 		node_process_import_manifest.psxview_session  = value;
				else if(key.equals("psxview_deskthrd")) 	node_process_import_manifest.psxview_deskthrd  = value;

				//
				//dlldump
				//
				else if(key.equals("offset_v_dlldump")) 	node_process_import_manifest.offset_V_dlldump  = value;
				else if(key.equals("offset_p_dlldump_trimmed")) node_process_import_manifest.offset_P_dlldump_trimmed  = value;
				else if(key.equals("module_base_address_dlldump")) node_process_import_manifest.module_base_address_dlldump  = value;
				else if(key.equals("module_base_address_dlldump_trimmed")) node_process_import_manifest.module_base_address_dlldump_trimmed  = value;

				//
				//dlllist
				//
				else if(key.equals("path")) 				node_process_import_manifest.path  = value;

				//
				//other
				//
				else if(key.startsWith("found_in_pslist")) 		
				{					
					try	{	node_process_import_manifest.found_in_pslist  = Boolean.parseBoolean(value.trim());	} catch(Exception e){}
				}
				else if(key.equals("found_in_psscan")) 		
				{
					try	{	node_process_import_manifest.found_in_psscan  = Boolean.parseBoolean(value.trim());	} catch(Exception e){}
				}
				
				else if(key.equals("relative_path_vadtree_image")) 
				{
					node_process_import_manifest.relative_path_vadtree_image  = value;
				}

				//
				//KEY NOT FOUND
				//
				else	
				{	
					list_import_manifest_file_error_message.add("Unknown manifest directive key [" + key + "] at mtd_designator [" + mtd_designator + "] at line [" + line_num + "] -->" + line);
				}
				
				
				
			}//end if
			
			//
			//Invalid line parameter
			//
			else
			{
				list_import_manifest_file_error_message.add("Invalid parsing parameters received in process_import_manifest_" + mtd_designator + "\t line_num[" + line_num + "] --> " + line);
			}
			
			
			//
			//notify
			//
//			if(this.file_attr_memory_image != null)
//			{
//				driver.directive("\nImport Manifest Particulars complete:");
//			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_import_manifest_" + mtd_designator);
		}
		
		return false;
	}
	
	/**
	 * continuation mtd. assumes line and lower are valid
	 * @param line
	 * @param lower
	 * @param mtd_designator
	 * @return
	 */
	public boolean process_import_manifest_my_vad_info(String line, String lower, String mtd_designator, Long line_num, BufferedReader br, int designator_len, boolean multi_lines_used_to_describe_single_node)
	{
		try
		{
			if(line == null || line.trim().equals("") || lower == null || lower.trim().equals(""))
				return false;
			
			if(!lower.startsWith(mtd_designator))
			{
				driver.directive("Unknown import at line [" + line_num + "] --> " + line);
				return false;
			}
			
			//
			//remove designator header
			//
			String line_entry = line.substring(designator_len).trim();
			
			//
			//split by "\t"
			//
			String [] arr = null;

			try
			{
				arr = line_entry.split("\t");
			}
			catch(Exception ee)
			{
				arr = null;
			}
			
			//
			//validate
			//
			if(arr == null || arr.length < 2)
			{
				driver.directive("I was unable to parse manifest line [" + line_num + "] --> " + line);
				return false;
			}
			
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			//process entry where EACH LINE DESCRIBES A DIFFERENT, INDIVIDUAL TOKEN ABOUT THE SAME NODE e.g. process node, dll node, and thread node descriptions
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			if(multi_lines_used_to_describe_single_node) 
			{
				String key = arr[0].toLowerCase().trim();
				String value = arr[1].trim();
				
				//
				//value_to_check
				//
				if(key.startsWith("plugin_name"))
				{
					if(node_process_import_manifest.VAD == null)
						node_process_import_manifest.VAD = new Node_Generic("vadinfo");					
				}	
				
				node_process_import_manifest.VAD.import_manifest_line_entry(line_entry, arr, key, value, this);
				
			}//end if
			
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			// process entry where ENTIRE DESCRIPTION IS ON SINGLE LINE i.e., each new line describes a complete node e.g. handle node, privilege node, impscan
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			else
			{
				driver.directive("invalid directive received in process_import_manifest_" + mtd_designator + " mtd in class: " + this.myClassName );
				
			}//end else
			
			
			
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_import_manifest_" + mtd_designator);
		}
		
		return false;
	}
	
	
	
	/**
	 * continuation mtd. assumes line and lower are valid
	 * @param line
	 * @param lower
	 * @param mtd_designator
	 * @return
	 */
	public boolean process_import_manifest_handle(String line, String lower, String mtd_designator, Long line_num, BufferedReader br, int designator_len, boolean multi_lines_used_to_describe_single_node)
	{
		try
		{
			if(line == null || line.trim().equals("") || lower == null || lower.trim().equals(""))
				return false;
			
			if(!lower.startsWith(mtd_designator))
			{
				driver.directive("Unknown import at line [" + line_num + "] --> " + line);
				return false;
			}
			
			//
			//remove designator header
			//
			String line_entry = line.substring(designator_len).trim();
			
			//
			//split by "\t"
			//
			String [] arr = null;

			try
			{
				arr = line_entry.split("\t");
			}
			catch(Exception ee)
			{
				arr = null;
			}
			
			//
			//validate
			//
			if(arr == null || arr.length < 2)
			{
				driver.directive("I was unable to parse manifest line [" + line_num + "] --> " + line);
				return false;
			}
			
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			//process entry where EACH LINE DESCRIBES A DIFFERENT, INDIVIDUAL TOKEN ABOUT THE SAME NODE e.g. process node, dll node, and thread node descriptions
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			if(multi_lines_used_to_describe_single_node) 
			{
				String key = arr[0].toLowerCase().trim();
				String value = arr[1].trim();
				
				//
				//value_to_check
				//
				if(key.startsWith(""))
				{
					//set value
					//driver.directive("key: " + key + "\t value: " + value);
				}	
				
			}//end if
			
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			// process entry where ENTIRE DESCRIPTION IS ON SINGLE LINE i.e., each new line describes a complete node e.g. handle node, privilege node, impscan
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			else
			{
				String key = "", value = "";
				
				for(int i = 0; i < arr.length; i+=2)
				{
					key = arr[i].toLowerCase().trim();
					value = arr[i+1].trim();
					
					//
					//value_to_check
					//
					
					if(key.startsWith(""))
					{
						//driver.sp("\tkey: " + key + "\t value: " + value);
					}
					
				}//end for loop
				
			}//end else
			
			
			
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_import_manifest_" + mtd_designator);
		}
		
		return false;
	}
	
	/**
	 * continuation mtd. assumes line and lower are valid
	 * @param line
	 * @param lower
	 * @param mtd_designator
	 * @return
	 */
	public boolean process_import_manifest_privilege(String line, String lower, String mtd_designator, Long line_num, BufferedReader br, int designator_len, boolean multi_lines_used_to_describe_single_node)
	{
		try
		{
			if(line == null || line.trim().equals("") || lower == null || lower.trim().equals(""))
				return false;
			
			if(!lower.startsWith(mtd_designator))
			{
				driver.directive("Unknown import at line [" + line_num + "] --> " + line);
				return false;
			}
			
			//
			//remove designator header
			//
			String line_entry = line.substring(designator_len).trim();
			
			//
			//split by "\t"
			//
			String [] arr = null;

			try
			{
				arr = line_entry.split("\t");
			}
			catch(Exception ee)
			{
				arr = null;
			}
			
			//
			//validate
			//
			if(arr == null || arr.length < 2)
			{
				driver.directive("I was unable to parse manifest line [" + line_num + "] --> " + line);
				return false;
			}
			
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			//process entry where EACH LINE DESCRIBES A DIFFERENT, INDIVIDUAL TOKEN ABOUT THE SAME NODE e.g. process node, dll node, and thread node descriptions
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			if(multi_lines_used_to_describe_single_node) 
			{
				String key = arr[0].toLowerCase().trim();
				String value = arr[1].trim();
				
				//
				//value_to_check
				//
				if(key.startsWith(""))
				{
					//set value
					//driver.directive("key: " + key + "\t value: " + value);
				}	
				
			}//end if
			
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			// process entry where ENTIRE DESCRIPTION IS ON SINGLE LINE i.e., each new line describes a complete node e.g. handle node, privilege node, impscan
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			else
			{
				String key = "", value = "";
				
				for(int i = 0; i < arr.length; i+=2)
				{
					key = arr[i].toLowerCase().trim();
					value = arr[i+1].trim();
					
					//
					//value_to_check
					//
					
					if(key.startsWith(""))
					{
						//driver.sp("\tkey: " + key + "\t value: " + value);
					}
					
				}//end for loop
				
			}//end else
			
			
			
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_import_manifest_" + mtd_designator);
		}
		
		return false;
	}
	
	
	/**
	 * continuation mtd. assumes line and lower are valid
	 * @param line
	 * @param lower
	 * @param mtd_designator
	 * @return
	 */
	public boolean process_import_manifest_svcscan(String line, String lower, String mtd_designator, Long line_num, BufferedReader br, int designator_len, boolean multi_lines_used_to_describe_single_node)
	{
		try
		{
			if(line == null || line.trim().equals("") || lower == null || lower.trim().equals(""))
				return false;
			
			if(!lower.startsWith(mtd_designator))
			{
				driver.directive("Unknown import at line [" + line_num + "] --> " + line);
				return false;
			}
			
			//
			//remove designator header
			//
			String line_entry = line.substring(designator_len).trim();
			
			//
			//split by "\t"
			//
			String [] arr = null;

			try
			{
				arr = line_entry.split("\t");
			}
			catch(Exception ee)
			{
				arr = null;
			}
			
			//
			//validate
			//
			if(arr == null || arr.length < 2)
			{
				driver.directive("I was unable to parse manifest line [" + line_num + "] --> " + line);
				return false;
			}
			
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			//process entry where EACH LINE DESCRIBES A DIFFERENT, INDIVIDUAL TOKEN ABOUT THE SAME NODE e.g. process node, dll node, and thread node descriptions
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			if(multi_lines_used_to_describe_single_node) 
			{
				String key = arr[0].toLowerCase().trim();
				String value = arr[1].trim();
				
				//
				//value_to_check
				//
				if(key.startsWith(""))
				{
					//set value
					//driver.directive("key: " + key + "\t value: " + value);
				}	
				
			}//end if
			
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			// process entry where ENTIRE DESCRIPTION IS ON SINGLE LINE i.e., each new line describes a complete node e.g. handle node, privilege node, impscan
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			else
			{
				String key = "", value = "";
				
				for(int i = 0; i < arr.length; i+=2)
				{
					key = arr[i].toLowerCase().trim();
					value = arr[i+1].trim();
					
					//
					//value_to_check
					//
					
					if(key.startsWith(""))
					{
						//driver.sp("\tkey: " + key + "\t value: " + value);
					}
					
				}//end for loop
				
			}//end else
			
			
			
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_import_manifest_" + mtd_designator);
		}
		
		return false;
	}
	
	
	
	
	/**
	 * continuation mtd. assumes line and lower are valid
	 * @param line
	 * @param lower
	 * @param mtd_designator
	 * @return
	 */
	public boolean process_import_manifest_sids(String line, String lower, String mtd_designator, Long line_num, BufferedReader br, int designator_len, boolean multi_lines_used_to_describe_single_node)
	{
		try
		{
			if(line == null || line.trim().equals("") || lower == null || lower.trim().equals(""))
				return false;
			
			if(!lower.startsWith(mtd_designator))
			{
				driver.directive("Unknown import at line [" + line_num + "] --> " + line);
				return false;
			}
			
			//
			//remove designator header
			//
			String line_entry = line.substring(designator_len).trim();
			
			//
			//split by "\t"
			//
			String [] arr = null;

			try
			{
				arr = line_entry.split("\t");
			}
			catch(Exception ee)
			{
				arr = null;
			}
			
			//
			//validate
			//
			if(arr == null || arr.length < 2)
			{
				driver.directive("I was unable to parse manifest line [" + line_num + "] --> " + line);
				return false;
			}
			
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			//process entry where EACH LINE DESCRIBES A DIFFERENT, INDIVIDUAL TOKEN ABOUT THE SAME NODE e.g. process node, dll node, and thread node descriptions
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			if(multi_lines_used_to_describe_single_node) 
			{
				String key = arr[0].toLowerCase().trim();
				String value = arr[1].trim();
				
				//
				//value_to_check
				//
				if(key.startsWith(""))
				{
					driver.directive("invalid MULTI-LINE directive received in process_import_manifest_" + mtd_designator + " mtd in class: " + this.myClassName );
				}	
				
			}//end if
			
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			// process entry where ENTIRE DESCRIPTION IS ON SINGLE LINE i.e., each new line describes a complete node e.g. handle node, privilege node, impscan
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			else
			{
				String key = "", value = "";
				
				for(int i = 0; i < arr.length; i+=2)
				{
					key = arr[i].toLowerCase().trim();
					value = arr[i+1].trim();
					
					//
					//value_to_check
					//
					
					if(key.startsWith(""))
					{
						if(node_process_import_manifest == null)
							node_process_import_manifest = this.NULL_PROCESS;
						
						if(node_process_import_manifest.tree_sids == null)
							node_process_import_manifest.tree_sids = new TreeMap<String, String>();
						
						//tree_SIDS
						this.node_process_import_manifest.tree_sids.put(key,  value);
						tree_SIDS.put(key,  value);
					}
					
				}//end for loop
				
			}//end else
			
			
						
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_import_manifest_" + mtd_designator);
		}
		
		return false;
	}
	
	
	
	
	/**
	 * continuation mtd. assumes line and lower are valid
	 * @param line
	 * @param lower
	 * @param mtd_designator
	 * @return
	 */
	public boolean process_import_manifest_thread(String line, String lower, String mtd_designator, Long line_num, BufferedReader br, int designator_len, boolean multi_lines_used_to_describe_single_node)
	{
		try
		{
			if(line == null || line.trim().equals("") || lower == null || lower.trim().equals(""))
				return false;
			
			if(!lower.startsWith(mtd_designator))
			{
				driver.directive("Unknown import at line [" + line_num + "] --> " + line);
				return false;
			}
			
			//
			//remove designator header
			//
			String line_entry = line.substring(designator_len).trim();
			
			//
			//split by "\t"
			//
			String [] arr = null;

			try
			{
				arr = line_entry.split("\t");
			}
			catch(Exception ee)
			{
				arr = null;
			}
			
			//
			//validate
			//
			if(arr == null || arr.length < 2)
			{
				driver.directive("I was unable to parse manifest line [" + line_num + "] --> " + line);
				return false;
			}
			
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			//process entry where EACH LINE DESCRIBES A DIFFERENT, INDIVIDUAL TOKEN ABOUT THE SAME NODE e.g. process node, dll node, and thread node descriptions
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			if(multi_lines_used_to_describe_single_node) 
			{
				String key = arr[0].toLowerCase().trim();
				String value = arr[1].trim();
				String key_lower = key.toLowerCase().trim();
				
				//
				//value_to_check
				//
				if(key_lower.equals("tid"))
				{
					node_threads_import_manifest = new Node_Threads();
				}	
				
				//process
				node_threads_import_manifest.import_manifest_line_entry(line_entry, arr, key_lower, value, this);
				
			}//end if
			
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			// process entry where ENTIRE DESCRIPTION IS ON SINGLE LINE i.e., each new line describes a complete node e.g. handle node, privilege node, impscan
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			else
			{
				driver.directive("invalid directive received in process_import_manifest_" + mtd_designator + " mtd in class: " + this.myClassName );
				
			}//end else
			
			
			
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_import_manifest_" + mtd_designator);
		}
		
		return false;
	}

	/**
	 * continuation mtd. assumes line and lower are valid
	 * @param line
	 * @param lower
	 * @param mtd_designator
	 * @return
	 */
	public boolean process_import_manifest_hashdump(String line, String lower, String mtd_designator, Long line_num, BufferedReader br, int designator_len, boolean multi_lines_used_to_describe_single_node)
	{
		try
		{
			if(line == null || line.trim().equals("") || lower == null || lower.trim().equals(""))
				return false;
			
			if(!lower.startsWith(mtd_designator))
			{
				driver.directive("Unknown import at line [" + line_num + "] --> " + line);
				return false;
			}
			
			//
			//remove designator header
			//
			String line_entry = driver.trim_key(mtd_designator, line, true);
			
			this.tree_hashdump.put(line_entry, null);
						
			
			return true;
		}
		catch(Exception e)
		{
			driver.directive("* I was unable to parse manifest line [" + line_num + "] --> " + line);
		}
		
		return false;
	}
	
	
	/**
	 * continuation mtd. assumes line and lower are valid
	 * @param line
	 * @param lower
	 * @param mtd_designator
	 * @return
	 */
	public boolean process_import_manifest_gdi_timer(String line, String lower, String mtd_designator, Long line_num, BufferedReader br, int designator_len, boolean multi_lines_used_to_describe_single_node)
	{
		try
		{
			if(line == null || line.trim().equals("") || lower == null || lower.trim().equals(""))
				return false;
			
			if(!lower.startsWith(mtd_designator))
			{
				driver.directive("Unknown import at line [" + line_num + "] --> " + line);
				return false;
			}
			
			//
			//remove designator header
			//
			String line_entry = line.substring(designator_len).trim();
			
			//
			//split by "\t"
			//
			String [] arr = null;

			try
			{
				arr = line_entry.split("\t");
			}
			catch(Exception ee)
			{
				arr = null;
			}
			
			//
			//validate
			//
			if(arr == null || arr.length < 2)
			{
				driver.directive("I was unable to parse manifest line [" + line_num + "] --> " + line);
				return false;
			}
			
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			//process entry where EACH LINE DESCRIBES A DIFFERENT, INDIVIDUAL TOKEN ABOUT THE SAME NODE e.g. process node, dll node, and thread node descriptions
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			if(multi_lines_used_to_describe_single_node) 
			{
				String key = arr[0].toLowerCase().trim();
				String value = arr[1].trim();
				
				//
				//value_to_check
				//
				if(key.startsWith(""))
				{
					//set value
					//driver.directive("key: " + key + "\t value: " + value);
				}	
				
			}//end if
			
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			// process entry where ENTIRE DESCRIPTION IS ON SINGLE LINE i.e., each new line describes a complete node e.g. handle node, privilege node, impscan
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			else
			{
				String key = "", value = "";
				
				for(int i = 0; i < arr.length; i+=2)
				{
					key = arr[i].toLowerCase().trim();
					value = arr[i+1].trim();
					
					//
					//value_to_check
					//
					
					if(key.startsWith(""))
					{
						//driver.sp("\tkey: " + key + "\t value: " + value);
					}
					
				}//end for loop
				
			}//end else
			
			
			
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_import_manifest_" + mtd_designator);
		}
		
		return false;
	}
	
	/**
	 * continuation mtd. assumes line and lower are valid
	 * @param line
	 * @param lower
	 * @param mtd_designator
	 * @return
	 */
	public boolean process_import_manifest_api_hooks(String line, String lower, String mtd_designator, Long line_num, BufferedReader br, int designator_len, boolean multi_lines_used_to_describe_single_node)
	{
		try
		{
			if(line == null || line.trim().equals("") || lower == null || lower.trim().equals(""))
				return false;
			
			if(!lower.startsWith(mtd_designator))
			{
				driver.directive("Unknown import at line [" + line_num + "] --> " + line);
				return false;
			}
			
			//
			//remove designator header
			//
			String line_entry = line.substring(designator_len).trim();
			
			//
			//split by "\t"
			//
			String [] arr = null;

			try
			{
				arr = line_entry.split("\t");
			}
			catch(Exception ee)
			{
				arr = null;
			}
			
			//
			//validate
			//
			if(arr == null || arr.length < 2)
			{
				driver.directive("I was unable to parse manifest line [" + line_num + "] --> " + line);
				return false;
			}
			
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			//process entry where EACH LINE DESCRIBES A DIFFERENT, INDIVIDUAL TOKEN ABOUT THE SAME NODE e.g. process node, dll node, and thread node descriptions
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			if(multi_lines_used_to_describe_single_node) 
			{
				String key = arr[0].toLowerCase().trim();
				String value = arr[1].trim();
				
				//
				//value_to_check
				//
				if(key.startsWith(""))
				{
					//set value
					//driver.directive("key: " + key + "\t value: " + value);
				}	
				
			}//end if
			
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			// process entry where ENTIRE DESCRIPTION IS ON SINGLE LINE i.e., each new line describes a complete node e.g. handle node, privilege node, impscan
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			else
			{
				String key = "", value = "";
				
				for(int i = 0; i < arr.length; i+=2)
				{
					key = arr[i].toLowerCase().trim();
					value = arr[i+1].trim();
					
					//
					//value_to_check
					//
					
					if(key.startsWith(""))
					{
						//driver.sp("\tkey: " + key + "\t value: " + value);
					}
					
				}//end for loop
				
			}//end else
			
			
			
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_import_manifest_" + mtd_designator);
		}
		
		return false;
	}
	
	
	
	/**
	 * continuation mtd. assumes line and lower are valid
	 * @param line
	 * @param lower
	 * @param mtd_designator
	 * @return
	 */
	public boolean process_import_manifest_vad_info(String line, String lower, String mtd_designator, Long line_num, BufferedReader br, int designator_len, boolean multi_lines_used_to_describe_single_node)
	{
		try
		{
			if(line == null || line.trim().equals("") || lower == null || lower.trim().equals(""))
				return false;
			
			if(!lower.startsWith(mtd_designator))
			{
				driver.directive("Unknown import at line [" + line_num + "] --> " + line);
				return false;
			}
			
			//
			//remove designator header
			//
			String line_entry = line.substring(designator_len).trim();
			
			//
			//split by "\t"
			//
			String [] arr = null;

			try
			{
				arr = line_entry.split("\t");
			}
			catch(Exception ee)
			{
				arr = null;
			}
			
			//
			//validate
			//
			if(arr == null || arr.length < 2)
			{
				driver.directive("I was unable to parse manifest line [" + line_num + "] --> " + line);
				return false;
			}
			
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			//process entry where EACH LINE DESCRIBES A DIFFERENT, INDIVIDUAL TOKEN ABOUT THE SAME NODE e.g. process node, dll node, and thread node descriptions
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			if(multi_lines_used_to_describe_single_node) 
			{
				String key = arr[0].toLowerCase().trim();
				String value = arr[1].trim();
				
				//
				//value_to_check
				//
				if(key.startsWith("plugin_name"))//determine if time to instantiate new VAD node
				{
					node_vad_import_manifest = new Node_Generic(value);	
					node_vad_import_manifest.list_details = new LinkedList<String>();
					node_vad_import_manifest.process = this.node_process_import_manifest;
															
					if(node_process_import_manifest.tree_vad_info == null)
						this.node_process_import_manifest.tree_vad_info = new TreeMap<String, Node_Generic>();
					
						//Link to main tree
					this.tree_VAD_INFO.put(node_process_import_manifest.PID, node_process_import_manifest);
				}	
				else if(key.startsWith("offset"))//determine if time to link VAD to node process
				{
					node_vad_import_manifest.offset = value;
					node_process_import_manifest.tree_vad_info.put(value, node_vad_import_manifest);					
				}
				else if(key.startsWith("list_details") && value.toLowerCase().trim().startsWith("protection:"))
				{
					try
					{
						String protection = value.substring(value.indexOf(":")+1).trim();
						
						if(node_process_import_manifest.tree_vad_page_protection == null)
							node_process_import_manifest.tree_vad_page_protection = new TreeMap<String, LinkedList<Node_Generic>>();
						
						TreeMap<Integer, Node_Process> tree_CURRENT_VAD_PAGE_PROTECTION = null;
						
						if(tree_VAD_PAGE_PROTECTION.containsKey(protection))
							tree_CURRENT_VAD_PAGE_PROTECTION = tree_VAD_PAGE_PROTECTION.get(protection);
						
						if(tree_CURRENT_VAD_PAGE_PROTECTION == null)
						{
							tree_CURRENT_VAD_PAGE_PROTECTION = new TreeMap<Integer, Node_Process>();
							tree_VAD_PAGE_PROTECTION.put(protection, tree_CURRENT_VAD_PAGE_PROTECTION);
						}
						
						if(!tree_CURRENT_VAD_PAGE_PROTECTION.containsKey(node_process_import_manifest.PID))
							tree_CURRENT_VAD_PAGE_PROTECTION.put(node_process_import_manifest.PID, node_process_import_manifest);
						
						//link this vad to process linked list
						LinkedList<Node_Generic> list_vad_protection = null;
																
						if(node_process_import_manifest.tree_vad_page_protection != null && node_process_import_manifest.tree_vad_page_protection.containsKey(protection))
							list_vad_protection = node_process_import_manifest.tree_vad_page_protection.get(protection);
						
						if(list_vad_protection == null)
						{
							list_vad_protection = new LinkedList<Node_Generic>();
							node_process_import_manifest.tree_vad_page_protection.put(protection,  list_vad_protection);
						}
						
						if(!list_vad_protection.contains(node_vad_import_manifest))
							list_vad_protection.add(node_vad_import_manifest);
						
					}
					
					
					catch(Exception e)
					{
						driver.directive("\n * encountered issue parsing proction VAD entry in " + this.myClassName);
					}
					
				}
				
				node_vad_import_manifest.import_manifest_line_entry(line_entry, arr, key, value, this);
				
			}//end if
			
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			// process entry where ENTIRE DESCRIPTION IS ON SINGLE LINE i.e., each new line describes a complete node e.g. handle node, privilege node, impscan
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			else
			{
				driver.directive("invalid directive received in process_import_manifest_" + mtd_designator + " mtd in class: " + this.myClassName );
				
			}//end else
			
			
			
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_import_manifest_" + mtd_designator);
		}
		
		return false;
	}
	
	/**
	 * continuation mtd. assumes line and lower are valid 
	 * 
	 * 
	 * NOTE: DON'T DO THIS PROCESS DESKSCAN, WE'LL LINK ALL DESKCANS WITH THE MAIN TREE_DESKSCAN THAT DESCRIBES THE PROCESSES
	 * 
	 * 
	 * @param line
	 * @param lower
	 * @param mtd_designator
	 * @return
	 */
	public boolean process_import_manifest_PROCESS_deskscan_DEPRECATED(String line, String lower, String mtd_designator, Long line_num, BufferedReader br, int designator_len, boolean multi_lines_used_to_describe_single_node)
	{
		try
		{
			if(line == null || line.trim().equals("") || lower == null || lower.trim().equals(""))
				return false;
			
			if(!lower.startsWith(mtd_designator))
			{
				driver.directive("Unknown import at line [" + line_num + "] --> " + line);
				return false;
			}
			
			//
			//remove designator header
			//
			String line_entry = line.substring(designator_len).trim();
			
			//
			//split by "\t"
			//
			String [] arr = null;

			try
			{
				arr = line_entry.split("\t");
			}
			catch(Exception ee)
			{
				arr = null;
			}
			
			//
			//validate
			//
			if(arr == null || arr.length < 2)
			{
				driver.directive("I was unable to parse manifest line [" + line_num + "] --> " + line);
				return false;
			}
			
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			//process entry where EACH LINE DESCRIBES A DIFFERENT, INDIVIDUAL TOKEN ABOUT THE SAME NODE e.g. process node, dll node, and thread node descriptions
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			if(multi_lines_used_to_describe_single_node) 
			{
				String key = arr[0].toLowerCase().trim();
				String value = arr[1].trim();
				
				//
				//value_to_check
				//
				if(key.startsWith(""))
				{
					//set value
					//driver.directive("key: " + key + "\t value: " + value);
				}	
				
			}//end if
			
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			// process entry where ENTIRE DESCRIPTION IS ON SINGLE LINE i.e., each new line describes a complete node e.g. handle node, privilege node, impscan
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			else
			{
				String key = "", value = "";
				
				for(int i = 0; i < arr.length; i+=2)
				{
					key = arr[i].toLowerCase().trim();
					value = arr[i+1].trim();
					
					//
					//value_to_check
					//
					
					if(key.startsWith(""))
					{
						//driver.sp("\tkey: " + key + "\t value: " + value);
					}
					
				}//end for loop
				
			}//end else
			
			
			
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_import_manifest_" + mtd_designator);
		}
		
		return false;
	}
	
	
	
	/**
	 * continuation mtd. assumes line and lower are valid
	 * @param line
	 * @param lower
	 * @param mtd_designator
	 * @return
	 */
	public boolean process_import_manifest_cmdscan(String line, String lower, String mtd_designator, Long line_num, BufferedReader br, int designator_len, boolean multi_lines_used_to_describe_single_node)
	{
		try
		{
			if(line == null || line.trim().equals("") || lower == null || lower.trim().equals(""))
				return false;
			
			if(!lower.startsWith(mtd_designator))
			{
				driver.directive("Unknown import at line [" + line_num + "] --> " + line);
				return false;
			}
			
			//
			//remove designator header
			//
			String line_entry = line.substring(designator_len).trim();
			
			if(line_entry.startsWith(":"))
				line_entry = line_entry.substring(1).trim();
			
			//
			//split by "\t"
			//
			String [] arr = null;

			try
			{
				arr = line_entry.split("\t");
			}
			catch(Exception ee)
			{
				arr = null;
			}
			
			//
			//validate
			//
//			if(arr == null || arr.length < 2)
//			{
//				driver.directive("I was unable to parse manifest line [" + line_num + "] --> " + line);
//				return false;
//			}
			
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			//process entry where EACH LINE DESCRIBES A DIFFERENT, INDIVIDUAL TOKEN ABOUT THE SAME NODE e.g. process node, dll node, and thread node descriptions
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			if(multi_lines_used_to_describe_single_node) 
			{
				String key = arr[0].toLowerCase().trim();
				String key_lower = key.toLowerCase().trim();
				String value = driver.trim_key(key_lower, line_entry, false);
				String value_lower = value.toLowerCase().trim();
				
				//
				//value_to_check
				//
				if(key_lower.equals("command_history_id"))
				{
					value = driver.trim_key(key, line_entry, true);								
					value_lower = value.toLowerCase().trim();
					
					node_cmdscan_import_manifest = new Node_CmdScan(this);
					node_cmdscan_import_manifest.command_history_id = value;
					node_cmdscan_import_manifest.process = node_process_import_manifest;
					
					//link (under current process)
					if(this.node_process_import_manifest != null )
					{												
						if(node_process_import_manifest.list_cmd_scan == null)
						{
							node_process_import_manifest.list_cmd_scan = new LinkedList<Node_CmdScan>();				
						}

						//link
						tree_process_to_link_cmdline_cmdscan_consoles.put(node_process_import_manifest.PID, node_process_import_manifest);						
						node_process_import_manifest.list_cmd_scan.add(node_cmdscan_import_manifest);
						
						if(node_process_import_manifest.tree_cmdscan_consoles == null)
							node_process_import_manifest.tree_cmdscan_consoles = new TreeMap<String, Node_CmdScan>();
							
						node_process_import_manifest.tree_cmdscan_consoles.put(value_lower, node_cmdscan_import_manifest);												
					}
					
//					else
//						driver.directive("ERROR! I could process appears to be unll in " + this.myClassName + " in mtd " + "process_import_manifest_" + mtd_designator);
					
				}	
						
				//
				//process data
				//
				if(this.node_process_import_manifest != null )
					node_cmdscan_import_manifest.import_manifest_line_entry(line_entry, arr, key_lower, value, this);
				
			}//end if
			
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			// process entry where ENTIRE DESCRIPTION IS ON SINGLE LINE i.e., each new line describes a complete node e.g. handle node, privilege node, impscan
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			else
			{
				driver.directive("invalid directive received in process_import_manifest_" + mtd_designator + " mtd in class: " + this.myClassName );
				
			}//end else
			
			
			
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_import_manifest_" + mtd_designator, e);
		}
		
		return false;
	}
	/**
	 * continuation mtd. assumes line and lower are valid
	 * @param line
	 * @param lower
	 * @param mtd_designator
	 * @return
	 */
	public boolean process_import_manifest_envars(String line, String lower, String mtd_designator, Long line_num, BufferedReader br, int designator_len, boolean multi_lines_used_to_describe_single_node)
	{
		try
		{
			if(line == null || line.trim().equals("") || lower == null || lower.trim().equals(""))
				return false;
			
			if(!lower.startsWith(mtd_designator))
			{
				driver.directive("Unknown import at line [" + line_num + "] --> " + line);
				return false;
			}
			
			//
			//remove designator header
			//
			String line_entry = line.substring(designator_len).trim();
			
			//
			//split by "\t"
			//
			String [] arr = null;

			try
			{
				arr = line_entry.split("\t");
			}
			catch(Exception ee)
			{
				arr = null;
			}
			
			//
			//validate
			//
			if(arr == null || arr.length < 2)
			{
				driver.directive("I was unable to parse manifest line [" + line_num + "] --> " + line);
				return false;
			}
			
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			//process entry where EACH LINE DESCRIBES A DIFFERENT, INDIVIDUAL TOKEN ABOUT THE SAME NODE e.g. process node, dll node, and thread node descriptions
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			if(multi_lines_used_to_describe_single_node) 
			{
				String key = arr[0].toLowerCase().trim();
				String value = arr[1].trim();
				
				//
				//value_to_check
				//
				if(key.startsWith(""))
				{
					//set value
					//driver.directive("key: " + key + "\t value: " + value);
				}	
				
			}//end if
			
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			// process entry where ENTIRE DESCRIPTION IS ON SINGLE LINE i.e., each new line describes a complete node e.g. handle node, privilege node, impscan
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			else
			{
				String key = "", value = "";
				
				for(int i = 0; i < arr.length; i+=2)
				{
					key = arr[i].toLowerCase().trim();
					value = arr[i+1].trim();
					
					//
					//value_to_check
					//
					
					if(key.startsWith(""))
					{
						//driver.sp("\tkey: " + key + "\t value: " + value);
					}
					
				}//end for loop
				
			}//end else
			
			
			
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_import_manifest_" + mtd_designator);
		}
		
		return false;
	}
	
	/**
	 * continuation mtd. assumes line and lower are valid
	 * @param line
	 * @param lower
	 * @param mtd_designator
	 * @return
	 */
	public boolean process_import_manifest_impscan(String line, String lower, String mtd_designator, Long line_num, BufferedReader br, int designator_len, boolean multi_lines_used_to_describe_single_node)
	{
		try
		{
			if(line == null || line.trim().equals("") || lower == null || lower.trim().equals(""))
				return false;
			
			if(!lower.startsWith(mtd_designator))
			{
				driver.directive("Unknown import at line [" + line_num + "] --> " + line);
				return false;
			}
			
			//
			//remove designator header
			//
			String line_entry = line.substring(designator_len).trim();
			
			//
			//split by "\t"
			//
			String [] arr = null;

			try
			{
				arr = line_entry.split("\t");
			}
			catch(Exception ee)
			{
				arr = null;
			}
			
			//
			//validate
			//
			if(arr == null || arr.length < 2)
			{
				driver.directive("I was unable to parse manifest line [" + line_num + "] --> " + line);
				return false;
			}
			
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			//process entry where EACH LINE DESCRIBES A DIFFERENT, INDIVIDUAL TOKEN ABOUT THE SAME NODE e.g. process node, dll node, and thread node descriptions
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			if(multi_lines_used_to_describe_single_node) 
			{
				String key = arr[0].toLowerCase().trim();
				String value = arr[1].trim();
				
				//
				//value_to_check
				//
				if(key.startsWith(""))
				{
					//set value
					//driver.directive("key: " + key + "\t value: " + value);
				}	
				
			}//end if
			
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			// process entry where ENTIRE DESCRIPTION IS ON SINGLE LINE i.e., each new line describes a complete node e.g. handle node, privilege node, impscan
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			else
			{
				String key = "", value = "";
				
				for(int i = 0; i < arr.length; i+=2)
				{
					key = arr[i].toLowerCase().trim();
					value = arr[i+1].trim();
					
					//
					//value_to_check
					//
					
					if(key.startsWith(""))
					{
						//driver.sp("\tkey: " + key + "\t value: " + value);
					}
					
				}//end for loop
				
			}//end else
			
			
			
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_import_manifest_" + mtd_designator);
		}
		
		return false;
	}
	
	
	
	/**
	 * continuation mtd. assumes line and lower are valid
	 * @param line
	 * @param lower
	 * @param mtd_designator
	 * @return
	 */
	public boolean process_import_manifest_child_process(String line, String lower, String mtd_designator, Long line_num, BufferedReader br, int designator_len, boolean multi_lines_used_to_describe_single_node)
	{
		try
		{
			if(line == null || line.trim().equals("") || lower == null || lower.trim().equals(""))
				return false;
			
			if(!lower.startsWith(mtd_designator))
			{
				driver.directive("Unknown import at line [" + line_num + "] --> " + line);
				return false;
			}
			
			//
			//remove designator header
			//
			String line_entry = line.substring(designator_len).trim();
			
		
			
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_import_manifest_" + mtd_designator);
		}
		
		return false;
	}
	
	
	
	
	
	/**
	 * continuation mtd. assumes line and lower are valid
	 * @param line
	 * @param lower
	 * @param mtd_designator
	 * @return
	 */
	public boolean process_import_manifest_orphaned_process_list(String line, String lower, String mtd_designator, Long line_num, BufferedReader br, int designator_len, boolean multi_lines_used_to_describe_single_node)
	{
		try
		{
			if(line == null || line.trim().equals("") || lower == null || lower.trim().equals(""))
				return false;
			
			if(!lower.startsWith(mtd_designator))
			{
				driver.directive("Unknown import at line [" + line_num + "] --> " + line);
				return false;
			}
			
			//
			//remove designator header
			//
			String line_entry = line.substring(designator_len).trim();
			
			
			
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_import_manifest_" + mtd_designator);
		}
		
		return false;
	}
	
	
	/**
	 * continuation mtd. assumes line and lower are valid
	 * @param line
	 * @param lower
	 * @param mtd_designator
	 * @return
	 */
	public boolean process_import_manifest_processes_linked_to_cmdline_cmdscan_consoles(String line, String lower, String mtd_designator, Long line_num, BufferedReader br, int designator_len, boolean multi_lines_used_to_describe_single_node)
	{
		try
		{
			if(line == null || line.trim().equals("") || lower == null || lower.trim().equals(""))
				return false;
			
			if(!lower.startsWith(mtd_designator))
			{
				driver.directive("Unknown import at line [" + line_num + "] --> " + line);
				return false;
			}
			
			//
			//remove designator header
			//
			String line_entry = line.substring(designator_len).trim();
			
						
			
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_import_manifest_" + mtd_designator);
		}
		
		return false;
	}
	
	
	
	
	/**
	 * continuation mtd. assumes line and lower are valid
	 * @param line
	 * @param lower
	 * @param mtd_designator
	 * @return
	 */
	public boolean process_import_manifest_dll(String line, String lower, String mtd_designator, Long line_num, BufferedReader br, int designator_len, boolean multi_lines_used_to_describe_single_node)
	{
		try
		{
			if(line == null || line.trim().equals("") || lower == null || lower.trim().equals(""))
				return false;
			
			if(!lower.startsWith(mtd_designator))
			{
				driver.directive("Unknown import at line [" + line_num + "] --> " + line);
				return false;
			}
			
			//
			//remove designator header
			//
			String line_entry = line.substring(designator_len).trim();
			
			//
			//split by "\t"
			//
			String [] arr = null;

			try
			{
				arr = line_entry.split("\t");
			}
			catch(Exception ee)
			{
				arr = null;
			}
			
			//
			//validate
			//
			if(arr == null || arr.length < 2)
			{
				driver.directive("I was unable to parse manifest line [" + line_num + "] --> " + line);
				return false;
			}
			
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			//process entry where EACH LINE DESCRIBES A DIFFERENT, INDIVIDUAL TOKEN ABOUT THE SAME NODE e.g. process node, dll node, and thread node descriptions
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			if(multi_lines_used_to_describe_single_node) 
			{
				String key = arr[0].toLowerCase().trim();
				String value = arr[1].trim();
				String key_lower = key.toLowerCase().trim();
				
				//
				//value_to_check
				//
				if(key_lower.equals("path"))
				{
					node_dll_import_manifest = new Node_DLL(this);										
				}
				
				node_dll_import_manifest.import_manifest_line_entry(line_entry, arr, key_lower, value, this);
				
			}//end if
			
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			// process entry where ENTIRE DESCRIPTION IS ON SINGLE LINE i.e., each new line describes a complete node e.g. handle node, privilege node, impscan
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			else
			{
				driver.directive("invalid directive received in process_import_manifest_" + mtd_designator + " mtd in class: " + this.myClassName );
				
			}//end else
			
			
			
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_import_manifest_" + mtd_designator, e);
		}
		
		return false;
	}
	
	
	
	
	
	/**
	 * continuation mtd. assumes line and lower are valid
	 * @param line
	 * @param lower
	 * @param mtd_designator
	 * @return
	 */
	public boolean process_import_manifest_driver_module(String line, String lower, String mtd_designator, Long line_num, BufferedReader br, int designator_len, boolean multi_lines_used_to_describe_single_node)
	{
		try
		{
			if(line == null || line.trim().equals("") || lower == null || lower.trim().equals(""))
				return false;
			
			if(!lower.startsWith(mtd_designator))
			{
				driver.directive("Unknown import at line [" + line_num + "] --> " + line);
				return false;
			}
			
			//
			//remove designator header
			//
			String line_entry = line.substring(designator_len).trim();
			
			//
			//split by "\t"
			//
			String [] arr = null;

			try
			{
				arr = line_entry.split("\t");
			}
			catch(Exception ee)
			{
				arr = null;
			}
			
			//
			//validate
			//
			if(arr == null || arr.length < 2)
			{
				driver.directive("I was unable to parse manifest line [" + line_num + "] --> " + line);
				return false;
			}
			
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			//process entry where EACH LINE DESCRIBES A DIFFERENT, INDIVIDUAL TOKEN ABOUT THE SAME NODE e.g. process node, dll node, and thread node descriptions
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			if(multi_lines_used_to_describe_single_node) 
			{
				String key = arr[0].trim();
				String value = arr[1].trim();
				String key_lower = key.toLowerCase().trim();
				String value_lower = value.toLowerCase().trim();
				String module_name_without_extension = "";
				
				//
				//recognize new node
				//
				if(key_lower.equals("driver_name"))
				{
					module_name_without_extension = value_lower;					

					if(module_name_without_extension.endsWith(".sys"))
						module_name_without_extension = module_name_without_extension.substring(0, module_name_without_extension.lastIndexOf(".sys")).trim();

					if(tree_DRIVERS == null)
						tree_DRIVERS = new TreeMap<String, Node_Driver>();
					
					if(node_driver_import_manifest == null)
						node_driver_import_manifest = new Node_Driver(null, value, null);
						
					else if(this.tree_DRIVERS.containsKey(module_name_without_extension))
						node_driver_import_manifest = tree_DRIVERS.get(module_name_without_extension);

					if(node_driver_import_manifest == null || !tree_DRIVERS.containsKey(module_name_without_extension))						
					{
						node_driver_import_manifest = new Node_Driver(null, value, null);	
					
						tree_DRIVERS.put(module_name_without_extension, node_driver_import_manifest);
					}
					
					node_driver_import_manifest.module_name_without_extension = module_name_without_extension;										
				}
				
				else if(key_lower.equals("module_name"))
				{
					module_name_without_extension = value_lower;					

					if(module_name_without_extension.endsWith(".sys"))
						module_name_without_extension = module_name_without_extension.substring(0, module_name_without_extension.lastIndexOf(".sys")).trim();

					if(tree_DRIVERS == null)
						tree_DRIVERS = new TreeMap<String, Node_Driver>();
					
					if(node_driver_import_manifest == null)
						node_driver_import_manifest = new Node_Driver(null, value, null);
						
					else if(this.tree_DRIVERS.containsKey(module_name_without_extension))
						node_driver_import_manifest = tree_DRIVERS.get(module_name_without_extension);

					if(node_driver_import_manifest == null || !tree_DRIVERS.containsKey(module_name_without_extension))						
					{
						node_driver_import_manifest = new Node_Driver(null, value, null);	
					
						tree_DRIVERS.put(module_name_without_extension, node_driver_import_manifest);
					}
					
					node_driver_import_manifest.module_name_without_extension = module_name_without_extension;										
				}
				
				//
				//process data
				//
				if(node_driver_import_manifest != null)
					node_driver_import_manifest.import_manifest_line_entry(line_entry, arr, key_lower, value, this);
				
			}//end if
			
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			// process entry where ENTIRE DESCRIPTION IS ON SINGLE LINE i.e., each new line describes a complete node e.g. handle node, privilege node, impscan
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			else
			{
				driver.directive("invalid directive received in process_import_manifest_" + mtd_designator + " mtd in class: " + this.myClassName );
				
			}//end else
			
			
			
			
			
			
			
			
			
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_import_manifest_" + mtd_designator, e);
		}
		
		return false;
	}
	
	
	
	/**
	 * continuation mtd. assumes line and lower are valid
	 * @param line
	 * @param lower
	 * @param mtd_designator
	 * @return
	 */
	public boolean process_import_manifest_sessions(String line, String lower, String mtd_designator, Long line_num, BufferedReader br, int designator_len, boolean multi_lines_used_to_describe_single_node)
	{
		try
		{
			if(line == null || line.trim().equals("") || lower == null || lower.trim().equals(""))
				return false;
			
			if(!lower.startsWith(mtd_designator))
			{
				driver.directive("Unknown import at line [" + line_num + "] --> " + line);
				return false;
			}
			
			//
			//remove designator header
			//
			String line_entry = line.substring(designator_len).trim();
			
			//
			//split by "\t"
			//
			String [] arr = null;

			try
			{
				arr = line_entry.split("\t");
			}
			catch(Exception ee)
			{
				arr = null;
			}
			
			//
			//validate
			//
			if(arr == null || arr.length < 2)
			{
				driver.directive("I was unable to parse manifest line [" + line_num + "] --> " + line);
				return false;
			}
			
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			//process entry where EACH LINE DESCRIBES A DIFFERENT, INDIVIDUAL TOKEN ABOUT THE SAME NODE e.g. process node, dll node, and thread node descriptions
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			if(multi_lines_used_to_describe_single_node) 
			{
				String key = arr[0].trim();
				String value = arr[1].trim();
				String key_lower = key.toLowerCase().trim();
				
				//
				//recognize new node
				//
				if(key_lower.equals("session_container"))
				{
					node_generic_import_manifest = new Node_Generic(value);
				}
				
				node_generic_import_manifest.import_manifest_line_entry(line_entry, arr, key_lower, value, this);
				
			}//end if
			
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			// process entry where ENTIRE DESCRIPTION IS ON SINGLE LINE i.e., each new line describes a complete node e.g. handle node, privilege node, impscan
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			else
			{
				driver.directive("invalid directive received in process_import_manifest_" + mtd_designator + " mtd in class: " + this.myClassName );
				
			}//end else
			
			
			
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_import_manifest_" + mtd_designator, e);
		}
		
		return false;
	}
	
	
	
	
	/**
	 * continuation mtd. assumes line and lower are valid
	 * @param line
	 * @param lower
	 * @param mtd_designator
	 * @return
	 */
	public boolean process_import_manifest_deskscan(String line, String lower, String mtd_designator, Long line_num, BufferedReader br, int designator_len, boolean multi_lines_used_to_describe_single_node)
	{
		try
		{
			if(line == null || line.trim().equals("") || lower == null || lower.trim().equals(""))
				return false;
			
			if(!lower.startsWith(mtd_designator))
			{
				driver.directive("Unknown import at line [" + line_num + "] --> " + line);
				return false;
			}
			
			//
			//remove designator header
			//
			String line_entry = line.substring(designator_len).trim();
			
			//
			//split by "\t"
			//
			String [] arr = null;

			try
			{
				arr = line_entry.split("\t");
			}
			catch(Exception ee)
			{
				arr = null;
			}
			
			//
			//validate
			//
			if(arr == null || arr.length < 2)
			{
				driver.directive("I was unable to parse manifest line [" + line_num + "] --> " + line);
				return false;
			}
			
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			//process entry where EACH LINE DESCRIBES A DIFFERENT, INDIVIDUAL TOKEN ABOUT THE SAME NODE e.g. process node, dll node, and thread node descriptions
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			if(multi_lines_used_to_describe_single_node) 
			{
				String key = arr[0].toLowerCase().trim();
				String value = arr[1].trim();
				String key_lower = key.toLowerCase().trim();
				
				//
				//value_to_check
				//
				if(key_lower.equals("plugin_name"))
				{
					node_generic_import_manifest = new Node_Generic(value);
				}
				
				node_generic_import_manifest.import_manifest_line_entry(line_entry, arr, key_lower, value, this);
				
			}//end if
			
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			// process entry where ENTIRE DESCRIPTION IS ON SINGLE LINE i.e., each new line describes a complete node e.g. handle node, privilege node, impscan
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			else
			{
				driver.directive("invalid directive received in process_import_manifest_" + mtd_designator + " mtd in class: " + this.myClassName );
				
			}//end else
			
			
			
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_import_manifest_" + mtd_designator, e);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	/**
	 * continuation mtd. assumes line and lower are valid
	 * @param line
	 * @param lower
	 * @param mtd_designator
	 * @return
	 */
	public boolean process_import_manifest_REGISTRY_HIVE(String line, String lower, String mtd_designator, Long line_num, BufferedReader br, int designator_len, boolean multi_lines_used_to_describe_single_node, TreeMap<String, Node_Registry_Hive> tree)
	{
		try
		{
			if(line == null || line.trim().equals("") || lower == null || lower.trim().equals(""))
				return false;
			
			if(!lower.startsWith(mtd_designator))
			{
				driver.directive("Unknown import at line [" + line_num + "] --> " + line);
				return false;
			}
			
			if(tree == null)
			{
				driver.directive("\n\n** ERROR! in " + myClassName + " in mtd process_import_manifest_" + mtd_designator + " import tree for " + mtd_designator + " appears to be null!");
				return false;
			}
			
			//
			//remove designator header
			//
			String line_entry = line.substring(designator_len).trim(); 
			
			//
			//split by "\t"
			//
			String [] arr = null;

			try
			{
				arr = line_entry.split("\t");
			}
			catch(Exception ee)
			{
				arr = null;
			}
			
			//
			//validate
			//
			if(arr == null || arr.length < 2)
			{
				driver.directive("I was unable to parse manifest line [" + line_num + "] --> " + line);
				return false;
			}
			
			String key = arr[0].trim();
			String value = arr[1].trim();
			String key_lower = key.toLowerCase().trim();
			String value_lower = value.toLowerCase().trim();
			String line_entry_lower = line_entry.toLowerCase().trim();
			
			
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			//process entry where EACH LINE DESCRIBES A DIFFERENT, INDIVIDUAL TOKEN ABOUT THE SAME NODE e.g. process node, dll node, and thread node descriptions
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			if(multi_lines_used_to_describe_single_node) 
			{
				//
				//recognize new node
				//
				if(key_lower.equals("registry_hive"))
				{										
					line_entry = driver.trim_key(key_lower, line_entry, true);	
					line_entry_lower = line_entry.toLowerCase().trim();
					
					node_registry_hive_import_manifest = null;	
					
					if(tree.containsKey(line_entry_lower))
						node_registry_hive_import_manifest = tree.get(line_entry_lower);
					
					if(node_registry_hive_import_manifest == null)
					{
						node_registry_hive_import_manifest = new Node_Registry_Hive(line_entry);
						tree.put(line_entry_lower,  node_registry_hive_import_manifest);
					}																																													
				}																
				
				
			}//end if
			
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			// process entry where ENTIRE DESCRIPTION IS ON SINGLE LINE i.e., each new line describes a complete node e.g. handle node, privilege node, impscan
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//			else
//			{
//				driver.directive("invalid directive received in process_import_manifest_" + mtd_designator + " mtd in class: " + this.myClassName );
//				
//			}//end else
			
			//
			//process any received line
			//
			if(node_registry_hive_import_manifest != null)
				node_registry_hive_import_manifest.import_manifest_line_entry(line_entry, arr, key_lower, value, this, tree);
			else
				driver.directive("\n\nERROR! in " + myClassName + " in mtd process_import_manifest_" + mtd_designator + " node_registry_hive_import_manifest appears to be null!");
			
			
			
			
			
			
			
			
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_import_manifest_" + mtd_designator, e, true);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	/**
	 * continuation mtd. assumes line and lower are valid
	 * @param line
	 * @param lower
	 * @param mtd_designator
	 * @return
	 */
	public boolean process_import_manifest_hivelist(String line, String lower, String mtd_designator, Long line_num, BufferedReader br, int designator_len, boolean multi_lines_used_to_describe_single_node)
	{
		try
		{
			if(line == null || line.trim().equals("") || lower == null || lower.trim().equals(""))
				return false;
			
			if(!lower.startsWith(mtd_designator))
			{
				driver.directive("Unknown import at line [" + line_num + "] --> " + line);
				return false;
			}
			
			//
			//remove designator header
			//
			String line_entry = line.substring(designator_len).trim();
			
			//
			//split by "\t"
			//
			String [] arr = null;

			try
			{
				arr = line_entry.split("\t");
			}
			catch(Exception ee)
			{
				arr = null;
			}
			
			//
			//validate
			//
			if(arr == null || arr.length < 2)
			{
				driver.directive("I was unable to parse manifest line [" + line_num + "] --> " + line);
				return false;
			}
			
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			//process entry where EACH LINE DESCRIBES A DIFFERENT, INDIVIDUAL TOKEN ABOUT THE SAME NODE e.g. process node, dll node, and thread node descriptions
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			if(multi_lines_used_to_describe_single_node) 
			{
				String key = arr[0].toLowerCase().trim();
				String value = arr[1].trim();
				
				//
				//value_to_check
				//
				if(key.startsWith(""))
				{
					//set value
					//driver.directive("key: " + key + "\t value: " + value);
				}	
				
			}//end if
			
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			// process entry where ENTIRE DESCRIPTION IS ON SINGLE LINE i.e., each new line describes a complete node e.g. handle node, privilege node, impscan
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			else
			{
				String key = "", value = "";
				
				for(int i = 0; i < arr.length; i+=2)
				{
					key = arr[i].toLowerCase().trim();
					value = arr[i+1].trim();
					
					//
					//value_to_check
					//
					
					if(key.startsWith(""))
					{
						//driver.sp("\tkey: " + key + "\t value: " + value);
					}
					
				}//end for loop
				
			}//end else
			
			
			
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_import_manifest_" + mtd_designator);
		}
		
		return false;
	}
	
	
	
	
	/**
	 * continuation mtd. assumes line and lower are valid
	 * @param line
	 * @param lower
	 * @param mtd_designator
	 * @return
	 */
	public boolean process_import_manifest_getservicesid(String line, String lower, String mtd_designator, Long line_num, BufferedReader br, int designator_len, boolean multi_lines_used_to_describe_single_node)
	{
		try
		{
			if(line == null || line.trim().equals("") || lower == null || lower.trim().equals(""))
				return false;
			
			if(!lower.startsWith(mtd_designator))
			{
				driver.directive("Unknown import at line [" + line_num + "] --> " + line);
				return false;
			}
			
			//
			//remove designator header
			//
			String line_entry = line.substring(designator_len).trim();
			
			//
			//split by "\t"
			//
			String [] arr = null;

			try
			{
				arr = line_entry.split("\t");
			}
			catch(Exception ee)
			{
				arr = null;
			}
			
			//
			//validate
			//
			if(arr == null || arr.length < 2)
			{
				driver.directive("I was unable to parse manifest line [" + line_num + "] --> " + line);
				return false;
			}
			
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			//process entry where EACH LINE DESCRIBES A DIFFERENT, INDIVIDUAL TOKEN ABOUT THE SAME NODE e.g. process node, dll node, and thread node descriptions
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			if(multi_lines_used_to_describe_single_node) 
			{
				String key = arr[0].toLowerCase().trim();
				String value = arr[1].trim();
				
				//
				//value_to_check
				//
				if(key.startsWith(""))
				{
					//set value
					//driver.directive("key: " + key + "\t value: " + value);
				}	
				
			}//end if
			
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			// process entry where ENTIRE DESCRIPTION IS ON SINGLE LINE i.e., each new line describes a complete node e.g. handle node, privilege node, impscan
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			else
			{
				String key = "", value = "";
				
				for(int i = 0; i < arr.length; i+=2)
				{
					key = arr[i].toLowerCase().trim();
					value = arr[i+1].trim();
					
					//
					//value_to_check
					//
					
					if(key.startsWith(""))
					{
						//driver.sp("\tkey: " + key + "\t value: " + value);
					}
					
				}//end for loop
				
			}//end else
			
			
			
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_import_manifest_" + mtd_designator);
		}
		
		return false;
	}
	
	
	
	/**
	 * continuation mtd. assumes line and lower are valid
	 * @param line
	 * @param lower
	 * @param mtd_designator
	 * @return
	 */
	public boolean process_import_manifest_getsids(String line, String lower, String mtd_designator, Long line_num, BufferedReader br, int designator_len, boolean multi_lines_used_to_describe_single_node)
	{
		try
		{
			if(line == null || line.trim().equals("") || lower == null || lower.trim().equals(""))
				return false;
			
			if(!lower.startsWith(mtd_designator))
			{
				driver.directive("Unknown import at line [" + line_num + "] --> " + line);
				return false;
			}
			
			//
			//remove designator header
			//
			String line_entry = line.substring(designator_len).trim();
			
			//
			//split by "\t"
			//
			String [] arr = null;

			try
			{
				arr = line_entry.split("\t");
			}
			catch(Exception ee)
			{
				arr = null;
			}
			
			//
			//validate
			//
			if(arr == null || arr.length < 2)
			{
				driver.directive("I was unable to parse manifest line [" + line_num + "] --> " + line);
				return false;
			}
			
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			//process entry where EACH LINE DESCRIBES A DIFFERENT, INDIVIDUAL TOKEN ABOUT THE SAME NODE e.g. process node, dll node, and thread node descriptions
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			if(multi_lines_used_to_describe_single_node) 
			{
				String key = arr[0].toLowerCase().trim();
				String value = arr[1].trim();
				
				//
				//value_to_check
				//
				if(key.startsWith(""))
				{
					//set value
					//driver.directive("key: " + key + "\t value: " + value);
				}	
				
			}//end if
			
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			// process entry where ENTIRE DESCRIPTION IS ON SINGLE LINE i.e., each new line describes a complete node e.g. handle node, privilege node, impscan
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			else
			{
				String key = "", value = "";
				
				for(int i = 0; i < arr.length; i+=2)
				{
					key = arr[i].toLowerCase().trim();
					value = arr[i+1].trim();
					
					//
					//value_to_check
					//
					
					if(key.startsWith(""))
					{
						//driver.sp("\tkey: " + key + "\t value: " + value);
					}
					
				}//end for loop
				
			}//end else
			
			
			
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_import_manifest_" + mtd_designator);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	/**
	 * continuation mtd. assumes line and lower are valid
	 * @param line
	 * @param lower
	 * @param mtd_designator
	 * @return
	 */
	public boolean process_import_manifest_TEMPLATE(String line, String lower, String mtd_designator, Long line_num, BufferedReader br, int designator_len, boolean multi_lines_used_to_describe_single_node)
	{
		try
		{
			if(line == null || line.trim().equals("") || lower == null || lower.trim().equals(""))
				return false;
			
			if(!lower.startsWith(mtd_designator))
			{
				driver.directive("Unknown import at line [" + line_num + "] --> " + line);
				return false;
			}
			
			//
			//remove designator header
			//
			String line_entry = line.substring(designator_len).trim();
			
			//
			//split by "\t"
			//
			String [] arr = null;

			try
			{
				arr = line_entry.split("\t");
			}
			catch(Exception ee)
			{
				arr = null;
			}
			
			//
			//validate
			//
			if(arr == null || arr.length < 2)
			{
				driver.directive("I was unable to parse manifest line [" + line_num + "] --> " + line);
				return false;
			}
			
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			//process entry where EACH LINE DESCRIBES A DIFFERENT, INDIVIDUAL TOKEN ABOUT THE SAME NODE e.g. process node, dll node, and thread node descriptions
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			if(multi_lines_used_to_describe_single_node) 
			{
				String key = arr[0].toLowerCase().trim();
				String value = arr[1].trim();
				
				//
				//value_to_check
				//
				if(key.startsWith(""))
				{
					//set value
					//driver.directive("key: " + key + "\t value: " + value);
				}	
				
			}//end if
			
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			// process entry where ENTIRE DESCRIPTION IS ON SINGLE LINE i.e., each new line describes a complete node e.g. handle node, privilege node, impscan
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			else
			{
				String key = "", value = "";
				
				for(int i = 0; i < arr.length; i+=2)
				{
					key = arr[i].toLowerCase().trim();
					value = arr[i+1].trim();
					
					//
					//value_to_check
					//
					
					if(key.startsWith(""))
					{
						//driver.sp("\tkey: " + key + "\t value: " + value);
					}
					
				}//end for loop
				
			}//end else
			
			
			
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_import_manifest_" + mtd_designator);
		}
		
		return false;
	}
	
	
	
	public boolean commence_action()
	{
		try
		{			
			///////////////////////////////////////////////////////////////////
			// mandatory actions:
			///////////////////////////////////////////////////////////////////
			
			//save null process
			try	{	this.tree_PROCESS.put(-1,  NULL_PROCESS);	}	catch(Exception e){}
			
			//save relative path
			relative_path_to_file_analysis_directory = driver.get_relative_path_from_directory_path(path_fle_analysis_directory, true);
			
						 
			
			///////////////////////////////////////////////////////////////////
			// Load manifest file!
			//////////////////////////////////////////////////////////////////
			if(this.fle_manifest_IMPORT != null)
			{
				return import_manifest(fle_manifest_IMPORT);
			}
			
			
			///////////////////////////////////////////////////////////////////
			//Load import file - rebuild analysis from output files
			//////////////////////////////////////////////////////////////////
			if(this.list_import_files != null && list_import_files.size() > 0)
			{
				return import_advanced_analysis(list_import_files, this.fle_import_directory);
			}
			
			
			///////////////////////////////////////////////////////////////////
			//Plugin Autorun - setup.conf
			//////////////////////////////////////////////////////////////////
			if(this.list_auto_plugins_execution != null && this.list_auto_plugins_execution.size() > 0)
			{
				return plugin_autorun_setup_conf();
			}
			
			///////////////////////////////////////////////////////////////////
			//owt, initiate Advanced Anslysis Plugin Execution
			//////////////////////////////////////////////////////////////////
			AUTOMATED_ANALYSIS_STARTED = true;
			AUTOMATED_ANALYSIS_COMPLETE = false;
			
			boolean enable_api_hooks = false;
			
			//if(driver.jop_Confirm("APIHooks takes a while to complete. Do you wish to enable it at this time?", "Enable APIHooks Plugin") == JOptionPane.YES_OPTION)
			//	enable_api_hooks = true;
			
			//
			//NOTIFY
			//
			sop("Analysis time stamp is set to [" + Interface.analysis_time_stamp + "]");
			
			LinkedList<String> list_output = new LinkedList<String>();
			
			
			
//delete/////////////////////////
//plugin_envars = new Analysis_Plugin_envars(null, this, "envars", "Display process environment variables", false, jta);

if(false)
{
	PROCESS_IMPSCAN = false;
	
	File fle = execute_plugin("pslist", "Print all running processes by following the EPROCESS lists", null, "", list_output, true);			
	process_pslist(list_output);
	
	plugin_moddump = new Analysis_Plugin_SUPER_MODULES(null, this, "moddump", "Dump a kernel driver to an executable file sample", false, jta); //runs modules and modscan within moddump!
	
	//plugin_driverirp = new Analysis_Plugin_driverirp(fle, this, "driverirp", "Driver IRP hook detection", false, jta);
	//plugin_callbacks  = new Analysis_Plugin_Callbacks(fle, this, "callbacks", "Print system-wide notification routines", false, jta);
	
	
	//this.launch_report_terminate_system();
	return this.launch_report_terminate_system(false);
}
			

			

	
//end delete
			
			//////////////////////////////////////////////////////////////////////
			// Instantiate Agnostic Worker Threads
			/////////////////////////////////////////////////////////////////////			
			plugin_hashdump = new Analysis_Plugin_hashdump(null, this, "hashdump", "Dumps passwords hashes (LM/NTLM) from memory", true, jta);
			plugin_get_service_sids = new Analysis_Plugin_get_service_sids(null, this, "getservicesids", "Get the names of services in the Registry and return Calculated SID", true, jta);
			plugin_mftparser = new Process_Plugin(null, "mftparser", "Scans for and parses potential MFT entries", null, null, this.fle_volatility.getName() + " -f " + this.fle_memory_image.getName() + " mftparser --profile=" + this.PROFILE, true, false, "", true);
			plugin_registry_startup = new Analysis_Plugin_Registry_Startup_Apps(null, this, "registry_startup", "Print Subkeys of Registry Startup Locations", true, jta);
			
			
			sop("Building process listing...");
			//////////////////////////////////////////////////////////////////////
			// PROCESSES
			/////////////////////////////////////////////////////////////////////			
				//
				//pslist - scan doubly linked-list from _EPROCESS
				//
				try	{	Advanced_Analysis_Director.list_plugins_in_execution.add("pslist");	} catch(Exception e){}

				fle_pslist = execute_plugin("pslist", "Print all running processes by following the EPROCESS lists", null, "", list_output, true);			
				process_pslist(list_output);
				try	{	Advanced_Analysis_Director.list_plugins_in_execution.remove("pslist");	} catch(Exception e){}

				//
				//psscan - scan for processes via pool-scanning
				//
				try	{	Advanced_Analysis_Director.list_plugins_in_execution.add("psscan");	} catch(Exception e){}

				fle_psscan = execute_plugin("psscan", "Pool scanner for process objects", null, "", list_output, true);			
				process_psscan(list_output);
				
				

				
//procdump = new Analysis_Plugin_Dump(null, this, "procdump", "Dump a process to an executable file sample", true, false);		
				//
				//dot file; then on linux: dot -Tjpg psscan.dot -o <path>.jpg  or dot -Tpng <path>.dot -o <path>.png
				//
				create_psscan_dot_file();
				try	{	Advanced_Analysis_Director.list_plugins_in_execution.remove("psscan");	} catch(Exception e){}
				//
				//pstree
				//
				try	{	Advanced_Analysis_Director.list_plugins_in_execution.add("pstree");	} catch(Exception e){}
				fle_pstree = execute_plugin("pstree", "Print process list as a tree", null, "", list_output, true);			
				process_pstree(list_output);
				try	{	Advanced_Analysis_Director.list_plugins_in_execution.remove("pstree");	} catch(Exception e){}
				//
				//psxview
				//
				try	{	Advanced_Analysis_Director.list_plugins_in_execution.add("psxview");	} catch(Exception e){}
				fle_psxview = execute_plugin("psxview", "Find hidden processes with various process listings", null, "", list_output, true);			
				process_psxview(list_output);
				try	{	Advanced_Analysis_Director.list_plugins_in_execution.remove("psxview");	} catch(Exception e){}
				
				
				//
				//service scan
				//
				plugin_svcscan = new Analysis_Plugin_svcscan(null, this, "svcscan", "Scan for Windows services", true, jta);
				
				//
				//Threads
				//
				plugin_threads = new Analysis_Plugin_Threads(null, this, "threads", "Investigate _ETHREAD and _KTHREADs", true, jta);	
				
				//
				//apihooks
				//
				plugin_apihooks = new Analysis_Plugin_apihooks(null, this, "apihooks", "Detect API hooks in process and kernel memory", true, jta);
				
				//
				//Privs - thread
				//
				plugin_privs = new Analysis_Plugin_Privs(null, this, "privs", "Display process privileges", true, jta);

				
			sop("\nBuilding environment variable listing...");
			//////////////////////////////////////////////////////////////////////
			// Envars
			/////////////////////////////////////////////////////////////////////
			plugin_envars = new Analysis_Plugin_envars(null, this, "envars", "Display process environment variables", false, jta);
			
			//////////////////////////////////////////////////////////////////////
			// INITIALIZE COMPONENT
			///////////////////////////////////////////////////////////////////////
			initialize_data();	
			
			
								
			//////////////////////////////////////////////////////////////////////
			// DLLs
			/////////////////////////////////////////////////////////////////////
			sop("\nBuilding dll listing...");
			
				//
				//DLLLIST
				//
				plugin_dlllist = new Analysis_Plugin_dlllist(null, this, "dlllist", "Print list of loaded dlls for each process", false, jta);
				
				//analyze dll listing
				//analyze_dll_listing_for_suspicious_processes_with_one_process_linking();
				
				//
				//LDRMODULES
				//
				plugin_ldrmodules = new Analysis_Plugin_ldrmodules(null, this, "ldrmodules", "Detect unlinked DLLs", false, jta);
				
			
				
				//////////////////////////////////////////////////////////////////////
				// Dumps
				/////////////////////////////////////////////////////////////////////

procdump = new Analysis_Plugin_Dump(null, this, "procdump", "Dump a process to an executable file sample", true, jta, false);
dlldump = new Analysis_Plugin_Dump(null, this, "dlldump", "Dump DLLs from a process address space", true, jta, false);
plugin_cmdscan = new Analysis_Plugin_cmdscan(null, this, "cmdscan", "Extract command history by scanning for _COMMAND_HISTORY", true, jta);
plugin_moddump = new Analysis_Plugin_SUPER_MODULES(null, this, "moddump", "Dump a kernel driver to an executable file sample", false, jta); //runs modules and modscan within moddump!

				//////////////////////////////////////////////////////////////////////
				// Instantiate Worker Thread 
				/////////////////////////////////////////////////////////////////////
				plugin_malfind = new Analysis_Plugin_malfind(null, this, "malfind", "Find hidden and injected code", true, jta);
				plugin_getsids = new Analysis_Plugin_getsids(null, this, "getsids", "Print the SIDs owning each process", true, jta);
				//plugin_get_service_sids = new Analysis_Plugin_get_service_sids(null, this, "getservicesids", "Get the names of services in the Registry and return Calculated SID", true, jta);
				plugin_hivelist = new Analysis_Plugin_hivelist(null, this, "hivelist", "Print list of registry hives", true, jta);
				plugin_hivescan = new Analysis_Plugin_EXECUTION(null, this, "hivescan", "Pool scanner for registry hives", true, jta);
				

//if(enable_api_hooks)



plugin_regdump = new Analysis_Plugin_EXECUTION(null, this, "dumpregistry", "Dumps registry files out to disk", true, jta);
plugin_deskscan = new Analysis_Plugin_Deskscan(null, this, "deskscan", "Poolscaner for tagDESKTOP (desktops)", true, jta);
//plugin_drivermodule = new Analysis_Plugin_EXECUTION(null, this, "drivermodule", "Associate driver objects to kernel modules", true, jta);
//plugin_driverscan = new Analysis_Plugin_EXECUTION(null, this, "driverscan", "Pool scanner for driver objects", true, jta);

if(PROFILE.toLowerCase().contains("xp") || PROFILE.toLowerCase().contains("2003"))
	plugin_evtlogs = new Analysis_Plugin_EXECUTION(null, this, "evtlogs", "Extract Windows Event Logs (XP/2003 only)", true, jta);
else if(PROFILE.toLowerCase().contains("win") || PROFILE.toLowerCase().contains("vista"))
	plugin_evtlogs = new Analysis_Plugin_EXECUTION(null, this, "dumpfiles --regex .evtx$ --ignore-case", "Dump Windows Event Logs ", true, jta);
				
plugin_filescan = new Analysis_Plugin_EXECUTION(null, this, "filescan", "Pool scanner for file objects", true, jta);
plugin_gditimers = new Analysis_Plugin_GDI_Timers(null, this, "gditimers", "Print installed GDI timers and callbacks", true, jta);
plugin_imageinfo = new Analysis_Plugin_EXECUTION(null, this, "imageinfo", "Identify information for the image", true, jta);
plugin_kdbgscan = new Analysis_Plugin_EXECUTION(null, this, "kdbgscan", "Search for and dump potential KDBG values", true, jta);
//plugin_kpcrscan = new Analysis_Plugin_EXECUTION(null, this, "kpcrscan", "Search for and dump potential KPCR values", true, jta);
plugin_lsadump = new Analysis_Plugin_EXECUTION(null, this, "lsadump", "Dump (decrypted) LSA secrets from the registry", true, jta);

//plugin_memmap = new Analysis_Plugin_EXECUTION(null, this, "memmap", "Print the memory map", true, jta);

plugin_messagehooks = new Analysis_Plugin_EXECUTION(null, this, "messagehooks", "List desktop and thread window message hooks", true, jta);

//plugin_impscan = new Analysis_Plugin_EXECUTION(null, this, "impscan", "Scan for calls to imported functions", true, jta);
plugin_joblinks = new Analysis_Plugin_EXECUTION(null, this, "joblinks", "Print process job link information", true, jta);
plugin_notepad = new Analysis_Plugin_EXECUTION(null, this, "notepad", "List currently displayed notepad text", true, jta);
plugin_sessions = new Analysis_Plugin_sessions(null, this, "sessions", "List details on _MM_SESSION_SPACE (user logon sessions)", true, jta);
plugin_ssdt = new Analysis_Plugin_EXECUTION(null, this, "ssdt", "Display SSDT entries", true, jta);

plugin_symlinkscan = new Analysis_Plugin_EXECUTION(null, this, "symlinkscan", "Pool scanner for symlink objects", true, jta);
plugin_thrdscan = new Analysis_Plugin_EXECUTION(null, this, "thrdscan", "Pool scanner for thread objects", true, jta);


//plugin_unloadedmodules = new Analysis_Plugin_EXECUTION(null, this, "unloadedmodules", "Print list of unloaded modules", true, jta);
plugin_userassist = new Analysis_Plugin_user_assist(null, this, "userassist", "Print userassist registry keys and information", false, jta);
plugin_printkey = new Analysis_Plugin_print_key(null, this, "printkey", "Print a registry key, and its subkeys and values", true, jta);
plugin_userhandles = new Analysis_Plugin_EXECUTION(null, this, "userhandles", "Dump the USER handle tables", true, jta);
plugin_vadinfo = new Analysis_Plugin_VAD_INFO(null, this, "vadinfo", "Dump the VAD info", true, jta);
plugin_vadtree = new Analysis_Plugin_vadtree(null, this, "vadtree", "vadtree", true, jta);
plugin_vadwalk = new Analysis_Plugin_EXECUTION(null, this, "vadwalk", "Walk the VAD tree", true, jta);
if(PROFILE.toLowerCase().trim().startsWith("win10"))
	plugin_win10cookie = new Analysis_Plugin_EXECUTION(null, this, "win10cookie", "Find the ObHeaderCookie value for Windows 10", true, jta);
plugin_windows = new Analysis_Plugin_EXECUTION(null, this, "windows", "Print Desktop Windows (verbose details)", true, jta);
plugin_wintree = new Analysis_Plugin_EXECUTION(null, this, "wintree", "Print Z", true, jta);
plugin_wndscan = new Analysis_Plugin_EXECUTION(null, this, "wndscan", "Pool scanner for window stations", true, jta);

plugin_shellbags = new Analysis_Plugin_EXECUTION(null, this, "shellbags", "Prints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags info", true, jta);
plugin_shimcache = new Analysis_Plugin_EXECUTION(null, this, "shimcache", "Parses the Application Compatibility Shim Cache registry key", true, jta);
plugin_timeliner = new Analysis_Plugin_EXECUTION(null, this, "timeliner", "Creates a timeline from various artifacts in memory", false, jta);

				//
				//VERINFO
				//				
				plugin_verinfo = new Analysis_Plugin_verinfo(null, this, "verinfo", "Prints out the version information from PE images", false, jta);
				
				//
				//CMDLINE
				//
				//solo, execute cmdline cmdscan first, determine which processes have cmdscan entries, enrich with cmdline, then add consoles output
				plugin_cmdline = new Analysis_Plugin_cmdline(null, this, "cmdline", "Display process command", false, jta);
				plugin_consoles = new Analysis_Plugin_consoles(null, this, "consoles", "Extract command history by scanning for _CONSOLE_INFORMATION", false, jta);
				
				//
				//APIHOOKS
				//
				//if(enable_api_hooks)
				//plugin_apihooks = new Analysis_Plugin_apihooks(null, this, "apihooks", "Detect API hooks in process and kernel memory", true, jta);
				

				
				
				sop("\nBuilding netstat listing...");
				//////////////////////////////////////////////////////////////////////
				// NETSTAT
				/////////////////////////////////////////////////////////////////////
				
					if(PROFILE.toLowerCase().contains("winxp") || PROFILE.toLowerCase().contains("2003"))
					{
						//
						//connections
						//
						
						plugin_connections = new Analysis_Plugin_connections(null, this, "connections", "Print list of open connections [Windows XP and 2003 Only]", false, jta);
						
						//
						//connscan
						//
						plugin_connscan = new Analysis_Plugin_connscan(null, this, "connscan", "Pool scanner for tcp connections", false, jta);
						
						//
						//sockets
						//
						plugin_sockets = new Analysis_Plugin_sockets(null, this, "sockets", "Print list of open sockets", false, jta);
						
						//
						//sockscan
						//
						plugin_sockscan = new Analysis_Plugin_sockscan(null, this, "sockscan", "Pool scanner for tcp socket objects", false, jta);
					}
					else//everything above WinXP
					{
						//
						//netscan
						//
						plugin_netscan = new Analysis_Plugin_netscan(null, this, "netscan", "Scan a Vista (or later) image for connections and sockets", false, jta);
					}
					
					
				
				
			//////////////////////////////////////////////////////////////////////
			// Handle
			/////////////////////////////////////////////////////////////////////
			sop("\nBuilding handles listing...");
			
				//
				//Handles
				//
				plugin_handles = new Analysis_Plugin_handles(null, this, "handles", "Print list of open handles for each process", false, jta);
				
				
	/*		//////////////////////////////////////////////////////////////////////
			// DONE!
			/////////////////////////////////////////////////////////////////////
		
			//
			//print
			//
			for(Node_Process process : tree_process.values())
			{
				sop(process.toString_header("\t"));	
				
				//process.print_handles(System.out);
			}
			
			for(Node_DLL dll_module : tree_modules_no_duplicates.values())
			{
				if(dll_module.file_version != null)
					sop(dll_module.toString());
			}
			
			for(Node_Process process : tree_process.values())
			{
				if(process.tree_netstat.size() > 0)
					sop(process.get_netstat_print("\t"));								
			}
						
*/			
				
				
				
			//////////////////////////////////////////////////////////////////////
			// Create Tree Structure
		    /////////////////////////////////////////////////////////////////////
			create_tree_structure(this.tree_PROCESS);
				
			/*for(Node_Process process : tree_ORPHAN_process.values())
			{
				sop(process.toString());
				
				if(process.tree_child_process == null || process.tree_child_process.size() < 1)
					continue;
				
				for(Node_Process child : process.tree_child_process.values())
					sop("\t" + child.toString());
				
			}	*/					
			
			
			/////////////////////////////////////////////////////////////////////
			//Check for suspicious DLLs
			////////////////////////////////////////////////////////////////////
			//suspicious DLL is a DLL that is only imported by a single process (recall: DLLs are meant to be shared by other processes...)
			LinkedList<String> list_dll = new LinkedList<String>();
			for(Node_DLL dll : this.tree_DLL_by_path.values())
			{
				if(dll == null )
					continue;
				if(dll.path == null)
					continue;
				if(!dll.path.toLowerCase().trim().endsWith(".dll"))
					continue;
				
				if(dll.tree_process == null || dll.tree_process.size() < 2 )
				{
					list_dll.add(dll.path.toLowerCase().trim());
					
//sp("\nSuspicious DLL with only [" + dll.tree_process.size() + "] importing process --> " + dll.path);
					
					if(dll.tree_process != null && !dll.tree_process.isEmpty())
					{
						for(Node_Process process : dll.tree_process.values())
						{
							sp("  Owning Process: " + process.get_process_html_header());
						}
					}
					
					
				}
			}
			
			
			//
			//print temp directories
			//
			sop("\n\nTemp Directories:");
			for(Node_Envar var : tree_ENVIRONMENT_TEMP.values())
			{
				sop("\t" + var.value);
			}
			
			boolean alerted_console = false;
			
			for(Node_Process process : this.tree_PROCESS.values())
			{
				if(process == null)
					continue;
				
				//pslist and psscan find executables in different ways...
				//if a process is in psscan, but not pslist, then the process may have MiTM itself
				
				if(process.found_in_psscan && !process.found_in_pslist)
				{
					if(!alerted_console)
					{
						sop("\n\nSuspicious process to investigate - potential rootkitting or MiTM:");
						alerted_console = true;
					}
					
					sop("\t" + process.get_process_html_header());
					
				}
			}
			
			
			//////////////////////////////////////////////////////////////////////
			// PRINT!
		    /////////////////////////////////////////////////////////////////////
			
			Start.intface.sop("\nPrimary Advanced Analysis Actions Complete");
			try	{ analyze_display_consoles();} catch(Exception e){}
			execute_completion_actions();
			
//			if(EXECUTE_EXPORT_MANIFEST)
//				this.write_manifest(WRITE_MANIFEST_DELIMITER);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "commence_action", e);
		}
		
		execute_completion_actions();
		
		return false;
	}
	
	public boolean execute_completion_actions()
	{		
		try
		{
			if(!executed_create_tree_structure)
				this.create_tree_structure(tree_PROCESS);
			
			try	{	analysis_report = new Analysis_Report_Container_Writer(this);	}	catch(Exception e){}					
			try	{	print_file_attributes();	}	catch(Exception e){}
			
			AUTOMATED_ANALYSIS_COMPLETE = true;
			
			//Process XREF if this initiated the advanced analysis
			if(Interface.AUTOMATE_XREF_SEARCH)
			{
				try	{	Start.intface.jtabbedPane_MAIN.setSelectedIndex(2);	} catch(Exception e){}
				
				if(!Start.intface.jtfFile_XREF_SearchString.getText().trim().equals(""))
				{
					Start.intface.file_xref = new File_XREF(Start.intface);
				}
			}			
			
			//prevent additional executions of this action since it is automatic from here on (i.e., after this class is called to execute the function
			try	{	Start.intface.jmnuitm_AnalyseUserAssist.setEnabled(true);} catch(Exception e){}
			
			if(this.EXECUTE_EXPORT_MANIFEST)
				this.write_manifest(WRITE_MANIFEST_DELIMITER);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "execute_completion_actions", e);
		}
		
		return false;
	}
	
	
	public boolean print_file_attributes()
	{
		try
		{
			if(FileAttributeData.tree_file_attributes == null || FileAttributeData.tree_file_attributes.size() < 1)
				return false;
			
			String time_stamp = driver.get_time_stamp("_");
			File fle = null;
			
			try
			{
				fle = new File(path_fle_analysis_directory + "file_attributes" + File.separator + "file_attributes_" + this.fle_memory_image.getName() + ".txt");
			}
			catch(Exception e)
			{
				if(file_attr_memory_image != null)					
					fle = new File(path_fle_analysis_directory + "file_attributes" + File.separator + "file_attributes_" + file_attr_memory_image.file_name + ".txt");
				
				else
					fle = new File(path_fle_analysis_directory + "file_attributes" + File.separator + "file_attributes" + ".txt");
			}
			
			try	{	fle.getParentFile().mkdirs();	}	catch(Exception e){}
			
			PrintWriter pw = new PrintWriter(new FileWriter(fle));
			
			//header
			pw.println(FileAttributeData.file_output_header);
			
			for(FileAttributeData attrib : FileAttributeData.tree_file_attributes.values())
			{
				try
				{
					pw.println(attrib.toString("\t"));
				}
				catch(Exception e)
				{
					continue;
				}
			}
			
			
			try	{	pw.flush();} catch(Exception e){}
			try	{	pw.close();} catch(Exception e){}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "print_file_attributes", e, true);
		}
		
		return false;
	}
	
	public boolean initialize_data()
	{
		try
		{
			initialize_computer_name();
			initialize_system_root();
			initialize_system_drive();
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "initialize_data", e);
		}
		
		return false;
	}
	
	
	
	/**
	 * 2 pass. Pass 1: assign parent processes based on PPID. Pass 2: assign orphan processes to tree of orphan processes
	 * @param tree
	 * @return
	 */
	public boolean create_tree_structure(TreeMap<Integer, Node_Process> tree)
	{
		try
		{
			//
			//Pass 1- assign parent processes
			//			
			for(Node_Process process : tree_PROCESS.values())
			{
				try
				{
					if(process == null)
						continue;
					
					if(process.PPID < 1)
					{
						if(process.parent_process == null)
							tree_ORPHAN_process.put(process.PID, process);
					}
					else
					{
						Node_Process parent_process = tree_PROCESS.get(process.PPID);
						
						if(parent_process == null)
						{
							tree_ORPHAN_process.put(process.PID, process);
							continue;
						}
						else
						{
							process.parent_process = parent_process;							
							parent_process.link_child_process(process);
						}
						
						
					}										
					
				}
				catch(Exception e)
				{
					driver.sop("Invalid process discovered in create_tree_structure analysis");
				}
			}
			
			//
			//Pass 2 - assign orphaned processes
			//
			for(Node_Process process : tree_PROCESS.values())
			{
				try
				{
					if(process == null)
						continue;
					
					if(process.parent_process == null)
						tree_ORPHAN_process.put(process.PID, process);
					
				}
				catch(Exception e)
				{
					driver.sop("check create_tree_structure analysis");
				}
			}
			
			executed_create_tree_structure = true;
			
			return true;
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "create_tree_structure", e);
		}
		
		return false;
	}
	
	/**
	 * search through for a dll that is only linked to a single process
	 * @return
	 */
	public boolean analyze_dll_listing_for_suspicious_processes_with_one_process_linking()
	{
		try
		{
			for(Node_DLL dll : this.tree_DLL_by_path.values())
			{
				if(dll.tree_process == null || dll.tree_process.size() < 2)
				{
					sop("suspicious process linked to " + dll.toString());
					
					for(Node_Process proc : dll.tree_process.values())
						sop(proc.toString());
				}
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_dll_listing_for_suspicious_processes_with_one_process_linking", e);
		}
		
		return false;
	}
	
	/**
	 * create dot file now, and then use a utility like graphviz to view it
	 * on linux machine, convert dot file to png or jpg via
	 * dot -Tpng infected.dot -o infected.png
	 * dot -Tjpg infected.dot > processes.jpg
	 * @return
	 */
	public boolean create_psscan_dot_file()
	{
		try
		{
			String image_extension = "png";
			
			String time_stamp = driver.get_time_stamp("_");
			String path_dot_file = path_fle_analysis_directory + "psscan" + File.separator + "_" + "psscan" + "_" + this.fle_memory_image.getName() + ".dot";
			path_dot_file = path_dot_file.substring(path_dot_file.indexOf(Driver.NAME_LOWERCASE)).trim();
			
			if(!path_dot_file.startsWith(File.separator))
				path_dot_file = File.separator + path_dot_file;
			
			if(!path_dot_file.endsWith(".dot"))
				path_dot_file = path_dot_file + ".dot";
			
			String path_converted_file = path_fle_analysis_directory + "psscan" + File.separator + "_" + "psscan" + "_" + this.fle_memory_image.getName() + "." + image_extension;
			path_converted_file = path_converted_file.substring(path_converted_file.indexOf(Driver.NAME_LOWERCASE)).trim();
			
			if(!path_converted_file.startsWith(File.separator))
				path_converted_file = File.separator + path_converted_file;
											
			relative_path_to_converted_dot_process_image = "psscan" + File.separator + "_" + "psscan" + "_" + this.fle_memory_image.getName() + "." + image_extension; 
			
			//String cmd = "\"" + fle_volatility.getCanonicalPath().trim() + "\" -f \"" + fle_memory_image.getCanonicalPath().trim() + "\"" + " --profile=" + PROFILE + " psscan --output=dot --output-file=\"" + fleOutput.getCanonicalPath() + "\"";
			//String cmd = "\"" + fle_volatility.getCanonicalPath().trim() + "\" -f \"" + fle_memory_image.getCanonicalPath().trim() + "\"" + " -f " + "\"" + fle_memory_image.getCanonicalPath().trim() + "\"" + " --profile=" + PROFILE + " psscan --output=dot --output-file=\"" + path_dot_file.replace("\\", "\\\\") + "\"";
			String cmd = "\"" + fle_volatility.getCanonicalPath().trim() + "\" -f \"" + fle_memory_image.getCanonicalPath().trim() + "\"" + " -f " + "\"" + fle_memory_image.getCanonicalPath().trim() + "\"" + " --profile=" + PROFILE + " psscan --output=dot --output-file=\"." + path_dot_file.trim().replace(File.separator,"/");
			
			
			
			//
			//NOTIFY
			//
			if(DEBUG)
				sop("[psscan - dot file]\t Executing command --> " + cmd);
			
			//
			//EXECUTE COMMAND!
			//
			ProcessBuilder process_builder = null;				
			
			if(driver.isWindows)
				process_builder = new ProcessBuilder("cmd.exe", "/C",  cmd);
							
			else//(driver.isLinux)
				process_builder = new ProcessBuilder("/bin/bash", "-c",  cmd);
			
			//
			//redirect error stream
			//
			process_builder.redirectErrorStream(true); 
						
			//
			//instantiate new process
			//
			Process process = process_builder.start();
						
					      
			BufferedReader brIn = new BufferedReader(new InputStreamReader(process.getInputStream()));
			
			//
			//process command output
			//
			LineIterator line_iterator = new LineIterator(brIn);
			String line = "";
		    try 
		    {
		        while (line_iterator.hasNext()) 
		        {		        	
		        	line = line_iterator.nextLine();
		        	
		        	if(line == null)
		        		continue;

		        	//sp(" " + line);		        	
		        }
	        	        		        		        	                		        		      
		    }
		    catch(Exception e)
		    {
		    	driver.sop("check plugin process execution " + "psscan dot" + " - " + cmd);
		    }
		        
		      
		   //clean up
		    try	{ 	brIn.close();       		}	catch(Exception e){}
		    try	{	process.destroy();			}	catch(Exception e){}
		    try	{ 	line_iterator.close();      }	catch(Exception e){}
		   
		  
		    //
		    //convert, transform into png if possible
		    //
		    try
		    {
		    	//dot -Tjpg psscan.dot -o <path>.jpg  or dot -Tpng <path>.dot -o <path>.png
		    			    			    			    			    	
		    	String command = "";
		    	
		    	File fle_dot_file = new File("." + path_dot_file);
		    	File fle_converted_file = new File("." + path_converted_file);
		    	
		    	if(driver.isWindows)
		    	{
		    		//dot -Tpng <path>.dot -o <path>.png
		    		
		    		//valid command below
		    		//command = "\"" + Start.fle_graphviz_dot.getCanonicalPath() + "\" -Tpng \"" + fle_dot_file.getCanonicalPath() + "\" -o \"" + fle_converted_file.getCanonicalPath() + "\"";
		    		
		    		//working directly from cmd prompt
		    		//command = "\"" + Start.fle_graphviz_dot.getCanonicalPath() + "\" -Tpng \"" + fle_dot_file.getCanonicalPath() + "\" -o \"" + "." + File.separator + "_" + Interface.analysis_time_stamp + "_psscan" + "_" + this.fle_memory_image.getName() + ".png";
		    	
		    		//output is working path from current execution location. do not end with closing "
		    		command = "\"" + Start.fle_graphviz_dot.getCanonicalPath() + "\" -T" + image_extension + " \"" + fle_dot_file.getCanonicalPath() + "\" -o \"." + path_converted_file;
		    		
		    		
		    	}
		    	else
		    	{		    		
		    		command = "dot -Tpng \"" + path_dot_file + "\" -o \"." + path_converted_file;
		    	}
		    	
		    	

		    	ProcessBuilder pb = null;				
				
				if(driver.isWindows)
					pb = new ProcessBuilder("cmd.exe", "/C",  command);
								
				else//(driver.isLinux)
					pb = new ProcessBuilder("/bin/bash", "-c",  command);
				
				//
				//redirect error stream
				//
				pb.redirectErrorStream(true); 
							
				//
				//instantiate new process
				//
				Process proc = pb.start();
							
						      
				BufferedReader br = new BufferedReader(new InputStreamReader(proc.getInputStream()));
				
				//
				//process command output
				//
				LineIterator li = new LineIterator(br);
				String in = "";
			    try 
			    {
			        while (li.hasNext()) 
			        {		        	
			        	in = li.nextLine();
			        	
			        	if(in == null)
			        		continue;

			        	driver.directive("--> " + in);		        	
			        }
		        	        		        		        	                		        		      
			    }
			    catch(Exception e)
			    {
			    	driver.sop("check plugin process execution " + "psscan png" + " - " + command);
			    }
			        
			   			      
			   //clean up
			    try	{ 	br.close();       		}	catch(Exception e){}
			    try	{	proc.destroy();			}	catch(Exception e){}
			    try	{ 	li.close();      }	catch(Exception e){}
			   
			    //
				//NOTIFY
				//			
				sp("\nNOTE: If writing to dot file was successful, converted output file has been written to --> " + path_converted_file + "\n");
		    	
		    }
		    catch(Exception e)
		    {
		    	//
				//NOTIFY
				//			
				sp("\n* * * NOTE: If writing to dot file was successful, output file has been written to --> " + path_dot_file + "\n");
		    }
		    
			
			
				
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "create_psscan_dot_file", e);
		}
		
		return false;
	}
	
	public File execute_plugin(String plugin_name, String plugin_description, String cmd, String additional_file_name_detail, LinkedList<String> list_output, boolean include_plugin_header)
	{
		File fleOutput = null;
		
		try
		{							
			if(fle_volatility == null || !fle_volatility.exists() || !fle_volatility.isFile())
			{
				driver.sop("* * ERROR! Valid volatility executable binary has not been set. I cannot proceed with execution of plugin: [" + plugin_name + "]. * * ");
				return null;
			}
			
			if(fle_memory_image == null || !fle_memory_image.exists() || !fle_memory_image.isFile())
			{
				driver.sop("* * ERROR! Valid memory image for analysis has not been set. I cannot proceed with execution of plugin: [" + plugin_name + "]. * *");				
				return null;
			}
			
			//
			//build cmd
			//
			if(cmd == null)
			{
				if(driver.TIME_ZONE == null)
					cmd = "\"" + fle_volatility.getCanonicalPath().trim() + "\" -f \"" + fle_memory_image.getCanonicalPath().trim() + "\" " + plugin_name + " --profile=" + PROFILE;
				else
					cmd = "\"" + fle_volatility.getCanonicalPath().trim() + "\" -f \"" + fle_memory_image.getCanonicalPath().trim() + "\" " + plugin_name + " --profile=" + PROFILE + " --tz=" + driver.TIME_ZONE;
			}
			else if(cmd.toLowerCase().contains("dump"))//cmd override provided!
			{
				sop("\n\nSOLO, PROCESS OVERRIDE CMD E.G. DUMPFILES\n\n");
			}
			
			//
			//clear list contents
			//
			try	{ list_output.clear();}catch(Exception e){ list_output = new LinkedList<String>();}
			
			//
			//notify
			//
			if(DEBUG)
				sop("\n* * * Processing plugin: [" + plugin_name + "]\n");
			else
				sp("\nprocessing plugin: [" + plugin_name + "]...");
			
								
			
			//split the command now into command and params
			String array [] = cmd.split("\\-f");
			
			String command = array[0].trim();
			String params = "";
			String execution_command = "";
			boolean rename_files = true;
			
			for(int i = 1; array != null && i < array.length; i++)
			{
				params = params + " -f " + array[i].trim();
			}
			
			//
			//NOTIFY
			//
			if(DEBUG)
				sop("[" + plugin_name + "]\t Executing command --> " + command + params);
			
			//
			//INITIALIZE OUTPUT DIRECTORY
			//
			String time_stamp = driver.get_time_stamp("_");

			if(Advanced_Analysis_Director.DO_NOT_INCLUDE_TIME_STAMP_IN_FILE_NAME)
				fleOutput = new File(path_fle_analysis_directory + plugin_name + File.separator + "_" + plugin_name + ".txt");
			else
				fleOutput = new File(path_fle_analysis_directory + plugin_name + File.separator + "_" + plugin_name + "_" + additional_file_name_detail + time_stamp + ".txt");
			
			File fleOutput_connections = null;
			
			try	
			{	
				if(!fleOutput.getParentFile().exists() || !fleOutput.getParentFile().isDirectory())
				fleOutput.getParentFile().mkdirs();	
			}	 catch(Exception e){}
			
			
			//
			//EXECUTE COMMAND!
			//
			ProcessBuilder process_builder = null;	
			
			
			if(driver.isWindows)
			{
				process_builder = new ProcessBuilder("cmd.exe", "/C",  command +  params);
				execution_command = command +  params;
				
				/*
				 * DUMP FILES
				 * plugin_name.equalsIgnoreCase("procdump") 	||
					plugin_name.equalsIgnoreCase("dlldump") 		||
					plugin_name.equalsIgnoreCase("dumpcerts") 	||
					plugin_name.equalsIgnoreCase("dumpfiles") 	||
					plugin_name.equalsIgnoreCase("dumpregistry") ||
					plugin_name.equalsIgnoreCase("memdump") 		||
					plugin_name.equalsIgnoreCase("moddump")		||
					plugin_name.equalsIgnoreCase("evtlogs")		||
					plugin_name.equalsIgnoreCase("vaddump")		||
					params.contains("--dump-dir")
				 */
			}
							
			//else if(driver.isLinux)
			else
			{
				process_builder = new ProcessBuilder("/bin/bash", "-c",  command +  params);
				
				execution_command = command +  params;
			}
			
			//
			//redirect error stream
			//
			process_builder.redirectErrorStream(true); 
						
			//
			//instantiate new process
			//
			Process process = process_builder.start();
						
			//
			//process input
			//
			PrintWriter pw = new PrintWriter(new FileWriter(fleOutput), true);
			
			//if(command.toLowerCase().contains("volatility") || params.toLowerCase().contains("volatility"))
			if(include_plugin_header)
			{
				//write_process_header(pw, plugin_name, plugin_description, execution_command);
				driver.write_process_header(investigator_name, investigation_description, EXECUTION_TIME_STAMP, file_attr_volatility, file_attr_memory_image, fle_memory_image, pw, plugin_name, plugin_description, execution_command);
			}
			
			BufferedReader brIn = new BufferedReader(new InputStreamReader(process.getInputStream()));
			
			//
			//process command output
			//
			LineIterator line_iterator = new LineIterator(brIn);
			String line = "";
			
		    try 
		    {
		        while (line_iterator.hasNext()) 
		        {		        	
		        	line = line_iterator.nextLine();
		        	
		        	if(line == null)
		        		continue;

		        	Start.intface.jpnlAdvancedAnalysisConsole.append_sp(".");
		        	

		        	list_output.add(line);
		        	
		        	//log
		        	pw.println(line);
		        }
		        
		        
		        //
		        //Check if we're providing output in TSV format as well
		        //
		        //if(include_output_as_tsv)
		        //	write_output_tsv(pw, list_output, "\t");
		        	                		        		      
		    }
		    catch(Exception e)
		    {
		    	driver.sop("check plugin process execution " + plugin_name + " - " + cmd);
		    }
		        
		      
		   //clean up
		    try	{ 	brIn.close();       		}	catch(Exception e){}
		    try	{	process.destroy();			}	catch(Exception e){}
		    try	{ 	line_iterator.close();      }	catch(Exception e){}
		    
		    try	{	pw.flush();} catch(Exception e){}
			try	{	pw.close();} catch(Exception e){}
			
			
			
			//
			//NOTIFY
			//
			if(DEBUG)
			{			
			
				sop("\n\nExecution complete. If successful, output file has been written to --> " + fleOutput + "\n");
						
			}
				
				if(fleOutput_connections != null && fleOutput_connections.exists())
					driver.sop("It appears I was able to extract specific foreign addresses from this plugin and write them to disk. If successful, connection information file has been written to --> " + fleOutput_connections + "\n");
									
			return fleOutput;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "execute_plugin", e);
		}
		
		return fleOutput;
	}
	
	public boolean process_pslist(LinkedList<String> output)
	{
		try
		{
			
			if(output == null || output.size() < 1)
				return false;
			
			process_in_execution_PSLIST = true;
			
			if(DEBUG)
				sop("\nPlugin execution complete. Processing results, building process tree now...\n");
			
			String [] array = null;
			String offset = "";
			String process_name = "";
			int PID = -1;
			int PPID = -1;
			String threads = "";
			String handles = "";
			String session = "";
			String wow64 = "";
			String start_date = "";
			String start_time = "";
			String start_UTC = "";
			String exit_date = "";
			String exit_time = "";
			String exit_UTC = "";
			String lower = "";
			
			
			
			for(String line : output)
			{
				//pslist --> 0x822349f0 winlogon.exe            632    552     21      650      0      0 2016-11-29 06:44:45 UTC+0000                                 
				
				if(line == null)
					continue;
				
				line = line.trim();
				
				if(line.length() < 4)
					continue;
				
				if(line.startsWith("#"))
					continue;
				
				if(!line.contains("0x"))
					continue;
				
				lower = line.toLowerCase().trim();
				
				array = line.split(" ");
				offset = "";
				process_name = "";
				PID = -1;
				PPID = -1;
				threads = "";
				handles = "";
				session = "";
				wow64 = "";
				start_date = "";
				start_time = "";
				start_UTC = "";
				exit_date = "";
				exit_time = "";
				exit_UTC = "";
				
				if(array == null || array.length < 3)
					continue;
				
				//Offset(V)  Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit                          
				for(String token : array)
				{
					if(token == null || token.trim().equals(""))
						continue;
					
					
					if(offset == null || offset.equals(""))
						offset = token;
					
					else if(process_name == null || process_name.equals(""))
						process_name = token;
					
					else if(PID < 0)
					{
						//check if this is part of process name, or true PID
						try
						{
							int val = Integer.parseInt(token.trim());
							
							if(val >= 0)
								PID = val;
						}
						catch(Exception e)
						{
							//assume it is part of process name
							process_name = process_name + " " + token;
						}
						
						continue;
					}
														
					else if(PPID < 0)
					{
						try
						{
							PPID = Integer.parseInt(token.trim());
						}
						catch(Exception e)
						{
							sop("Error! I could not process PID: [" + PID + "] PPID for token[" + token + "] on line -->" + line);
							sop("I will set PPID = -1 at this time...");
							PPID = -1;
						}
					}
					
					else if(threads == null || threads.equals(""))
						threads = token;
					
					else if(handles == null || handles.equals(""))
						handles = token;
					
					else if(session == null || session.equals(""))
						session = token;
					
					else if(wow64 == null || wow64.equals(""))
						wow64 = token;
					
					else if(start_date == null || start_date.equals(""))
						start_date = token;
					
					else if(start_time == null || start_time.equals(""))
						start_time = token;
					
					else if(start_UTC == null || start_UTC.equals(""))
						start_UTC = token;
					
					else if(exit_date == null || exit_date.equals(""))
						exit_date = token;
					
					else if(exit_time == null || exit_time.equals(""))
						exit_time = token;
					
					else if(exit_UTC == null || exit_UTC.equals(""))
						exit_UTC = token;
				}
				
				if(PID < 0)
				{
					if(lower.startsWith("volatility") || lower.startsWith("offset") || lower.startsWith("----"))
						continue;
					else
						sop("I was not able to extract PID from line --> " + line);
				}
				else//process node!
				{
					//come here to store the info!
					Node_Process process = null;
					
					//
					//procure node
					//
					if(tree_PROCESS.containsKey(PID))
						process = tree_PROCESS.get(PID);
					else
					{
						//Link!
						process = new Node_Process(this, PID, process_name);
						tree_PROCESS.put(PID,  process);
					}
					
					process.found_in_pslist = true;
					
					//
					//populate / update
					//
					process.offset_pslist = offset;
					process.process_name = process_name;
					process.PID = PID;
					process.PPID = PPID;
					process.threads = threads;
					process.handles = handles;
					process.session = session;
					process.wow64 = wow64;
					process.time_created_date = start_date;
					process.time_created_time = start_time;
					process.time_created_UTC = start_UTC;
					process.time_exited_date = exit_date;
					process.time_exited_time = exit_time;
					process.time_exited_UTC = exit_UTC;	
					
					
					//
					//additional linking
					//
					if(offset != null && !offset.equals(""))
					{
						tree_PROCESS_linked_by_pslist_EPROCESS_base_address.put(offset,  process);											 
					}
				}
				
					
			}
			
			process_in_execution_PSLIST = false;
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_pslist", e);
		}
		
		process_in_execution_PSLIST = false;
		return false;
		
	}
	
	public boolean process_psscan(LinkedList<String> output)
	{
		try
		{						
			if(output == null || output.size() < 1)
				return false;
			
			process_in_execution_PSSCAN = true;	
			
			if(DEBUG)
				sop("\nPlugin execution complete. Processing results, building process tree now...\n");
			
			String [] array = null;
			String offset = "";
			String process_name = "";
			int PID = -1;
			int PPID = -1;
			String PDB = "";			
			String time_created_date = "";
			String time_created_time = "";
			String time_created_UTC = "";
			String time_exited_date = "";
			String time_exited_time = "";
			String time_exited_UTC = "";
			String lower = "";
			
			
			
			for(String line : output)
			{
				//psscan --> 0x000000003953e030 Sample-14-1.ex     2492   2236 0x3eba2200 2020-02-13 17:20:16 UTC+0000   2020-02-13 17:20:16 UTC+0000                                   
				
				if(line == null)
					continue;
				
				line = line.trim();
				
				if(line.length() < 4)
					continue;
				
				if(line.startsWith("#"))
					continue;
				
				if(!line.contains("0x"))
					continue;
				
				lower = line.toLowerCase().trim();
				
				array = line.split(" ");
				offset = "";
				process_name = "";
				PID = -1;
				PPID = -1;
				PDB = "";				
				time_created_date = "";
				time_created_time = "";
				time_created_UTC = "";
				time_exited_date = "";
				time_exited_time = "";
				time_exited_UTC = "";
				
				if(array == null || array.length < 3)
					continue;
				
				//Offset(P)          Name                PID   PPID PDB        Time created                   Time exited                                             
				for(String token : array)
				{
					if(token == null || token.trim().equals(""))
						continue;					
					
					if(offset == null || offset.equals(""))
						offset = token;
					
					else if(process_name == null || process_name.equals(""))
						process_name = token;
					
					else if(PID < 0)
					{
						//check if this is part of process name, or true PID
						try
						{
							int val = Integer.parseInt(token.trim());
							
							if(val >= 0)
								PID = val;
						}
						catch(Exception e)
						{
							//assume it is part of process name
							process_name = process_name + " " + token;
						}
						
						continue;
					}
														
					else if(PPID < 0)
					{
						try
						{
							PPID = Integer.parseInt(token.trim());
						}
						catch(Exception e)
						{
							sop("Error! I could not process PID: [" + PID + "] PPID for token[" + token + "] on line -->" + line);
							sop("I will set PPID = -1 at this time...");
							PPID = -1;
						}
					}
					
					else if(PDB == null || PDB.equals(""))
						PDB = token;
															
					else if(time_created_date == null || time_created_date.equals(""))
						time_created_date = token;
					
					else if(time_created_time == null || time_created_time.equals(""))
						time_created_time = token;
					
					else if(time_created_UTC == null || time_created_UTC.equals(""))
						time_created_UTC = token;
					
					else if(time_exited_date == null || time_exited_date.equals(""))
						time_exited_date = token;
					
					else if(time_exited_time == null || time_exited_time.equals(""))
						time_exited_time = token;
					
					else if(time_exited_UTC == null || time_exited_UTC.equals(""))
						time_exited_UTC = token;
				}
				
				if(PID < 0)
				{
					if(lower.startsWith("volatility") || lower.startsWith("offset") || lower.startsWith("----"))
						continue;
					else
						sop("I was not able to extract PID from line --> " + line);
				}
				else//process node!
				{
					//come here to store the info!
					Node_Process process = null;
					
					//
					//procure node
					//
					if(tree_PROCESS.containsKey(PID))
						process = tree_PROCESS.get(PID);
					else
					{
						//Link!
						process = new Node_Process(this, PID, process_name);
						tree_PROCESS.put(PID,  process);												
					}
					
					process.found_in_psscan = true;
					
					//
					//populate / update
					//
					process.offset_psscan = offset;
										
					if(process.process_name.equals("") || process.process_name == null)
						process.process_name = process_name;					

					if(process.PID < 0)
						process.PID = PID;

					if(process.PPID < 0)
						process.PPID = PPID;
					
					process.PDB = PDB;					
					process.time_created_date = time_created_date;
					process.time_created_time = time_created_time;
					process.time_created_UTC = time_created_UTC;
					process.time_exited_date = time_exited_date;
					process.time_exited_time = time_exited_time;
					process.time_exited_UTC = time_exited_UTC;																			
				}
				
					
			}
			
			process_in_execution_PSSCAN = false;
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_psscan", e);
		}
		
		process_in_execution_PSSCAN = false;
		return false;
		
	}
	
	
	
	public boolean process_pstree(LinkedList<String> output)
	{
		try
		{
			
			if(output == null || output.size() < 1)
				return false;
			
			process_in_execution_PSTREE = true;
			
			if(DEBUG)
				sop("\nPlugin execution complete. Processing results, building process tree now...\n");
			
			String [] array = null;
			String offset = "";
			String process_name = "";
			int PID = -1;
			int PPID = -1;
			String threads = "";
			String handles = "";
			
			String start_date = "";
			String start_time = "";
			String start_UTC = "";

			String lower = "";
			
			
			
			for(String line : output)
			{
				//pstree --> 0x85f59100:wininit.exe                               400    340      3     76 2020-02-12 02:53:41 UTC+0000                                 
				
				if(line == null)
					continue;
				
				line = line.trim();
				
				if(line.startsWith("#"))
					continue;
				
				if(line.length() < 4)
					continue;
				
				if(!line.contains("0x"))
					continue;
				
				//remove leading "." e.g --> ... 0x86876c10:WmiPrvSE.exe                           292    636     10    196 2020-02-12 02:53:45 UTC+0000				
				line = line.substring(line.indexOf("0x")).trim(); 
								
				lower = line.toLowerCase().trim();
				
				array = line.split(" ");
				offset = "";
				process_name = "";
				PID = -1;
				PPID = -1;
				threads = "";
				handles = "";
				
				start_date = "";
				start_time = "";
				start_UTC = "";
				
				
				if(array == null || array.length < 3)
					continue;
				
				//Name                                                  Pid   PPid   Thds   Hnds Time                          
				//0x8699f030:audiodg.exe                                632    780      6    126 2020-02-13 17:19:40 UTC+0000
				for(String token : array)
				{
					if(token == null || token.trim().equals(""))
						continue;
					
					//bifurcate offset from name
					if(offset == null || offset.equals(""))
					{
						offset = token.substring(0, token.indexOf(":")).trim();
						process_name = token.substring(token.indexOf(":")+1).trim();						
					}
					
					
					
					else if(PID < 0)
					{
						//check if this is part of process name, or true PID
						try
						{
							int val = Integer.parseInt(token.trim());
							
							if(val >= 0)
								PID = val;
						}
						catch(Exception e)
						{
							//assume it is part of process name
							process_name = process_name + " " + token;
						}
						
						continue;
					}
														
					else if(PPID < 0)
					{
						try
						{
							PPID = Integer.parseInt(token.trim());
						}
						catch(Exception e)
						{
							sop("Error! I could not process PID: [" + PID + "] PPID for token[" + token + "] on line -->" + line);
							sop("I will set PPID = -1 at this time...");
							PPID = -1;
						}
					}
					
					else if(threads == null || threads.equals(""))
						threads = token;
					
					else if(handles == null || handles.equals(""))
						handles = token;
										
				}
				
				//
				//validate good process
				//
				if(PID < 0)
				{
					if(lower.startsWith("volatility") || lower.startsWith("offset") || lower.startsWith("----"))
						continue;
					else
						sop("I was not able to extract PID from line --> " + line);
				}
				
				//
				//otw, process node!
				//
				else
				{
					//come here to store the info!
					Node_Process process = null;
					
					//
					//procure node
					//
					if(tree_PROCESS.containsKey(PID))
						process = tree_PROCESS.get(PID);

					if(process == null)
					{
						//Link!
						process = new Node_Process(this, PID, process_name);
						tree_PROCESS.put(PID,  process);
					}
					
					//
					//populate / update
					//
					process.offset_pstree = offset;
					
					if(process.process_name == null || process.process_name.trim().equals(""))
						process.process_name = process_name;
					
					if(process.PPID < 0)
						process.PPID = PPID;
					
					if(process.threads == null || process.threads.trim().equals(""))
						process.threads = threads;					
					
					if(process.handles == null || process.handles.trim().equals(""))
						process.handles = handles;

					if(process.time_created_date == null || process.time_created_date.trim().equals(""))
						process.time_created_date = start_date;
					
					if(process.time_created_time == null || process.time_created_time.trim().equals(""))
						process.time_created_time = start_time;
						
					if(process.time_created_UTC == null || process.time_created_UTC.trim().equals(""))	
						process.time_created_UTC = start_UTC;									
				}
				
					
			}
			
			process_in_execution_PSTREE = false;
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_pstree", e);
		}
		
		process_in_execution_PSTREE = false;
		return false;
		
	}
	
	
	
	
	
	
	
	
	
	
	public boolean sop(String out)
	{
		try
		{
			Interface.jpnlAdvancedAnalysisConsole.append(out);						
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
			Interface.jpnlAdvancedAnalysisConsole.append_sp(out);						
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "sop", e);
		}
		
		return false;
	}
	
	
	public boolean write_process_header(PrintWriter pw, String plugin_name, String plugin_description, String execution_command)
	{
		try
		{
			if(pw == null)
				return false;
			
			//
			//determine the number of hash signs we'll need
			//
			int size = 0;
			
			if(investigator_name != null && investigator_name.trim().length() > 0 && investigation_description != null && investigation_description.trim().length() > 0)
			{
				if(("# Investigator Name: " + investigator_name + "\t Investigation Description: " + investigation_description).length() > size);
					size = ("# Investigator Name: " + investigator_name + "\t Investigation Description: " + investigation_description).length();
				
			}
			else if(investigation_description != null && investigation_description.trim().length() > 0)
			{
				if(("# Investigation Description: " + investigation_description).length() > size)
					size = ("# Investigation Description: " + investigation_description).length();
			}
			
			if(("# Investigation Date: " + EXECUTION_TIME_STAMP).length() > size)
				size = ("# Investigation Date: " + EXECUTION_TIME_STAMP).length();
			
			
			if(file_attr_volatility != null)
			{
				if(("# Memory Analysis Binary: " + file_attr_volatility.get_attributes("\t ")).length() > size)
					size = ("# Memory Analysis Binary: " + file_attr_volatility.get_attributes("\t ")).length();
			}
			
			if(fle_memory_image != null)
			{
				if(("# Memory Image Path: " + fle_memory_image.getCanonicalPath()).length() > size)
					size = ("# Memory Image Path: " + fle_memory_image.getCanonicalPath()).length();
			}
			
			if(file_attr_memory_image != null)
			{
				if(("# Memory Image Attributes: " + file_attr_memory_image.get_attributes("\t ")).length() > size)
					size = ("# Memory Image Attributes: " + file_attr_memory_image.get_attributes("\t ")).length();
			}
			
			if(("# Plugin Name: " + plugin_name).length() > size)
				size = ("# Plugin Name: " + plugin_name).length();
			
			if(("# Plugin Description: " + plugin_description).length() > size)
				size = ("# Plugin Description: " + plugin_description).length();
			
			if(("# Execution Command: " + execution_command).length() > size)
				size = ("# Execution Command: " + execution_command).length();
			
			//
			//print data
			//
			for(int i = 0; i < size+8; i ++)
				pw.print("#");
			
			pw.print("\n");
			
			if(investigator_name != null && investigator_name.trim().length() > 0 && investigation_description != null && investigation_description.trim().length() > 0)
				pw.println("# Investigator Name: " + investigator_name + "\t Investigation Description: " + investigation_description);	
			else if(investigation_description != null && investigation_description.trim().length() > 0)
				pw.println("# Investigation Description: " + investigation_description);	
			
			pw.println("# Investigation Date: " + EXECUTION_TIME_STAMP);
			
			if(file_attr_volatility != null)
				pw.println("# Memory Analysis Binary: " + file_attr_volatility.get_attributes("\t "));
			
			if(fle_memory_image != null)
				pw.println("# Memory Image Path: " + fle_memory_image.getCanonicalPath());
			
			if(file_attr_memory_image != null)
				pw.println("# Memory Image Attributes: " + file_attr_memory_image.get_attributes("\t "));
			
			
			pw.println("# Plugin Name: " + plugin_name);
			pw.println("# Plugin Description: " + plugin_description);
			pw.println("# Execution Command: " + execution_command);
			
			for(int i = 0; i < size+8; i ++)
				pw.print("#");
			
			pw.println("\n");
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "write_process_header", e);
		}
		
		return false;
	}
	
	public boolean write_output_tsv(PrintWriter pw, LinkedList<String> output, String delimiter)
	{
		try
		{
			sop("\nSOLO, RETURN TO THIS FUNCTION, CHANGE INPUT FROM output list to PROCESS NODE!");
			
			if(pw == null)
				return false;
			
			if(output == null || output.isEmpty())
				return false;
			
			if(pw != null)
			{
				pw.println("\n#################################################################################################################");
				pw.println("# OUTPUT - TSV");
				pw.println("#################################################################################################################");
				

				sp(".");
			}
			
			String [] array = null;
			String lower = "";
			
			for(String line : output)
			{
				if(line == null)
					continue;
				
				line = line.trim();
				
				if(line.trim().equals(""))
					continue;
				
				lower = line.toLowerCase().trim();
				
				//reject Volatility	Foundation	Volatility	Framework
				if(lower.contains("volatility") && lower.contains("foundation") && lower.contains("framework"))
					continue;
				
				array = line.split(" ");
				
				if(array == null || array.length < 1)
					continue;
				
				for(String token : array)
				{
					token = token.trim();
					
					if(token.length() < 1 || token.equals(""))
						continue;
					
					pw.print(token + delimiter);										
				}
				
				pw.println();												
			}
			
			try	{pw.flush(); 	}	catch(Exception e){}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_output_tsv", e);
		}
		
		return false;
	}
	
	
	public boolean process_psxview(LinkedList<String> output)
	{
		try
		{			
			if(output == null || output.size() < 1)
				return false;
			
			process_in_execution_PSXVIEW = true;
			
			if(DEBUG)
				sop("\nPlugin execution complete. Processing results, building process tree now...\n");
			
			String [] array = null;
			String offset = "";
			String process_name = "";
			int PID = -1;

			String psxview_pslist = "";
			String psxview_psscan = "";
			String psxview_thrdproc = "";
			String psxview_pspcid = "";
			String psxview_csrss = "";
			String psxview_session = "";
			String psxview_deskthrd = "";			
			
			String time_exited_date = "";
			String time_exited_time = "";
			String time_exited_UTC = "";
			String lower = "";
			
			
			
			for(String line : output)
			{
				//psscan --> 0x000000003953e030 Sample-14-1.ex     2492   2236 0x3eba2200 2020-02-13 17:20:16 UTC+0000   2020-02-13 17:20:16 UTC+0000                                   
				
				if(line == null)
					continue;
				
				line = line.trim();
				
				if(line.startsWith("#"))
					continue;
				
				if(line.length() < 4)
					continue;
				
				if(!line.contains("0x"))
					continue;
				
				lower = line.toLowerCase().trim();
				
				array = line.split(" ");
				
				if(array == null || array.length < 3)
					continue;
				
				offset = "";
				process_name = "";
				PID = -1;

				psxview_pslist = "";
				psxview_psscan = "";
				psxview_thrdproc = "";
				psxview_pspcid = "";
				psxview_csrss = "";
				psxview_session = "";
				psxview_deskthrd = "";
				
				time_exited_date = "";
				time_exited_time = "";
				time_exited_UTC = "";
				
				
				
				//Offset(P)          Name                PID   PPID PDB        Time created                   Time exited                                             
				for(String token : array)
				{
					if(token == null || token.trim().equals(""))
						continue;					
					
					if(offset == null || offset.equals(""))
						offset = token;
					
					else if(process_name == null || process_name.equals(""))
						process_name = token;
					
					else if(PID < 0)
					{
						//check if this is part of process name, or true PID
						try
						{
							int val = Integer.parseInt(token.trim());
							
							if(val >= 0)
								PID = val;
						}
						catch(Exception e)
						{
							//assume it is part of process name
							process_name = process_name + " " + token;
						}
						
						continue;
					}
														
					else if(psxview_pslist == null || psxview_pslist.equals(""))
						psxview_pslist = token;
					
					else if(psxview_psscan == null || psxview_psscan.equals(""))
						psxview_psscan = token;
					
					else if(psxview_thrdproc == null || psxview_thrdproc.equals(""))
						psxview_thrdproc = token;
					
					else if(psxview_pspcid == null || psxview_pspcid.equals(""))
						psxview_pspcid = token;
					
					else if(psxview_csrss == null || psxview_csrss.equals(""))
						psxview_csrss = token;
					
					else if(psxview_session == null || psxview_session.equals(""))
						psxview_session = token;
					
					else if(psxview_deskthrd == null || psxview_deskthrd.equals(""))
						psxview_deskthrd = token;					
					
					else if(time_exited_date == null || time_exited_date.equals(""))
						time_exited_date = token;
					
					else if(time_exited_time == null || time_exited_time.equals(""))
						time_exited_time = token;
					
					else if(time_exited_UTC == null || time_exited_UTC.equals(""))
						time_exited_UTC = token;
				}
				
				if(PID < 0)
				{
					if(lower.startsWith("volatility") || lower.startsWith("offset") || lower.startsWith("----"))
						continue;
					else
						sop("I was not able to extract PID from line --> " + line);
				}
				else//process node!
				{
					//come here to store the info!
					Node_Process process = null;
					
					//
					//procure node
					//
					if(tree_PROCESS.containsKey(PID))
						process = tree_PROCESS.get(PID);
					else
					{
						//Link!
						process = new Node_Process(this, PID, process_name);
						tree_PROCESS.put(PID,  process);
					}
					
					//
					//populate / update
					//
					process.offset_psxview = offset;
										
					if(process.process_name.equals("") || process.process_name == null)
						process.process_name = process_name;					

					if(process.PID < 0)
						process.PID = PID;
							
					process.psxview_pslist = psxview_pslist;
					process.psxview_psscan = psxview_psscan;
					process.psxview_thrdproc = psxview_thrdproc;
					process.psxview_pspcid = psxview_pspcid;
					process.psxview_csrss = psxview_csrss;
					process.psxview_session = psxview_session;
					process.psxview_deskthrd = psxview_deskthrd;
					
					if(process.time_exited_date == null || process.time_exited_date.trim().equals(""))					
						process.time_exited_date = time_exited_date;
					
					if(process.time_exited_time == null || process.time_exited_time.trim().equals(""))
						process.time_exited_time = time_exited_time;
					
					if(process.time_exited_UTC == null || process.time_exited_UTC.trim().equals(""))
						process.time_exited_UTC = time_exited_UTC;																			
				}				
					
			}
			
			process_in_execution_PSXVIEW = false;
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_psxview", e);
		}
		
		process_in_execution_PSXVIEW = false;
		return false;
		
	}
	
	
	
	
	
	public boolean initialize_computer_name()
	{
		try
		{
			if(computer_name != null && !computer_name.trim().equals(""))
				return true;
			
			Node_Envar env_var = null;
			if(tree_ENVIRONMENT_VARS.containsKey("computername"))
				env_var = tree_ENVIRONMENT_VARS.get("computername");
			else if(tree_ENVIRONMENT_VARS.containsKey("computer_name"))
				env_var = tree_ENVIRONMENT_VARS.get("computer_name");
			else if(tree_ENVIRONMENT_VARS.containsKey("logonserver"))
				env_var = tree_ENVIRONMENT_VARS.get("logon_server");
			
			try	{	this.computer_name = env_var.value.trim();	} catch(Exception e){}
			
			if(computer_name == null || computer_name.trim().equals(""))
				computer_name = "Computer Name";
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "initialize_computer_name", e);
		}
		
		return false;
	}
	
	/**
	 * SystemRoot                     C:\WINDOWS
	 * @return
	 */
	public boolean initialize_system_root()
	{
		try
		{
			if(system_root != null && !system_root.trim().equals(""))
				return true;
			
			Node_Envar env_var = null;
			if(tree_ENVIRONMENT_VARS.containsKey("systemroot"))
				env_var = tree_ENVIRONMENT_VARS.get("systemroot");
			else if(tree_ENVIRONMENT_VARS.containsKey("system_root"))
				env_var = tree_ENVIRONMENT_VARS.get("system_root");
			else if(tree_ENVIRONMENT_VARS.containsKey("SystemRoot"))
				env_var = tree_ENVIRONMENT_VARS.get("SystemRoot");
			
			try	{	this.system_root = env_var.value.trim();	} catch(Exception e){}
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "initialize_system_root", e);
		}
		
		return false;
	}
	
	
	/**
	 * Systemdrive                     C:
	 * @return
	 */
	public boolean initialize_system_drive()
	{
		try
		{
			if(system_drive != null && !system_drive.trim().equals(""))
				return true;
			
			Node_Envar env_var = null;
			if(tree_ENVIRONMENT_VARS.containsKey("systemdrive"))
				env_var = tree_ENVIRONMENT_VARS.get("systemdrive");
			else if(tree_ENVIRONMENT_VARS.containsKey("system_drive"))
				env_var = tree_ENVIRONMENT_VARS.get("system_drive");
			else if(tree_ENVIRONMENT_VARS.containsKey("SystemDrive"))
				env_var = tree_ENVIRONMENT_VARS.get("SystemDrive");
			
			try	{	this.system_drive = env_var.value.toUpperCase().trim();	} catch(Exception e){}
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "initialize_system_drive", e);
		}
		
		return false;
	}
	
	/**Determine if Consoles had txt relating to a process, if so, display a new console tab with the contents displayed to the user*/
	public boolean analyze_display_consoles()
	{
		try
		{
			if(tree_PROCESS == null || tree_PROCESS.size() < 1)
				return false;
			
			for(Node_Process process : tree_PROCESS.values())
			{
				if(process == null)						
					continue;
				
				process.check_to_display_consoles();
			}					
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_display_consoles", e);
		}
		
		return false;
	}
	
	
	public boolean write_manifest_header(PrintWriter pw, String header)
	{
		try
		{
			if(pw == null)
				return false;
			
			if(header == null)
				header = "";
			
			String outline = "####################################################################################################";
			
			pw.println(outline);
			pw.println("# " + header);
			pw.println(outline);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_manifest_header", e);
		}
		
		return false;
	}
	
	public boolean write_manifest(String delimiter)
	{
		/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		// Need to check export:
		//		Node_DLL
		//			tree_import_function_table_impscan, tree_import_function_table_impscan
		//
		///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		
		PrintWriter pw = null;
		String fle_manifest_path = null;
		
		try
		{
			if(!DEBUG && (this.tree_PROCESS == null || this.tree_PROCESS.isEmpty()))
			{
				driver.jop_Error("It looks like advanced analysis is not complete. Please try again later...");
				return false;
			}
			
			fle_manifest_EXPORT = new File(path_fle_analysis_directory + "manifest" + File.separator + "_manifest.txt");
			
			try	{	fle_manifest_EXPORT.getParentFile().mkdir();} catch(Exception e){}
			
			pw = new PrintWriter(new FileWriter(fle_manifest_EXPORT));
			
			//////////////////////////////////////////////////////////
			//
			// Investigation Particulars
			//
			////////////////////////////////////////////////////////
			write_manifest_header(pw, "Investigation Particulars");
			write_manifest_investigation_particulars(pw, "investigation_particulars");
			
			
			//////////////////////////////////////////////////////////
			//
			// process
			//
			////////////////////////////////////////////////////////
			write_manifest_header(pw, "Process");
			
			if(this.tree_PROCESS != null)
			{
				for(Node_Process process : this.tree_PROCESS.values())
				{
					if(process == null)
						continue;
					
					process.write_manifest(pw);
				}
			}
			
			//////////////////////////////////////////////////////////
			//
			// child process
			//
			////////////////////////////////////////////////////////
			write_manifest_header(pw, "Child Process(es)");
			
			if(!executed_create_tree_structure)
				this.create_tree_structure(tree_PROCESS);
			
			if(this.tree_PROCESS != null)
			{
				for(Node_Process process : this.tree_PROCESS.values())
				{					
					if(process == null)
						continue;
					
					process.write_manifest_child_process(pw);
				}
			}
			
			//////////////////////////////////////////////////////////
			//
			// Orphaned Process(es)
			//
			////////////////////////////////////////////////////////
			try
			{
				if(tree_ORPHAN_process != null && tree_ORPHAN_process.size() > 0)
				{
					LinkedList<Integer> list = new LinkedList<Integer>(tree_ORPHAN_process.keySet());
					
					String process_list = ""+list.removeFirst();
					
					for(int i : list)
						process_list = process_list + ", " + i;
					
					if(process_list != null && process_list.trim().length() > 0)
					{
						write_manifest_header(pw, "Orphaned Process(es)");   //tree_ORPHAN_process
						driver.write_manifest_entry(pw, "orphaned_process_list", process_list);
					}
					
				}
				
				  
			}
			catch(Exception e)
			{
				driver.directive("unexpected Punt in " + this.myClassName + " while accumulating orphaned processing...");
			}
	
			//////////////////////////////////////////////////////////
			//
			// tree_process_to_link_cmdline_cmdscan_consoles
			//
			////////////////////////////////////////////////////////
			try
			{
				if(tree_process_to_link_cmdline_cmdscan_consoles != null && tree_process_to_link_cmdline_cmdscan_consoles.size() > 0)
				{
					LinkedList<Integer> list = new LinkedList<Integer>(tree_process_to_link_cmdline_cmdscan_consoles.keySet());
					
					String process_list = ""+list.removeFirst();
					
					for(int i : list)
						process_list = process_list + ", " + i;
					
					if(process_list != null && process_list.trim().length() > 0)
					{
						write_manifest_header(pw, "Processes linked to cmdline, cmdscan, consoles");
						driver.write_manifest_entry(pw, "processes_linked_to_cmdline_cmdscan_consoles", process_list);
					}
					
				}
				
				  
			}
			catch(Exception e)
			{
				driver.directive("unexpected Punt in " + this.myClassName + " while accumulating processes linked to cmdline, cmdscan, consoles...");
			}
			
			
			
			
			//////////////////////////////////////////////////////////
			//
			// DLL
			//
			////////////////////////////////////////////////////////
			if(tree_DLL_by_path != null && !tree_DLL_by_path.isEmpty())
			{
				write_manifest_header(pw, "DLL");
				if(this.tree_DLL_by_path != null)
				{
					boolean include_underline = (tree_DLL_by_path != null) & (!tree_DLL_by_path.isEmpty());
					
					for(Node_DLL node : this.tree_DLL_by_path.values())
					{
						if(node == null)
							continue;
						
						node.write_manifest(pw, delimiter, include_underline);
					}
				}
			}
			
			//////////////////////////////////////////////////////////
			//
			// Drivers
			//
			////////////////////////////////////////////////////////
			if(tree_DRIVERS != null && !tree_DRIVERS.isEmpty())
			{
				write_manifest_header(pw, "Driver Modules"); //tree_DRIVERS = new TreeMap<String, >();
				if(this.tree_DRIVERS != null)
				{
					for(Node_Driver node : this.tree_DRIVERS.values())
					{
						if(node == null)
							continue;
						
						node.write_manifest(pw, "driver_module");
						pw.println(Driver.END_OF_ENTRY_MAJOR);
					}
				}
			}
			
			//////////////////////////////////////////////////////////
			//
			// Driver IRP Hook Modules
			//
			////////////////////////////////////////////////////////
//			write_manifest_header(pw, "Driver IRP Hook Modules"); 
//			if(this.tree_DRIVER_IRP_HOOK != null)
//			{
//				for(Node_Driver node : this.tree_DRIVER_IRP_HOOK.values())
//				{
//					node.write_manifest(pw, "driver_irp_hook");
//					pw.println(Driver.END_OF_ENTRY_MAJOR);
//				}
//			}

		
					
			//////////////////////////////////////////////////////////
			//
			// Callbacks
			//
			////////////////////////////////////////////////////////
//			write_manifest_header(pw, "Callbacks"); 
//			if(this.tree_CALLBACKS != null)
//			{
//				for(Node_Driver node : this.tree_CALLBACKS.values())
//				{
//					node.write_manifest(pw, "callback");
//					pw.println(Driver.END_OF_ENTRY_MAJOR);
//				}
//			}
					
			
			//////////////////////////////////////////////////////////
			//
			// Temp Environment Vars
			//
			////////////////////////////////////////////////////////
//			write_manifest_header(pw, "Temp Environment Variables"); //tree_ENVIRONMENT_TEMP = new TreeMap<String, Node_Envar>();
//			if(this.tree_PROCESS != null)
//			{
//				for(Node_Process process : this.tree_PROCESS.values())
//				{
//					process.write_manifest(pw);
//				}
//			}
			
			//////////////////////////////////////////////////////////
			//
			// tree_session_entries
			//
			////////////////////////////////////////////////////////
			if(tree_session_entries != null && tree_session_entries.size() > 0)
			{
				write_manifest_header(pw, "Sessions");		//tree_session_entries = new TreeMap<String, LinkedList<String>>();

				boolean i_have_printed_first_entry = false;
				String header = "sessions";
				
				for(String key : tree_session_entries.keySet())
				{
					try
					{
						LinkedList<String> list = tree_session_entries.get(key);
						
						//print new major heading if this is not the first entry
						if(i_have_printed_first_entry)
							pw.println(Driver.END_OF_ENTRY_MAJOR);
						else
							i_have_printed_first_entry = true;
						
						driver.write_manifest_entry(pw, header, "session_container", key);
						
						//output details
						for(String entry : list)
							driver.write_manifest_entry(pw, header, "session_entry", entry);
							
					}
					catch(Exception e)
					{
						driver.directive("Exception handled in in " + myClassName + " on tree_session_entries key [" + key + "]");
						continue;
					}

				}				
			}
			
			
			
			//////////////////////////////////////////////////////////
			//
			// tree_DESKSCAN
			//
			////////////////////////////////////////////////////////
			if(this.tree_DESKSCAN != null && tree_DESKSCAN.size() > 0)
			{
				String header = "deskscan";
				
				write_manifest_header(pw, "DeskScan");		
							
				for(Node_Generic desktop : tree_DESKSCAN.values())
				{
					if(desktop == null)
						continue;
					
					desktop.write_manifest(pw, header, delimiter, false, false, false);
					
					//print processes
					if(desktop.tree_process != null && !desktop.tree_process.isEmpty() && desktop.desktop_offset != null)
					{						
						for(Node_Process process : desktop.tree_process.values())
						{
							if(process == null)
								continue;
							
							driver.write_manifest_entry(pw, header, "process", process.get_deskscan_manifest_thread_list(desktop.desktop_offset));
						}												
					}					
					pw.println(Driver.END_OF_ENTRY_MAJOR);
				}				
			}
			
			
			//////////////////////////////////////////////////////////
			//
			// tree_REGISTRY_KEY_USER_ASSIST
			//
			////////////////////////////////////////////////////////
			if(tree_REGISTRY_HIVE_USER_ASSIST != null && !tree_REGISTRY_HIVE_USER_ASSIST.isEmpty())
			{
				write_manifest_header(pw, "User Assist");
				
				String header = "user_assist";
				
				for(Node_Registry_Hive node : this.tree_REGISTRY_HIVE_USER_ASSIST.values())
				{
					if(node == null)
						continue;
					
					node.write_manifest(pw, header, delimiter);
					pw.println(Driver.END_OF_ENTRY_MAJOR);
				}
			}

			
			//////////////////////////////////////////////////////////
			//
			// tree_REGISTRY_KEY_PRINTKEY
			//
			////////////////////////////////////////////////////////
			if(tree_REGISTRY_HIVE_PRINTKEY != null && !tree_REGISTRY_HIVE_PRINTKEY.isEmpty())
			{
				write_manifest_header(pw, "Print Key");
				
				String header = "print_key";
				
				for(Node_Registry_Hive node : this.tree_REGISTRY_HIVE_PRINTKEY.values())
				{
					if(node == null)
						continue;
					
					node.write_manifest(pw, header, delimiter);
					pw.println(Driver.END_OF_ENTRY_MAJOR);
				}
			}
			
			
			
			//////////////////////////////////////////////////////////
			//
			// tree_hashdump
			//
			////////////////////////////////////////////////////////
			if(this.tree_hashdump != null && this.tree_hashdump.size() > 0)
			{
				write_manifest_header(pw, "HashDump"); // = new TreeMap<String, String>();
				
				for(String hash : tree_hashdump.keySet())
				{
					driver.write_manifest_entry(pw, "hashdump", hash);
				}
			}
			

			
			//////////////////////////////////////////////////////////
			//
			// tree_hivelist
			//
			////////////////////////////////////////////////////////
			if(tree_hivelist != null && !tree_hivelist.isEmpty())
			{
				write_manifest_header(pw, "HiveList");
				
				String header = "hivelist";
				
				for(Node_hivelist node : tree_hivelist.values())
				{
					if(node == null)
						continue;
					
					node.write_manifest(pw, header, delimiter);
				}
			}
			 //tree_hivelist = new TreeMap<String, Node_hivelist>();

			
			//////////////////////////////////////////////////////////
			//
			// tree_get_service_sids
			//
			////////////////////////////////////////////////////////
			if(tree_get_service_sids != null && !tree_get_service_sids.isEmpty())
			{
				write_manifest_header(pw, "Service SIDS");
				
				String header = "getservicesid";
				
				for(Node_get_service_sid node : tree_get_service_sids.values())
				{
					if(node == null)
						continue;
					
					node.write_manifest(pw, header, delimiter);
				}
			}

			
			//////////////////////////////////////////////////////////
			//
			// tree_SIDS
			//
			////////////////////////////////////////////////////////
			if(tree_SIDS != null && !tree_SIDS.isEmpty())
			{
				write_manifest_header(pw, "SIDS");
				
				String owner_name = null;
				
				String header = "getsids";
				
				for(String sid : tree_SIDS.keySet())
				{
					try
					{
						if(sid == null || sid.trim().equals(""))
							continue;
						
						owner_name = tree_SIDS.get(sid);
						
						driver.write_manifest_entry(pw, header, "sid:\t " + sid + delimiter + "owner_name:\t " + owner_name);						
					}
					catch(Exception e)
					{
						driver.directive("Exception handled in " + this.myClassName + " attempting to extract SID/Ower_name tuple on SID: " + sid);
						continue;
					}																		
				}
			}
			 

			
			//////////////////////////////////////////////////////////
			//
			// tree_audit_policies
			//
			////////////////////////////////////////////////////////		
			if(this.tree_AUDIT_POLICY != null && !tree_AUDIT_POLICY.isEmpty())
			{
				write_manifest_header(pw, "Audit Policy");
				
				String header = "auditpol";
												
				boolean include_underline = (tree_AUDIT_POLICY.size() > 1);
				
				for(Node_Generic node : tree_AUDIT_POLICY.values())
				{
					if(node == null)
						continue;

					node.write_manifest(pw, header, delimiter, include_underline, false, false);			
							
				}																																	
			}

			
			
			//////////////////////////////////////////////////////////
			//
			// shutdown time
			//
			////////////////////////////////////////////////////////		
			if(this.node_shutdown_time != null && !node_shutdown_time.list_details.isEmpty())
			{
				write_manifest_header(pw, "Shutdown Time");

				String header = "shutdown_time";

				boolean include_underline = false;

				node_shutdown_time.write_manifest(pw, header, delimiter, include_underline, false, false);																																
			}

			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			try	{	pw.close();} catch(Exception e){}
			
			try	{	fle_manifest_path = fle_manifest_EXPORT.getCanonicalPath();} catch(Exception e){}
			
			Start.intface.sop("\nDone! If successful, manifest file has been written to " + fle_manifest_path);
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_manifest", e);
		}
		
		
		try	{	pw.close();} catch(Exception e){}
		Start.intface.sop("\n* * * Complete! If successful, manifest file has been written to " + fle_manifest_path);
		return false;
	}
	
	
	
	public boolean write_manifest_investigation_particulars(PrintWriter pw, String header)
	{
		try
		{						
			driver.write_manifest_entry(pw, header, "investigator_name", investigator_name);
			driver.write_manifest_entry(pw, header, "investigation_description", investigation_description);
			driver.write_manifest_entry(pw, header, "execution_time_stamp", EXECUTION_TIME_STAMP);
			driver.write_manifest_entry(pw, header, "profile", PROFILE);
			driver.write_manifest_entry(pw, header, "profile_lower ", profile_lower );
			driver.write_manifest_entry(pw, header, "relative_path_to_file_analysis_directory", relative_path_to_file_analysis_directory);
			
			driver.write_manifest_entry(pw, header, "analysis_framework", driver.NAME_LOWERCASE + "\t " + driver.VERSION);
			
			/*if(analysis_framework_export_name != null && analysis_framework_export_name.trim().length() > 0)
			{
				driver.write_manifest_entry(pw, header, "analysis_framework_export_named", analysis_framework_export_name + "\t " + analysis_framework_export_version);
			}*/
			
			if(file_attr_volatility != null)
				file_attr_volatility.write_manifest_investigation_particulars(pw, header, "analysis_kit", "\t ");
			
			if(file_attr_memory_image != null)
				file_attr_memory_image.write_manifest_investigation_particulars(pw, header, "analysis_image", "\t ");
			
			driver.write_manifest_entry(pw, header, "memory_image_system_drive", system_drive);
			driver.write_manifest_entry(pw, header, "memory_image_system_root", system_root);
			driver.write_manifest_entry(pw, header, "memory_image_computer_name", computer_name);
			driver.write_manifest_entry(pw, header, "memory_image_processor_identifier", PROCESSOR_IDENTIFIER);
			driver.write_manifest_entry(pw, header, "memory_image_processor_architecture", PROCESSOR_ARCHITECTURE);
			
			
			
			//Node_Generic node_shutdown_time
			//Node_Generic node_audit_policy
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_manifest_investigation_particulars", e);
		}
		
		return false;
	}
	
			
	/**
	 * continuation mtd. assumes line and lower are valid
	 * @param line
	 * @param lower
	 * @param mtd_designator
	 * @return
	 */
	public boolean process_import_manifest_malfind(String line, String lower, String mtd_designator, Long line_num, BufferedReader br, int designator_len, boolean multi_lines_used_to_describe_single_node)
	{
		try
		{
			if(line == null || line.trim().equals("") || lower == null || lower.trim().equals(""))
				return false;
			
			if(!lower.startsWith(mtd_designator))
			{
				driver.directive("Unknown import at line [" + line_num + "] --> " + line);
				return false;
			}
			
			//
			//remove designator header
			//
			String line_entry = line.substring(designator_len).trim();
			
			//
			//split by "\t"
			//
			String [] arr = null;

			try
			{
				arr = line_entry.split("\t");
			}
			catch(Exception ee)
			{
				arr = null;
			}
			
			//
			//validate
			//
			if(arr == null || arr.length < 2)
			{
				driver.directive("I was unable to parse manifest line [" + line_num + "] --> " + line);
				return false;
			}
			
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			//process entry where EACH LINE DESCRIBES A DIFFERENT, INDIVIDUAL TOKEN ABOUT THE SAME NODE e.g. process node, dll node, and thread node descriptions
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			if(multi_lines_used_to_describe_single_node) 
			{
				String key = arr[0].toLowerCase().trim();
				String value = arr[1].trim();
				
				String PID_value = "";
				String process_name = "";
				String address = "";
				String vad_tag = "";
				String protection = "";
				String flags = "";
				String mz_present = "";
				String trampoline_initial_JMP_detected = "";
				
				//
				//value_to_check
				//
				if(key.startsWith("PID") || key.startsWith("pid"))//determine if time to instantiate new VAD node
				{						
					
					
					//new node - parse entries
					for(int i = 0; i < arr.length; i+=2)
					{
						try
						{
							key = arr[i].toLowerCase().trim();
							value = arr[i+1].trim();
							//driver.sp("\n" + key + " --> " + value +"\n\t");
							if(key.startsWith("pid")) 	PID_value = value;
							else if(key.startsWith("process_name")) 	process_name = value;
							else if(key.startsWith("address")) 	address = value;
							else if(key.startsWith("vad_tag")) 	vad_tag = value;
							else if(key.startsWith("protection")) 	protection = value;
							else if(key.startsWith("flags")) 	flags = value;
							else if(key.startsWith("mz_present")) 	mz_present = value;
							else if(key.startsWith("trampoline_initial_jmp_detected")) 	trampoline_initial_JMP_detected = value;
							
							else
							{
								this.error_import_manifest(mtd_designator, key, line_num, line_entry);
							}
							
						}
						catch(Exception e)
						{
							driver.directive("error in parsing malfind line --> " + line_entry);
						}
					}//end for
					
					//analyze initial import
					
					node_process_malfind_import_manifest = this.tree_PROCESS.get(Integer.parseInt(PID_value));
					
					if(node_process_malfind_import_manifest == null)
					{
						this.error_import_manifest(mtd_designator, key + "( I could not determine PID)", line_num, line_entry);
					}
					else
					{									
						//create malfind node						
						this.node_malfind_import_manifest = new Node_Malfind(process_name, PID_value, node_process_malfind_import_manifest, address);
							
						//populate node
						node_malfind_import_manifest.address = address;
						node_malfind_import_manifest.flags = flags;
						
						if(mz_present != null && mz_present.startsWith("true"))
							node_malfind_import_manifest.MZ_present = true;
						node_malfind_import_manifest.pid = PID_value;
						node_malfind_import_manifest.process = node_process_malfind_import_manifest;
						node_malfind_import_manifest.process_name = process_name;
						node_malfind_import_manifest.protection = protection;
						if(trampoline_initial_JMP_detected != null && trampoline_initial_JMP_detected.startsWith("true"))
						node_malfind_import_manifest.Trampoline_initial_JMP_Detected = true;
						node_malfind_import_manifest.vad_tag = vad_tag;												
						
						//link
						if(node_process_malfind_import_manifest.tree_malfind == null)
							node_process_malfind_import_manifest.tree_malfind = new TreeMap<String, Node_Malfind>();
						
						//link to process	
						node_process_malfind_import_manifest.tree_malfind.put(address,  node_malfind_import_manifest);

						//link by dump file name as well - not the most elegant... but it'll work
						//process.tree_malfind.put(original_dump_file_name,  malfind);

						//link to director
						tree_MALFIND.put(node_process_malfind_import_manifest.PID, node_process_malfind_import_manifest);
					
					
					}
					
				}	
				else if(node_process_malfind_import_manifest == null)
				{
					//reject further processing if we failed to locate the process
					return false;
				}

				else if(key.startsWith("fle"))	node_malfind_import_manifest.fle_name_descriptor = value;
				
				else if(key.startsWith("file_attr"))
				{
					if(node_malfind_import_manifest.fle_attributes == null)
						node_malfind_import_manifest.fle_attributes = new FileAttributeData(node_process_malfind_import_manifest);										

					//trim to key pair
					String key_pair = line_entry.substring(line_entry.indexOf("find_attr") + "find_attr".length()+1).trim();
					
					String []array = key_pair.split("\t");
					
					//set new key value pair
					key = array[0];
					value = array[1];
					
					node_malfind_import_manifest.fle_attributes.import_manifest_entry(key, value, line_entry);
				}
								
				else if(key.startsWith("list_details"))
				{
					try
					{
						if(node_malfind_import_manifest.list_details == null)
							node_malfind_import_manifest.list_details = new LinkedList<String>();
						
						
						try
						{
							node_malfind_import_manifest.list_details.add(line_entry.substring(line_entry.indexOf("list_details:") + "list_details:".length()+1).trim());
						}
						catch(Exception e)
						{
							node_malfind_import_manifest.list_details.add(line_entry.substring(line_entry.indexOf("list_details") + "list_details".length()+1).trim());
						}
					}
					
					
					catch(Exception e)
					{
						driver.directive("\n * encountered issue parsing malfind entry in " + this.myClassName);
					}
					
				}
												
			}//end if
			
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			// process entry where ENTIRE DESCRIPTION IS ON SINGLE LINE i.e., each new line describes a complete node e.g. handle node, privilege node, impscan
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			else
			{
				driver.directive("invalid directive received in process_import_manifest_malfind mtd in class: " + this.myClassName );
				
			}//end else
			
			
			
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_import_manifest_" + mtd_designator);
		}
		
		return false;
	}
	
	
	
	public boolean error_import_manifest(String mtd_designator, String key, long line_num, String line)
	{
		try
		{
			list_import_manifest_file_error_message.add("Unknown manifest " + mtd_designator.toUpperCase() + " directive key [" + key + "] at line [" + line_num + "] -->" + line);
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "error_import_manifest", e);
		}
		
		return false;
	}
	
	
	/**
	 * adaptation of mtd in Analysis_Plugin_user_assist
	 * @return
	 */
	public boolean analyze_user_assist()
	{
		try
		{
			if(tree_user_assist_linked_by_time_focused == null || tree_user_assist_linked_by_time_focused.isEmpty())
				return false;
			
			boolean status = false;
			
			if(Advanced_Analysis_Director.jtaUserAssistConsole == null)
			{
				
				
				Advanced_Analysis_Director.jtaUserAssistConsole = new JTextArea_Solomon("", true, "User Assist Entries - TSV", false);				
				Start.intface.populate_export_btn(Advanced_Analysis_Director.jtaUserAssistConsole);
				Start.intface.jtabbedpane_AdvancedAnalysis.addTab("User Assist Entries", Advanced_Analysis_Director.jtaUserAssistConsole);	
				
				try	{	Start.intface.jtabbedpane_AdvancedAnalysis.setToolTipTextAt(1, "<html>Entries are Tab-separated values<br>You can paste these entries for instance into an Excel type spreadsheet, <br> and sort by time_focused to provide indications of programs the user spent more time using.  </html>");} catch(Exception e){}
				
			}
						
			
			Advanced_Analysis_Director.jtaUserAssistConsole.clear();
			
			String delimiter = "\t ";
			String header = " registry_hive" + delimiter + "path" + delimiter + "reg_binary" + delimiter + "time_focused" + delimiter + "last_updated" + delimiter + "count" + delimiter + "focus_count" + delimiter + "reg_data_first_line";
									
			Advanced_Analysis_Director.jtaUserAssistConsole.append(header);
			
			String registry_hive = "";
			String path = "";
			String line = "";
			
			for(LinkedList<Node_Generic> list_keys : tree_user_assist_linked_by_time_focused.values())
			{
				if(list_keys == null || list_keys.isEmpty())
					continue;
				
				for(Node_Generic key : list_keys)
				{
					if(key == null)
						continue;
					
					line = key.get_user_assist_line_for_sortable_array(delimiter);
					
					if(line == null || line.trim().equals(""))
						continue;
					
					Advanced_Analysis_Director.jtaUserAssistConsole.append(line);
					
					status = true;
				}
			}									
			
			return status;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_user_agent", e);
		}
		
		return false;
	}
	
	
	
	/**
	 * continuation mtd. assumes line and lower are valid
	 * @param line
	 * @param lower
	 * @param mtd_designator
	 * @return
	 */
	public boolean process_import_manifest_auditpol(String line, String lower, String mtd_designator, Long line_num, BufferedReader br, int designator_len, boolean multi_lines_used_to_describe_single_node)
	{
		try
		{
			if(line == null || line.trim().equals("") || lower == null || lower.trim().equals(""))
				return false;
			
			if(!lower.startsWith(mtd_designator))
			{
				driver.directive("Unknown import at line [" + line_num + "] --> " + line);
				return false;
			}
			
			//
			//remove designator header
			//
			String line_entry = line.substring(designator_len).trim();
			
			//
			//split by "\t"
			//
			String [] arr = null;

			try
			{
				arr = line_entry.split("\t");
			}
			catch(Exception ee)
			{
				arr = null;
			}
			
			//
			//validate
			//
			if(arr == null || arr.length < 2)
			{
				driver.directive("I was unable to parse manifest line [" + line_num + "] --> " + line);
				return false;
			}
			
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			//process entry where EACH LINE DESCRIBES A DIFFERENT, INDIVIDUAL TOKEN ABOUT THE SAME NODE e.g. process node, dll node, and thread node descriptions
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			if(multi_lines_used_to_describe_single_node) 
			{
				String key = arr[0].toLowerCase().trim();
				String value = arr[1].trim();
				String key_lower = key.toLowerCase().trim();
				
				//
				//value_to_check
				//
				if(key_lower.equals("plugin_name"))
				{
					node_generic_import_manifest = new Node_Generic(value);					
				}
				else if(key_lower.equals("name"))
				{
					this.tree_AUDIT_POLICY.put(value.toLowerCase().trim(), node_generic_import_manifest);
					node_generic_import_manifest.GRAPH_KEY_NAME = value;
					
					//other
					if(node_audit_policy == null)
					{
						node_audit_policy = new Node_Generic(node_generic_import_manifest.plugin_name);
						node_audit_policy.list_details = new LinkedList<String>();						
					}
				}
				
				node_generic_import_manifest.import_manifest_line_entry(line_entry, arr, key_lower, value, this);
				
				//other
				if(node_audit_policy != null && node_audit_policy.list_details != null)
				{
					if(line_entry.toLowerCase().trim().startsWith("name"))
						line_entry = driver.trim_key("name", line_entry, true);
					else if(line_entry.toLowerCase().trim().startsWith("list_details"))
						line_entry = driver.trim_key("list_details", line_entry, true);
					
					if(!line_entry.toLowerCase().trim().startsWith("plugin_name"))
						node_audit_policy.list_details.add(line_entry);
				}
				
			}//end if
			
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			// process entry where ENTIRE DESCRIPTION IS ON SINGLE LINE i.e., each new line describes a complete node e.g. handle node, privilege node, impscan
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			else
			{
				driver.directive("invalid directive received in process_import_manifest_" + mtd_designator + " mtd in class: " + this.myClassName );
				
			}//end else
			
			
			
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_import_manifest_" + mtd_designator, e);
		}
		
		return false;
	}
	
	
	
	
	/**
	 * continuation mtd. assumes line and lower are valid
	 * @param line
	 * @param lower
	 * @param mtd_designator
	 * @return
	 */
	public boolean process_import_manifest_shutdown_time(String line, String lower, String mtd_designator, Long line_num, BufferedReader br, int designator_len, boolean multi_lines_used_to_describe_single_node)
	{
		try
		{
			if(line == null || line.trim().equals("") || lower == null || lower.trim().equals(""))
				return false;
			
			if(!lower.startsWith(mtd_designator))
			{
				driver.directive("Unknown import at line [" + line_num + "] --> " + line);
				return false;
			}
			
			//
			//remove designator header
			//
			String line_entry = line.substring(designator_len).trim();
			
			//
			//split by "\t"
			//
			String [] arr = null;

			try
			{
				arr = line_entry.split("\t");
			}
			catch(Exception ee)
			{
				arr = null;
			}
			
			//
			//validate
			//
			if(arr == null || arr.length < 2)
			{
				driver.directive("I was unable to parse manifest line [" + line_num + "] --> " + line);
				return false;
			}
			
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			//process entry where EACH LINE DESCRIBES A DIFFERENT, INDIVIDUAL TOKEN ABOUT THE SAME NODE e.g. process node, dll node, and thread node descriptions
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			if(multi_lines_used_to_describe_single_node) 
			{
				String key = arr[0].toLowerCase().trim();
				String value = arr[1].trim();
				String key_lower = key.toLowerCase().trim();
				
				//
				//value_to_check
				//
				if(key_lower.equals("plugin_name"))
				{
					node_shutdown_time = new Node_Generic(value);
					node_shutdown_time.GRAPH_KEY_NAME = value;
					node_shutdown_time.list_details = new LinkedList<String>();						
				}
								
				//other
				if(node_shutdown_time != null && node_shutdown_time.list_details != null)
				{
					if(line_entry.toLowerCase().trim().startsWith("list_details"))
						line_entry = driver.trim_key("list_details", line_entry, true);
					
					if(!line_entry.toLowerCase().trim().startsWith("plugin_name"))
						node_shutdown_time.list_details.add(line_entry);
				}
				
			}//end if
			
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			// process entry where ENTIRE DESCRIPTION IS ON SINGLE LINE i.e., each new line describes a complete node e.g. handle node, privilege node, impscan
			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			else
			{
				driver.directive("invalid directive received in process_import_manifest_" + mtd_designator + " mtd in class: " + this.myClassName );
				
			}//end else
			
			
			
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_import_manifest_" + mtd_designator, e);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	//converting to 20 node
		/**
		 * 			if(tree_threads.size() > MAX_TREE_NODE_COUNT)
				{
					int count = 0;				
					pw.println("\t\t\t" +  "{ \"name\": \"" + driver.normalize_html("[" + count + "]").replace("\\", "\\\\") + "\" , \"children\": [");
					
					for(Node_Threads node : tree_threads.values())
					{															
						if(count % MAX_TREE_NODE_COUNT == 0 && count > 0)
						{
							pw.println("\t\t\t" +  "]},");
							
							pw.println("\t\t\t" +  "{ \"name\": \"" + driver.normalize_html("[" + count + "]").replace("\\", "\\\\") + "\" , \"children\": [");
						}
						
						++count;
						
						node.write_node_information(pw);
						
						
					}
					
					pw.println("\t\t\t" +  "]},");								
				}
		 * 
		 */
			

}
