/**
 * Extension of Interface - activated each time user has token to search
 * @author Solomon Sonya
 */

package Driver;

import java.io.*;
import java.util.*;

import javax.swing.JCheckBox;

import Advanced_Analysis.*;
import Advanced_Analysis.Analysis_Plugin.*;
import Interface.*;
import Plugin.Process_Plugin;

public class File_XREF extends Thread implements Runnable 
{
	public static final String myClassName = "File_XREF";
	public volatile static Driver driver = new Driver();

	public volatile Interface intrface = null;
	
	public static final boolean use_updated_import_routine = true; 
	
	public volatile static TreeMap<String, Node_Generic> tree_dump_file_entries_FILEDUMP_XREF = new TreeMap<String, Node_Generic>();
	public static volatile TreeMap<String, File> tree_container_files_with_search_hits_for_JTEXTAREA = new TreeMap<String, File>();
	public static volatile TreeMap<String, Node_Generic> tree_container_files_with_search_hits_for_Container_JTAB = new TreeMap<String, Node_Generic>();
	
	public boolean memory_image_is_WINDOWS = false;
	
	public static final int index_dump_files_store_action_FILESCAN = 0;
	public static final int index_dump_files_store_action_MFTPARSER = 1;
	public static final int index_dump_files_store_action_USERASSIST = 2;
	public static final int index_dump_files_store_action_DLLLIST = 3;
	
	public volatile Analysis_Plugin_YaraScan plugin_yarascan = null; 
	
	public static volatile JTextArea_Solomon jta = Start.intface.jpnlConsole;
	
	public File_XREF(Interface INTERFACE)
	{
		try
		{
			intrface = INTERFACE;
			start();
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e, true);
		}
	}
	
	public void run()
	{
		try
		{
			commence_action();
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "run", e);
		}
	}
	
	public boolean commence_action()
	{
		try
		{
			process_search_File_XREF();
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "commence_action", e);
		}
		
		return false;
	}
	
	
	public boolean process_search_File_XREF()
	{
		try
		{
			boolean disable_impscan = true;
			
			this.memory_image_is_WINDOWS = intrface.is_memory_image_WINDOWS();
			

			
			intrface.AUTOMATE_XREF_SEARCH = false;
			intrface.configure_processlist_for_xref = false;
			intrface.execute_xref_search_plugins_if_import_files_are_missing = false;
			String XREF_SEARCH_STRING = "";
			String XREF_SEARCH_STRING_LOWER = "";
			
			try	{	intrface.XREF_SEARCH_STRING = intrface.jtfFile_XREF_SearchString.getText().trim();	}	catch(Exception e)	{ intrface.XREF_SEARCH_STRING = "";	}
			
			XREF_SEARCH_STRING = intrface.XREF_SEARCH_STRING; 
			
			if(XREF_SEARCH_STRING.equals(""))
			{
				try	{	intrface.jtfFile_XREF_SearchString.setEditable(true);} catch(Exception e){}
				intrface.jtfFile_XREF_SearchString.validate();
				return false;
			}
			
			if(XREF_SEARCH_STRING.equals("*") || XREF_SEARCH_STRING.equals("**"))
			{
				driver.jop("Note, you need to specify additional characters for this xref search...");
				try	{	intrface.jtfFile_XREF_SearchString.setText("");} 		catch(Exception e){}
				try	{	intrface.jtfFile_XREF_SearchString.setEditable(true);} 	catch(Exception e){}
				
				return false;
			}
			
			//
			//process search string
			//
						
			//check contains - which is the default search option
			if(XREF_SEARCH_STRING.startsWith("*") && XREF_SEARCH_STRING.endsWith("*"))
			{
				XREF_SEARCH_STRING = XREF_SEARCH_STRING.substring(1, XREF_SEARCH_STRING.length()-1).trim();
			}
			
			else if(XREF_SEARCH_STRING.startsWith("\"") && XREF_SEARCH_STRING.endsWith("\""))
			{
				XREF_SEARCH_STRING = XREF_SEARCH_STRING.substring(1, XREF_SEARCH_STRING.length()-1).trim();
			}
			
			else if(XREF_SEARCH_STRING.startsWith("*"))
			{
				XREF_SEARCH_STRING = XREF_SEARCH_STRING.substring(1).trim();					
			}
			else if(XREF_SEARCH_STRING.endsWith("*"))
			{
				XREF_SEARCH_STRING = XREF_SEARCH_STRING.substring(0, XREF_SEARCH_STRING.length()-1).trim();					
			}
				
			if(XREF_SEARCH_STRING.equals(""))
			{
				driver.jop("* * * Note, you need to specify additional characters for this xref search...");
				try	{	intrface.jtfFile_XREF_SearchString.setText("");} 		catch(Exception e){}
				try	{	intrface.jtfFile_XREF_SearchString.setEditable(true);} 	catch(Exception e){}
				
				return false;
			}
					
			XREF_SEARCH_STRING_LOWER = XREF_SEARCH_STRING.toLowerCase().trim();
			
			//
			//continue
			//
			
			if(intrface.path_fle_analysis_directory == null || intrface.path_fle_analysis_directory.trim().equals("") || intrface.advanced_analysis_director == null)
			{
				//check if we are configured to execute volatility
				if(!intrface.ensure_volatility_and_memory_image_are_configured())
				{
					try	{	intrface.jtfFile_XREF_SearchString.setEditable(true);} catch(Exception e){}
					intrface.jtfFile_XREF_SearchString.validate();
					intrface.jfrm.validate();
					
					intrface.sop("\nPunt! I am not configured to execute volatility and it does not appear you have executed Advanced Analysis.\nIf necessary, either configure volatility and an image for me to analyze, initiate Advanced Analysis, or Specify Output Folder for me to analyze...");
					return false;
				}
			}
			
			if(intrface.PROFILE == null)
				intrface.PROFILE = "";
			
			//
			//Determine workflow...
			//
			
			File fle_working_directory = null;
			if(intrface.path_fle_analysis_directory != null && intrface.path_fle_analysis_directory.trim().length() > 1)
				fle_working_directory = new File(intrface.path_fle_analysis_directory);
			
			
			if(intrface.advanced_analysis_director == null) //and working directory path was not specified previously
			{
				Object [] buttons = new Object[]{"Initiate Advanced Analysis", "Import analysis working directory", "Proceed here and configure for XREF searching...", "Cancel"};
				
				int selection = driver.jop_custom_buttons("Advanced Analysis was not executed in intrface program instantiation. \nPlease select from one of the following options:\n\n"
						+ "1) Initiate Advanced Analysis and return to XREF search after analysis is complete\n"
						+ "2) Import analysis working directory for XREF search (NOTE: intrface will only search within the specified working directory - no new plugins will be executed if a needed file within import directory is missing)\n"
						+ "3) Proceed here to enable execution of specific analysis plugins required for XREF search (NOTE: intrface may take a while to configure the system for the first time. Subsequent searching should be quicker.)\n"
						+ "4) Cancel"
						+ "\n\nPlease specify how to continue...\n", "Configure XREF Workflow...", buttons);
				
				
				if(selection == 0)
				{
					intrface.sop("I am executing Advanced Analysis.  Return to XREF search at the completion of Advanced Analysis. Please standby...");
					
					intrface.XREF_SEARCH_STRING = intrface.jtfFile_XREF_SearchString.getText().trim();
					
					try	{	intrface.jtabbedPane_MAIN.setSelectedIndex(1);	}	catch(Exception e){}
					
					//initiate advanced analysis
					intrface.advanced_analysis_director = new Advanced_Analysis_Director(intrface.fle_volatility, intrface.fle_memory_image, intrface.PROFILE, intrface.path_fle_analysis_directory, intrface.file_attr_volatility, intrface.file_attr_memory_image, intrface.investigator_name, intrface.investigation_description, true);
					intrface.AUTOMATE_XREF_SEARCH = true;
					
					return true;
				}
				else if(selection == 1) //specify import directory
				{										
					
					if(use_updated_import_routine)
					{
						intrface.import_advanced_analysis_directory(this);
						return true;
					}
					else //do not configure and rebuild trees, only search given directory of output files
					{
						//invoke import directory
						fle_working_directory = intrface.specify_investigation_output_directory(1);
						
						if(fle_working_directory == null)//user declined, exit
						{
							try	{	intrface.jtfFile_XREF_SearchString.setEditable(true);} catch(Exception e){}
							return false;
						}
						
						//configure advanced analysis in case it is needed (since it was null previously)
						intrface.advanced_analysis_director = new Advanced_Analysis_Director(intrface.fle_volatility, intrface.fle_memory_image, intrface.PROFILE, intrface.path_fle_analysis_directory, intrface.file_attr_volatility, intrface.file_attr_memory_image, intrface.investigator_name, intrface.investigation_description, false);						
					}					
					
				}
				
				else if(selection == 2) //proceed here and execute respective plugins to enable XREF search
				{
					//configure advanced analysis in prep to execute respective searching
					intrface.advanced_analysis_director = new Advanced_Analysis_Director(intrface.fle_volatility, intrface.fle_memory_image, intrface.PROFILE, intrface.path_fle_analysis_directory, intrface.file_attr_volatility, intrface.file_attr_memory_image, intrface.investigator_name, intrface.investigation_description, false);
					
					intrface.execute_xref_search_plugins_if_import_files_are_missing = true;
					
					if(disable_impscan)
						intrface.advanced_analysis_director.PROCESS_IMPSCAN = false;
					
					//set focus
					try	{ intrface.jtabbedPane_MAIN.setSelectedIndex(1);} catch(Exception e){}
					
					//create processlist
					intrface.advanced_analysis_director.process_list(true, false);
				}
				else
				{
					//action was canceled
					try	{	intrface.jtfFile_XREF_SearchString.setEditable(true);} catch(Exception e){}
					intrface.jfrm.validate();
					
					return true;
				}
			}
			

			//check if advanced analysis was started, and is still running
			if(intrface.advanced_analysis_director != null && intrface.advanced_analysis_director.AUTOMATED_ANALYSIS_STARTED && !intrface.advanced_analysis_director.AUTOMATED_ANALYSIS_COMPLETE)
			{
				driver.jop("Punt! It looks like Advanced Analysis is still running. \nPlease wait to execute intrface process after Advanced Analysis has completed.");
				try	{	intrface.jtfFile_XREF_SearchString.setEditable(true);} catch(Exception e){}
				return false;
			}
						
			
			//intrface is an extension of Advanced Analysis, thus, procure the files to search
			File dumpfiles = null;
			File filescan = null;
			File handles = null;
			File timeliner = null;
			File mftparser = null;
			File userassist = null;
			File shellbags = null;
			File shimcache = null;
			File svcscan = null;
			File joblink = null;
			File vadinfo = null;
			File verinfo = null;
			File modules = null;
			File moddump = null;
			File modscan = null;
			File drivermodule = null;
			File driverscan = null;
			File dlllist = null;
			File procdump = null;
			
			//above is core
			
			File apihooks = null;
			File file_imports_dependencies = null;
			File dumpfiles_evtx = null;
			File callbacks = null;
			File cmdline = null;
			File cmdscan = null;
			File consoles = null;
			File deskscan = null;
			File dlldump = null;
			File driverirp = null;
			File envars = null;
			File gditimers = null;
			File getservicesids = null;
			File getsids = null;
			File hashdump = null;
			File hivelist = null;
			File hivescan = null;
			File kdbgscan = null;
			File ldrmodules = null;
			File lsadump = null;
			File malfind = null;
			File messagehooks = null;
			File netscan = null;
			File notepad = null;
			File printkey = null;
			File privs = null;
			File pslist = null;
			File psscan = null;
			File pstree = null;
			File services = null;
			File file_attributes = null;
			File sessions = null;
			File shutdowntime = null;
			File ssdt = null;
			File symlinkscan = null;
			File thrdscan = null;
			File threads = null;
			File timers = null;
			File unloadedmodules = null;
			File userhandles = null;
			File vadtree = null;
			File vadwalk = null;
			File windows = null;
			File wintree = null;
			File wndscan = null;
			File file_imports_dependeicies = null;
			

			
			//
			//Take inventory of files present in working directory
			//
			
			//Search directory for expected files
			LinkedList<File> list_files = new LinkedList<File>();
			list_files = driver.getFileListing(new File(intrface.path_fle_analysis_directory), true, null, list_files);
			
			LinkedList<File> list_impscan = new LinkedList<File>();
			LinkedList<File> list_dependency_import_files = new LinkedList<File>();
			LinkedList<File> list_whois = new LinkedList<File>();
			
			if(list_files != null && list_files.size() > 0)
			{
				String fle_name = null;
				for(File fle : list_files)
				{
					if(fle == null || !fle.exists() || !fle.isFile())
						continue;
														
					fle_name = fle.getName().toLowerCase().trim();
					
					if(!fle_name.endsWith(".txt"))
						continue;
						
					//remove _ if present
					if(fle_name.startsWith("_"))
						fle_name = fle_name.substring(1).trim();					
					
					//iterate through for files that we would like
					
					if(fle_name.startsWith("dumpfiles"))		dumpfiles = fle;
					else if(fle_name.startsWith("filescan"))	filescan = fle;
					else if(fle_name.startsWith("handles"))		handles = fle;
					else if(fle_name.startsWith("timeliner"))	timeliner = fle;
					else if(fle_name.startsWith("mftparser"))	mftparser = fle;
					else if(fle_name.startsWith("userassist"))	userassist = fle;
					else if(fle_name.startsWith("shellbags"))	shellbags = fle;
					else if(fle_name.startsWith("shimcache"))	shimcache = fle;
					else if(fle_name.startsWith("svcscan"))		svcscan = fle;
					else if(fle_name.startsWith("joblink"))		joblink = fle;
					else if(fle_name.startsWith("vadinfo"))	 	vadinfo= fle;
					else if(fle_name.startsWith("verinfo"))		verinfo = fle;
					else if(fle_name.startsWith("modules"))	 	modules = fle;
					else if(fle_name.startsWith("moddump"))	 	moddump = fle;
					else if(fle_name.startsWith("modscan"))	 	modscan = fle;
					else if(fle_name.startsWith("drivermodule"))drivermodule	 = fle;
					else if(fle_name.startsWith("driverscan"))	 driverscan= fle;
					else if(fle_name.startsWith("dlllist"))	 	dlllist = fle;
					else if(fle_name.startsWith("procdump"))	 	procdump = fle;
					
					
					
					else if(fle_name.startsWith("file_imports"))	 	file_imports_dependencies = fle;
					else if(fle_name.startsWith("apihooks"))		apihooks = fle;
					else if(fle_name.startsWith("dumpfiles --regex"))	 	dumpfiles_evtx = fle;
					else if(fle_name.startsWith("callbacks"))	 	callbacks = fle;
					else if(fle_name.startsWith("cmdline"))	 	cmdline = fle;
					else if(fle_name.startsWith("cmdscan"))	 	cmdscan = fle;
					else if(fle_name.startsWith("consoles"))	 	consoles = fle;
					else if(fle_name.startsWith("deskscan"))	 	deskscan = fle;
					else if(fle_name.startsWith("dlldump"))	 	dlldump = fle;
					else if(fle_name.startsWith("driverirp"))	 	driverirp = fle;
					else if(fle_name.startsWith("envars"))	 	envars = fle;
					else if(fle_name.startsWith("gditimers"))	 	gditimers = fle;
					else if(fle_name.startsWith("getservicesids"))	 	getservicesids = fle;
					else if(fle_name.startsWith("getsids"))	 	getsids = fle;
					else if(fle_name.startsWith("hashdump"))	 	hashdump = fle;
					else if(fle_name.startsWith("hivelist"))	 	hivelist = fle;
					else if(fle_name.startsWith("hivescan"))	 	hivescan = fle;
					else if(fle_name.startsWith("kdbgscan"))	 	kdbgscan = fle;
					else if(fle_name.startsWith("kdbgscan"))	 	kdbgscan = fle;
					else if(fle_name.startsWith("ldrmodules"))	 	ldrmodules = fle;
					else if(fle_name.startsWith("lsadump"))	 	lsadump = fle;
					else if(fle_name.startsWith("malfind"))	 	malfind = fle;
					else if(fle_name.startsWith("messagehooks"))	 	messagehooks = fle;
					else if(fle_name.startsWith("netscan"))	 	netscan = fle;
					else if(fle_name.startsWith("notepad"))	 	notepad = fle;
					else if(fle_name.startsWith("printkey"))	 	printkey = fle;
					else if(fle_name.startsWith("privs"))	 	privs = fle;
					else if(fle_name.startsWith("pslist"))	 	pslist = fle;
					else if(fle_name.startsWith("psscan"))	 	psscan = fle;
					else if(fle_name.startsWith("pstree"))	 	pstree = fle;
					else if(fle_name.startsWith("file_attributes"))	 file_attributes	 = fle;
					else if(fle_name.startsWith("services"))	 services	 = fle;
					else if(fle_name.startsWith("sessions"))	 	sessions = fle;
					else if(fle_name.startsWith("shutdowntime"))	 	shutdowntime = fle;
					else if(fle_name.startsWith("ssdt"))	 	ssdt = fle;
					else if(fle_name.startsWith("svcscan"))	 	svcscan = fle;
					else if(fle_name.startsWith("symlinkscan"))	 	symlinkscan = fle;
					else if(fle_name.startsWith("thrdscan"))	 	thrdscan = fle;
					else if(fle_name.startsWith("threads"))	 	threads = fle;
					else if(fle_name.startsWith("timer"))	 	timers = fle;
					else if(fle_name.startsWith("unloadedmodules"))	 	unloadedmodules = fle;
					else if(fle_name.startsWith("userhandles"))	 	userhandles = fle;
					else if(fle_name.startsWith("vadtree"))	 	vadtree = fle;
					else if(fle_name.startsWith("vadwalk"))	 	vadwalk = fle;
					else if(fle_name.startsWith("window"))	 	windows = fle;
					else if(fle_name.startsWith("winree"))	 	wintree = fle;
					else if(fle_name.startsWith("wndscan"))	 	wndscan = fle;
					else if(fle_name.startsWith("impscan_") && !list_impscan.contains(fle))	list_impscan.add(fle);
					else if(fle_name.endsWith("dependencies.txt") && !list_dependency_import_files.contains(fle))	list_impscan.add(fle);
					else if(fle_name.startsWith("whois") && !list_whois.contains(fle))	list_whois.add(fle);
					else if(fle_name.startsWith("file_imports"))	 	file_imports_dependeicies = fle;
					
					
					
					
				}//end for loop
				
//				//prepare advanced analysis if necessary
//				if(intrface.advanced_analysis_director == null)
//					advanced_analysis_director = new Advanced_Analysis_Director(fle_volatility, fle_memory_image, PROFILE, path_fle_analysis_directory, file_attr_volatility, file_attr_memory_image, investigator_name, investigation_description, false);
//				
				//			
				//execute missing plugins if enabled
				//
				if(intrface.execute_xref_search_plugins_if_import_files_are_missing)
				{
					
					
					//
					//filescan
					//
					if(!intrface.is_valid_file(filescan))
					{						
						intrface.advanced_analysis_director.plugin_filescan = new Analysis_Plugin_EXECUTION(null, intrface.advanced_analysis_director, "filescan", "Pool scanner for file objects", false, jta);
						filescan = intrface.advanced_analysis_director.plugin_filescan.fleOutput;															
					}
					
					//handles
					if(!intrface.is_valid_file(handles))
						intrface.advanced_analysis_director.plugin_handles = new Analysis_Plugin_handles(null, intrface.advanced_analysis_director, "handles", "Print list of open handles for each process", false, jta);
						
					//timeliner
					if(!intrface.is_valid_file(timeliner))
						intrface.advanced_analysis_director.plugin_timeliner = new Analysis_Plugin_EXECUTION(null, intrface.advanced_analysis_director, "timeliner", "Creates a timeline from various artifacts in memory", false, jta);
						
					//mftparser
					if(!intrface.is_valid_file(mftparser))
						intrface.advanced_analysis_director.plugin_mftparser = new Process_Plugin(null, "mftparser", "Scans for and parses potential MFT entries", null, null, intrface.advanced_analysis_director.fle_volatility.getName() + " -f " + intrface.advanced_analysis_director.fle_memory_image.getName() + " mftparser --profile=" + intrface.advanced_analysis_director.PROFILE, true, false, "", false);
						
					//userassist
					if(!intrface.is_valid_file(userassist))
						intrface.advanced_analysis_director.plugin_userassist = new Analysis_Plugin_user_assist(null, intrface.advanced_analysis_director, "userassist", "Print userassist registry keys and information", false, jta);
						
					//shellbags
					if(!intrface.is_valid_file(shellbags))
						intrface.advanced_analysis_director.plugin_shellbags = new Analysis_Plugin_EXECUTION(null, intrface.advanced_analysis_director, "shellbags", "Prints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags infoPrints ShellBags info", false, jta);
					
					//shimcache
					if(!intrface.is_valid_file(shimcache))
						intrface.advanced_analysis_director.plugin_shimcache = new Analysis_Plugin_EXECUTION(null, intrface.advanced_analysis_director, "shimcache", "Parses the Application Compatibility Shim Cache registry key", false, jta);	
						
					//svcscan
					if(!intrface.is_valid_file(svcscan))
						intrface.advanced_analysis_director.plugin_svcscan = new Analysis_Plugin_svcscan(null, intrface.advanced_analysis_director, "svcscan", "Scan for Windows services", false, jta);
						
					//joblink
					if(!intrface.is_valid_file(joblink))
						intrface.advanced_analysis_director.plugin_joblinks = new Analysis_Plugin_EXECUTION(null, intrface.advanced_analysis_director, "joblinks", "Print process job link information", false, jta);

					//vadinfo
					if(!intrface.is_valid_file(vadinfo))
						intrface.advanced_analysis_director.plugin_vadinfo = new Analysis_Plugin_VAD_INFO(null, intrface.advanced_analysis_director, "vadinfo", "Dump the VAD info", false, jta);
						
					//verinfo
					if(!intrface.is_valid_file(verinfo))
						intrface.advanced_analysis_director.plugin_verinfo = new Analysis_Plugin_verinfo(null, intrface.advanced_analysis_director, "verinfo", "Prints out the version information from PE images", false, jta);
						
										
					//moddump
					if(!intrface.is_valid_file(moddump))
						intrface.advanced_analysis_director.plugin_moddump = new Analysis_Plugin_SUPER_MODULES(null, intrface.advanced_analysis_director, "moddump", "Dump a kernel driver to an executable file sample", false, jta); //runs modules and modscan within moddump!
											
						
					//dlllist
					if(!intrface.is_valid_file(dlllist))
						intrface.advanced_analysis_director.plugin_dlllist = new Analysis_Plugin_dlllist(null, intrface.advanced_analysis_director, "dlllist", "Print list of loaded dlls for each process", false, jta);
						
					//dumpfiles evt
					if(!intrface.is_valid_file(dumpfiles))
						intrface.advanced_analysis_director.plugin_evtlogs = new Analysis_Plugin_EXECUTION(null, intrface.advanced_analysis_director, "dumpfiles --regex .evtx$ --ignore-case", "Dump Windows Event Logs ", false, jta);
				
			
					
					//
					//dumpfiles evt
					//
//					if(!intrface.is_valid_file(dumpfiles))
//					{
//						if(intrface.PROFILE.toLowerCase().contains("win") || intrface.PROFILE.toLowerCase().contains("vista"))
//						{	
//							intrface.advanced_analysis_director.plugin_evtlogs = new Analysis_Plugin_EXECUTION(null, intrface.advanced_analysis_director, "dumpfiles --regex .evtx$ --ignore-case", "Dump Windows Event Logs ", false, jta);
//							dumpfiles = intrface.advanced_analysis_director.plugin_evtlogs.fleOutput;
//						}
//					}
					
					
					
					//done executing plugins if necessary, reset focus
					try	{ intrface.jtabbedPane_MAIN.setSelectedIndex(2);} catch(Exception e){}
					
				}
				
				//
				//clear prev results...
				//
				try	{ intrface.jtaFile_XREF_Search_Results.clear();	}	catch(Exception e){}
				
				try	{ tree_container_files_with_search_hits_for_JTEXTAREA.clear(); } catch(Exception e){this.tree_container_files_with_search_hits_for_JTEXTAREA = new TreeMap<String, File>();}
				
				try	{ tree_container_files_with_search_hits_for_Container_JTAB.clear(); } catch(Exception e){this.tree_container_files_with_search_hits_for_Container_JTAB = new TreeMap<String, Node_Generic>();}
				
				long hits_found = 0;
				File fle = null;
				String plugin_name = "";
				
				//clear previous results
				try{	tree_dump_file_entries_FILEDUMP_XREF.clear();} catch(Exception e){tree_dump_file_entries_FILEDUMP_XREF = new TreeMap<String, Node_Generic>();}
				intrface.populate_dump_files_FILESCAN_XREF(this.tree_dump_file_entries_FILEDUMP_XREF);
				
				

				/////////////////////////////////////////////////////
				//
				// search through processes for presence of search string
				//
				/////////////////////////////////////////////////////
				
				//iterate through each process
				for(Node_Process process : intrface.advanced_analysis_director.tree_PROCESS.values())
				{
					try
					{
						if(process == null)
							continue;	
												
						if(process.search_XREF(XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, intrface.jtaFile_XREF_Search_Results))
						{
							//add node to mem dump
							String process_line = process.process_name + " PID " + process.PID; 
							Node_Generic node_mem_dump = new Node_Generic("XREF Search");		        				
	        				node_mem_dump.jcb = new JCheckBox("memdump - " + process_line);
	        				node_mem_dump.jcb.setToolTipText("memdump - " + process_line);
	        				node_mem_dump.pid = ""+process.PID;
	        				tree_dump_file_entries_FILEDUMP_XREF.put("memdump - " + process_line.toLowerCase().trim(), node_mem_dump);							
								
							
							//cleanup
							intrface.jtaFile_XREF_Search_Results.append("\n");
						}
						
						intrface.populate_dump_files_FILESCAN_XREF(tree_dump_file_entries_FILEDUMP_XREF);

					}
					catch(Exception e)
					{
						e.printStackTrace(System.out);
						continue;
					}										
				}
				
				
				//
				//search additional trees e.g. unlinked modules, etc
				//
				
				/////////////////////////////////////////////////////
				//
				//search through files for presence of search string
				//
				/////////////////////////////////////////////////////
				
				//
				//filescan
				//
				fle = filescan;
				plugin_name = "filescan";				
				if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, index_dump_files_store_action_FILESCAN) > 0)
					tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);	
								
				/**apihooks*/			fle = apihooks;				plugin_name = "apihooks";		if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
				
				/**handles*/  			fle = handles;				plugin_name = "handles";		if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);	
				
				/**	timeliner	*/		fle = 	timeliner	;	plugin_name = "timeliner";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
				/**	mftparser	*/		fle = 	mftparser	;	plugin_name = "mftparser";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, index_dump_files_store_action_MFTPARSER) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
				/**	userassist	*/		fle = 	userassist	;	plugin_name = "userassist";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, this.index_dump_files_store_action_USERASSIST) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
				/**	shellbags	*/		fle = 	shellbags	;	plugin_name = "shellbags";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
				/**	shimcache	*/		fle = 	shimcache	;	plugin_name = "shimcache";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
				/**	svcscan	*/			fle = 	svcscan	;	plugin_name = "svcscan";		if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
				/**	joblink	*/			fle = 	joblink	;	plugin_name = "joblink";		if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
				/**	vadinfo	*/			fle = 	vadinfo	;	plugin_name = "vadinfo";		if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
				/**	verinfo	*/			fle = 	verinfo	;	plugin_name = "verinfo";		if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
				/**	modules	*/			fle = 	modules	;	plugin_name = "modules";		if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
				/**	moddump	*/			fle = 	moddump	;	plugin_name = "moddump";		if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
				/**	modscan	*/			fle = 	modscan	;	plugin_name = "modscan";		if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
				/**	drivermodule	*/	fle = 	drivermodule	;	plugin_name = "drivermodule";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
				/**	driverscan	*/		fle = 	driverscan	;	plugin_name = "driverscan";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
				/**	dlllist	*/			fle = 	dlllist	;	plugin_name = "dlllist";		if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, index_dump_files_store_action_DLLLIST) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
				

				//above is core
				
				if(!Start.intface.jcb_RestrictSearch_to_Core_XREF_Plugins.isSelected())
				{
					
				
					/**	dumpfiles_evtx	*/	fle = 	dumpfiles_evtx	; plugin_name = "dumpfiles_evtx";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
					/**	callbacks	*/	fle = 	callbacks	; plugin_name = "callbacks";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
					/**	cmdline	*/	fle = 	cmdline	; plugin_name = "cmdline";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
					/**	cmdscan	*/	fle = 	cmdscan	; plugin_name = "cmdscan";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
					/**	consoles	*/	fle = 	consoles	; plugin_name = "consoles";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
					/**	deskscan	*/	fle = 	deskscan	; plugin_name = "deskscan";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
					/**	dlldump	*/	fle = 	dlldump	; plugin_name = "dlldump";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
					/**	driverirp	*/	fle = 	driverirp	; plugin_name = "driverirp";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
					/**	envars	*/	fle = 	envars	; plugin_name = "envars";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
					/**	gditimers	*/	fle = 	gditimers	; plugin_name = "gditimers";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
					/**	getservicesids	*/	fle = 	getservicesids	; plugin_name = "getservicesids";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
					/**	getsids	*/	fle = 	getsids	; plugin_name = "getsids";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
					/**	hashdump	*/	fle = 	hashdump	; plugin_name = "hashdump";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
					/**	hivelist	*/	fle = 	hivelist	; plugin_name = "hivelist";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
					/**	hivescan	*/	fle = 	hivescan	; plugin_name = "hivescan";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
					/**	kdbgscan	*/	fle = 	kdbgscan	; plugin_name = "kdbgscan";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
					/**	ldrmodules	*/	fle = 	ldrmodules	; plugin_name = "ldrmodules";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
					/**	lsadump	*/	fle = 	lsadump	; plugin_name = "lsadump";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
					/**	malfind	*/	fle = 	malfind	; plugin_name = "malfind";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
					/**	messagehooks	*/	fle = 	messagehooks	; plugin_name = "messagehooks";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
					/**	netscan	*/	fle = 	netscan	; plugin_name = "netscan";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
					
					
					//check import files
					if(list_whois != null && list_whois.size() > 0)
					{
						for(File import_file : list_whois)
						{
							if(import_file == null || !import_file.isFile())
								continue;
							
							plugin_name = import_file.getName();
							
							if(search_file(import_file, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
						}
					}
					
					
					/**	notepad	*/	fle = 	notepad	; plugin_name = "notepad";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
					/**	printkey	*/	fle = 	printkey	; plugin_name = "printkey";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
					/**	privs	*/	fle = 	privs	; plugin_name = "privs";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
					/**	pslist	*/	fle = 	pslist	; plugin_name = "pslist";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
					/**	psscan	*/	fle = 	psscan	; plugin_name = "psscan";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
					/**	pstree	*/	fle = 	pstree	; plugin_name = "pstree";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
					/**	procdump	*/			fle = 	procdump	;	plugin_name = "procdump";		if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
					
					//check import files
					if(list_impscan != null && list_impscan.size() > 0)
					{
						for(File import_file : list_impscan)
						{
							if(import_file == null || !import_file.isFile())
								continue;
							
							plugin_name = import_file.getName();
							
							if(search_file(import_file, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
						}
					}
					
					//check import files
					if(list_dependency_import_files != null && list_dependency_import_files.size() > 0)
					{
						for(File import_file : list_dependency_import_files)
						{
							if(import_file == null || !import_file.isFile())
								continue;
							
							plugin_name = import_file.getName();
							
							if(search_file(import_file, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
						}
					}
					
					/**	file_imports_dependeicies	*/			fle = 	file_imports_dependeicies	;	plugin_name = "dependencies";		if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
					
					/**	file_attributes	*/	fle = 	file_attributes	; plugin_name = "file_attributes";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
					
					/**	services	*/	fle = 	services	; plugin_name = "services";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
					/**	sessions	*/	fle = 	sessions	; plugin_name = "sessions";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
					/**	shutdowntime	*/	fle = 	shutdowntime	; plugin_name = "shutdowntime";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
					/**	ssdt	*/	fle = 	ssdt	; plugin_name = "ssdt";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
					/**	symlinkscan	*/	fle = 	symlinkscan	; plugin_name = "symlinkscan";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
					/**	thrdscan	*/	fle = 	thrdscan	; plugin_name = "thrdscan";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
					/**	threads	*/	fle = 	threads	; plugin_name = "threads";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
					/**	timers	*/	fle = 	timers	; plugin_name = "timers";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
					/**	unloadedmodules	*/	fle = 	unloadedmodules	; plugin_name = "unloadedmodules";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
					/**	userhandles	*/	fle = 	userhandles	; plugin_name = "userhandles";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
					/**	vadtree	*/	fle = 	vadtree	; plugin_name = "vadtree";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
					/**	vadwalk	*/	fle = 	vadwalk	; plugin_name = "vadwalk";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
					/**	windows	*/	fle = 	windows	; plugin_name = "windows";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
					/**	wintree	*/	fle = 	wintree	; plugin_name = "wintree";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
					/**	wndscan	*/	fle = 	wndscan	; plugin_name = "wndscan";	if(search_file(fle, plugin_name, XREF_SEARCH_STRING, XREF_SEARCH_STRING_LOWER, -1) > 0) 	tree_container_files_with_search_hits_for_JTEXTAREA.put(plugin_name, fle);
				}
				
				/////////////////////////////////////
				// DONE
				///////////////////////////////////
				
				//
				//notify if files were found
				//
				if(tree_container_files_with_search_hits_for_JTEXTAREA != null && tree_container_files_with_search_hits_for_JTEXTAREA.size() > 0)
				{
					//
					//process jtextarea
					//
					try	{ intrface.jtaFile_XREF_Search_Results.append("FILES\n" + driver.UNDERLINE);	} catch(Exception e){}
					
					for(String key : tree_container_files_with_search_hits_for_JTEXTAREA.keySet())
					{
						//process jtextarea
						try	{ intrface.jtaFile_XREF_Search_Results.append(key + "\t\t" + tree_container_files_with_search_hits_for_JTEXTAREA.get(key));	} catch(Exception e){}
																
					}
				}
				else
				{
					try	{ intrface.jtaFile_XREF_Search_Results.append("No results were returned for selected query");	} catch(Exception e){}
				}
				
				//
				//add search string
				//
				try	{ intrface.jtaFile_XREF_Search_Results.append("\n\nSEARCH STRING\n=============================\n" + XREF_SEARCH_STRING);	} catch(Exception e){}
				
				/////////////////////////////////
				//yarascan - String search
				///////////////////////////////
				if(intrface.jcb_IncludeYaraStringScan != null && intrface.jcb_IncludeYaraStringScan.isSelected())
				{
					//notify
					try	{ intrface.jtaFile_XREF_Search_Results.append("\n\nYARASEARCH\n" + driver.UNDERLINE);	} catch(Exception e){}
					
					//search
					plugin_yarascan = new Analysis_Plugin_YaraScan(null, intrface.advanced_analysis_director, "yarascan", "Scan process or kernel memory with Yara signatures", true, jta, XREF_SEARCH_STRING, Start.intface.jtaFile_XREF_Search_Results, this);
				}
				
				/////////////////////////////////
				//yarascan - Signature File
				///////////////////////////////
				if(this.intrface.jcb_IncludeYaraSignatureFile != null && this.intrface.jcb_IncludeYaraSignatureFile.isSelected())
				{
					//ensure we have yara signature file
					if(this.intrface.fle_yara_signature_file == null || !this.intrface.fle_yara_signature_file.exists() || !this.intrface.fle_yara_signature_file.isFile())
					{
						//launch file selection
						this.intrface.specify_yara_signature_file();
						
						//verify valid file
						if(this.intrface.fle_yara_signature_file == null || !this.intrface.fle_yara_signature_file.exists() || !this.intrface.fle_yara_signature_file.isFile())
						{
							//still no file selected, disable this option
							try	{	this.intrface.jcb_IncludeYaraSignatureFile.setSelected(false);}	catch(Exception e){}
							driver.sop("NOTE: no valid YARA signature file has been selected, I am omitting this option in my search until valid file is specified...");
							return false;
						}
					}//otw, fall through, we have a valid file to vector into yarascan plugin					
					
					
					//ensure advanced analysis director is available
					if(intrface.path_fle_analysis_directory == null || intrface.path_fle_analysis_directory.trim().equals(""))
					{
						//check if we are configured to execute volatility
						if(!intrface.ensure_volatility_and_memory_image_are_configured())
						{
							try	{	intrface.jtfFile_XREF_SearchString.setEditable(true);} catch(Exception e){}
							intrface.jtfFile_XREF_SearchString.validate();
							intrface.jfrm.validate();
							
							intrface.sop("\nPunt! I am not configured to execute volatility.");
							return false;
						}
					}
					
					if(intrface.advanced_analysis_director == null)
					{
						//ensure advanced analysis instance exists...
						if(Start.intface.advanced_analysis_director == null)
							Start.intface.advanced_analysis_director = new Advanced_Analysis_Director(Start.intface.fle_volatility, Start.intface.fle_memory_image, Start.intface.PROFILE, Start.intface.path_fle_analysis_directory, Start.intface.file_attr_volatility, Start.intface.file_attr_memory_image, Start.intface.investigator_name, Start.intface.investigation_description, false);
						 
					}
					
					//specify command
					String cmd_override = "\"" + Start.intface.advanced_analysis_director.fle_volatility.getCanonicalPath().trim() + "\" -f \"" + Start.intface.advanced_analysis_director.fle_memory_image.getCanonicalPath().trim() + "\"" + " --profile=" + Start.intface.advanced_analysis_director.PROFILE + " yarascan --yara-file=\"" + this.intrface.fle_yara_signature_file.getCanonicalPath(); //leave off last quotation mark 

					//notify
					try	{ intrface.jtaFile_XREF_Search_Results.append("\n\nYARA FILE - " + this.intrface.fle_yara_signature_file.getName() + "\n=============================");	} catch(Exception e){}
					
					//instantiate plugin
					Analysis_Plugin_EXECUTION PLUGIN = new Analysis_Plugin_EXECUTION(null, Start.intface.advanced_analysis_director, "yarascan", "Scan process or kernel memory with Yara signatures", false, Start.intface.jpnlAdvancedAnalysisConsole, this.intrface.fle_yara_signature_file.getName() + "_", cmd_override, Start.intface.jtaFile_XREF_Search_Results);
					
					
					
				}
				
				
			}
			
			//
			//populate dump files
			//
			intrface.populate_dump_files_FILESCAN_XREF(this.tree_dump_file_entries_FILEDUMP_XREF);
			
			//
			//populate container files
			//
			intrface.populate_container_files_FILE_XREF(tree_container_files_with_search_hits_for_Container_JTAB);
			
			try	{	intrface.jtfFile_XREF_SearchString.setEditable(true);} catch(Exception e){}
			intrface.jfrm.validate();
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_search_File_XREF", e);
		}
		
		
		try	{	intrface.jtfFile_XREF_SearchString.setEditable(true);} catch(Exception e){}
		intrface.jfrm.validate();
		return false;
		
	}
	
	/**
	 * use file_scan_index to indicate how to process and store a line if we're adding it to the Dump Files for filescan plugin
	 * @param fle
	 * @param plugin_name
	 * @param search_string
	 * @param search_string_lower
	 * @param file_scan_index
	 * @return
	 */
	public long search_file(File fle, String plugin_name, String search_string, String search_string_lower, int index_dump_files_processing_action)
	{
		long num_hits_found = 0;
		
		try
		{						
			if(plugin_name == null)
				plugin_name = "";
			
			if(search_string == null || search_string.trim().equals(""))
			{
				driver.jop("Invalid search parameter receieved. Please type string for xref search...");
				return -1;
			}
			
			if(fle == null || !fle.isFile() || !fle.exists())
			{
				boolean prev = driver.output_enabled;
				
				driver.sop_CONSOLE_ONLY("Empty file received. No search actions for plugin/output file [" + plugin_name + "]");
				return -1;
			}
			
			intrface.sp("Searching file [" + fle.getName() + "] for search string [" + search_string + "]...");
			
			BufferedReader br = new BufferedReader(new FileReader(fle));
			String line = "", lower = "";
			boolean notified_gui = false, hit_found = false;
			
			
			int count = 0;
			intrface.sp("\n");
			
			String header = null;
			String underlines = null;
			long line_number = 0;
			
			while((line = br.readLine()) != null)
			{
				hit_found = false;
				line_number++;
				
				if((count++) % 20 == 0)
					intrface.sp(".");
				
				if(count % 1500 == 0)
					intrface.sop("\n");
				
				lower = line.toLowerCase().trim();
				
				if(lower.equals(""))
					continue;
				
				if(lower.startsWith("#"))
					continue;
				
				if(lower.startsWith("volatility"))
					continue;
				
				if(lower.startsWith("error"))
					continue;
				
				if(lower.startsWith("offset"))
				{
					header = line;
					continue;
				}
				
				if(lower.startsWith("last modified"))//shimcache
				{
					header = line;
					continue;
				}
				
				if(lower.startsWith("base "))
				{
					header = line;
					continue;
				}
				
				if(lower.startsWith("iat "))
				{
					header = line;
					continue;
				}
				
				if(lower.startsWith("name "))
				{
					header = line;
					continue;
				}
				
				if(lower.startsWith("pid "))
				{
					header = line;
					continue;
				}
				
				if(lower.startsWith("legend "))
				{
					header = line;
					continue;
				}
				
				if(lower.startsWith("sess "))
				{
					header = line;
					continue;
				}
				
				if(lower.startsWith("process "))
				{
					header = line;
					continue;
				}
				
				if(lower.startsWith("offset("))
				{
					header = line;
					continue;
				} 
				
				if(lower.startsWith("offset ("))
				{
					header = line;
					continue;
				} 
				
				if(lower.startsWith("address "))
				{
					header = line;
					continue;
				}  
				
				if(lower.startsWith("module "))
				{
					header = line;
					continue;
				} 
				
				if(lower.startsWith("type "))
				{
					header = line;
					continue;
				} 
				
				if(lower.startsWith("process("))
				{
					header = line;
					continue;
				}
				
				if(lower.startsWith("virtual "))
				{
					header = line;
					continue;
				} 
				
				if(lower.startsWith("----"))
				{
					underlines = line;
					continue;
				}
				
				//
				//test if hit can be found
				//
				if(lower.contains(search_string_lower))
					hit_found = true;
				
				//
				//determine if search string was found
				//
				if(hit_found)
				{
					//
					//increment
					//
					++num_hits_found;
					
					//
					//write plugin header where hit was found
					//
					if(!notified_gui)
					{
						notified_gui = true;
						try	{ intrface.jtaFile_XREF_Search_Results.append(plugin_name.toUpperCase() + "\n" + driver.UNDERLINE);	} catch(Exception e){}
						
						
						
						if(index_dump_files_processing_action == index_dump_files_store_action_MFTPARSER)
						{
							try	{ intrface.jtaFile_XREF_Search_Results.append("Line#\tCreation Date	Creation Time	Creation UTC	Modified Date	Modified Time	Modified UTC	MFT Altered Date	MFT Altered Time	MFT Altered UTC	Access Date	Access Time	Access UTC	Type/Name/Path	Entry Atrribute	Extension");	} catch(Exception e){}
							underlines = "-----\t-------------	-------------	------------	-------------	-------------	------------	-----------------	----------------	---------------	-----------	-----------	----------	---------------	---------------	---------";
							try	{ intrface.jtaFile_XREF_Search_Results.append(underlines.trim());	} catch(Exception e){}
						}
						else if(index_dump_files_processing_action == index_dump_files_store_action_USERASSIST)
						{
							//regular line count and details header
							try	{ intrface.jtaFile_XREF_Search_Results.append("Line#\tDetails");	} catch(Exception e){}
							try	{ intrface.jtaFile_XREF_Search_Results.append("-----\t-------");	} catch(Exception e){}
						}
						else if(index_dump_files_processing_action == index_dump_files_store_action_DLLLIST)
						{
							//regular line count and details header
							try	{ intrface.jtaFile_XREF_Search_Results.append("Line#\tDetails");	} catch(Exception e){}
							try	{ intrface.jtaFile_XREF_Search_Results.append("-----\t-------");	} catch(Exception e){}
						}
						else
						{
							if(header != null)
								try	{ intrface.jtaFile_XREF_Search_Results.append("Line#\t"+header.trim());	} catch(Exception e){}
							else
								try	{ intrface.jtaFile_XREF_Search_Results.append("Line#\tDetails");	} catch(Exception e){}
							if(underlines != null)
								try	{ intrface.jtaFile_XREF_Search_Results.append("-----\t"+underlines.trim());	} catch(Exception e){}
							else
								try	{ intrface.jtaFile_XREF_Search_Results.append("-----\t-------");	} catch(Exception e){}
						}
					}
					
					///////////////////////
					//write contents
					////////////////////////////
					
					//
					//special processing for MFTPARSER
					//
					if(index_dump_files_processing_action == index_dump_files_store_action_MFTPARSER )
					{
						if(line.contains("\t"))
							try	{ intrface.jtaFile_XREF_Search_Results.append("[" + line_number + "]\t" + line.trim());	} catch(Exception e){}
					}
					else
						try	{ intrface.jtaFile_XREF_Search_Results.append("[" + line_number + "]\t" + line.trim());	} catch(Exception e){}		
										
					//
					//save contents to export file list if this is FILESCAN					
					//
					if(index_dump_files_processing_action == this.index_dump_files_store_action_FILESCAN)
					{
						Node_Generic node_file = new Node_Generic("filescan");
						node_file.process_file_scan_entry(line, intrface.is_memory_image_WINDOWS());					
						this.tree_dump_file_entries_FILEDUMP_XREF.put("filescan - " + node_file.path_name + " " + node_file.offset_p, node_file);
					}	
					
					//
					//store file container
					//
					try
					{
						if(tree_container_files_with_search_hits_for_Container_JTAB.containsKey(fle.getCanonicalPath()))
							continue;
						
						Node_Generic node = new Node_Generic(plugin_name);
						node.fle = fle; 
						node.jcb = new JCheckBox("" + fle.getName());
						node.jcb.setToolTipText(fle.getCanonicalPath());
						
						//link
						tree_container_files_with_search_hits_for_Container_JTAB.put(fle.getCanonicalPath(), node);
					}
					catch(Exception e)
					{
						continue;
					}
					
				}//end if hit_found
				
			}//end while
			
			
			try	{	br.close();} catch(Exception e){}
			
			if(num_hits_found > 0)
			{
				try	{ intrface.jtaFile_XREF_Search_Results.append("\n");	} catch(Exception e){}
			}
			
			//
			//notify
			//
			intrface.sop("done! Num hits found: [" + num_hits_found + "]");
			
			return num_hits_found;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "search_file_FILESCAN", e);
		}
		
		return num_hits_found;
	}
	
	
	
	
	
	
//	public boolean sop(String out)
//	{
//		try
//		{
//			System.out.println(out);
//			return true;
//		}
//		catch(Exception e)
//		{
//			driver.eop(myClassName, "sop", e);
//		}
//		
//		return false;
//	}
//	
//	
//	public boolean sp(String out)
//	{
//		try
//		{
//			System.out.print(out);
//			return true;
//		}
//		catch(Exception e)
//		{
//			driver.eop(myClassName, "sp", e);
//		}
//		
//		return false;
//	}
	
	
	
	
	
	
	
}
