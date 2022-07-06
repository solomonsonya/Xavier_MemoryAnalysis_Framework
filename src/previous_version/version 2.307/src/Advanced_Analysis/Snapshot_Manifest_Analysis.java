package Advanced_Analysis;

import Driver.*;
import Interface.*;
import java.io.*;
import java.util.*;

/**
 * The purpose of this class is to execute comparison routines between snapshot 1 and 2 and display the results to the user
 * 
 * Input data is prepopulated by calling Interface class
 * 
 * KNOWN ISSUES:
 * 	- Unloaded Modules does no seem to iterate properly. 
 * 
 * package Advanced_Analysis;
 * @author Solomon Sonya
 *
 */

public class Snapshot_Manifest_Analysis extends Thread implements Runnable
{
	public static final String myClassName = "Snapshot_Manifest_Analysis";
	public static volatile Driver driver = new Driver();
	
	public volatile Interface intrface = null;
	public volatile Advanced_Analysis_Director director_snapshot_1 = null;
	public volatile Advanced_Analysis_Director director_snapshot_2 = null;
	
	public static final int index_callbacks = 0;
	public static final int index_timers = 1;
	public static final int index_unloaded_modules = 2;
	
	
	public volatile LinkedList<Node_Generic> list_visited_nodes = new LinkedList<Node_Generic>();
	
	////////////////////////////////////////////////////////////////////////
	// ADDITIONS
	////////////////////////////////////////////////////////////////////////
	
	///////////////////////////////// PROCESS
	public volatile TreeMap<Integer, Node_Process> tree_addition_PROCESS = new TreeMap<Integer, Node_Process>();
	public volatile TreeMap<Integer, Node_Process> tree_addition_ORPHAN_process = new TreeMap<Integer, Node_Process>();
	public volatile TreeMap<Integer, Node_Process> tree_addition_Process_from_offset_P_trimmed = new TreeMap<Integer, Node_Process>();
	public volatile TreeMap<Integer, Node_Process> tree_addition_Process_from_offset_V = new TreeMap<Integer, Node_Process>();
	public volatile TreeMap<Integer, Node_Process> tree_addition_Process_from_module_base_address = new TreeMap<Integer, Node_Process>();
	public volatile TreeMap<Integer, Node_Process> tree_addition_Process_from_module_base_address_trimmed = new TreeMap<Integer, Node_Process>();
	public volatile TreeMap<Integer, Node_Process> tree_addition_GDI_TIMERS = new TreeMap<Integer, Node_Process>();
	public volatile TreeMap<Integer, Node_Process> tree_addition_malfind_original_dump_name_to_process = new TreeMap<Integer, Node_Process>();
	public volatile TreeMap<Integer, Node_Process> tree_addition_process_to_link_cmdline_cmdscan_consoles = new TreeMap<Integer, Node_Process>();
	
	///////////////////////////////// DLL
	public volatile TreeMap<String, Node_DLL> tree_addition_DLL_by_path = new TreeMap<String, Node_DLL>();
	public volatile TreeMap<String, Node_DLL> tree_addition_DLL_MODULES_linked_by_VAD_base_start_address = new TreeMap<String, Node_DLL>();
	public volatile TreeMap<String, String> tree_addition_Module_Name_from_base_address_as_key = new TreeMap<String, String>();
	public volatile TreeMap<String, Node_DLL> tree_addition_Process_Name_from_process_offset_V = new TreeMap<String, Node_DLL>();
	public volatile TreeMap<String, Node_DLL> tree_addition_Process_Name_from_process_offset_P_trimmed = new TreeMap<String, Node_DLL>();
	public volatile LinkedList<Node_DLL> list_addition_API_HOOKS_WITH_HEAD_TRAMPOLINE_PRESENT = new LinkedList<Node_DLL>();
	public volatile LinkedList<Node_DLL> list_addition_API_HOOKS_WITH_MZ_PRESENT = new LinkedList<Node_DLL> ();
	
	
	///////////////////////////////// DRIVERS
	public volatile TreeMap<String, Node_Driver> tree_addition_DRIVERS = new TreeMap<String, Node_Driver>();
	public volatile TreeMap<String, Node_Driver> tree_addition_DRIVER_IRP_HOOK = new TreeMap<String, Node_Driver>();
	public volatile TreeMap<String, Node_Driver> tree_addition_CALLBACKS = new TreeMap<String, Node_Driver>();
	public volatile TreeMap<String, Node_Driver> tree_addition_UNLOADED_MODULES = new TreeMap<String, Node_Driver>();
	public volatile TreeMap<String, Node_Driver> tree_addition_TIMERS = new TreeMap<String, Node_Driver>();
	
	///////////////////////////////// REGISTRY
	public volatile TreeMap<String, Node_Registry_Hive> tree_addition_REGISTRY_HIVE_USER_ASSIST = new TreeMap<String, Node_Registry_Hive>();
	public volatile TreeMap<String, Node_Registry_Hive> tree_addition_REGISTRY_HIVE_PRINTKEY = new TreeMap<String, Node_Registry_Hive>(); 
	
	///////////////////////////////// VARIOUS
	
	
	///////////////////////////////// NODE GENERIC
	public volatile TreeMap<String, Node_Generic> tree_addition_DESKSCAN = new TreeMap<String, Node_Generic>();
	public volatile TreeMap<String, Node_Generic> tree_addition_AUDIT_POLICY = new TreeMap<String, Node_Generic>();
	
	
	
	////////////////////////////////////////////////////////////////////////
	// MISSING
	////////////////////////////////////////////////////////////////////////
	
	/////////////////////////////////PROCESS
	public volatile TreeMap<Integer, Node_Process> tree_missing_PROCESS = new TreeMap<Integer, Node_Process>();
	public volatile TreeMap<Integer, Node_Process> tree_missing_ORPHAN_process = new TreeMap<Integer, Node_Process>();
	public volatile TreeMap<Integer, Node_Process> tree_missing_Process_from_offset_P_trimmed = new TreeMap<Integer, Node_Process>();
	public volatile TreeMap<Integer, Node_Process> tree_missing_Process_from_offset_V = new TreeMap<Integer, Node_Process>();
	public volatile TreeMap<Integer, Node_Process> tree_missing_Process_from_module_base_address = new TreeMap<Integer, Node_Process>();
	public volatile TreeMap<Integer, Node_Process> tree_missing_Process_from_module_base_address_trimmed = new TreeMap<Integer, Node_Process>();
	public volatile TreeMap<Integer, Node_Process> tree_missing_GDI_TIMERS = new TreeMap<Integer, Node_Process>();
	public volatile TreeMap<Integer, Node_Process> tree_missing_malfind_original_dump_name_to_process = new TreeMap<Integer, Node_Process>();
	public volatile TreeMap<Integer, Node_Process> tree_missing_process_to_link_cmdline_cmdscan_consoles = new TreeMap<Integer, Node_Process>();
	
	///////////////////////////////// DLL
	public volatile TreeMap<String, Node_DLL> tree_missing_DLL_by_path = new TreeMap<String, Node_DLL>();
	public volatile TreeMap<String, Node_DLL> tree_missing_DLL_MODULES_linked_by_VAD_base_start_address = new TreeMap<String, Node_DLL>();
	public volatile TreeMap<String, String> tree_missing_Module_Name_from_base_address_as_key = new TreeMap<String, String>(); 
	public volatile TreeMap<String, Node_DLL> tree_missing_Process_Name_from_process_offset_V = new TreeMap<String, Node_DLL>();
	public volatile TreeMap<String, Node_DLL> tree_missing_Process_Name_from_process_offset_P_trimmed = new TreeMap<String, Node_DLL>();
	public volatile LinkedList<Node_DLL> list_missing_API_HOOKS_WITH_HEAD_TRAMPOLINE_PRESENT = new LinkedList<Node_DLL>();
	public volatile LinkedList<Node_DLL> list_missing_API_HOOKS_WITH_MZ_PRESENT = new LinkedList<Node_DLL> ();
	
	///////////////////////////////// DRIVERS
	public volatile TreeMap<String, Node_Driver> tree_missing_DRIVERS = new TreeMap<String, Node_Driver>();
	public volatile TreeMap<String, Node_Driver> tree_missing_DRIVER_IRP_HOOK = new TreeMap<String, Node_Driver>();
	public volatile TreeMap<String, Node_Driver> tree_missing_CALLBACKS = new TreeMap<String, Node_Driver>();
	public volatile TreeMap<String, Node_Driver> tree_missing_UNLOADED_MODULES = new TreeMap<String, Node_Driver>();
	public volatile TreeMap<String, Node_Driver> tree_missing_TIMERS = new TreeMap<String, Node_Driver>();
	
	///////////////////////////////// REGISTRY
	public volatile TreeMap<String, Node_Registry_Hive> tree_missing_REGISTRY_HIVE_USER_ASSIST = new TreeMap<String, Node_Registry_Hive>();
	public volatile TreeMap<String, Node_Registry_Hive> tree_missing_REGISTRY_HIVE_PRINTKEY = new TreeMap<String, Node_Registry_Hive>();
	
	///////////////////////////////// VARIOUS
	
	///////////////////////////////// NODE GENERIC
	public volatile TreeMap<String, Node_Generic> tree_missing_DESKSCAN = new TreeMap<String, Node_Generic>();
	public volatile TreeMap<String, Node_Generic> tree_missing_AUDIT_POLICY = new TreeMap<String, Node_Generic>();
	
	////////////////////////////////////////////////////////////////////////
	// MODIFIED
	////////////////////////////////////////////////////////////////////////
	
	///////////////////////////////// PROCESS
	public volatile TreeMap<Integer, Node_Process> tree_MODIFIED_PROCESS = new TreeMap<Integer, Node_Process>();
	
	///////////////////////////////// STRINGS
	public volatile TreeMap<String, String> tree_MODIFIED_Module_Name_from_base_address_as_key = new TreeMap<String, String>(); 
	
	///////////////////////////////// DLL
	
	///////////////////////////////// DRIVERS
	public volatile TreeMap<String, Node_Driver> tree_MODIFIED_DRIVERS = new TreeMap<String, Node_Driver>();
	public volatile TreeMap<String, Node_Driver> tree_MODIFIED_DRIVER_IRP_HOOK = new TreeMap<String, Node_Driver>();
	public volatile TreeMap<String, Node_Driver> tree_MODIFIED_CALLBACKS = new TreeMap<String, Node_Driver>();
	public volatile TreeMap<String, Node_Driver> tree_MODIFIED_UNLOADED_MODULES = new TreeMap<String, Node_Driver>();
	public volatile TreeMap<String, Node_Driver> tree_MODIFIED_TIMERS = new TreeMap<String, Node_Driver>();
	
	///////////////////////////////// REGISTRY
	
	///////////////////////////////// VARIOUS
	
	///////////////////////////////// NODE GENERIC
	public volatile TreeMap<String, Node_Generic> tree_MODIFIED_DESKSCAN = new TreeMap<String, Node_Generic>();
	public volatile TreeMap<String, Node_Generic> tree_MODIFIED_AUDIT_POLICY = new TreeMap<String, Node_Generic>();
	
	
	//
	//investigation particulars - set these values if the info is the same between both snapshots
	//
	public volatile LinkedList<Node_Generic> lst_investigation_particulars = new LinkedList<Node_Generic>();
	
	
	////////////////////////////////////////////////////////////////////////
	// COMBINED
	////////////////////////////////////////////////////////////////////////
	
	//
	//HIVELIST
	//
	public volatile TreeMap<String, Node_hivelist> tree_addition_HIVELIST = new TreeMap<String, Node_hivelist>();
	public volatile TreeMap<String, Node_hivelist> tree_missing_HIVELIST = new TreeMap<String, Node_hivelist>();
	public volatile TreeMap<String, Node_hivelist> tree_MODIFIED_HIVELIST = new TreeMap<String, Node_hivelist>();
	int count_additional_HIVELIST = 0, count_missing_HIVELIST = 0, additional_count_MODIFIED_HIVELIST = 0;

	//
	//GET_SERVICE_SIDS
	//
	public volatile TreeMap<String, Node_get_service_sid> tree_addition_GET_SERVICE_SIDS = new TreeMap<String, Node_get_service_sid>();
	public volatile TreeMap<String, Node_get_service_sid> tree_missing_GET_SERVICE_SIDS = new TreeMap<String, Node_get_service_sid>();
	public volatile TreeMap<String, Node_get_service_sid> tree_MODIFIED_GET_SERVICE_SIDS = new TreeMap<String, Node_get_service_sid>();
	int count_additional_GET_SERVICE_SIDS = 0, count_missing_GET_SERVICE_SIDS = 0, additional_count_MODIFIED_GET_SERVICE_SIDS = 0;
	
	//
	//HASHDUMP
	//
	public volatile TreeMap<String, String> tree_addition_HASHDUMP = new TreeMap<String, String>();
	public volatile TreeMap<String, String> tree_missing_HASHDUMP = new TreeMap<String, String>();
	public volatile TreeMap<String, String> tree_MODIFIED_HASHDUMP = new TreeMap<String, String>();
	int count_additional_HASHDUMP = 0, count_missing_HASHDUMP = 0, additional_count_MODIFIED_HASHDUMP = 0;
	
	//
	//SIDS
	//
	public volatile TreeMap<String, String> tree_addition_SIDS = new TreeMap<String, String>();
	public volatile TreeMap<String, String> tree_missing_SIDS = new TreeMap<String, String>();
	public volatile TreeMap<String, String> tree_MODIFIED_SIDS = new TreeMap<String, String>();
	int count_additional_SIDS = 0, count_missing_SIDS = 0, additional_count_MODIFIED_SIDS = 0;

	
	//
	//SESSION ENTRIES
	//
	public volatile TreeMap<String, LinkedList<String>> tree_addition_SESSION_ENTRIES = new TreeMap<String, LinkedList<String>>();
	public volatile TreeMap<String, LinkedList<String>> tree_missing_SESSION_ENTRIES = new TreeMap<String, LinkedList<String>>();
	public volatile TreeMap<String, LinkedList<String>> tree_MODIFIED_SESSION_ENTRIES = new TreeMap<String, LinkedList<String>>();
	int count_additional_SESSION_ENTRIES = 0, count_missing_SESSION_ENTRIES = 0, additional_count_MODIFIED_SESSION_ENTRIES = 0;
	
	
	//
	//ANALYSIS TREES
	//
	public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_PROCESS = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();
	public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_DLL = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();
	public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_DRIVER = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();
	public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_DRIVER_IRP = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();
	public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_CALLBACKS = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();	
	public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_TIMERS = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();
	public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_UNLOADED_MODULES = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();
	
	
	
	//
	//trees
	//
	public volatile TreeMap<String, String> tree_filescan_addition = new TreeMap<String, String>();
	public volatile TreeMap<String, String> tree_filescan_missing = new TreeMap<String, String>();
	public volatile TreeMap<String, String> tree_filescan_MODIFICATION = new TreeMap<String, String>();
	
	public volatile TreeMap<String, String> tree_mftparser_addition = new TreeMap<String, String>();
	public volatile TreeMap<String, String> tree_mftparser_missing = new TreeMap<String, String>();
	public volatile TreeMap<String, String> tree_mftparser_MODIFICATION = new TreeMap<String, String>();
	
	public volatile TreeMap<String, String> tree_timeliner_addition = new TreeMap<String, String>();
	public volatile TreeMap<String, String> tree_timeliner_missing = new TreeMap<String, String>();
	public volatile TreeMap<String, String> tree_timeliner_MODIFICATION = new TreeMap<String, String>();
	
	public volatile TreeMap<String, String> tree_userassist_specific_entries_addition = new TreeMap<String, String>();
	public volatile TreeMap<String, String> tree_userassist_specific_entries_missing = new TreeMap<String, String>();
	public volatile TreeMap<String, String> tree_userassist_specific_entries_MODIFICATION = new TreeMap<String, String>();
	
	public volatile TreeMap<String, String> tree_shellbags_addition = new TreeMap<String, String>();
	public volatile TreeMap<String, String> tree_shellbags_missing = new TreeMap<String, String>();
	public volatile TreeMap<String, String> tree_shellbags_MODIFICATION = new TreeMap<String, String>();
	
	public volatile TreeMap<String, String> tree_shimcache_addition = new TreeMap<String, String>();
	public volatile TreeMap<String, String> tree_shimcache_missing = new TreeMap<String, String>();
	public volatile TreeMap<String, String> tree_shimcache_MODIFICATION = new TreeMap<String, String>();
	
	
	/*public volatile TreeMap<String, Node_Malfind> tree_malfind_addition = new TreeMap<String, Node_Malfind>();
	public volatile TreeMap<String, Node_Malfind> tree_malfind_missing = new TreeMap<String, Node_Malfind>();
	public volatile TreeMap<String, Node_Generic> tree_malfind_modified = new TreeMap<String, Node_Generic>();*/
	
	LinkedList<String> list_malfind_addition_instructions = new LinkedList<String>();
	LinkedList<String> list_malfind_missing_instructions = new LinkedList<String>();
	LinkedList<String> list_malfind_MODIFIED_instructions = new LinkedList<String>();
	
	
	
	public Snapshot_Manifest_Analysis(Interface Intrface, Advanced_Analysis_Director Director_snapshot_1, Advanced_Analysis_Director Director_snapshot_2)
	{
		try
		{
			intrface = Intrface;
			director_snapshot_1 = Director_snapshot_1;
			director_snapshot_2 = Director_snapshot_2;
			
			this.start();			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 0");
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
	
	public boolean snapshot_analysis_summary_DLL(Advanced_Analysis_Director director_1, Advanced_Analysis_Director director_2, JTextArea_Solomon jta)
	{
		try
		{
			TreeMap<String, String> tree_dlls_with_missing_processes = new TreeMap<String, String>();
			TreeMap<String, String> tree_dlls_with_added_processes = new TreeMap<String, String>();
			
			TreeMap<String, String> tree_additional_dlls = new TreeMap<String, String>();
			TreeMap<String, String> tree_missing_dlls = new TreeMap<String, String>();
			
			
			TreeMap<String, Node_DLL> tree_1 = null;
			TreeMap<String, Node_DLL> tree_2 = null;
			
			try	{	tree_1 = director_1.tree_DLL_by_path;	}	catch(Exception e)	{	tree_1 = null;	}
			try	{	tree_2 = director_2.tree_DLL_by_path;	}	catch(Exception e)	{	tree_2 = null;	}
			
			if(tree_1 == null && tree_2 != null)
			{
				jta.append("\nDLL\n" + Driver.UNDERLINE);
				jta.append("Entire DLL tree is found in snapshot 2 yet missing from snapshot 1!!!");
				return true;
			}
			else if(tree_1 != null && tree_2 == null)
			{
				jta.append("\nDLL\n" + Driver.UNDERLINE);
				jta.append("Entire DLL tree is missing in snapshot 2 yet present from snapshot 1!!!");
				return true;
			}
			
			Node_DLL dll_1 = null;
			Node_DLL dll_2 = null;
			boolean printed_header_addition = false;
			boolean printed_header_missing = false;
			boolean printed_header_MODIFIED = false;
			
			//build key of paths
			TreeMap<String, String> tree_key_set = new TreeMap<String, String>();
			
			for(String key : tree_1.keySet())
				tree_key_set.put(key, null);
			
			for(String key : tree_2.keySet())
				tree_key_set.put(key, null);
			
			for(String key: tree_key_set.keySet())
			{
				if(key == null || key.trim().equals(""))
					continue;
				
				if(key.toLowerCase().contains("all rights reserved."))
					continue;
				
				try	{	dll_1 = tree_1.get(key);	} catch(Exception e) { dll_1 = null;	}
				try	{	dll_2 = tree_2.get(key);	} catch(Exception e) { dll_2 = null;	}
				
				if(dll_1 == null && dll_2 != null)
				{
					if(!printed_header_addition)
					{
						//jta.append("\nADDITIONAL DLLS DETECTED\n" + Driver.UNDERLINE);
						//printed_header_addition = true;
					}
					
					//path
					//jta.append(dll_2.path);
					
					//importing processes
					String importing_process = dll_2.get_importing_processes(", ");
					
					//if(importing_process != null && importing_process.length() > 1)
					//	jta.append("\timporting process(s): " + importing_process);
					
					tree_additional_dlls.put(dll_2.path, dll_2.get_importing_processes(", "));
				}
				
				else if(dll_1 != null && dll_2 == null)
				{
					if(!printed_header_missing)
					{
						//jta.append("\nMISSING DLLS DETECTED\n" + Driver.UNDERLINE);
						//printed_header_missing = true;
					}
					
					//path
					//jta.append(dll_1.path);
					
					//importing processes
					String importing_process = dll_1.get_importing_processes(", ");
															
					//if(importing_process != null && importing_process.length() > 1)
					//	jta.append("\timporting process(s): " + importing_process);
					tree_missing_dlls.put(dll_1.path, dll_1.get_importing_processes(", "));
				}
				
				else//compare both DLL's importing process
				{
					
					String added_processes = "", missing_processes = "";
					
					LinkedList<String> list_1_importing_processes = dll_1.get_importing_processes();
					LinkedList<String> list_2_importing_processes = dll_2.get_importing_processes();
										
					TreeMap<String, String> tree_importing_process_key = new TreeMap<String, String>();
					
					if(list_1_importing_processes != null)
					{
						for(String PID : list_1_importing_processes)
						{
							tree_importing_process_key.put(PID,  null);
						}
					}
					
					if(list_2_importing_processes != null)
					{
						for(String PID : list_2_importing_processes)
						{
							tree_importing_process_key.put(PID,  null);
						}
					}
					
					for(String PID : tree_importing_process_key.keySet())
					{
						if(list_1_importing_processes != null && !list_1_importing_processes.contains(PID))
							added_processes = added_processes + ", " + PID;
						
						else if(list_2_importing_processes != null && !list_2_importing_processes.contains(PID))
							missing_processes = missing_processes + ", " + PID;							
					}
					
					//
					//normalize
					//
					if(added_processes != null && added_processes.trim().startsWith(","))
						added_processes = added_processes.trim().substring(1).trim();
					
					if(missing_processes != null && missing_processes.trim().startsWith(","))
						missing_processes = missing_processes.trim().substring(1).trim();
							
					//
					//populate trees
					//
					if(added_processes != null && added_processes.length() > 0)
						tree_dlls_with_added_processes.put(dll_2.path, added_processes);
					
					if(missing_processes != null && missing_processes.length() > 0)
						tree_dlls_with_missing_processes.put(dll_1.path, missing_processes);
				}
				
				
			}//end for
			
			
			//
			//print output
			//
			
			if(tree_dlls_with_added_processes != null && tree_dlls_with_added_processes.size() > 0)
			{
				jta.append("\nMODIFIED DLLS - ADDED PROCESS(S)\n" + Driver.UNDERLINE);
				jta.append("path\tdisposition\tprocess(s)");
				
				for(String key : tree_dlls_with_added_processes.keySet())
				{
					String importing_process = tree_dlls_with_added_processes.get(key);
					jta.append(key + "\t" + "added process(s): \t" + importing_process);
				}
			}
			
			if(tree_dlls_with_missing_processes != null && tree_dlls_with_missing_processes.size() > 0)
			{
				jta.append("\nMODIFIED DLLS - MISSING PROCESS(S)\n" + Driver.UNDERLINE);
				jta.append("path\tdisposition\tprocess(s)");
				
				for(String key : tree_dlls_with_missing_processes.keySet())
				{
					String importing_process = tree_dlls_with_missing_processes.get(key);
					jta.append(key + "\t" + "missing process(s): \t" + importing_process);
				}
			}
			
			if(tree_additional_dlls != null && tree_additional_dlls.size() > 0)
			{
				jta.append("\nADDITIONAL DLLS DETECTED\n" + Driver.UNDERLINE);
				jta.append("path\tdisposition\tprocess(s)");
				
				
				for(String key : tree_additional_dlls.keySet())
				{
					String importing_process = tree_additional_dlls.get(key);
					jta.append(key + "\t" + "importing process(s): \t" + importing_process);
				}
			}
			
			if(tree_missing_dlls != null && tree_additional_dlls.size() > 0)
			{
				jta.append("\nMISSING DLLS DETECTED\n" + Driver.UNDERLINE);
				jta.append("path\tdisposition\tprocess(s)");
				
				
				for(String key : tree_missing_dlls.keySet())
				{
					String importing_process = tree_missing_dlls.get(key);
					jta.append(key + "\t" + "importing process(s): \t" + importing_process);
				}
			}
			
			
			
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "snapshot_analysis_summary_DLL", e);
		}
		
		return false;
	}
	
	public boolean snapshot_analysis_summary_MALFIND(Advanced_Analysis_Director director_1, Advanced_Analysis_Director director_2)
	{
		try
		{
			JTextArea_Solomon jta = intrface.jtaSnapshotAnalysisConsole;
			
			boolean printed_header = false;
			
			LinkedList<Node_Malfind> list_already_visited_nodes = new LinkedList<Node_Malfind>();
			
			//check MZ first
			TreeMap<String, Node_Malfind> tree_1 = null; 
			TreeMap<String, Node_Malfind> tree_2 = null;
			
			try	{	 tree_1 = director_1.tree_malfind_MZ_Detcted;	} catch(Exception e) { tree_1 = null;}
			try	{	 tree_2 = director_2.tree_malfind_MZ_Detcted;	} catch(Exception e) { tree_2 = null;}
			
			this.analyze_malfind_nodes(tree_1, tree_2, jta, "MZ", list_already_visited_nodes);
			
			try	{	 tree_1 = director_1.tree_malfind_JMP_Detcted;	} catch(Exception e) { tree_1 = null;}
			try	{	 tree_2 = director_2.tree_malfind_JMP_Detcted;	} catch(Exception e) { tree_2 = null;}
			
			this.analyze_malfind_nodes(tree_1, tree_2, jta, "JMP", list_already_visited_nodes);
			
			
			
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "snapshot_analysis_summary_MALFIND", e);
		}
		
		return false;
	}
	
	/**
	 * continuation mtd, assumes tree_1 and tree_2 are both not null!
	 * @param tree_1
	 * @param tree_2
	 * @param printed_header
	 * 
	 * 
	 * @return
	 */
	public boolean analyze_malfind_nodes(TreeMap<String, Node_Malfind> tree_1, TreeMap<String, Node_Malfind> tree_2, JTextArea_Solomon jta, String malfind_type, LinkedList<Node_Malfind> list_already_visited_nodes)
	{
		try
		{
			String delimiter = "\t";
			
			boolean printed_header = false;
			
			//
			//check entire structures first
			//
			if(tree_1 == null && tree_2 != null)
			{
				if(!printed_header)
				{
					jta.append("\n\nMALFIND WITH " + malfind_type + " HEADER TYPE\n" + Driver.UNDERLINE);								
					jta.append("New Malfind Nodes detected with " + malfind_type + " header indicative of code injection.");				
					String header = "plugin" + delimiter +  "PID" + delimiter + "process_name" + delimiter + "address" + delimiter + "vad_tag" + delimiter + "protection" + delimiter + "flags" + delimiter + "MZ_present" + delimiter + "Trampoline_initial_JMP_Detected" +  delimiter + "culprit line";				
					jta.append(header);
					printed_header = true;
				}
				
				for(Node_Malfind malfind : tree_2.values())
				{
					if(list_already_visited_nodes.contains(malfind))
						continue;
					
					jta.append("malfind" + delimiter + malfind.pid + delimiter + malfind.process_name + delimiter + malfind.address + delimiter + malfind.vad_tag + delimiter + malfind.protection + delimiter + malfind.flags + delimiter + malfind.MZ_present + delimiter + malfind.Trampoline_initial_JMP_Detected +  delimiter + malfind.culprit_line);
					list_already_visited_nodes.add(malfind);
				}	
				
				return true;
			}
			
			else if(tree_1 != null && tree_2 == null)
			{
				if(!printed_header)
				{
					jta.append("\n\nMALFIND WITH " + malfind_type + " HEADER TYPE\n" + Driver.UNDERLINE);										
					jta.append("Malfind Nodes are missing from Snapshot 2 that were present in Snapshot 1 with " + malfind_type + " headers indicative of code injection.");					
					String header = "plugin" + delimiter +  "PID" + delimiter + "process_name" + delimiter + "address" + delimiter + "vad_tag" + delimiter + "protection" + delimiter + "flags" + delimiter + "MZ_present" + delimiter + "Trampoline_initial_JMP_Detected" +  delimiter + "culprit line";					
					jta.append(header);
					printed_header = true;
				}
				
				for(Node_Malfind malfind : tree_1.values())
				{
					if(list_already_visited_nodes.contains(malfind))
						continue;
					
					jta.append("malfind" + delimiter + malfind.pid + delimiter + malfind.process_name + delimiter + malfind.address + delimiter + malfind.vad_tag + delimiter + malfind.protection + delimiter + malfind.flags + delimiter + malfind.MZ_present + delimiter + malfind.Trampoline_initial_JMP_Detected +  delimiter + malfind.culprit_line);
					list_already_visited_nodes.add(malfind);
				}	
				
				return true;
			}

			//ELSE, FALL THRU
			
			//constitute the trees
			TreeMap<String, String> key_list = new TreeMap<String, String>();
			
			for(String key :tree_1.keySet())
				key_list.put(key,  null);
			
			for(String key :tree_2.keySet())
				key_list.put(key,  null);
			
			Node_Malfind malfind_1 = null;
			Node_Malfind malfind_2 = null;
			
			
			for(String key : key_list.keySet())
			{
				if(key == null || key.trim().equals(""))
					continue;
				
				try	{	malfind_1 = tree_1.get(key);	} catch(Exception e)	{	malfind_1 = null;	}
				try	{	malfind_2 = tree_2.get(key);	} catch(Exception e)	{	malfind_2 = null;	}
				
				if(malfind_1 == null && malfind_2 != null)
				{
					if(!printed_header)
					{
						jta.append("\n\nMALFIND WITH " + malfind_type + " HEADER TYPE\n" + Driver.UNDERLINE);
						jta.append("New Malfind Nodes are detected with " + malfind_type + " headers indicative of code injection/hooking.");
						String header = "plugin" + delimiter +  "PID" + delimiter + "process_name" + delimiter + "address" + delimiter + "vad_tag" + delimiter + "protection" + delimiter + "flags" + delimiter + "MZ_present" + delimiter + "Trampoline_initial_JMP_Detected" +  delimiter + "culprit line";						
						jta.append(header);
						printed_header = true;
					}												
						
						for(Node_Malfind malfind : tree_2.values())
						{
							if(list_already_visited_nodes.contains(malfind))
								continue;
							
							jta.append("malfind" + delimiter + malfind.pid + delimiter + malfind.process_name + delimiter + malfind.address + delimiter + malfind.vad_tag + delimiter + malfind.protection + delimiter + malfind.flags + delimiter + malfind.MZ_present + delimiter + malfind.Trampoline_initial_JMP_Detected +  delimiter + malfind.culprit_line);
							list_already_visited_nodes.add(malfind);
						}	
					
						
				}//end if
				
				else if(malfind_1 != null && malfind_2 == null)
				{
					if(!printed_header)
					{
						jta.append("\n\nMALFIND WITH " + malfind_type + " HEADER TYPE\n" + Driver.UNDERLINE);
						jta.append("Malfind Nodes are missing from Snapshot 2 that were present in Snapshot 1 with MZ headers indicative of code injection.");
						String header = "plugin" + delimiter +  "PID" + delimiter + "process_name" + delimiter + "address" + delimiter + "vad_tag" + delimiter + "protection" + delimiter + "flags" + delimiter + "MZ_present" + delimiter + "Trampoline_initial_JMP_Detected" +  delimiter + "culprit line";						
						jta.append(header);
						printed_header = true;
					}												
						
						for(Node_Malfind malfind : tree_1.values())
						{
							if(list_already_visited_nodes.contains(malfind))
								continue;
							
							jta.append("malfind" + delimiter + malfind.pid + delimiter + malfind.process_name + delimiter + malfind.address + delimiter + malfind.vad_tag + delimiter + malfind.protection + delimiter + malfind.flags + delimiter + malfind.MZ_present + delimiter + malfind.Trampoline_initial_JMP_Detected +  delimiter + malfind.culprit_line);
							list_already_visited_nodes.add(malfind);
						}	
					
						
				}//end if
				
				else //both existed, compare each value
				{					
					if(list_already_visited_nodes.contains(malfind_1) || list_already_visited_nodes.contains(malfind_2)) 
						continue;
				
					//
					//check header
					//
					
					String malfind_summary_1 = malfind_1.pid + delimiter + malfind_1.process_name + delimiter + malfind_1.address + delimiter + malfind_1.vad_tag + delimiter + malfind_1.protection + delimiter + malfind_1.flags + delimiter + malfind_1.MZ_present + delimiter + malfind_1.Trampoline_initial_JMP_Detected +  delimiter + malfind_1.culprit_line;
					String malfind_summary_2 = malfind_2.pid + delimiter + malfind_2.process_name + delimiter + malfind_2.address + delimiter + malfind_2.vad_tag + delimiter + malfind_2.protection + delimiter + malfind_2.flags + delimiter + malfind_2.MZ_present + delimiter + malfind_2.Trampoline_initial_JMP_Detected +  delimiter + malfind_2.culprit_line;
										
					if(!malfind_summary_1.toLowerCase().trim().equals(malfind_summary_2.toLowerCase().trim()))
					{
						if(!printed_header)
						{
							jta.append("\n\nMALFIND WITH " + malfind_type + " HEADER TYPE ALTERED PROCESS DESCRIPTOR\n" + Driver.UNDERLINE);							
							String header = "plugin" + delimiter + "snapshot value" + delimiter + "PID" + delimiter + "process_name" + delimiter + "address" + delimiter + "vad_tag" + delimiter + "protection" + delimiter + "flags" + delimiter + "MZ_present" + delimiter + "Trampoline_initial_JMP_Detected" +  delimiter + "culprit line";						
							jta.append(header);
							printed_header = true;
						}	
						
						jta.append("malfind_1" + delimiter + "1" + delimiter + malfind_1.pid + delimiter + malfind_1.process_name + delimiter + malfind_1.address + delimiter + malfind_1.vad_tag + delimiter + malfind_1.protection + delimiter + malfind_1.flags + delimiter + malfind_1.MZ_present + delimiter + malfind_1.Trampoline_initial_JMP_Detected +  delimiter + malfind_1.culprit_line);
						jta.append("malfind_2" + delimiter + "2" + delimiter + malfind_2.pid + delimiter + malfind_2.process_name + delimiter + malfind_2.address + delimiter + malfind_2.vad_tag + delimiter + malfind_2.protection + delimiter + malfind_2.flags + delimiter + malfind_2.MZ_present + delimiter + malfind_2.Trampoline_initial_JMP_Detected +  delimiter + malfind_2.culprit_line);
						
						list_already_visited_nodes.add(malfind_1);
						list_already_visited_nodes.add(malfind_2);						
					}
					
					//
					//check dump file
					//
					FileAttributeData attr_1 = null;
					FileAttributeData attr_2 = null;
					
					String file_attr_descriptor_1 = null;
					String file_attr_descriptor_2 = null;
					
					try	
					{	
						attr_1 = malfind_1.fle_attributes;							
						file_attr_descriptor_1 = "file_name:" + delimiter + attr_1.file_name + delimiter + "size:" + delimiter + attr_1.size + delimiter + "md5:" + delimiter + attr_1.hash_md5 + delimiter + "sha256: " + delimiter + attr_1.hash_sha256;
					}catch(Exception e)	{	attr_1 = null;	}
					
					try	
					{	
						attr_2 = malfind_2.fle_attributes;							
						file_attr_descriptor_2 = "file_name:" + delimiter + attr_2.file_name + delimiter + "size:" + delimiter + attr_2.size + delimiter + "md5:" + delimiter + attr_2.hash_md5 + delimiter + "sha256: " + delimiter + attr_2.hash_sha256;
					}catch(Exception e)	{	attr_2 = null;	}
					
					if(attr_1 == null && attr_2 != null)
					{
						jta.append("New file dump detected for snapshot 2: " + file_attr_descriptor_2);
					}
					
					else if(attr_1 != null && attr_2 == null)
					{
						jta.append("File dump is missing from snapshot 2. Details found in snapshot 1: " + file_attr_descriptor_1);
					}
					else if(!file_attr_descriptor_1.toLowerCase().trim().equals(file_attr_descriptor_2.toLowerCase().trim()))
					{
						jta.append("There is a value change in File Descriptors between snapshots:");
						jta.append("snapshot 1: " + file_attr_descriptor_1);
						jta.append("snapshot 2: " + file_attr_descriptor_2);
					}
							
					//
					//check list entries
					//
					LinkedList<String> list_1 = null;
					LinkedList<String> list_2 = null;
					
					try	{	list_1 = malfind_1.list_details;	} catch(Exception e)	{	list_1 = null;	}
					try	{	list_2 = malfind_2.list_details;	} catch(Exception e)	{	list_2 = null;	}
					
					if(list_1 == null && list_2 != null)
					{
						jta.append("New Details found in snapshot 2 --> " + malfind_summary_2);
					}
					
					else if(list_1 != null && list_2 == null)
					{
						jta.append("Details missing in snapshot 2 on entry --> " + malfind_summary_1);
					}
					
					else //iterate through list
					{
						for(String entry : list_2)
						{
							if(entry == null || entry.trim().equals(""))
								continue;
							
							if(!list_1.contains(entry.trim()))
							{
								jta.append("malfind list details are different. please compare details for analysis between nodes:");
								jta.append("\t" + malfind_summary_1);
								jta.append("\t" + malfind_summary_2);
								
								list_already_visited_nodes.add(malfind_1);
								list_already_visited_nodes.add(malfind_2);			
								
								break;
							}														
						}
						
						//compare this one later
//						for(String entry : list_2)
//						{
//							if(entry == null || entry.trim().equals(""))
//								continue;
//							
//							if(!list_1.contains(entry.trim()))
//							{
//								jta.append("malfind list details are different. please compare details for analysis between nodes:");
//								jta.append("\t" + malfind_summary_1);
//								jta.append("\t" + malfind_summary_2);
//								
//								list_already_visited_nodes.add(malfind_1);
//								list_already_visited_nodes.add(malfind_2);			
//								
//								break;
//							}														
//						}
					}
					
					
					
				}//end else
				
				
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_malfind_nodes", e);
		}
		
		return false;
	}
	
	
	
	/**
	 * assumes snapshot 1 and snapshot 2 are populated with data. reject analysis if either of the snapshots are null
	 * @return
	 */
	public boolean commence_action()
	{
		try
		{
			//
			//validate 
			//
			if(director_snapshot_1 == null)
			{
				driver.jop_Error("Snapshot Manifest 1 Director is null!!!");
				
				if(intrface != null)
					intrface.jtaSnapshotAnalysisConsole.append("Unable to continue. Snapshot 1 Director is null! Halting analysis actions here...");				
				return false;				
			}
			
			if(director_snapshot_2 == null)
			{
				driver.jop_Error("Snapshot Manifest 2 Director is null!!!");
				
				if(intrface != null)
					intrface.jtaSnapshotAnalysisConsole.append("Unable to continue. Snapshot 2 Director is null! Halting analysis actions here...");				
				return false;
			}
			
			
			JTextArea_Solomon jta = intrface.jtaSnapshotAnalysisConsole;
			jta.append("\n\n* * * INVESTIGATION SUMMARY * * *");
			
			//
			//Phase !: Investigation Summary - Process
			//
			snapshot_analysis_summary_PROCESS(director_snapshot_1, director_snapshot_2, jta);
			
			//
			//Phase B: Investigation Summary - Malfind
			//			
			snapshot_analysis_summary_MALFIND(director_snapshot_1, director_snapshot_2);
			
			//
			//Phase C: Investigation Summary - DLLs
			//			
			snapshot_analysis_summary_DLL(director_snapshot_1, director_snapshot_2, jta);
			
			//
			//Phase D: Investigation Summary - MFT
			//
			snapshot_analysis_summary_MFT(director_snapshot_1, director_snapshot_2, jta);
			
			//
			//Phase E: Investigation Summary - Files
			//
			snapshot_analysis_summary_FILESCAN(director_snapshot_1, director_snapshot_2, jta);
			
			
			
			jta.append("\n* * * INVESTIGATION SUMMARY COMPLETE * * * \n" + Driver.UNDERLINE);
			jta.append(Driver.UNDERLINE);
			jta.append(Driver.UNDERLINE + "\n");
			
			
			/////////////////////
			////////////////////
			/////////////
			
			//need to return and adjust sensitivity of comparisons!
			
			//
			//Phase 0: Analyze Investigation Particulars
			//
			snapshot_analysis_investigation_particulars(director_snapshot_1, director_snapshot_2);
									
			//
			//Phase 1b: Check for Additions and Missing
			//
			snapshot_analysis_CHECK_ARTIFACTS(director_snapshot_1, director_snapshot_2);
			
			//
			//Phase 2: Deep Dive - Check for Modified
			//
			execute_deep_inspection_analysis(director_snapshot_1, director_snapshot_2);
			
			//
			//Phase 3: Analyze Files (filescan, timeliner, shellbags, shimcache, etc)
			//
			analyze_file_entries(director_snapshot_1, director_snapshot_2);
			
			
			//
			//print results
			//						
			sop("\nInspection Complete! Printing Reports now...");
			this.PRINT_REPORT();

			//
			//GC!
			//
			try
			{
				System.gc();
			}catch(Exception eee){}

			
			return true;
			
					}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "commence_action", e);
		}
		
		return false;
	}
	
	public boolean snapshot_analysis_summary_PROCESS(Advanced_Analysis_Director director_1, Advanced_Analysis_Director director_2, JTextArea_Solomon jta)
	{
		try
		{
			TreeMap<Integer, Node_Process> tree_1 = null;
			TreeMap<Integer, Node_Process> tree_2 = null;
			
			try	{	 tree_1 = director_1.tree_PROCESS	;	} catch(Exception e){tree_1 = null;}
			try	{	 tree_2 = director_2.tree_PROCESS	;	} catch(Exception e){tree_2 = null;}
			
			if(tree_1 == null && tree_2 != null)
			{
				jta.append("\nPROCESS\n" + Driver.UNDERLINE);
				jta.append("Entire Process structure is added in snapshot 2 yet is missing from snapshot 1!");
				return true;
			}
			
			else if(tree_1 != null && tree_2 == null)
			{
				jta.append("\nPROCESS\n" + Driver.UNDERLINE);
				jta.append("Entire Process structure is missing in snapshot 2 yet is present from snapshot 1!");
				return true;
			}
			
			
			TreeMap<Integer, String> tree_pid_keys = new TreeMap<Integer, String>();
			
			TreeMap<Integer, Node_Process> tree_process_add = new TreeMap<Integer, Node_Process>();
			TreeMap<Integer, Node_Process> tree_process_miss = new TreeMap<Integer, Node_Process>();
			
			try
			{
				for(int pid : tree_1.keySet())
				{
					tree_pid_keys.put(pid,  null);
				}
			}catch(Exception e){}
			
			try
			{
				for(int pid : tree_2.keySet())
				{
					tree_pid_keys.put(pid,  null);
				}
			}catch(Exception e){}
			
			
			TreeMap<String, Node_Generic> tree_dll_add = new TreeMap<String, Node_Generic>();
			TreeMap<String, Node_Generic> tree_dll_miss = new TreeMap<String, Node_Generic>();
			
			Node_Process process_1 = null;
			Node_Process process_2 = null;
			
			TreeMap<String, Node_DLL> tree_dll_1 = null;
			TreeMap<String, Node_DLL> tree_dll_2 = null;
			
			for(int pid : tree_pid_keys.keySet())
			{
				process_1 = tree_1.get(pid);
				process_2 = tree_2.get(pid);
				
				if(process_1 == null && process_2 != null)
				{
					tree_process_add.put(pid,  process_2);
					continue;
				}
				
				else if(process_1 != null && process_2 == null)
				{
					tree_process_miss.put(pid,  process_1);
					continue;
				}
				
				String process_name = "";
				
				//otw, check dlls!
				try	{	tree_dll_1 = process_1.tree_dll;	process_name = process_1.get_process_html_header(); } catch(Exception e)	{ tree_dll_1 = null;	}
				try	{	tree_dll_2 = process_2.tree_dll;	process_name = process_2.get_process_html_header(); } catch(Exception e)	{ tree_dll_2 = null;	}
				
				if(tree_dll_1 == null && tree_dll_2 == null)
					continue;
				
				if(tree_dll_1 == null && tree_dll_2 != null)
				{
					Node_Generic node = new Node_Generic("Snapshot Analysis");
					node.list_details = new LinkedList<String>();
					node.list_details.add("Entire new DLL structure is present in Snapshot 2 that is missing from Snapshot 1!");
					tree_dll_add.put(process_2.get_process_html_header(),  node);
					continue;
				}
				else if(tree_dll_1 != null && tree_dll_2 == null)
				{
					Node_Generic node = new Node_Generic("Snapshot Analysis");
					node.list_details = new LinkedList<String>();
					node.list_details.add("Entire new DLL structure is missing from Snapshot 2 that is present in Snapshot 1!");
					tree_dll_miss.put(process_1.get_process_html_header(),  node);
					continue;
				}
				
				//build paths
				TreeMap<String, String> tree_path = new TreeMap<String, String>();
				
				for(String path : tree_dll_1.keySet())
					tree_path.put(path,  null);
				
				for(String path : tree_dll_2.keySet())
					tree_path.put(path,  null);
				
				Node_Generic node = null;
				
				//check paths for each process!
				for(String path : tree_path.keySet())
				{
					if(!tree_dll_1.containsKey(path))
					{
						//new path
						node = tree_dll_add.get(process_name);
						
						if(node == null)
						{
							node = new Node_Generic("Snapshot Analysis");
							node.process_name = process_name;
							node.list_details = new LinkedList<String>();
							tree_dll_add.put(process_name, node);
						}
						
						node.list_details.add(path);
					}
					
					if(!tree_dll_2.containsKey(path))
					{
						//new path
						node = tree_dll_miss.get(process_name);
						
						if(node == null)
						{
							node = new Node_Generic("Snapshot Analysis");
							node.process_name = process_name;
							node.list_details = new LinkedList<String>();
							tree_dll_miss.put(process_name, node);
						}
						
						node.list_details.add(path);
					}
					
					
					
				}//end for on dll
				
				
			}//end outter for on process
			
			
			//
			//NOTIFY
			//
			
			if(tree_process_add != null && tree_process_add.size() > 0)
			{
				jta.append("\nADDED PROCESSES\n" + Driver.UNDERLINE);
				
				for(Node_Process process: tree_process_add.values())
				{
					jta.append(process.get_process_html_header());
				}
			}
			
			if(tree_process_miss != null && tree_process_add.size() > 0)
			{
				jta.append("\nMISSING PROCESSES\n" + Driver.UNDERLINE);
				
				for(Node_Process process: tree_process_miss.values())
				{
					jta.append(process.get_process_html_header());
				}
			}
			
			//
			//DLL MODIFICATIONS!
			//
			if(tree_dll_add != null && tree_dll_add.size() > 0)
			{
				jta.append_sp("\nADDED DLLS TO EACH PROCESS\n" + Driver.UNDERLINE);
				
				for(Node_Generic node: tree_dll_add.values())
				{
					jta.append("\n" + node.process_name);
					
					if(node.list_details == null || node.list_details.isEmpty())
						continue;
					
					for(String entry : node.list_details)
					{
						jta.append("\t" + entry);
					}
				}								
			}
						
			
			if(tree_dll_miss != null && tree_dll_miss.size() > 0)
			{
				jta.append_sp("\nMISSING DLLS FROM EACH PROCESS\n" + Driver.UNDERLINE);
				
				for(Node_Generic node: tree_dll_miss.values())
				{
					jta.append("\n" + node.process_name);
					
					if(node.list_details == null || node.list_details.isEmpty())
						continue;
					
					for(String entry : node.list_details)
					{
						jta.append("\t" + entry);
					}
					
					
				}
				
				//jta.append("\n");
			}
			
			
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "snapshot_analysis_summary_PROCESS", e);
		}
		
		return false;
		
	}
	
	public boolean snapshot_analysis_summary_MFT(Advanced_Analysis_Director director_1, Advanced_Analysis_Director director_2, JTextArea_Solomon jta)
	{
		try
		{
			TreeMap<String, Node_Generic> MFT_1 = null;
			TreeMap<String, Node_Generic> MFT_2 = null;
			
			try	{	MFT_1 = director_1.tree_mftparser	;	}	catch(Exception e)	{	MFT_1 = null;	}
			try	{	MFT_2 = director_2.tree_mftparser	;	}	catch(Exception e)	{	MFT_2 = null;	}
			
			if(MFT_1 == null && MFT_2 != null)
			{
				jta.append("\nMFT\n" + Driver.UNDERLINE);
				jta.append("Entire MFT structure is added in snapshot 2 that was not present in snapshot 1!");
				return true;
			}
			
			else if(MFT_1 != null && MFT_2 == null)
			{
				jta.append("\nMFT\n" + Driver.UNDERLINE);
				jta.append("Entire MFT structure is missing in snapshot 2 that was present in snapshot 1!");
				return true;
			}
			
			//"1 == snapshot 1 only, 2 snapshot 2 only, 3 == both";
			TreeMap<String, Integer> tree_files_mft = new TreeMap<String, Integer>();
			
			try
			{
				for(Node_Generic node : MFT_1.values())
				{
					tree_files_mft.put(node.path.toLowerCase().trim(), 1);
				}
				
			}catch(Exception e){}
			
			try
			{
				String path = "";
				for(Node_Generic node : MFT_2.values())
				{
					path = node.path.toLowerCase().trim();
					
					//only include file paths
					if(!path.contains("\\"))
						continue;
					
					if(tree_files_mft.containsKey(path))
						tree_files_mft.put(path, 3);
					else
						tree_files_mft.put(path, 2);
				}
				
			}catch(Exception e){}
			
			
			//analyze results
			TreeMap<String, String> tree_files_mft_addition = new TreeMap<String, String>();
			TreeMap<String, String> tree_files_mft_missing = new TreeMap<String, String>();
			
			for(String path : tree_files_mft.keySet())
			{
				int value = tree_files_mft.get(path);
				
				//only include file paths
				if(!path.contains("\\"))
					continue;
				
				if(value == 1)
					tree_files_mft_missing.put(path, null);
				else if(value == 2)
					tree_files_mft_addition.put(path, null);
				
				//otw, both had the path!
			}
			
			//notify results
			
			if(tree_files_mft_addition != null && tree_files_mft_addition.size() > 0)
			{
				jta.append("\nADDITIONAL MFT ENTRIES DETECTED\n" + Driver.UNDERLINE);
				
				for(String path : tree_files_mft_addition.keySet())
				{
					jta.append(path);
				}
			}
			
			
			if(tree_files_mft_missing != null && tree_files_mft_missing.size() > 0)
			{
				jta.append("\nMISSING MFT ENTRIES DETECTED\n" + Driver.UNDERLINE);
				
				for(String path : tree_files_mft_missing.keySet())
				{
					jta.append(path);
				}
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "snapshot_analysis_summary_MFT", e);
		}
		
		return false;
	}
	
	public boolean snapshot_analysis_summary_FILESCAN(Advanced_Analysis_Director director_1, Advanced_Analysis_Director director_2, JTextArea_Solomon jta)
	{
		try
		{
			TreeMap<String, Node_Generic> filescan_1 = null;
			TreeMap<String, Node_Generic> filescan_2 = null;
			
			try	{	filescan_1 = director_1.tree_filescan	;	}	catch(Exception e)	{	filescan_1 = null;	}
			try	{	filescan_2 = director_2.tree_filescan	;	}	catch(Exception e)	{	filescan_2 = null;	}
			
			if(filescan_1 == null && filescan_2 != null)
			{
				jta.append("\nFILESCAN\n" + Driver.UNDERLINE);
				jta.append("Entire Filescan structure is added in snapshot 2 that was not present in snapshot 1!");
				return true;
			}
			
			else if(filescan_1 != null && filescan_2 == null)
			{
				jta.append("\nFILESCAN\n" + Driver.UNDERLINE);
				jta.append("Entire Filescan structure is missing in snapshot 2 that was present in snapshot 1!");
				return true;
			}
			
			//"1 == snapshot 1 only, 2 snapshot 2 only, 3 == both";
			TreeMap<String, Integer> tree_files_filescan = new TreeMap<String, Integer>();
			
			try
			{
				for(Node_Generic node : filescan_1.values())
				{
					tree_files_filescan.put(node.path.toLowerCase().trim(), 1);
				}
				
			}catch(Exception e){}
			
			try
			{
				String path = "";
				for(Node_Generic node : filescan_2.values())
				{
					path = node.path.toLowerCase().trim();
					
					if(tree_files_filescan.containsKey(path))
						tree_files_filescan.put(path, 3);
					else
						tree_files_filescan.put(path, 2);
				}
				
			}catch(Exception e){}
			
			
			//analyze results
			TreeMap<String, String> tree_files_filescan_addition = new TreeMap<String, String>();
			TreeMap<String, String> tree_files_filescan_missing = new TreeMap<String, String>();
			
			for(String path : tree_files_filescan.keySet())
			{
				int value = tree_files_filescan.get(path);
				
				if(value == 1)
					tree_files_filescan_missing.put(path, null);
				else if(value == 2)
					tree_files_filescan_addition.put(path, null);
				
				//otw, both had the path!
			}
			
			//notify results
			
			if(tree_files_filescan_addition != null && tree_files_filescan_addition.size() > 0)
			{
				jta.append("\nADDITIONAL FILESCAN ENTRIES DETECTED\n" + Driver.UNDERLINE);
				
				for(String path : tree_files_filescan_addition.keySet())
				{
					jta.append(path);
				}
			}
			
			
			if(tree_files_filescan_missing != null && tree_files_filescan_missing.size() > 0)
			{
				jta.append("\nMISSING FILESCAN ENTRIES DETECTED\n" + Driver.UNDERLINE);
				
				for(String path : tree_files_filescan_missing.keySet())
				{
					jta.append(path);
				}
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "snapshot_analysis_summary_FILESCAN", e);
		}
		
		return false;
	}
	
	public boolean analyze_file_entries(Advanced_Analysis_Director director_1, Advanced_Analysis_Director director_2)
	{
		try
		{
			DEEP_INSPECTION_NODE_GENERIC_FILE_TYPES(director_snapshot_1, director_snapshot_2, "FileScan", director_snapshot_1.tree_filescan, director_snapshot_2.tree_filescan, Node_Snapshot_Analysis_Artifact.ARTIFACT_TYPE_filescan, Node_Snapshot_Analysis_Artifact.initialization_index_filescan, this.tree_filescan_addition, this.tree_filescan_missing, this.tree_filescan_MODIFICATION);
			DEEP_INSPECTION_NODE_GENERIC_FILE_TYPES(director_snapshot_1, director_snapshot_2, "MFTParser", director_snapshot_1.tree_mftparser, director_snapshot_2.tree_mftparser, Node_Snapshot_Analysis_Artifact.ARTIFACT_TYPE_mftparser, Node_Snapshot_Analysis_Artifact.initialization_index_mftparser, this.tree_mftparser_addition, this.tree_mftparser_missing, this.tree_mftparser_MODIFICATION);
			
			DEEP_INSPECTION_NODE_GENERIC_FILE_TYPES(director_snapshot_1, director_snapshot_2, "timeliner", director_snapshot_1.tree_timeliner, director_snapshot_2.tree_timeliner, Node_Snapshot_Analysis_Artifact.ARTIFACT_TYPE_timeliner, Node_Snapshot_Analysis_Artifact.initialization_index_timeliner, this.tree_timeliner_addition, this.tree_timeliner_missing, this.tree_timeliner_MODIFICATION);
			DEEP_INSPECTION_NODE_GENERIC_FILE_TYPES(director_snapshot_1, director_snapshot_2, "userassist_specific_entries", director_snapshot_1.tree_userassist_specific_entries, director_snapshot_2.tree_userassist_specific_entries, Node_Snapshot_Analysis_Artifact.ARTIFACT_TYPE_userassist_specific_entries, Node_Snapshot_Analysis_Artifact.initialization_index_userassist_specific_entries, this.tree_userassist_specific_entries_addition, this.tree_userassist_specific_entries_missing, this.tree_userassist_specific_entries_MODIFICATION);
			
			DEEP_INSPECTION_NODE_GENERIC_FILE_TYPES(director_snapshot_1, director_snapshot_2, "shellbags", director_snapshot_1.tree_shellbags_TYPE_1, director_snapshot_2.tree_shellbags_TYPE_1, Node_Snapshot_Analysis_Artifact.ARTIFACT_TYPE_shellbags, Node_Snapshot_Analysis_Artifact.initialization_index_shellbags, this.tree_shellbags_addition, this.tree_shellbags_missing, this.tree_shellbags_MODIFICATION);
			DEEP_INSPECTION_NODE_GENERIC_FILE_TYPES(director_snapshot_1, director_snapshot_2, "shellbags", director_snapshot_1.tree_shellbags_TYPE_2, director_snapshot_2.tree_shellbags_TYPE_2, Node_Snapshot_Analysis_Artifact.ARTIFACT_TYPE_shellbags, Node_Snapshot_Analysis_Artifact.initialization_index_shellbags, this.tree_shellbags_addition, this.tree_shellbags_missing, this.tree_shellbags_MODIFICATION);
			DEEP_INSPECTION_NODE_GENERIC_FILE_TYPES(director_snapshot_1, director_snapshot_2, "shellbags", director_snapshot_1.tree_shellbags_TYPE_3, director_snapshot_2.tree_shellbags_TYPE_3, Node_Snapshot_Analysis_Artifact.ARTIFACT_TYPE_shellbags, Node_Snapshot_Analysis_Artifact.initialization_index_shellbags, this.tree_shellbags_addition, this.tree_shellbags_missing, this.tree_shellbags_MODIFICATION);
			DEEP_INSPECTION_NODE_GENERIC_FILE_TYPES(director_snapshot_1, director_snapshot_2, "shellbags", director_snapshot_1.tree_shellbags_TYPE_4, director_snapshot_2.tree_shellbags_TYPE_4, Node_Snapshot_Analysis_Artifact.ARTIFACT_TYPE_shellbags, Node_Snapshot_Analysis_Artifact.initialization_index_shellbags, this.tree_shellbags_addition, this.tree_shellbags_missing, this.tree_shellbags_MODIFICATION);
			
			DEEP_INSPECTION_NODE_GENERIC_FILE_TYPES(director_snapshot_1, director_snapshot_2, "shimcache", director_snapshot_1.tree_shimcache, director_snapshot_2.tree_shimcache, Node_Snapshot_Analysis_Artifact.ARTIFACT_TYPE_shimcache, Node_Snapshot_Analysis_Artifact.initialization_index_shimcache, this.tree_shimcache_addition, this.tree_shimcache_missing, this.tree_shimcache_MODIFICATION);
			
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_file_entries", e);
		}
		
		return false;
	}
	
	public boolean execute_deep_inspection_analysis(Advanced_Analysis_Director director_1, Advanced_Analysis_Director director_2)
	{
		try
		{
			
			DEEP_INSPECTION_PROCESS(director_snapshot_1, director_snapshot_2);
			DEEP_INSPECTION_DLL(director_snapshot_1, director_snapshot_2);
			DEEP_INSPECTION_DRIVER(director_snapshot_1, director_snapshot_2, "Driver", director_snapshot_1.tree_DRIVERS, director_snapshot_2.tree_DRIVERS, Node_Snapshot_Analysis_Artifact.ARTIFACT_TYPE_DRIVER, Node_Snapshot_Analysis_Artifact.initialization_index_driver, this.tree_DRIVER);
			DEEP_INSPECTION_DRIVER(director_snapshot_1, director_snapshot_2, "Driver IRP HOOK", director_snapshot_1.tree_DRIVER_IRP_HOOK, director_snapshot_2.tree_DRIVER_IRP_HOOK, Node_Snapshot_Analysis_Artifact.ARTIFACT_TYPE_DRIVER_IRP, Node_Snapshot_Analysis_Artifact.initialization_index_driver_irp, this.tree_DRIVER_IRP);
			DEEP_INSPECTION_DRIVER(director_snapshot_1, director_snapshot_2, "Callback", director_snapshot_1.tree_CALLBACKS, director_snapshot_2.tree_CALLBACKS, Node_Snapshot_Analysis_Artifact.ARTIFACT_TYPE_CALLBACKS, Node_Snapshot_Analysis_Artifact.initialization_index_callbacks, this.tree_CALLBACKS);
			DEEP_INSPECTION_DRIVER(director_snapshot_1, director_snapshot_2, "Timer", director_snapshot_1.tree_TIMERS, director_snapshot_2.tree_TIMERS, Node_Snapshot_Analysis_Artifact.ARTIFACT_TYPE_TIMERS, Node_Snapshot_Analysis_Artifact.initialization_index_timers, this.tree_TIMERS);
			DEEP_INSPECTION_DRIVER(director_snapshot_1, director_snapshot_2, "Unloaded Module", director_snapshot_1.tree_UNLOADED_MODULES, director_snapshot_2.tree_UNLOADED_MODULES, Node_Snapshot_Analysis_Artifact.ARTIFACT_TYPE_UNLOADED_MODULES, Node_Snapshot_Analysis_Artifact.initialization_index_unloaded_modules, this.tree_UNLOADED_MODULES);
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "execute_deep_inspection_analysis", e);
		}
		
		return false;
	}
	
			
	
	public boolean snapshot_analysis_CHECK_ARTIFACTS(Advanced_Analysis_Director director_1, Advanced_Analysis_Director director_2)
	{
		try
		{
			///////////////////////////////////////////////////////
			// Phase 1 - Check Outter Lists
			///////////////////////////////////////////////////////
			
			//
			//PROCESS
			//
			snapshot_analysis_director_check_PROCESS(director_snapshot_1, director_snapshot_2);
			
			//
			//DLL
			//
			snapshot_analysis_director_check_DLL_PATHS(director_snapshot_1, director_snapshot_2);
			
			//
			//DRIVER
			//
			snapshot_analysis_director_check_DRIVER(director_snapshot_1, director_snapshot_2);
			
			//
			//Node_Generic
			//
			snapshot_analysis_director_check_NODE_GENERIC(director_snapshot_1, director_snapshot_2);
			
			//
			//Registry
			//
			snapshot_analysis_director_check_REGISTRY(director_snapshot_1, director_snapshot_2);
			
			//
			//HIVELIST
			//
			snapshot_analysis_director_check_HIVELIST(director_snapshot_1, director_snapshot_2);
			
			//
			//GET SERVICE SID
			//
			snapshot_analysis_director_check_GET_SERVICE_SID(director_snapshot_1, director_snapshot_2);
			
			//
			//HASHDUMP
			//
			this.analysis_check_Tree_String("tree_hashdump", director_snapshot_1.tree_hashdump, director_snapshot_2.tree_hashdump, this.tree_addition_HASHDUMP, tree_missing_HASHDUMP, tree_MODIFIED_HASHDUMP, true);
			
			//
			//SIDS
			//
			//NOTE: these trees are populated from process - the final # SIDS are dummy vars printed out in the manifest
			this.analysis_check_Tree_String("tree_SIDS", director_snapshot_1.tree_SIDS, director_snapshot_2.tree_SIDS, this.tree_addition_SIDS, tree_missing_SIDS, tree_MODIFIED_SIDS, false);
			
			//
			//HIVELIST
			//
			snapshot_analysis_director_check_SESSIONS(director_snapshot_1, director_snapshot_2);
			
						
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "snapshot_analysis_CHECK_ARTIFACTS", e);
		}
		
		return false;
	}
	
	public boolean DEEP_INSPECTION_PROCESS(Advanced_Analysis_Director director_1, Advanced_Analysis_Director director_2)
	{
		try
		{
			//we've already checked if there is an added or removed process, now we need to compare values within each process
			if(director_1 == null || director_2 == null || director_1.tree_PROCESS == null || director_2.tree_PROCESS == null)
				return false;
			
			sop("Commencing Deep Inspection of PROCESSES");
			
			Node_Process process_1 = null, process_2 = null;
			
			for(int PID_2 : director_2.tree_PROCESS.keySet())
			{
				try
				{
					process_2 = director_2.tree_PROCESS.get(PID_2);
					process_1 = director_1.tree_PROCESS.get(PID_2);
					
					if(process_2 == null)
					{
						driver.directive("Omitting analysis for PID_2 [" + PID_2 + "] - missing process");
						continue;
					}
					
					if(process_1 == null)
					{
						driver.directive("Omitting analysis for PID_1 [" + PID_2 + "] - missing process");
						continue;
					}
					
					
					//
					//process particulars
					//
					analyze_process_PARTICULARS(process_1, process_2, Node_Snapshot_Analysis_Artifact.initialization_index_process_particulars, this.tree_PROCESS, (""+process_2.PID), Node_Snapshot_Analysis_Artifact.ARTIFACT_TYPE_PROCESS);
															
					//
					//my_vad_info
					//
					analyze_process_my_VAD_INFO(process_1, process_2, Node_Snapshot_Analysis_Artifact.initialization_index_my_vad_info, this.tree_PROCESS, (""+process_2.PID), Node_Snapshot_Analysis_Artifact.ARTIFACT_TYPE_PROCESS, "My VAD_Info");
					
					//
					//netstat
					//
					analyze_process_NETSTAT(process_1, process_2, Node_Snapshot_Analysis_Artifact.initialization_index_netstat, this.tree_PROCESS, (""+process_2.PID), Node_Snapshot_Analysis_Artifact.ARTIFACT_TYPE_PROCESS);
					
					//
					//Handles
					//
					analyze_process_HANDLES(process_1, process_2, Node_Snapshot_Analysis_Artifact.initialization_index_handles, this.tree_PROCESS, (""+process_2.PID), Node_Snapshot_Analysis_Artifact.ARTIFACT_TYPE_PROCESS);
					
					//
					//Privs
					//
					analyze_process_PRIVILEGE(process_1, process_2, Node_Snapshot_Analysis_Artifact.initialization_index_privs, this.tree_PROCESS, (""+process_2.PID), Node_Snapshot_Analysis_Artifact.ARTIFACT_TYPE_PROCESS);
					
					//
					//Service Scan
					//
					analyze_process_SERVICE_SCAN(process_1, process_2, Node_Snapshot_Analysis_Artifact.initialization_index_svcscan, this.tree_PROCESS, (""+process_2.PID), Node_Snapshot_Analysis_Artifact.ARTIFACT_TYPE_PROCESS);
					
					//
					//SIDS
					//
					analyze_process_SIDS(process_1, process_2, Node_Snapshot_Analysis_Artifact.initialization_index_sids, this.tree_PROCESS, (""+process_2.PID), Node_Snapshot_Analysis_Artifact.ARTIFACT_TYPE_PROCESS);
					
					//
					//malfind
					//
					analyze_process_MALFIND(process_1, process_2, Node_Snapshot_Analysis_Artifact.initialization_index_malfind, this.tree_PROCESS, (""+process_2.PID), Node_Snapshot_Analysis_Artifact.ARTIFACT_TYPE_PROCESS);
					
					//
					//threads
					//
					analyze_process_THREADS(process_1, process_2, Node_Snapshot_Analysis_Artifact.initialization_index_threads, this.tree_PROCESS, (""+process_2.PID), Node_Snapshot_Analysis_Artifact.ARTIFACT_TYPE_PROCESS);
					
					
					//
					//GDI Timers
					//
					analyze_process_GDI_TIMERS(process_1, process_2, Node_Snapshot_Analysis_Artifact.initialization_index_gdi_timers, this.tree_PROCESS, (""+process_2.PID), Node_Snapshot_Analysis_Artifact.ARTIFACT_TYPE_PROCESS);
					
					//
					//APIHooks
					//
					analyze_process_API_HOOKS(process_1, process_2, Node_Snapshot_Analysis_Artifact.initialization_index_api_hooks, this.tree_PROCESS, (""+process_2.PID), Node_Snapshot_Analysis_Artifact.ARTIFACT_TYPE_PROCESS);
					
					//
					//vad_info
					//
					analyze_process_NODE_GENERIC(process_1, process_2, Node_Snapshot_Analysis_Artifact.initialization_index_vad_info, this.tree_PROCESS, (""+process_2.PID), Node_Snapshot_Analysis_Artifact.ARTIFACT_TYPE_PROCESS, "VAD_Info");
					
					//
					//deskscan
					//
					analyze_process_DESKSCAN_PART_1(process_1, process_2, Node_Snapshot_Analysis_Artifact.initialization_index_deskscan, this.tree_PROCESS, (""+process_2.PID), Node_Snapshot_Analysis_Artifact.ARTIFACT_TYPE_PROCESS, "Deskscan");
					
					//
					//list_cmd_scan
					//
					
					//
					//tree_cmdscan_consoles
					//
					
					//
					//envars
					//
					analyze_process_ENVARS(process_1, process_2, Node_Snapshot_Analysis_Artifact.initialization_index_envars, this.tree_PROCESS, (""+process_2.PID), Node_Snapshot_Analysis_Artifact.ARTIFACT_TYPE_PROCESS);
					
					//
					//import functions
					//
					analyze_process_IMPSCAN(process_1, process_2, Node_Snapshot_Analysis_Artifact.initialization_index_import_functions, this.tree_PROCESS, (""+process_2.PID), Node_Snapshot_Analysis_Artifact.ARTIFACT_TYPE_PROCESS);
					
					
					
				}
				catch(Exception e)
				{
					driver.directive("Error caught in analysis_compare_PROCESS while analyzing PID_2: [" + PID_2 + "]");
				}
			}
			
			sop("\nDONE! Deep Inspection of PROCESSES Complete.");
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "DEEP_INSPECTION_PROCESS", e);
		}
		
		sop("\n* * * DONE!Deep Inspection of PROCESSES Complete.");
		return false;
	}
	
	
	public boolean DEEP_INSPECTION_DLL(Advanced_Analysis_Director director_1, Advanced_Analysis_Director director_2)
	{
		try
		{
			//we've already checked if there is an added or removed process, now we need to compare values within each process
			if(director_1 == null || director_2 == null || director_1.tree_DLL_by_path == null || director_2.tree_DLL_by_path == null)
				return false;			
			
			
			int INITIALIZATION_INDEX = Node_Snapshot_Analysis_Artifact.initialization_index_dll;
			TreeMap<String, Node_Snapshot_Analysis_Artifact>  TREE_ANALYSIS = this.tree_DLL;
			String ARTIFACT_TYPE = Node_Snapshot_Analysis_Artifact.ARTIFACT_TYPE_DLL;

			
			//notify
			sop("\nCommencing Deep Inspection of DLL modules.");
			
			//
			//Set analysis trees
			//
			TreeMap<String, Node_DLL> tree_1 = director_1.tree_DLL_by_path, tree_2 = director_2.tree_DLL_by_path;
			Node_DLL entry_1 = null, entry_2 = null;
								
			//
			//populate all keys first
			//
			TreeMap<String, String> tree_KEY_SET = new TreeMap<String, String>();
			
			try
			{
				for(String key : tree_1.keySet())
					tree_KEY_SET.put(key, null);					
			}catch(Exception e){}
			
			try
			{
				for(String key : tree_2.keySet())
					tree_KEY_SET.put(key, null);					
			}catch(Exception e){}
			
			//
			//analyze
			//
			for(String key : tree_KEY_SET.keySet())
			{
				try	{	entry_1 = tree_1.get(key);	} catch(Exception e){}
				try	{	entry_2 = tree_2.get(key);	} catch(Exception e){}
				
				//
				//procure
				//
				Node_Snapshot_Analysis_Artifact node = TREE_ANALYSIS.get(key);
												
				//
				//initialize if necessary
				//
				if(node == null)
				{
					//use the instances to handle the comparison and building of the trees
					node = new Node_Snapshot_Analysis_Artifact(this, key, ARTIFACT_TYPE);												
					
					node.dll_1 = entry_1; 
					node.dll_2 = entry_2;
					
					node.initialize_structures(INITIALIZATION_INDEX);
					TREE_ANALYSIS.put(key,  node);	
					
					try
					{
						if(key.contains("\\"))
						{
							String short_key = key.substring(key.lastIndexOf("\\")+1).trim();
							node.short_descriptor = short_key;
						}
					}catch(Exception ee){}
				}				
				
				//
				//update initialization trees
				//
				node.set_my_tree_pointers(INITIALIZATION_INDEX);
											
				//
				//analyze structures!
				//
				this.compare_module_description_DEEP_INSPECTION(node, INITIALIZATION_INDEX, entry_1, entry_2, ARTIFACT_TYPE);												
			}
			
			
			
			
			
			sop("\nDONE! Deep Inspection of DLL modules complete.");
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "DEEP_INSPECTION_DLL", e);
		}
		
		sop("\n* * * DONE! Deep Inspection of DLL modules complete.");
		return false;
	}
	
	
	/**
	 * continuation mtd - assumes process 1 and 2 are NOT NULL!
	 * @param process_1
	 * @param process_2
	 * @param INITIALIZATION_INDEX
	 * @param tree
	 * @param key
	 * @param ARTIFACT_TYPE
	 * @return
	 */
	public boolean analyze_process_PARTICULARS(Node_Process process_1, Node_Process process_2, int INITIALIZATION_INDEX, TreeMap<String, Node_Snapshot_Analysis_Artifact> tree, String key, String ARTIFACT_TYPE)
	{
		try
		{						
			//
			//procure
			//
			Node_Snapshot_Analysis_Artifact node = tree.get(key);
			
			//
			//initialize if necessary
			//
			if(node == null)
			{
				//use the instances to handle the comparison and building of the trees
				node = new Node_Snapshot_Analysis_Artifact(this, process_2.get_process_html_header(), ARTIFACT_TYPE);
				
				//adjust name if needed
				try
				{
					if((node.descriptor == null || node.descriptor.toLowerCase().trim().endsWith("unknown")) && !process_1.get_process_html_header().toLowerCase().trim().endsWith("unknown"))
						node.descriptor = process_1.get_process_html_header();	
				}catch(Exception e){}				
				
				node.process_1 = process_1; 
				node.proces_2 = process_2;
				
				node.initialize_structures(INITIALIZATION_INDEX);
				tree.put(key,  node);				
			}
			
			//
			//invoke compare routine
			//
			node.compare_artifacts(INITIALIZATION_INDEX, "process_name", process_1.process_name, process_2.process_name, null);
			node.compare_artifacts(INITIALIZATION_INDEX, "PPID", ""+process_1.PPID, ""+process_2.PPID, null);
			node.compare_artifacts(INITIALIZATION_INDEX, "command_line", process_1.command_line, process_2.command_line, null);
			node.compare_artifacts(INITIALIZATION_INDEX, "file_name", process_1.file_name, process_2.file_name, null);
			node.compare_artifacts(INITIALIZATION_INDEX, "extension", process_1.extension, process_2.extension, null);
			node.compare_artifacts(INITIALIZATION_INDEX, "wow64", process_1.wow64, process_2.wow64, null);
			node.compare_artifacts(INITIALIZATION_INDEX, "session", process_1.session, process_2.session, null);
			node.compare_artifacts(INITIALIZATION_INDEX, "offset_pslist", process_1.offset_pslist, process_2.offset_pslist, null);
			node.compare_artifacts(INITIALIZATION_INDEX, "PDB", process_1.PDB, process_2.PDB, null);
			node.compare_artifacts(INITIALIZATION_INDEX, "time_created_date", process_1.time_created_date, process_2.time_created_date, null);
			node.compare_artifacts(INITIALIZATION_INDEX, "time_created_time", process_1.time_created_time, process_2.time_created_time, null);
			node.compare_artifacts(INITIALIZATION_INDEX, "time_created_UTC", process_1.time_created_UTC, process_2.time_created_UTC, null);
			node.compare_artifacts(INITIALIZATION_INDEX, "time_exited_date", process_1.time_exited_date, process_2.time_exited_date, null);
			node.compare_artifacts(INITIALIZATION_INDEX, "time_exited_time", process_1.time_exited_time, process_2.time_exited_time, null);
			node.compare_artifacts(INITIALIZATION_INDEX, "time_exited_UTC", process_1.time_exited_UTC, process_2.time_exited_UTC, null);
			node.compare_artifacts(INITIALIZATION_INDEX, "offset_psscan", process_1.offset_psscan, process_2.offset_psscan, null);
			node.compare_artifacts(INITIALIZATION_INDEX, "offset_pstree", process_1.offset_pstree, process_2.offset_pstree, null);
			node.compare_artifacts(INITIALIZATION_INDEX, "offset_psxview", process_1.offset_psxview, process_2.offset_psxview, null);
			node.compare_artifacts(INITIALIZATION_INDEX, "psxview_pslist", process_1.psxview_pslist, process_2.psxview_pslist, null);
			node.compare_artifacts(INITIALIZATION_INDEX, "psxview_psscan", process_1.psxview_psscan, process_2.psxview_psscan, null);
			node.compare_artifacts(INITIALIZATION_INDEX, "psxview_thrdproc", process_1.psxview_thrdproc, process_2.psxview_thrdproc, null);
			node.compare_artifacts(INITIALIZATION_INDEX, "psxview_pspcid", process_1.psxview_pspcid, process_2.psxview_pspcid, null);
			node.compare_artifacts(INITIALIZATION_INDEX, "psxview_csrss", process_1.psxview_csrss, process_2.psxview_csrss, null);
			node.compare_artifacts(INITIALIZATION_INDEX, "psxview_session", process_1.psxview_session, process_2.psxview_session, null);
			node.compare_artifacts(INITIALIZATION_INDEX, "psxview_deskthrd", process_1.psxview_deskthrd, process_2.psxview_deskthrd, null);
			node.compare_artifacts(INITIALIZATION_INDEX, "offset_V_dlldump", process_1.offset_V_dlldump, process_2.offset_V_dlldump, null);
			node.compare_artifacts(INITIALIZATION_INDEX, "offset_P_dlldump_trimmed", process_1.offset_P_dlldump_trimmed, process_2.offset_P_dlldump_trimmed, null);
			node.compare_artifacts(INITIALIZATION_INDEX, "module_base_address_dlldump", process_1.module_base_address_dlldump, process_2.module_base_address_dlldump, null);
			node.compare_artifacts(INITIALIZATION_INDEX, "module_base_address_dlldump_trimmed", process_1.module_base_address_dlldump_trimmed, process_2.module_base_address_dlldump_trimmed, null);
			node.compare_artifacts(INITIALIZATION_INDEX, "path", process_1.path, process_2.path, null);
			node.compare_artifacts(INITIALIZATION_INDEX, "found_in_pslist", ""+process_1.found_in_pslist, ""+process_2.found_in_pslist, null);
			node.compare_artifacts(INITIALIZATION_INDEX, "found_in_psscan", ""+process_1.found_in_psscan, ""+process_2.found_in_psscan, null);
			node.compare_artifacts(INITIALIZATION_INDEX, "relative_path_vadtree_image", process_1.relative_path_vadtree_image, process_2.relative_path_vadtree_image, null);

			int process_1_thread_count = 0, process_2_thread_count = 0;
			int process_1_handle_count = 0, process_2_handle_count = 0;
			
			try
			{
				process_1_thread_count = process_1.tree_threads.size();
			}catch(Exception e){}
			
			try
			{
				process_2_thread_count = process_2.tree_threads.size();
			}catch(Exception e){}
			
			try
			{
				process_1_handle_count = process_1.tree_handles.size();
			}catch(Exception e){}
			
			try
			{
				process_2_handle_count = process_2.tree_handles.size();
			}catch(Exception e){}
			
			
			node.compare_artifacts(INITIALIZATION_INDEX, "thread_count", ""+process_1_thread_count, ""+process_2_thread_count, null);
			node.compare_artifacts(INITIALIZATION_INDEX, "handle_count", ""+process_1_handle_count, ""+process_2_handle_count, null);
			
			//
			//module description
			//			
			this.compare_module_description_DEEP_INSPECTION(node, INITIALIZATION_INDEX, process_1.my_module_description, process_2.my_module_description, "(image meta-data) my_module_description ");
			
			//
			//Process Attribute!
			//			
			this.compare_file_attributes(node, INITIALIZATION_INDEX, process_1.fle_attributes, process_2.fle_attributes, "Process - FILE ATTRIBUTE");
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_process_PARTICULARS", e);
		}
		
		return false;
	}
	
	public boolean DEEP_INSPECTION_DRIVER(Advanced_Analysis_Director director_1, Advanced_Analysis_Director director_2, String VARIABLE_NAME, TreeMap<String, Node_Driver> tree_1, TreeMap<String, Node_Driver> tree_2, String ARTIFACT_TYPE, int INITIALIZATION_INDEX, TreeMap<String, Node_Snapshot_Analysis_Artifact> TREE_ANALYSIS)
	{
		try
		{
			//we've already checked if there is an added or removed process, now we need to compare values within each process
			if(director_1 == null || director_2 == null)
				return false;			
			
			
						

			
			//notify
			sop("\nCommencing Deep Inspection of " + VARIABLE_NAME + " modules.");
			
			//
			//Set analysis trees
			//
			Node_Driver entry_1 = null, entry_2 = null;
								
			//
			//populate all keys first
			//
			TreeMap<String, String> tree_KEY_SET = new TreeMap<String, String>();
			
			try
			{
				for(String key : tree_1.keySet())
					tree_KEY_SET.put(key, null);					
			}catch(Exception e){}
			
			try
			{
				for(String key : tree_2.keySet())
					tree_KEY_SET.put(key, null);					
			}catch(Exception e){}
			
			//
			//analyze
			//
			for(String key : tree_KEY_SET.keySet())
			{
				try	{	entry_1 = tree_1.get(key);	} catch(Exception e){}
				try	{	entry_2 = tree_2.get(key);	} catch(Exception e){}
				
				//
				//procure
				//
				Node_Snapshot_Analysis_Artifact node = TREE_ANALYSIS.get(key);
												
				//
				//initialize if necessary
				//
				if(node == null)
				{
					//use the instances to handle the comparison and building of the trees
					node = new Node_Snapshot_Analysis_Artifact(this, key, ARTIFACT_TYPE);												
					
					node.driver_1 = entry_1; 
					node.driver_2 = entry_2;
					
					node.initialize_structures(INITIALIZATION_INDEX);
					TREE_ANALYSIS.put(key,  node);	
					
					//normalize key descriptor
					try
					{
						if(key.contains("\\"))
						{
							String short_key = key.substring(key.lastIndexOf("\\")+1).trim();
							node.short_descriptor = short_key;
						}
					}catch(Exception ee){}
				}				
				
				//
				//update initialization trees
				//
				node.set_my_tree_pointers(INITIALIZATION_INDEX);
											
				//
				//analyze structures!
				//
				this.compare_driver_description_DEEP_INSPECTION(node, INITIALIZATION_INDEX, entry_1, entry_2, ARTIFACT_TYPE);												
			}
			
			
			
			
			
			sop("\nDONE! Deep Inspection of " + VARIABLE_NAME + " modules complete.");
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "DEEP_INSPECTION_DRIVER", e);
		}
		
		sop("\n* * * DONE! Deep Inspection of " + VARIABLE_NAME + " modules complete.");
		return false;
	}
	

	
	public boolean analyze_structure_filescan(int INITIALIZATION_INDEX, String type, TreeMap<String, Node_Generic> tree_1, TreeMap<String, Node_Generic> tree_2, TreeMap<String, String> tree_addition, TreeMap<String, String> tree_missing, TreeMap<String, String> tree_MODIFIED)
	{
		try
		{
			TreeMap<String, String>tree_KEY_SET = new TreeMap<String, String>();
			
			String key = "";
			
			if((tree_1 == null || tree_1.size() < 1) && tree_2 != null && tree_2.size() > 0)
			{
				this.tree_filescan_addition.put(type, "Entirely new " + type + " detected!");
				return true;
			}
			
			else if((tree_1 != null && tree_1.size() > 0) && (tree_2 == null || tree_2.size() < 0))
			{
				this.tree_filescan_missing.put(type, "Entirely missing " + type + " detected!");
				return true;
			}
			
			TreeMap<String, Node_Generic> tree_analysis_1 = new TreeMap<String, Node_Generic>();
			TreeMap<String, Node_Generic> tree_analysis_2 = new TreeMap<String, Node_Generic>();
			
			for(Node_Generic generic : tree_1.values())
			{
				try
				{
					//identify key
					key = generic.path;
					
					//populate keyset
					tree_KEY_SET.put(key, null);
					
					//populate tree via new index
					tree_analysis_1.put(key, generic);
				}
				catch(Exception e)
				{
					continue;
				}								
			}
			
			for(Node_Generic generic : tree_2.values())
			{
				try
				{
					//identify key
					key = generic.path;
					
					//populate keyset
					tree_KEY_SET.put(key, null);
					
					//populate tree via new index
					tree_analysis_2.put(key, generic);
				}
				catch(Exception e)
				{
					continue;
				}								
			}
			
			Node_Generic node_1 = null, node_2 = null;
			String value_1 = null, value_2 = null;
			
			for(String key_name : tree_KEY_SET.keySet())
			{
				value_1 = null;
				value_2 = null;		
				
				node_1 = null; 
				node_2 = null;
				
				try	{	node_1 = tree_analysis_1.get(key_name);  value_1 = node_1.path;}	catch(Exception e ) { value_1 = null;	}
				try	{	node_2 = tree_analysis_2.get(key_name);  value_2 = node_2.path;}	catch(Exception e ) { value_2 = null;	}
				
				if((value_1 == null) && value_2 == null)
					continue;
								
				
				//addition
				if((value_1 == null || value_1.length() < 1) && (value_2 != null && value_2.length() > 0))					
				{
					tree_addition.put(key_name, "Entirely new entry detected");
					continue;
				}
				
				//missing
				else if((value_1 != null && value_1.length() > 0) && (value_2 == null || value_2.length() < 0))					
				{
					tree_missing.put(key_name, "Entire entry is missing");
					continue;
				}
				else
				{
					//iterate through the values
					compare_artifacts(INITIALIZATION_INDEX, type, key_name, "offset_p",  node_1.offset_p, node_2.offset_p, tree_addition, tree_missing, tree_MODIFIED);
					compare_artifacts(INITIALIZATION_INDEX, type, key_name, "num_ptr",  node_1.num_ptr, node_2.num_ptr, tree_addition, tree_missing, tree_MODIFIED);
					compare_artifacts(INITIALIZATION_INDEX, type, key_name, "num_hnd",  node_1.num_hnd, node_2.num_hnd, tree_addition, tree_missing, tree_MODIFIED);
					compare_artifacts(INITIALIZATION_INDEX, type, key_name, "access",  node_1.access, node_2.access, tree_addition, tree_missing, tree_MODIFIED);
					//compare_artifacts(INITIALIZATION_INDEX, type, key_name, "path",  node_1., node_2., tree_addition, tree_missing, tree_MODIFIED);
					compare_artifacts(INITIALIZATION_INDEX, type, key_name, "additional_details",  node_1.additional_details, node_2.additional_details, tree_addition, tree_missing, tree_MODIFIED);
				}
				
				
				
			}
				
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_structure_filescan", e);
		}
		
		return false;
	}
	
	public boolean compare_artifacts(int INITIALIZATION_INDEX, String artifact_type, String key, String VARIABLE_NAME, String value_1, String value_2, TreeMap<String, String> tree_addition, TreeMap<String, String> tree_missing, TreeMap<String, String> tree_MODIFIED)
	{
		try
		{
			if(value_1 == null && value_2 == null)
				return false;
			
			if(value_1 == null)
				value_1 = "";
			
			if(value_2 == null)
				value_2 = "";
			
			String VALUE_1 = value_1.toLowerCase().trim();
			String VALUE_2 = value_2.toLowerCase().trim();
			
			if(VALUE_1.equals(VALUE_2))
				return false;
			
			String notes = "";
			
			//addition
			if(VALUE_1.length() < 1 && VALUE_2.length() > 0)
			{
				try	
				{	notes = tree_addition.get(key).trim();	
					notes = notes + "\t" + VARIABLE_NAME + ": " + VALUE_2;
					
					notes = notes.trim();
					
					tree_addition.put(key, notes);
				}	
				
				catch(Exception e)	
				{	
					tree_addition.put(key,  VARIABLE_NAME + ": " + VALUE_2);					
				}
			}
			
			//missing
			else if(VALUE_1.length() > 0 && VALUE_2.length() < 1)
			{
				try	
				{	notes = tree_missing.get(key).trim();	
					notes = notes + "\t" + VARIABLE_NAME + ": " + VALUE_1;
					
					notes = notes.trim();
					
					tree_missing.put(key, notes);
				}	
				
				catch(Exception e)	
				{	
					tree_missing.put(key,  VARIABLE_NAME + ": " + VALUE_1);					
				}
			}
			else if(!VALUE_1.equals(VALUE_2))
			{
				//modified: they don't equal e/o, yet both values exist, they must be different!
				try	
				{	notes = tree_MODIFIED.get(key).trim();	
					notes = notes + "\t" + VARIABLE_NAME + " --> value_1: " + VALUE_1 + ", value_2: " + VALUE_2;
					
					notes = notes.trim();
					
					tree_MODIFIED.put(key,  notes);
				}	
				
				catch(Exception e)	
				{	
					tree_MODIFIED.put(key,  VARIABLE_NAME + " --> value_1: " + VALUE_1 + ", value_2: " + VALUE_2);				
				}
			}
			
			
			
			//store entry back!
			
			
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "compare_artifacts", e);
		}
		
		return false;
	}
	
	public boolean DEEP_INSPECTION_NODE_GENERIC_FILE_TYPES(Advanced_Analysis_Director director_1, Advanced_Analysis_Director director_2, String VARIABLE_NAME, TreeMap<String, Node_Generic> tree_1, TreeMap<String, Node_Generic> tree_2, String ARTIFACT_TYPE, int INITIALIZATION_INDEX, TreeMap<String, String> tree_addition, TreeMap<String, String> tree_missing, TreeMap<String, String> tree_MODIFIED)
	{
		try
		{
			//we've already checked if there is an added or removed process, now we need to compare values within each process
			if(director_1 == null || director_2 == null)
				return false;	
			
			
			//notify
			sop("\nCommencing Deep Inspection of " + ARTIFACT_TYPE + " entries.");
		
			//
			//Set analysis trees
			//
			Node_Generic entry_1 = null, entry_2 = null;
								
			//
			//populate all keys first
			//
			TreeMap<String, String> tree_KEY_SET = new TreeMap<String, String>();
			
			if(tree_1 == null && tree_2 == null)
				return false;
						
			//
			//analyze
			//
			String line_1 = "", line_2 = "";
									
			switch(INITIALIZATION_INDEX)
			{										
				case Node_Snapshot_Analysis_Artifact.initialization_index_filescan:
				{
					this.analyze_structure_filescan(INITIALIZATION_INDEX, ARTIFACT_TYPE, tree_1, tree_2, tree_addition, tree_missing, tree_MODIFIED);
		
					break;
				}
				
				case Node_Snapshot_Analysis_Artifact.initialization_index_mftparser:
				{
					this.analyze_structure_mftparser(INITIALIZATION_INDEX, ARTIFACT_TYPE, tree_1, tree_2, tree_addition, tree_missing, tree_MODIFIED);
					
//					compare_artifacts(INITIALIZATION_INDEX, "create_date",  entry_1.create_date, entry_2.create_date, tree_addition, tree_missing, tree_MODIFIED);
//					compare_artifacts(INITIALIZATION_INDEX, "modified_date",  entry_1.modified_date, entry_2.modified_date, tree_addition, tree_missing, tree_MODIFIED);
//					compare_artifacts(INITIALIZATION_INDEX, "mft_altered_date",  entry_1.mft_altered_date, entry_2.mft_altered_date, tree_addition, tree_missing, tree_MODIFIED);
//					compare_artifacts(INITIALIZATION_INDEX, "access_date",  entry_1.access_date, entry_2.access_date, tree_addition, tree_missing, tree_MODIFIED);
//					compare_artifacts(INITIALIZATION_INDEX, "path",  entry_1.path, entry_2.path, tree_addition, tree_missing, tree_MODIFIED);
//					compare_artifacts(INITIALIZATION_INDEX, "entry_attr",  entry_1.entry_attr, entry_2.entry_attr, tree_addition, tree_missing, tree_MODIFIED);
//					compare_artifacts(INITIALIZATION_INDEX, "extension",  entry_1.extension, entry_2.extension, tree_addition, tree_missing, tree_MODIFIED);
//					compare_artifacts(INITIALIZATION_INDEX, "additional_details",  entry_1.additional_details, entry_2.additional_details, tree_addition, tree_missing, tree_MODIFIED);
//	
		
					break;
				}
				
				case Node_Snapshot_Analysis_Artifact.initialization_index_shellbags:
				{
					this.analyze_structure_shellbags(INITIALIZATION_INDEX, ARTIFACT_TYPE, tree_1, tree_2, tree_addition, tree_missing, tree_MODIFIED);
					
//					compare_artifacts(INITIALIZATION_INDEX, "modified_date",  entry_1.modified_date, entry_2.modified_date, tree_addition, tree_missing, tree_MODIFIED);
//					compare_artifacts(INITIALIZATION_INDEX, "create_date",  entry_1.create_date, entry_2.create_date, tree_addition, tree_missing, tree_MODIFIED);
//					compare_artifacts(INITIALIZATION_INDEX, "access_date",  entry_1.access_date, entry_2.access_date, tree_addition, tree_missing, tree_MODIFIED);
//					compare_artifacts(INITIALIZATION_INDEX, "last_updated",  entry_1.last_updated, entry_2.last_updated, tree_addition, tree_missing, tree_MODIFIED);
//					compare_artifacts(INITIALIZATION_INDEX, "file_name",  entry_1.file_name, entry_2.file_name, tree_addition, tree_missing, tree_MODIFIED);
//					compare_artifacts(INITIALIZATION_INDEX, "unicode_name",  entry_1.unicode_name, entry_2.unicode_name, tree_addition, tree_missing, tree_MODIFIED);
//					compare_artifacts(INITIALIZATION_INDEX, "file_attr",  entry_1.file_attr, entry_2.file_attr, tree_addition, tree_missing, tree_MODIFIED);
//					compare_artifacts(INITIALIZATION_INDEX, "shellbag_value",  entry_1.shellbag_value, entry_2.shellbag_value, tree_addition, tree_missing, tree_MODIFIED);
//					compare_artifacts(INITIALIZATION_INDEX, "registry_name",  entry_1.registry_name, entry_2.registry_name, tree_addition, tree_missing, tree_MODIFIED);
//					compare_artifacts(INITIALIZATION_INDEX, "registry_key_name",  entry_1.registry_key_name, entry_2.registry_key_name, tree_addition, tree_missing, tree_MODIFIED);
//					compare_artifacts(INITIALIZATION_INDEX, "shellbag_type",  entry_1.shellbag_type, entry_2.shellbag_type, tree_addition, tree_missing, tree_MODIFIED);
//					compare_artifacts(INITIALIZATION_INDEX, "additional_details",  entry_1.additional_details, entry_2.additional_details, tree_addition, tree_missing, tree_MODIFIED);
//					compare_artifacts(INITIALIZATION_INDEX, "guid_description",  entry_1.guid_description, entry_2.guid_description, tree_addition, tree_missing, tree_MODIFIED);
//					compare_artifacts(INITIALIZATION_INDEX, "guid",  entry_1.guid, entry_2.guid, tree_addition, tree_missing, tree_MODIFIED);
//					compare_artifacts(INITIALIZATION_INDEX, "folder_ids",  entry_1.folder_ids, entry_2.folder_ids, tree_addition, tree_missing, tree_MODIFIED);
//					compare_artifacts(INITIALIZATION_INDEX, "entry_type",  entry_1.entry_type, entry_2.entry_type, tree_addition, tree_missing, tree_MODIFIED);
//					compare_artifacts(INITIALIZATION_INDEX, "mru",  entry_1.mru, entry_2.mru, tree_addition, tree_missing, tree_MODIFIED);
//					compare_artifacts(INITIALIZATION_INDEX, "path",  entry_1.path, entry_2.path, tree_addition, tree_missing, tree_MODIFIED);
					
					break;
				}
	


				case Node_Snapshot_Analysis_Artifact.initialization_index_shimcache:
				{
					
					this.analyze_structure_shimcache(INITIALIZATION_INDEX, ARTIFACT_TYPE, tree_1, tree_2, tree_addition, tree_missing, tree_MODIFIED);
					
//					compare_artifacts(INITIALIZATION_INDEX, "last_updated",  entry_1.last_updated, entry_2.last_updated, tree_addition, tree_missing, tree_MODIFIED);
//					compare_artifacts(INITIALIZATION_INDEX, "path",  entry_1.path, entry_2.path, tree_addition, tree_missing, tree_MODIFIED);
//					compare_artifacts(INITIALIZATION_INDEX, "additional_details",  entry_1.additional_details, entry_2.additional_details, tree_addition, tree_missing, tree_MODIFIED);
//	
					break;
				}
//	
				case Node_Snapshot_Analysis_Artifact.initialization_index_timeliner:
				{
					this.analyze_structure_timeliner(INITIALIZATION_INDEX, ARTIFACT_TYPE, tree_1, tree_2, tree_addition, tree_missing, tree_MODIFIED);
					
//					compare_artifacts(INITIALIZATION_INDEX, "time",  entry_1.time, entry_2.time, tree_addition, tree_missing, tree_MODIFIED);
//					compare_artifacts(INITIALIZATION_INDEX, "key_name",  entry_1.key_name, entry_2.key_name, tree_addition, tree_missing, tree_MODIFIED);
//					compare_artifacts(INITIALIZATION_INDEX, "value",  entry_1.value, entry_2.value, tree_addition, tree_missing, tree_MODIFIED);
//					compare_artifacts(INITIALIZATION_INDEX, "details",  entry_1.details, entry_2.details, tree_addition, tree_missing, tree_MODIFIED);
//					compare_artifacts(INITIALIZATION_INDEX, "additional_details",  entry_1.additional_details, entry_2.additional_details, tree_addition, tree_missing, tree_MODIFIED);
//	
					break;
				}
//	
				case Node_Snapshot_Analysis_Artifact.initialization_index_userassist_specific_entries:
				{
					
					this.analyze_structure_userassist_specific_entries(INITIALIZATION_INDEX, ARTIFACT_TYPE, tree_1, tree_2, tree_addition, tree_missing, tree_MODIFIED);
					
//					compare_artifacts(INITIALIZATION_INDEX, "last_updated",  entry_1.last_updated, entry_2.last_updated, tree_addition, tree_missing, tree_MODIFIED);
//					compare_artifacts(INITIALIZATION_INDEX, "reg_binary",  entry_1.reg_binary, entry_2.reg_binary, tree_addition, tree_missing, tree_MODIFIED);
//					compare_artifacts(INITIALIZATION_INDEX, "time_focused",  entry_1.time_focused, entry_2.time_focused, tree_addition, tree_missing, tree_MODIFIED);
//					compare_artifacts(INITIALIZATION_INDEX, "count",  entry_1.count, entry_2.count, tree_addition, tree_missing, tree_MODIFIED);
//					compare_artifacts(INITIALIZATION_INDEX, "focus_count",  entry_1.focus_count, entry_2.focus_count, tree_addition, tree_missing, tree_MODIFIED);
//					compare_artifacts(INITIALIZATION_INDEX, "registry_name",  entry_1.registry_name, entry_2.registry_name, tree_addition, tree_missing, tree_MODIFIED);
//					compare_artifacts(INITIALIZATION_INDEX, "path",  entry_1.path, entry_2.path, tree_addition, tree_missing, tree_MODIFIED);
//					compare_artifacts(INITIALIZATION_INDEX, "reg_data_first_line",  entry_1.reg_data_first_line, entry_2.reg_data_first_line, tree_addition, tree_missing, tree_MODIFIED);
//					compare_artifacts(INITIALIZATION_INDEX, "additional_details",  entry_1.additional_details, entry_2.additional_details, tree_addition, tree_missing, tree_MODIFIED);
//	
					break;
				}
	
	
	
				default:
				{
					driver.directive("* * * Unknown initialization vector received in DEEP_INSPECTION_NODE_GENERIC_FILESCAN_TYPES mtd in " + this.myClassName);
					break;
				}
	
				}//end switch
	
	
	




			sop("\nDONE! Deep Inspection of " + VARIABLE_NAME + " modules complete.");
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "DEEP_INSPECTION_NODE_GENERIC_FILESCAN_TYPES", e, true);
		}

		sop("\n* * * * * DONE! Deep Inspection of " + VARIABLE_NAME + " modules complete.");
		return false;
	}

	public boolean compare_module_description_DEEP_INSPECTION(Node_Snapshot_Analysis_Artifact node, int INITIALIZATION_INDEX, Node_DLL module_description_1, Node_DLL module_description_2, String VARIABLE_NAME)
	{
		try
		{
			if((module_description_1 == null && module_description_2 == null) || node == null)
				return false;

			//initialize respective tree structure
			node.set_my_tree_pointers(INITIALIZATION_INDEX);

			if(module_description_1 == null && module_description_2 != null)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "module data NOT specified", "[+] ENTIRE NEW STRUCTURE ADDED!", null);				
				return true;
			}

			else if(module_description_1 != null && module_description_2 == null)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "module data specified", "[-] ENTIRE STRUCTURE MISSING!", null);				
				return true;
			}

			else//check each data point
			{				
				//
				//check module particulars
				//
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + "[base]",  module_description_1.base, module_description_2.base, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + "[size]",  module_description_1.size, module_description_2.size, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + "[load_count]",  module_description_1.load_count, module_description_2.load_count, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + "[path]",  module_description_1.path, module_description_2.path, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + "[found_in_dlllist]",  module_description_1.found_in_dlllist, module_description_2.found_in_dlllist, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + "[found_in_ldrmodule]",  module_description_1.found_in_ldrmodule, module_description_2.found_in_ldrmodule, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + "[in_load]",  module_description_1.in_load, module_description_2.in_load, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + "[in_init]",  module_description_1.in_init, module_description_2.in_init, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + "[in_mem]",  module_description_1.in_mem, module_description_2.in_mem, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + "[found_in_verinfo_plugin]",  VARIABLE_NAME + "["+module_description_1.found_in_verinfo_plugin, VARIABLE_NAME + "["+module_description_2.found_in_verinfo_plugin, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + "[file_version]",  module_description_1.file_version, module_description_2.file_version, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + "[product_name]",  module_description_1.product_name, module_description_2.product_name, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + "[comments]",  module_description_1.comments, module_description_2.comments, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + "[company_name]",  module_description_1.company_name, module_description_2.company_name, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + "[flags]",  module_description_1.flags, module_description_2.flags, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + "[internal_name]",  module_description_1.internal_name, module_description_2.internal_name, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + "[legal_trademarks]",  module_description_1.legal_trademarks, module_description_2.legal_trademarks, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + "[ole_self_register]",  module_description_1.ole_self_register, module_description_2.ole_self_register, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + "[os]",  module_description_1.os, module_description_2.os, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + "[original_file_name]",  module_description_1.original_file_name, module_description_2.original_file_name, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + "[copyright_legal_copyright]",  module_description_1.copyright_legal_copyright, module_description_2.copyright_legal_copyright, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + "[file_description]",  module_description_1.file_description, module_description_2.file_description, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + "[file_type]",  module_description_1.file_type, module_description_2.file_type, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + "[product_version]",  module_description_1.product_version, module_description_2.product_version, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + "[file_size]",  module_description_1.file_size, module_description_2.file_size, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + "[date_modified]",  module_description_1.date_modified, module_description_2.date_modified, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + "[language]",  module_description_1.language, module_description_2.language, null);				
				
				//
				//File attr
				//
				this.compare_file_attributes(node, INITIALIZATION_INDEX, module_description_1.fle_attributes, module_description_2.fle_attributes, VARIABLE_NAME + " - FILE ATTRIBUTE");												
			}
			
			
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "compare_module_description_DEEP_INSPECTION", e);
		}				
		
		return false;
	}
	
	
	public boolean compare_driver_description_DEEP_INSPECTION(Node_Snapshot_Analysis_Artifact node, int INITIALIZATION_INDEX, Node_Driver driver_1, Node_Driver driver_2, String VARIABLE_NAME)
	{
		try
		{
			if((driver_1 == null && driver_2 == null) || node == null)
				return false;
			
			//initialize respective tree structure
			node.set_my_tree_pointers(INITIALIZATION_INDEX);
			
			if(driver_1 == null && driver_2 != null)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "driver data NOT specified", "[+] ENTIRE NEW STRUCTURE ADDED!", null);				
				return true;
			}
			
			else if(driver_1 != null && driver_2 == null)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "driver data specified", "[-] ENTIRE STRUCTURE MISSING!", null);				
				return true;
			}
			
			else//check each data point
			{				
				//
				//check module particulars
				//
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [module_base_module_dump]",  driver_1.module_base_module_dump, driver_2.module_base_module_dump, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [offset_modules]",  driver_1.offset_modules, driver_2.offset_modules, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [offset_modscan]",  driver_1.offset_modscan, driver_2.offset_modscan, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [module_name]",  driver_1.module_name, driver_2.module_name, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [dump_file_name]",  driver_1.dump_file_name, driver_2.dump_file_name, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [size_V]",  driver_1.size_V, driver_2.size_V, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [file_path_from_memory]",  driver_1.file_path_from_memory, driver_2.file_path_from_memory, null);				
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [driver_name]",  driver_1.driver_name, driver_2.driver_name, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [alt_name]",  driver_1.alt_name, driver_2.alt_name, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [offset_driverscan]",  driver_1.offset_driverscan, driver_2.offset_driverscan, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [num_ptr]",  driver_1.num_ptr, driver_2.num_ptr, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [num_handle]",  driver_1.num_handle, driver_2.num_handle, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [start]",  driver_1.start, driver_2.start, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [service_key]",  driver_1.service_key, driver_2.service_key, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [size_P]",  driver_1.size_P, driver_2.size_P, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [start_io]",  driver_1.start_io, driver_2.start_io, null);
			
				
				//
				//File attr
				//
				this.compare_file_attributes(node, INITIALIZATION_INDEX, driver_1.fle_attributes, driver_2.fle_attributes, VARIABLE_NAME + " - FILE ATTRIBUTE");	
				
				//
				//list_driver_irp
				//
				this.compare_list_irp_entries(node, INITIALIZATION_INDEX, driver_1, driver_2, VARIABLE_NAME);
			}
			
			
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "compare_driver_description_DEEP_INSPECTION", e);
		}				
		
		return false;
	}
	
	/**
	 * continuation mtd
	 * @param node
	 * @param INITIALIZATION_INDEX
	 * @param driver_1
	 * @param driver_2
	 * @param VARIABLE_NAME
	 * @return
	 */
	public boolean compare_list_irp_entries(Node_Snapshot_Analysis_Artifact node, int INITIALIZATION_INDEX, Node_Driver driver_1, Node_Driver driver_2, String VARIABLE_NAME)
	{
		try
		{
			if(driver_1 == null && driver_2 == null)
				return false;
			
			LinkedList<Node_Driver_IRP>  list_driver_irp_1 = null;
			LinkedList<Node_Driver_IRP>  list_driver_irp_2 = null;
			
			try{  list_driver_irp_1 = driver_1.list_driver_irp;	} catch(Exception e){}
			try{  list_driver_irp_2 = driver_2.list_driver_irp; } catch(Exception e){}
			
			if(list_driver_irp_1 == null && list_driver_irp_2 == null)
			{
				//do n/t
			}
			
			else if((list_driver_irp_1 == null || list_driver_irp_1.isEmpty()) && (list_driver_irp_2 != null && !list_driver_irp_2.isEmpty()))  
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "driver list_driver_irp_1 data NOT specified", "[+] ENTIRE NEW list_driver_irp_2 STRUCTURE ADDED!", null);
			}
			
			else if((list_driver_irp_1 != null && !list_driver_irp_1.isEmpty()) && (list_driver_irp_2 == null || list_driver_irp_2.isEmpty()))  
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "driver list_driver_irp_1 data specified", "[-] ENTIRE list_driver_irp_2 STRUCTURE MISSING!", null);
			}
			else
			{
				//otw, search to find the node, then compare entries
				String start = null;
				
				//
				//check for additions
				//
				for(Node_Driver_IRP driver_irp_2 : list_driver_irp_2)
				{
					if(driver_irp_2 == null)
						continue;
					
					start = driver_irp_2.driver_irp_start;
					
					//search through the other list
					for(Node_Driver_IRP driver_irp_1 : list_driver_irp_1)
					{
						if(driver_irp_1 == null)
							continue;
						
						if(driver_irp_1.driver_irp_start == null || driver_irp_1.driver_irp_start.trim().equals(""))
							continue;
						
						if(start.equals(driver_irp_1.driver_irp_start))
						{
							//match found! compare the entries
							node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " Node_Driver_IRP Start",  driver_irp_1.driver_irp_start, driver_irp_2.driver_irp_start, "@ driver_irp_start: " + start);
							node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " Node_Driver_IRP Size",  driver_irp_1.driver_irp_size, driver_irp_2.driver_irp_size, "@ driver_irp_start: " + start);
							node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " Node_Driver_IRP Stat IO",  driver_irp_1.driver_irp_start_io, driver_irp_2.driver_irp_start_io, "@ driver_irp_start: " + start);
							
							//now check entries
							if(driver_irp_1.list_irp_entries == null && driver_irp_2.list_irp_entries == null)
							{
								//do n/t
							}
							
							else if((driver_irp_1.list_irp_entries == null || driver_irp_1.list_irp_entries.isEmpty()) && (driver_irp_2.list_irp_entries != null && !driver_irp_2.list_irp_entries.isEmpty()))  
							{
								node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "driver list_driver_irp_1 values NOT specified", "[+] ENTIRE NEW list_driver_irp_2 STRUCTURE AND ENTRIES ADDED!", null);
							}
							
							else if((driver_irp_1.list_irp_entries != null && !driver_irp_1.list_irp_entries.isEmpty()) && (driver_irp_2.list_irp_entries == null || driver_irp_2.list_irp_entries.isEmpty()))  
							{
								node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "driver list_driver_irp_1 values specified", "[-] ENTIRE list_driver_irp_2 STRUCTURE AND ENTRIES MISSING!", null);
							}
							
							else
							{
								int i = -1;
								
								//iterate to compare entries of lists
								for(String entry_2 : driver_irp_2.list_irp_entries)
								{
									++i;
									
									if(entry_2 == null)
										continue;
									
									if(driver_irp_1.list_irp_entries.contains(entry_2))
										continue;
									
									//otw, added value discovered!
									node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [list_driver_irp snapshot 2]" + " index: [" + i + "]",  null, entry_2, "@ driver_irp_start: " + start);
								}
								
							}
							
						}
						
					}
				}//end for check for Additions
				
				
				
				//
				//check for missing
				//
				for(Node_Driver_IRP driver_irp_1 : list_driver_irp_1)
				{
					if(driver_irp_1 == null)
						continue;
					
					start = driver_irp_1.driver_irp_start;
					
					//search through the other list
					for(Node_Driver_IRP driver_irp_2 : list_driver_irp_2)
					{
						if(driver_irp_2 == null)
							continue;
						
						if(driver_irp_2.driver_irp_start == null || driver_irp_2.driver_irp_start.trim().equals(""))
							continue;
						
						if(start.equals(driver_irp_2.driver_irp_start))
						{
							//match found! compare the entries
							node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " Node_Driver_IRP Start",  driver_irp_1.driver_irp_start, driver_irp_2.driver_irp_start, "@ driver_irp_start: " + start);
							node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " Node_Driver_IRP Size",  driver_irp_1.driver_irp_size, driver_irp_2.driver_irp_size, "@ driver_irp_start: " + start);
							node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " Node_Driver_IRP Stat IO",  driver_irp_1.driver_irp_start_io, driver_irp_2.driver_irp_start_io, "@ driver_irp_start: " + start);
							
							//now check entries
							if(driver_irp_1.list_irp_entries == null && driver_irp_2.list_irp_entries == null)
							{
								//do n/t
							}
							
							else if((driver_irp_1.list_irp_entries == null || driver_irp_1.list_irp_entries.isEmpty()) && (driver_irp_2.list_irp_entries != null && !driver_irp_2.list_irp_entries.isEmpty()))  
							{
								node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "driver list_driver_irp_1 values NOT specified", "[+] ENTIRE NEW list_driver_irp_2 STRUCTURE AND ENTRIES ADDED!", null);
							}
							
							else if((driver_irp_1.list_irp_entries != null && !driver_irp_1.list_irp_entries.isEmpty()) && (driver_irp_2.list_irp_entries == null || driver_irp_2.list_irp_entries.isEmpty()))  
							{
								node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "driver list_driver_irp_1 values specified", "[-] ENTIRE list_driver_irp_2 STRUCTURE AND ENTRIES MISSING!", null);
							}
							
							else
							{
								int i = -1;
								
								//iterate to compare entries of lists
								for(String entry_1 : driver_irp_1.list_irp_entries)
								{
									++i;
									
									if(entry_1 == null)
										continue;
									
									if(driver_irp_2.list_irp_entries.contains(entry_1))
										continue;
									
									//otw, missing value discovered!
									node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [list_driver_irp snapshot 1]" + " index: [" + i + "]", entry_1 ,  null, "@ driver_irp_start: " + start);
								}
								
							}
							
						}
						
					}
				}//end for check for Missing
				
				
				
			}//end else check lists
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "compare_list_irp_entries", e);
		}
		
		return false;
	}
	

	/**
	 * continuation mtd - assumes process 1 and 2 are NOT NULL!
	 * @param process_1
	 * @param process_2
	 * @param INITIALIZATION_INDEX
	 * @param tree
	 * @param key
	 * @param ARTIFACT_TYPE
	 * @return
	 */
	public boolean analyze_process_HANDLES(Node_Process process_1, Node_Process process_2, int INITIALIZATION_INDEX, TreeMap<String, Node_Snapshot_Analysis_Artifact> tree, String node_key, String ARTIFACT_TYPE)
	{
		try
		{						
			//
			//procure
			//
			Node_Snapshot_Analysis_Artifact node = tree.get(node_key);
			
			//
			//initialize if necessary
			//
			if(node == null)
			{
				//use the instances to handle the comparison and building of the trees
				node = new Node_Snapshot_Analysis_Artifact(this, process_2.get_process_html_header(), ARTIFACT_TYPE);
				
				//adjust name if needed
				try
				{
					if(node.descriptor == null || node.descriptor.toLowerCase().trim().endsWith("unknown") && !process_1.get_process_html_header().toLowerCase().trim().endsWith("unknown"))
						node.descriptor = process_1.get_process_html_header();	
				}catch(Exception e){}				
				
				node.process_1 = process_1; 
				node.proces_2 = process_2;
				
				node.initialize_structures(INITIALIZATION_INDEX);
				tree.put(node_key,  node);				
			}

			//
			//update node's initialization vecto
			//
			node.set_my_tree_pointers(INITIALIZATION_INDEX);
			
			//
			//init structures to compare			
			//
			String VARIABLE_NAME = "Handle";
			TreeMap<String, Node_Handle> tree_1 = process_1.tree_handles;
			TreeMap<String, Node_Handle> tree_2 = process_2.tree_handles;
			Node_Handle entry_1 = null, entry_2 = null;
			
			//
			//compsre structures
			//
			if(tree_1 == null && tree_2 == null)
				return false;
			
			//
			//check addition
			//
			if(tree_1 == null && tree_2 != null)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "file handle data NOT specified", "[+] ENTIRE NEW FILE HANDLE STRUCTURE ADDED!", null);				
				return true;
			}
			
			//
			//check missing
			//
			else if(tree_1 != null && tree_2 == null)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "file handle data specified", "[-] ENTIRE FILE HANDLE STRUCTURE MISSING!", null);				
				return true;
			}
			
			//at this point, both trees are not null, check sizes for additional and missing
			
			//
			//check addition
			//
			if(tree_1.size() < 1 && tree_2.size() > 0)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "file handle data NOT specified", "[+] ENTIRE NEW FILE HANDLE STRUCTURE ADDED!", null);				
				return true;
			}
			
			//
			//check missing
			//
			else if(tree_1.size() > 0 && tree_2.size() < 1)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "file handle data specified", "[-] ENTIRE FILE HANDLE STRUCTURE MISSING!", null);				
				return true;
			}
			
			//
			//check structure entries
			//
			else
			{			
				///////////////////////////////////////////////////////////////////////
				// check for addition and modified
				///////////////////////////////////////////////////////////////////////
				for(String key : tree_2.keySet())
				{
					if(key == null || key.trim().equals(""))
						continue;
															
					//
					//procure nodes
					//
					entry_1 = tree_1.get(key);
					entry_2 = tree_2.get(key);  	 								

					//
					//validate entry
					//
					if(entry_1 == null && entry_2 == null)
						continue;
											
													
					//
					//check addition
					//
					if(entry_1 == null && entry_2 != null)
					{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " @ offset " + entry_2.offset, null, entry_2.get_manifest_file_entry("\t"), null);
					}
					
					//
					//check missing
					//
					else if(entry_1 != null && entry_2 == null)
					{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " @ offset " + entry_1.offset, entry_1.get_manifest_file_entry("\t"), null, null);
					}
					
					//
					//else, iterate and check each value
					//
					else
					{
						//
						//specify unique key
						//
						String variable_key_identifier = VARIABLE_NAME + " @ offset " + entry_2.offset ;
						
						//
						//invoke compare routine on the data-transform
						//
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.get_manifest_file_entry("\t"), entry_2.get_manifest_file_entry("\t"), null);
					}														
				}
				
				///////////////////////////////////////////////////////////////////////
				// check for missing and modified
				///////////////////////////////////////////////////////////////////////
				for(String key : tree_1.keySet())
				{
					if(key == null || key.trim().equals(""))
						continue;
															
					//
					//procure nodes
					//
					entry_1 = tree_1.get(key);
					entry_2 = tree_2.get(key);  	 								

					//
					//validate entry
					//
					if(entry_1 == null && entry_2 == null)
						continue;
											
													
					//
					//check addition
					//
					if(entry_1 == null && entry_2 != null)
					{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " @ offset " + entry_2.offset, null, entry_2.get_manifest_file_entry("\t"), null);
					}
					
					//
					//check missing
					//
					else if(entry_1 != null && entry_2 == null)
					{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " @ offset " + entry_1.offset, entry_1.get_manifest_file_entry("\t"), null, null);
					}
					
					//
					//else, iterate and check each value
					//
					else
					{
						//
						//specify unique key
						//
						String variable_key_identifier = VARIABLE_NAME + " @ offset " + entry_1.offset ;
												
						//
						//invoke compare routine on the data-transform
						//
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.get_manifest_file_entry("\t"), entry_2.get_manifest_file_entry("\t"), null);
					}														
				}
			}
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_process_HANDLES", e);
		}
		
		return false;
	}
	
	public boolean compare_file_attributes(Node_Snapshot_Analysis_Artifact node, int INITIALIZATION_INDEX, FileAttributeData attr_1, FileAttributeData attr_2, String VARIABLE_NAME)
	{
		try
		{
			if(attr_1 == null && attr_2 == null)
				return false;
			
			//
			//check addition
			//
			if(attr_1 == null && attr_2 != null)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "file attribute data NOT specified", "[+] ENTIRE NEW FILE ATTRIBUTE STRUCTURE ADDED!", null);				
				return true;
			}
			
			//
			//check missing
			//
			else if(attr_1 != null && attr_2 == null)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "file attribute data specified", "[-] ENTIRE FILE ATTRIBUTE STRUCTURE MISSING!", null);				
				return true;
			}
			
			//
			//check file attr particulars
			//
			else
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + "[raw_file_length]",  ""+attr_1.raw_file_length, ""+attr_2.raw_file_length, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + "[length]",  ""+attr_1.length, ""+attr_2.length, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + "[size]",  attr_1.size, attr_2.size, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + "[file_name]",  attr_1.file_name, attr_2.file_name, null);
//node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + "[creation_date]",  attr_1.creation_date, attr_2.creation_date, null);
//				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + "[last_accessed]",  attr_1.last_accessed, attr_2.last_accessed, null);
//				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + "[last_modified]",  attr_1.last_modified, attr_2.last_modified, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + "[hash_md5]",  attr_1.hash_md5, attr_2.hash_md5, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + "[hash_sha256]",  attr_1.hash_sha256, attr_2.hash_sha256, null);
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + "[short_file_name]",  attr_1.short_file_name, attr_2.short_file_name, null);

			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "compare_file_attributes", e);
		}
		
		return false;
	}
	
	public boolean snapshot_analysis_director_check_PROCESS(Advanced_Analysis_Director director_1, Advanced_Analysis_Director director_2)
	{
		try
		{
			analysis_check_PROCESS("tree_PROCESS", director_1.tree_PROCESS, director_2.tree_PROCESS, this.tree_addition_PROCESS, this.tree_missing_PROCESS, this.tree_MODIFIED_PROCESS);
			
			analysis_check_PROCESS("tree_ORPHAN_process", director_1.tree_ORPHAN_process, director_2.tree_ORPHAN_process, this.tree_addition_ORPHAN_process, this.tree_missing_ORPHAN_process, null);
			
			//need to pri deeper into each gdi per process in future update
			//analysis_check_PROCESS("tree_GDI_TIMERS", director_1.tree_GDI_TIMERS, director_2.tree_GDI_TIMERS, this.tree_addition_GDI_TIMERS, this.tree_missing_GDI_TIMERS, null);
//			tree_ORPHAN_process
//			tree_Process_from_offset_P_trimmed
//			tree_Process_from_offset_V
//			tree_Process_from_module_base_address
//			tree_Process_from_module_base_address_trimmed
//			tree_GDI_TIMERS
//			tree_malfind_original_dump_name_to_process
//			tree_process_to_link_cmdline_cmdscan_consoles
			//analysis_check_PROCESS("tree_addition_process_to_link_cmdline_cmdscan_consoles", director_1.tree_process_to_link_cmdline_cmdscan_consoles, director_2.tree_process_to_link_cmdline_cmdscan_consoles, this.tree_addition_process_to_link_cmdline_cmdscan_consoles, this.tree_missing_process_to_link_cmdline_cmdscan_consoles, null);
						
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "snapshot_analysis_director_check_PROCESS", e);
		}
		
		return false;
	}
	
	public boolean snapshot_analysis_director_check_DLL_PATHS(Advanced_Analysis_Director director_1, Advanced_Analysis_Director director_2)
	{
		try
		{
			analysis_check_DLL_PATHS("tree_DLL_by_path", director_1.tree_DLL_by_path, director_2.tree_DLL_by_path, this.tree_addition_DLL_by_path, this.tree_missing_DLL_by_path, null);
			//analysis_check_DLL("tree_DLL_MODULES_linked_by_VAD_base_start_address", director_1.tree_DLL_MODULES_linked_by_VAD_base_start_address, director_2.tree_DLL_MODULES_linked_by_VAD_base_start_address, this.tree_addition_DLL_MODULES_linked_by_VAD_base_start_address, this.tree_missing_DLL_MODULES_linked_by_VAD_base_start_address, null);
			//analysis_check_Tree_String("tree_Module_Name_from_base_address_as_key", director_1.tree_Module_Name_from_base_address_as_key, director_2.tree_Module_Name_from_base_address_as_key, this.tree_addition_Module_Name_from_base_address_as_key, this.tree_missing_Module_Name_from_base_address_as_key, tree_MODIFIED_Module_Name_from_base_address_as_key);

			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "snapshot_analysis_director_check_DLL", e);
		}
		
		return false;
	}
	
	
	public boolean snapshot_analysis_director_check_REGISTRY(Advanced_Analysis_Director director_1, Advanced_Analysis_Director director_2)
	{
		try
		{
			analysis_check_REGISTRY("tree_REGISTRY_HIVE_USER_ASSIST", director_1.tree_REGISTRY_HIVE_USER_ASSIST, director_2.tree_REGISTRY_HIVE_USER_ASSIST, this.tree_addition_REGISTRY_HIVE_USER_ASSIST, this.tree_missing_REGISTRY_HIVE_USER_ASSIST, null);
			analysis_check_REGISTRY("tree_REGISTRY_HIVE_PRINTKEY", director_1.tree_REGISTRY_HIVE_PRINTKEY, director_2.tree_REGISTRY_HIVE_PRINTKEY, this.tree_addition_REGISTRY_HIVE_PRINTKEY, this.tree_missing_REGISTRY_HIVE_PRINTKEY, null);
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "snapshot_analysis_director_check_Node_Generic", e);
		}
		
		return false;
	}
	
	public boolean snapshot_analysis_director_check_NODE_GENERIC(Advanced_Analysis_Director director_1, Advanced_Analysis_Director director_2)
	{
		try
		{
			analysis_check_Tree_Node_Generic("tree_DESKSCAN", director_1.tree_DESKSCAN, director_2.tree_DESKSCAN, this.tree_addition_DESKSCAN, this.tree_missing_DESKSCAN, tree_MODIFIED_DESKSCAN);
			analysis_check_Tree_Node_Generic("tree_AUDIT_POLICY", director_1.tree_AUDIT_POLICY, director_2.tree_AUDIT_POLICY, this.tree_addition_AUDIT_POLICY, this.tree_missing_AUDIT_POLICY, tree_MODIFIED_AUDIT_POLICY);
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "snapshot_analysis_director_check_Node_Generic", e);
		}
		
		return false;
	}
	
	public boolean snapshot_analysis_director_check_GET_SERVICE_SID(Advanced_Analysis_Director director_1, Advanced_Analysis_Director director_2)
	{
		try
		{
			analysis_check_GET_SERVICE_SID("tree_get_service_sids", director_1.tree_get_service_sids, director_2.tree_get_service_sids, this.tree_addition_GET_SERVICE_SIDS, this.tree_missing_GET_SERVICE_SIDS, this.tree_MODIFIED_GET_SERVICE_SIDS);
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "snapshot_analysis_director_check_GET_SERVICE_SID", e);
		}
		
		return false;
	}
	
	public boolean snapshot_analysis_director_check_HIVELIST(Advanced_Analysis_Director director_1, Advanced_Analysis_Director director_2)
	{
		try
		{
			analysis_check_HIVELIST("tree_hivelist", director_1.tree_hivelist, director_2.tree_hivelist, this.tree_addition_HIVELIST, this.tree_missing_HIVELIST, this.tree_MODIFIED_HIVELIST);
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "snapshot_analysis_director_check_HIVELIST", e);
		}
		
		return false;
	}
	
	public boolean snapshot_analysis_director_check_DRIVER(Advanced_Analysis_Director director_1, Advanced_Analysis_Director director_2)
	{
		try
		{
			analysis_check_DRIVER("tree_DRIVERS", director_1.tree_DRIVERS, director_2.tree_DRIVERS, this.tree_addition_DRIVERS, this.tree_missing_DRIVERS, tree_MODIFIED_DRIVERS);
			analysis_check_DRIVER("tree_DRIVER_IRP_HOOK", director_1.tree_DRIVER_IRP_HOOK, director_2.tree_DRIVER_IRP_HOOK, this.tree_addition_DRIVER_IRP_HOOK, this.tree_missing_DRIVER_IRP_HOOK, tree_MODIFIED_DRIVER_IRP_HOOK);
			//analysis_check_DRIVER("tree_session_entries", director_1.tree_session_entries, director_2.tree_session_entries, this.tree_addition_session_entries, this.tree_missing_session_entries, tree_MODIFIED_session_entries);
			analysis_check_DRIVER("tree_CALLBACKS", director_1.tree_CALLBACKS, director_2.tree_CALLBACKS, this.tree_addition_CALLBACKS, this.tree_missing_CALLBACKS, tree_MODIFIED_CALLBACKS);
			analysis_check_DRIVER("tree_UNLOADED_MODULES", director_1.tree_UNLOADED_MODULES, director_2.tree_UNLOADED_MODULES, this.tree_addition_UNLOADED_MODULES, this.tree_missing_UNLOADED_MODULES, tree_MODIFIED_UNLOADED_MODULES);
			analysis_check_DRIVER("tree_TIMERS", director_1.tree_TIMERS, director_2.tree_TIMERS, this.tree_addition_TIMERS, this.tree_missing_TIMERS, tree_MODIFIED_TIMERS);
			
			//peer into Node_Generic of each node
			analysis_check_DRIVER_Node_Generic("tree_CALLBACKS Entries", director_1.tree_CALLBACKS, director_2.tree_CALLBACKS, this.tree_addition_CALLBACKS, this.tree_missing_CALLBACKS, tree_MODIFIED_CALLBACKS, index_callbacks);
			analysis_check_DRIVER_Node_Generic("tree_UNLOADED_MODULES Entries", director_1.tree_UNLOADED_MODULES, director_2.tree_UNLOADED_MODULES, this.tree_addition_UNLOADED_MODULES, this.tree_missing_UNLOADED_MODULES, tree_MODIFIED_UNLOADED_MODULES, index_unloaded_modules);
			analysis_check_DRIVER_Node_Generic("tree_TIMERS Entries", director_1.tree_TIMERS, director_2.tree_TIMERS, this.tree_addition_TIMERS, this.tree_missing_TIMERS, tree_MODIFIED_TIMERS, index_timers);
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "snapshot_analysis_director_check_DRIVER", e);
		}
		
		return false;
	}
	
	public boolean analysis_check_PROCESS(String description, TreeMap<Integer, Node_Process> tree_1, TreeMap<Integer, Node_Process> tree_2, TreeMap<Integer, Node_Process> tree_addition_results, TreeMap<Integer, Node_Process> tree_missing_results, TreeMap<Integer, Node_Process> tree_MODIFIED_results)
	{
		try
		{		
			
			////////////////////////////////////////////////////////////////////////////////////
			// first determine if snapshot 1 is empty -> add every process from snapshot 2
			///////////////////////////////////////////////////////////////////////////////////
			
			if((tree_1 == null || tree_1.isEmpty()) && tree_2 != null) 
			{
				//everything is an addition
				for(Node_Process node : tree_2.values())
				{
					if(node == null)
						continue;

					tree_addition_results.put(node.PID,  node);
				}								
			}

			
			////////////////////////////////////////////////////////////////////////////////////
			// Check absolute missing: ensure snapshot 2 is not blank
			///////////////////////////////////////////////////////////////////////////////////
			
			else if((tree_2 == null || tree_2.isEmpty()) && tree_1 != null)
			{
				//everything is missing from snapshot 2
				for(Node_Process node : tree_1.values())
				{
					if(node == null)
						continue;

					tree_missing_results.put(node.PID,  node);
				}
			}

			else
			{
				/////////////////////////////////////////
				// CHECK ADDITIONS
				////////////////////////////////////////					
				for(int key : tree_2.keySet())
				{
					//if tree_1 does not contain a node present in tree_2, this is an addition
					if(!tree_1.containsKey(key))
						try	{	tree_addition_results.put(key, tree_2.get(key));	} catch(Exception e) {driver.directive("Error! I encountered difficulties trying to retrieve key [" + key + "] for ADDITIONS results tree");}
				}


				/////////////////////////////////////////
				// CHECK MISSING
				////////////////////////////////////////
				for(int key : tree_1.keySet())
				{
					//if tree_2 does not contain a node present in tree_1, this is a missing value
					if(!tree_2.containsKey(key))
						try	{	tree_missing_results.put(key, tree_1.get(key));	} catch(Exception e) {driver.directive("Error! I encountered difficulties trying to retrieve key [" + key + "] for MISSING results tree");}
				}

				/////////////////////////////////////////
				// CHECK MODIFIED
				////////////////////////////////////////


			}








			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analysis_check_PROCESS", e);
		}
		
		return false;
	}
	
	public boolean analysis_check_DLL_PATHS(String description, TreeMap<String, Node_DLL> tree_1, TreeMap<String, Node_DLL> tree_2, TreeMap<String, Node_DLL> tree_addition_results, TreeMap<String, Node_DLL> tree_missing_results, TreeMap<String, Node_DLL> tree_MODIFIED_results)
	{
		try
		{				
			////////////////////////////////////////////////////////////////////////////////////
			// first determine if snapshot 1 is empty -> add every process from snapshot 2
			///////////////////////////////////////////////////////////////////////////////////
			
			if((tree_1 == null || tree_1.isEmpty()) && tree_2 != null) 
			{
				//everything is an addition
				for(String key : tree_2.keySet())
				{
					if(key == null || key.trim().equals(""))
						continue;										

					tree_addition_results.put(key, tree_2.get(key));
				}								
			}

			
			////////////////////////////////////////////////////////////////////////////////////
			// Check absolute missing: ensure snapshot 2 is not blank
			///////////////////////////////////////////////////////////////////////////////////
			
			else if((tree_2 == null || tree_2.isEmpty()) && tree_1 != null)
			{
				//everything is missing from snapshot 2
				for(String key : tree_1.keySet())
				{
					if(key == null || key.trim().equals(""))
						continue;															
					
					tree_missing_results.put(key,  tree_1.get(key));
				}
			}

			else
			{
				/////////////////////////////////////////
				// CHECK ADDITIONS
				////////////////////////////////////////					
				for(String key : tree_2.keySet())
				{
					//if tree_1 does not contain a node present in tree_2, this is an addition
					if(!tree_1.containsKey(key))
						try	{	tree_addition_results.put(key, tree_2.get(key));	} catch(Exception e) {driver.directive("Error! I encountered difficulties trying to retrieve key [" + key + "] for ADDITIONS results tree");}
				}


				/////////////////////////////////////////
				// CHECK MISSING
				////////////////////////////////////////
				for(String key : tree_1.keySet())
				{
					//if tree_2 does not contain a node present in tree_1, this is a missing value
					if(!tree_2.containsKey(key))
						try	{	tree_missing_results.put(key, tree_1.get(key));	} catch(Exception e) {driver.directive("Error! I encountered difficulties trying to retrieve key [" + key + "] for MISSING results tree");}
				}

				/////////////////////////////////////////
				// CHECK MODIFIED
				////////////////////////////////////////


			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analysis_check_DLL_PATHS", e);
		}
		
		return false;
	}
	
	public boolean analysis_check_DRIVER(String description, TreeMap<String, Node_Driver> tree_1, TreeMap<String, Node_Driver> tree_2, TreeMap<String, Node_Driver> tree_addition_results, TreeMap<String, Node_Driver> tree_missing_results, TreeMap<String, Node_Driver> tree_MODIFIED_results)
	{
		try
		{				
			////////////////////////////////////////////////////////////////////////////////////
			// first determine if snapshot 1 is empty -> add every process from snapshot 2
			///////////////////////////////////////////////////////////////////////////////////
			
			if((tree_1 == null || tree_1.isEmpty()) && tree_2 != null) 
			{
				//everything is an addition
				for(String key : tree_2.keySet())
				{
					if(key == null || key.trim().equals(""))
						continue;										

					tree_addition_results.put(key, tree_2.get(key));
				}								
			}

			
			////////////////////////////////////////////////////////////////////////////////////
			// Check absolute missing: ensure snapshot 2 is not blank
			///////////////////////////////////////////////////////////////////////////////////
			
			else if((tree_2 == null || tree_2.isEmpty()) && tree_1 != null)
			{
				//everything is missing from snapshot 2
				for(String key : tree_1.keySet())
				{
					if(key == null || key.trim().equals(""))
						continue;															
					
					tree_missing_results.put(key,  tree_1.get(key));
				}
			}

			else
			{
				/////////////////////////////////////////
				// CHECK ADDITIONS
				////////////////////////////////////////					
				for(String key : tree_2.keySet())
				{
					//if tree_1 does not contain a node present in tree_2, this is an addition
					if(!tree_1.containsKey(key))
						try	{	tree_addition_results.put(key, tree_2.get(key));	} catch(Exception e) {driver.directive("Error! I encountered difficulties trying to retrieve key [" + key + "] for ADDITIONS results tree");}
				}


				/////////////////////////////////////////
				// CHECK MISSING
				////////////////////////////////////////
				for(String key : tree_1.keySet())
				{
					//if tree_2 does not contain a node present in tree_1, this is a missing value
					if(!tree_2.containsKey(key))
						try	{	tree_missing_results.put(key, tree_1.get(key));	} catch(Exception e) {driver.directive("Error! I encountered difficulties trying to retrieve key [" + key + "] for MISSING results tree");}
				}

				/////////////////////////////////////////
				// CHECK MODIFIED
				////////////////////////////////////////


			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analysis_check_DRIVER on structure [" + description + "]", e);
		}
		
		return false;
	}
	
	public boolean analysis_check_Tree_String(String description, TreeMap<String, String> tree_1, TreeMap<String, String> tree_2, TreeMap<String, String> tree_addition_results, TreeMap<String, String> tree_missing_results, TreeMap<String, String> tree_MODIFIED_results, boolean only_use_key_for_check_for_modification_function)
	{
		try
		{				
			////////////////////////////////////////////////////////////////////////////////////
			// first determine if snapshot 1 is empty -> add every process from snapshot 2
			///////////////////////////////////////////////////////////////////////////////////
			
			if((tree_1 == null || tree_1.isEmpty()) && tree_2 != null) 
			{
				//everything is an addition
				for(String key : tree_2.keySet())
				{
					if(key == null || key.trim().equals(""))
						continue;										

					tree_addition_results.put(key, tree_2.get(key));
				}								
			}

			
			////////////////////////////////////////////////////////////////////////////////////
			// Check absolute missing: ensure snapshot 2 is not blank
			///////////////////////////////////////////////////////////////////////////////////
			
			else if((tree_2 == null || tree_2.isEmpty()) && tree_1 != null)
			{
				//everything is missing from snapshot 2
				for(String key : tree_1.keySet())
				{
					if(key == null || key.trim().equals(""))
						continue;															
					
					tree_missing_results.put(key,  tree_1.get(key));
				}
			}

			else
			{
				/////////////////////////////////////////
				// CHECK ADDITIONS
				////////////////////////////////////////					
				for(String key : tree_2.keySet())
				{
					//if tree_1 does not contain a node present in tree_2, this is an addition
					if(!tree_1.containsKey(key))
						try	{	tree_addition_results.put(key, tree_2.get(key));	} catch(Exception e) {driver.directive("Error! I encountered difficulties trying to retrieve key [" + key + "] for ADDITIONS results tree");}
				}

				
				/////////////////////////////////////////
				// CHECK MISSING
				////////////////////////////////////////
				for(String key : tree_1.keySet())
				{
					//if tree_2 does not contain a node present in tree_1, this is a missing value
					if(!tree_2.containsKey(key))
						try	{	tree_missing_results.put(key, tree_1.get(key));	} catch(Exception e) {driver.directive("Error! I encountered difficulties trying to retrieve key [" + key + "] for MISSING results tree");}
				}

				/////////////////////////////////////////
				// CHECK MODIFIED
				////////////////////////////////////////
				
				String value_1 = "", value_2 = "";
				for(String key : tree_1.keySet())
				{
					try
					{
						if(tree_addition_results.containsKey(key))
							continue;
						
						if(tree_missing_results.containsKey(key))
							continue;
						
						//at this point, we should be left with keys that are shared in both trees: 1 and 2. check the value of each
						if(only_use_key_for_check_for_modification_function)
						{
							//here, since we don't have a value to retrieve, all we can do is check lists of the keys
							LinkedList<String> list_1 = new LinkedList<String>(tree_1.values()) ;
							LinkedList<String> list_2 = new LinkedList<String>(tree_2.values()) ;
																					
							for(String entry_1 : list_1)
							{
								if(entry_1 == null || entry_1.trim().equals(""))
									continue;
								
								//ensure we have not added previously
								if(tree_addition_results != null && tree_addition_results.containsKey(entry_1))
									continue;
								
								else if(tree_addition_results != null && tree_addition_results.containsKey(entry_1))
									continue;
								
								else if(tree_missing_results != null && tree_missing_results.containsKey(entry_1))
									continue;
								
								else if(tree_missing_results != null && tree_missing_results.containsKey(entry_1))
									continue;															
								
								//otw, add as modified								
								else if(!list_2.contains(entry_1))
									tree_MODIFIED_results.put(entry_1, "");
							}
						}
						else
						{
							value_1 = tree_1.get(key);
							value_2 = tree_2.get(key);
							
							if(!value_1.toLowerCase().trim().equals(value_2.toLowerCase().trim()))
								tree_MODIFIED_results.put(key,  "value from snapshot 1: [" + value_1 + "] value from snapshot 2: [" + value_2 + "]");
						}
						
						
					}
					catch(Exception e)
					{
						driver.directive("Error! I encountered difficulties trying to retrieve key [" + key + "] for MODIFIED results tree");
						continue;
					}
					
				}
				
				for(String key : tree_2.keySet())
				{
					try
					{
						if(tree_addition_results.containsKey(key))
							continue;
						
						if(tree_missing_results.containsKey(key))
							continue;
						
						//at this point, we should be left with keys that are shared in both trees: 1 and 2. check the value of each
						if(only_use_key_for_check_for_modification_function)
						{
							//here, since we don't have a value to retrieve, all we can do is check lists of the keys
							LinkedList<String> list_1 = new LinkedList<String>(tree_1.values()) ;
							LinkedList<String> list_2 = new LinkedList<String>(tree_2.values()) ;
																					
							for(String entry_2 : list_2)
							{
								if(entry_2 == null || entry_2.trim().equals(""))
									continue;
								
								//ensure we have not added previously
								if(tree_addition_results != null && tree_addition_results.containsKey(entry_2))
									continue;
								
								else if(tree_addition_results != null && tree_addition_results.containsKey(entry_2))
									continue;
								
								else if(tree_missing_results != null && tree_missing_results.containsKey(entry_2))
									continue;
								
								else if(tree_missing_results != null && tree_missing_results.containsKey(entry_2))
									continue;															
								
								//otw, add as modified
								else if(!list_1.contains(entry_2))
									tree_MODIFIED_results.put(entry_2, "");
							}
						}
						else
						{
							value_1 = tree_1.get(key);
							value_2 = tree_2.get(key);
							
							if(!value_1.toLowerCase().trim().equals(value_2.toLowerCase().trim()))
								tree_MODIFIED_results.put(key,  "value from snapshot 1: [" + value_1 + "] value from snapshot 2: [" + value_2 + "]");
						}
						
						
					}
					catch(Exception e)
					{
						driver.directive("Error! I encountered difficulties trying to retrieve key [" + key + "] for MODIFIED results tree");
						continue;
					}
					
				}

			}//end else
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analysis_check_Tree_String", e);
		}
		
		return false;
	}
	
	
	
	
	public boolean snapshot_analysis_investigation_particulars(Advanced_Analysis_Director director_1, Advanced_Analysis_Director director_2)
	{
		try
		{
			sop("\nAnalyzing investigation particulars...");
			
			this.lst_investigation_particulars.add(new Node_Generic("investigator_name", director_1.investigator_name, director_2.investigator_name));
			this.lst_investigation_particulars.add(new Node_Generic("investigation_description", director_1.investigation_description, director_2.investigation_description));
			this.lst_investigation_particulars.add(new Node_Generic("execution_time_stamp", director_1.EXECUTION_TIME_STAMP, director_2.EXECUTION_TIME_STAMP));
			this.lst_investigation_particulars.add(new Node_Generic("profile", director_1.PROFILE, director_2.PROFILE));
			this.lst_investigation_particulars.add(new Node_Generic("profile_lower", director_1.profile_lower, director_2.profile_lower));  
			this.lst_investigation_particulars.add(new Node_Generic("relative_path_to_file_analysis_directory", director_1.relative_path_to_file_analysis_directory, director_2.relative_path_to_file_analysis_directory));
			this.lst_investigation_particulars.add(new Node_Generic("analysis_framework_name", director_1.analysis_framework_export_name, director_2.analysis_framework_export_name));
			this.lst_investigation_particulars.add(new Node_Generic("analysis_framework_version", director_1.analysis_framework_export_version, director_2.analysis_framework_export_version));
			
			populate_analysis_of_file_attributes("analysis_kit", director_1.file_attr_volatility, director_2.file_attr_volatility, lst_investigation_particulars);
			populate_analysis_of_file_attributes("memory_image", director_1.file_attr_memory_image, director_2.file_attr_memory_image, this.lst_investigation_particulars);
			
			//need to compare memory image file attributes
						
			this.lst_investigation_particulars.add(new Node_Generic("system_drive", director_1.system_drive, director_2.system_drive));
			this.lst_investigation_particulars.add(new Node_Generic("system_root", director_1.system_root, director_2.system_root));
			this.lst_investigation_particulars.add(new Node_Generic("computer_name", director_1.computer_name, director_2.computer_name));
			this.lst_investigation_particulars.add(new Node_Generic("processor_identifier", director_1.PROCESSOR_IDENTIFIER, director_2.PROCESSOR_IDENTIFIER));
			this.lst_investigation_particulars.add(new Node_Generic("processor_architecture", director_1.PROCESSOR_ARCHITECTURE, director_2.PROCESSOR_ARCHITECTURE));

			sop("Done!");
									
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "snapshot_analysis_investigation_particulars", e);
		}
		
		return false;
	}
	
	
	
	
	
		
	
	
	
	public boolean sop(String out)
	{
		try
		{
			if(intrface != null)
				intrface.jtaSnapshotAnalysisConsole.append(out);
			
			else 
				driver.sop(out);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "sop");
		}
		
		return false;
	}
	
	
	
	
	public boolean PRINT_REPORT()
	{
		try
		{
			//create printwriter
			PrintWriter pw = null;
			JTextArea_Solomon jta = intrface.jtaSnapshotAnalysisConsole;
									
			int count_differences_investigation_particulars = this.write_report_investigation_particulars(pw, jta);
			
			//
			//ADDITIONAL
			//
			int additional_processes = this.write_report_process("\nADDITIONAL PROCESSES DETECTED", this.tree_addition_PROCESS, pw, jta);
			int additional_orphaned_processes = this.write_report_process("\nADDITIONAL ORPHANED PROCESSES DETECTED", this.tree_addition_ORPHAN_process, pw, jta);
			int additional_dll = this.write_report_dll("\nADDITIONAL DLLs DETECTED", this.tree_addition_DLL_by_path, pw, jta);
			int additional_drivers = this.write_report_driver("\nADDITIONAL DRIVERS DETECTED", this.tree_addition_DRIVERS, pw, jta);
			int additional_drivers_irp_hooks = this.write_report_driver("\nADDITIONAL DRIVER IRP HOOKS DETECTED", this.tree_addition_DRIVER_IRP_HOOK, pw, jta);
			
			int additional_callbacks = this.write_report_driver("\nADDITIONAL DRIVER CALLBACKS DETECTED - CrossRef to identify specific modification", this.tree_addition_CALLBACKS, pw, jta);
			int additional_unloaded_modules = this.write_report_driver("\nADDITIONAL UNLOADED MODULES DETECTED - CrossRef to identify specific modification", this.tree_addition_UNLOADED_MODULES, pw, jta);
			int additional_timers = this.write_report_driver("\nADDITIONAL DRIVER TIMERS DETECTED - CrossRef to identify specific modification", this.tree_addition_TIMERS, pw, jta);
			int additional_user_assists = this.write_report_registry("\nADDITIONAL USER ASSIST ENTRIES DETECTED", this.tree_addition_REGISTRY_HIVE_USER_ASSIST, pw, jta);
			int additional_print_key = this.write_report_registry("\nADDITIONAL PRINT KEY ENTRIES DETECTED", this.tree_addition_REGISTRY_HIVE_PRINTKEY, pw, jta);
			
			this.count_additional_HIVELIST = this.write_report_hivelist("\nADDITIONAL HIVELIST ENTRIES DETECTED", this.tree_addition_HIVELIST, pw, jta);
			this.count_additional_HASHDUMP = this.write_report_tree_string("\nADDITIONAL HASHDUMP ENTRIES DETECTED", this.tree_addition_HASHDUMP, pw, jta);
			this.count_additional_GET_SERVICE_SIDS = this.write_report_get_service_sid("\nADDITIONAL SERVICE SID ENTRIES DETECTED", this.tree_addition_GET_SERVICE_SIDS, pw, jta);
			
			this.count_additional_SIDS = this.write_report_tree_string("\nADDITIONAL SID ENTRIES DETECTED", this.tree_addition_SIDS, pw, jta);
			
			count_additional_SESSION_ENTRIES = this.write_report_tree_SESSIONS("\nADDITIONAL SESSION ENTRY DETECTED", this.tree_addition_SESSION_ENTRIES, pw, jta);
			int additional_deskscan = this.write_report_node_generic("\nADDITIONAL DESKSCAN ENTRIES DETECTED", this.tree_addition_DESKSCAN, pw, jta);
			int additional_audit_policy = this.write_report_node_generic("\nADDITIONAL AUDIT POLICY ENTRIES DETECTED", this.tree_addition_AUDIT_POLICY, pw, jta);

			//
			//MISSING
			//
			int missing_processes = this.write_report_process("\nMISSING PROCESSES DETECTED", this.tree_missing_PROCESS, pw, jta);
			int missing_orphaned_processes = this.write_report_process("\nMISSING ORPHANED PROCESSES DETECTED", this.tree_missing_ORPHAN_process, pw, jta);
			int missing_dll = this.write_report_dll("\nMISSING DLLs DETECTED", this.tree_missing_DLL_by_path, pw, jta);
			int missing_drivers = this.write_report_driver("\nMISSING DRIVERS DETECTED", this.tree_missing_DRIVERS, pw, jta);
			int missing_drivers_irp_hooks = this.write_report_driver("\nMISSING DRIVER IRP HOOKS DETECTED", this.tree_missing_DRIVER_IRP_HOOK, pw, jta);
			int missing_callbacks = this.write_report_driver("\nMISSING DRIVER CALLBACKS DETECTED - CrossRef to identify specific modification", this.tree_missing_CALLBACKS, pw, jta);
			int missing_unloaded_modules = this.write_report_driver("\nMISSING UNLOADED MODULES DETECTED - CrossRef to identify specific modification", this.tree_missing_UNLOADED_MODULES, pw, jta);
			int missing_timers = this.write_report_driver("\nMISSING DRIVER TIMERS DETECTED - CrossRef to identify specific modification", this.tree_missing_TIMERS, pw, jta);
			int missing_user_assists = this.write_report_registry("\nMISSING USER ASSIST ENTRIES DETECTED", this.tree_missing_REGISTRY_HIVE_USER_ASSIST, pw, jta);
			int missing_print_key = this.write_report_registry("\nMISSING PRINT KEY ENTRIES DETECTED", this.tree_missing_REGISTRY_HIVE_PRINTKEY, pw, jta);
			
			this.count_missing_HIVELIST = this.write_report_hivelist("\nMISSING HIVELIST ENTRIES DETECTED", this.tree_missing_HIVELIST, pw, jta);
			this.count_missing_HASHDUMP = this.write_report_tree_string("\nMISSING HASHDUMP ENTRIES DETECTED", this.tree_missing_HASHDUMP, pw, jta);
			this.count_missing_GET_SERVICE_SIDS = this.write_report_get_service_sid("\nMISSING SERVICE SID ENTRIES DETECTED", this.tree_missing_GET_SERVICE_SIDS, pw, jta);
			this.count_missing_SIDS = this.write_report_tree_string("\nMISSING SID ENTRIES DETECTED", this.tree_missing_SIDS, pw, jta);
			count_missing_SESSION_ENTRIES = this.write_report_tree_SESSIONS("\nMISSING SESSION ENTRY DETECTED", this.tree_missing_SESSION_ENTRIES, pw, jta);
			int missing_deskscan = this.write_report_node_generic("\nMISSING DESKSCAN ENTRIES DETECTED", this.tree_missing_DESKSCAN, pw, jta);
			int missing_audit_policy = this.write_report_node_generic("\nMISSING AUDIT POLICY ENTRIES DETECTED", this.tree_missing_AUDIT_POLICY, pw, jta);
			
			//
			//MODIFIED
			//
			//int modified_dll_module_name = this.write_report_tree_string("\nMODIFIED DLLs BASE ADDRESS TO MODULE NAME", this.tree_MODIFIED_Module_Name_from_base_address_as_key, pw, jta);
			//this.additional_count_MODIFIED_HASHDUMP = this.write_report_tree_string("\nMODIFIED HASHDUMP ENTRIES DETECTED", this.tree_missing_HASHDUMP, pw, jta);
			//this.additional_count_MODIFIED_SIDS = this.write_report_tree_string("\nMODIFIED SID ENTRIES DETECTED", this.tree_missing_SIDS, pw, jta);
			
			jta.append("\n");
			
			PRINT_REPORT_DEEP_INSPECTION(jta, this.tree_PROCESS);
			PRINT_REPORT_DEEP_INSPECTION(jta, this.tree_DLL);
			PRINT_REPORT_DEEP_INSPECTION(jta, this.tree_DRIVER);
			PRINT_REPORT_DEEP_INSPECTION(jta, this.tree_DRIVER_IRP);
			PRINT_REPORT_DEEP_INSPECTION(jta, this.tree_CALLBACKS);
			PRINT_REPORT_DEEP_INSPECTION(jta, this.tree_TIMERS);
			PRINT_REPORT_DEEP_INSPECTION(jta, this.tree_UNLOADED_MODULES);
			
			PRINT_REPORT_DEEP_INSPECTION(jta, Node_Snapshot_Analysis_Artifact.ARTIFACT_TYPE_filescan, this.tree_filescan_addition, this.tree_filescan_missing, this.tree_filescan_MODIFICATION);
			PRINT_REPORT_DEEP_INSPECTION(jta, Node_Snapshot_Analysis_Artifact.ARTIFACT_TYPE_mftparser, this.tree_mftparser_addition, this.tree_mftparser_missing, this.tree_mftparser_MODIFICATION);
			PRINT_REPORT_DEEP_INSPECTION(jta, Node_Snapshot_Analysis_Artifact.ARTIFACT_TYPE_timeliner, this.tree_timeliner_addition, this.tree_timeliner_missing, this.tree_timeliner_MODIFICATION);
			PRINT_REPORT_DEEP_INSPECTION(jta, Node_Snapshot_Analysis_Artifact.ARTIFACT_TYPE_userassist_specific_entries, this.tree_userassist_specific_entries_addition, this.tree_userassist_specific_entries_missing, this.tree_userassist_specific_entries_MODIFICATION);
			PRINT_REPORT_DEEP_INSPECTION(jta, Node_Snapshot_Analysis_Artifact.ARTIFACT_TYPE_shellbags, this.tree_shellbags_addition, this.tree_shellbags_missing, this.tree_shellbags_MODIFICATION);
			PRINT_REPORT_DEEP_INSPECTION(jta, Node_Snapshot_Analysis_Artifact.ARTIFACT_TYPE_shimcache, this.tree_shimcache_addition, this.tree_shimcache_missing, this.tree_shimcache_MODIFICATION);
			
			
			sop("\n\nANALYSIS COMPLETE! ");
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "print_report", e);
		}
		
		return false;
	}
	
	public boolean PRINT_REPORT_DEEP_INSPECTION(JTextArea_Solomon jta, TreeMap<String, Node_Snapshot_Analysis_Artifact> tree)
	{
		try
		{
			if(tree == null)
				return false;
			
			for(Node_Snapshot_Analysis_Artifact node : tree.values())
			{
				if(node == null)
					continue;
				
				if(!node.MODIFICATION_DETECTED)
					continue;
																
				if(node.short_descriptor != null && node.short_descriptor.length() > 0)
				{
					jta.append(node.my_artifact_type + " " + node.short_descriptor);
					jta.append(driver.UNDERLINE);
					jta.append("Full Descriptor: " + node.descriptor);
				}
				else
				{
					jta.append(node.my_artifact_type + " " + node.descriptor);
					jta.append_sp(driver.UNDERLINE);
				}
				
				
				
				node.PRINT_REPORT();
				jta.append("");
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "PRINT_REPORT_DEEP_INSPECTION", e);
		}
		
		return false;
	}
	
	public boolean PRINT_REPORT_DEEP_INSPECTION(JTextArea_Solomon jta, String my_artifact_type, TreeMap<String, String> tree_addition, TreeMap<String, String> tree_missing, TreeMap<String, String> tree_MODIFICATION)
	{
		try
		{


			
			//
			//addition
			//
			if(tree_addition != null && tree_addition.size() > 0)
			{
				
				jta.append("Additional " + my_artifact_type + " entries detected");
				jta.append(driver.UNDERLINE);
				jta.append("entry\tdisposition");
				
				for(String key : tree_addition.keySet())
				{
					jta.append(key + ":\t" + tree_addition.get(key));
				}
				
				jta.append("\n");
			}
			
			//
			//missing
			//
			if(tree_missing != null && tree_missing.size() > 0)
			{
				
				jta.append("Missing " + my_artifact_type + " entries detected");
				jta.append(driver.UNDERLINE);
				jta.append("entry\tdisposition");
				
				for(String key : tree_missing.keySet())
				{
					jta.append(key + ":\t" + tree_missing.get(key));
				}
				
				jta.append("\n");
			}
			
			//
			//Modified
			//
			if(tree_MODIFICATION != null && tree_MODIFICATION.size() > 0)
			{
				
				jta.append("Modified " + my_artifact_type + " entries detected");
				jta.append(driver.UNDERLINE);
				jta.append("entry\tdisposition");
				
				for(String key : tree_MODIFICATION.keySet())
				{
					jta.append(key + ":\t" + tree_MODIFICATION.get(key));
				}
				
				jta.append("\n");
			}
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "PRINT_REPORT_DEEP_INSPECTION - file attributes", e);
		}
		
		return false;
	}
	
	public int write_report_process(String identifier, TreeMap<Integer, Node_Process> tree, PrintWriter pw, JTextArea_Solomon jta)
	{
		int count_differences = 0;
		
		try
		{
			if(tree == null || tree.isEmpty())
				return 0;
			
			//otw, process the differences
			count_differences = tree.size();
			
			jta.append(identifier + ": [" + count_differences + "]\n" + driver.UNDERLINE);
			
			for(Node_Process node : tree.values())
			{
				jta.append(node.toString());
			}
			
			
		}
		catch(Exception e)
		{
			driver.eop(identifier, "write_report_process", e);
		}
		
		return count_differences;
	}
	
	
	public int write_report_node_generic(String identifier, TreeMap<String, Node_Generic> tree, PrintWriter pw, JTextArea_Solomon jta)
	{
		int count_differences = 0;
		
		try
		{
			if(tree == null || tree.isEmpty())
				return 0;
			
			//otw, process the differences
			count_differences = tree.size();
			
			jta.append(identifier + ": [" + count_differences + "]\n" + driver.UNDERLINE);
			
			for(Node_Generic node : tree.values())
			{
				jta.append(node.write_manifest_as_single_line(null, "", "\t").trim());
			}
			
			
		}
		catch(Exception e)
		{
			driver.eop(identifier, "write_report_node_generic", e);
		}
		
		return count_differences;
	}
	
	public int write_report_registry(String identifier, TreeMap<String, Node_Registry_Hive> tree, PrintWriter pw, JTextArea_Solomon jta)
	{
		int count_differences = 0;
		
		try
		{
			if(tree == null || tree.isEmpty())
				return 0;
			
			//otw, process the differences
			count_differences = tree.size();
			
			jta.append(identifier + ": [" + count_differences + "]\n" + driver.UNDERLINE);
								
			for(Node_Registry_Hive hive : tree.values())
			{
				jta.append("Registry hive: " + hive.registry_hive);
				
				for(Node_Registry_Key key : hive.tree_registry_key.values())
				{
					if(key.key_name == null)
						jta.append("\tRegistry key: " + key.path);
					else
						jta.append("\tRegistry key: " + key.key_name);
					
					if(key.list_sub_key_names != null)
					{
						for(String sub_key : key.list_sub_key_names)
							jta.append("\t\t" + sub_key);
					}
					
					if(key.list_values != null)
					{
						for(String value : key.list_values)
							jta.append("\t\t" + value);
					}
					
					if(key.tree_reg_subkey != null)
					{
						for(Node_Generic node : key.tree_reg_subkey.values())
							jta.append("\t\t" + node.write_manifest_as_single_line(null, "", "\t").trim());
					}
				}
									
			}
			
			
			
			
		}
		catch(Exception e)
		{
			driver.eop(identifier, "write_report_registry", e);
		}
		
		return count_differences;
	}
	
	public int write_report_environment_var(String identifier, TreeMap<String, Node_Envar> tree, PrintWriter pw, JTextArea_Solomon jta)
	{
		int count_differences = 0;
		
		try
		{
			if(tree == null || tree.isEmpty())
				return 0;
			
			//otw, process the differences
			count_differences = tree.size();
			
			jta.append(identifier + ": [" + count_differences + "]\n" + driver.UNDERLINE);
			
			for(Node_Envar node : tree.values())
			{
				jta.append(node.toString());
			}
			
			
		}
		catch(Exception e)
		{
			driver.eop(identifier, "write_report_driver", e);
		}
		
		return count_differences;
	}
	
	public int write_report_driver(String identifier, TreeMap<String, Node_Driver> tree, PrintWriter pw, JTextArea_Solomon jta)
	{
		int count_differences = 0;
		
		try
		{
			if(tree == null || tree.isEmpty())
				return 0;
			
			//otw, process the differences
			count_differences = tree.size();
			
			jta.append(identifier + ": [" + count_differences + "]\n" + driver.UNDERLINE);
			
			for(Node_Driver node : tree.values())
			{
				jta.append(node.toString());
			}
			
			
		}
		catch(Exception e)
		{
			driver.eop(identifier, "write_report_driver", e);
		}
		
		return count_differences;
	}
	
	public int write_report_hivelist(String identifier, TreeMap<String, Node_hivelist> tree, PrintWriter pw, JTextArea_Solomon jta)
	{
		int count_differences = 0;
		
		try
		{
			if(tree == null || tree.isEmpty())
				return 0;
			
			//otw, process the differences
			count_differences = tree.size();
			
			jta.append(identifier + ": [" + count_differences + "]\n" + driver.UNDERLINE);
			
			for(Node_hivelist node : tree.values())
			{
				jta.append(node.toString());
			}
			
			
		}
		catch(Exception e)
		{
			driver.eop(identifier, "write_report_hivelist", e);
		}
		
		return count_differences;
	}
	
	public int write_report_get_service_sid(String identifier, TreeMap<String, Node_get_service_sid> tree, PrintWriter pw, JTextArea_Solomon jta)
	{
		int count_differences = 0;
		
		try
		{
			if(tree == null || tree.isEmpty())
				return 0;
			
			//otw, process the differences
			count_differences = tree.size();
			
			jta.append(identifier + ": [" + count_differences + "]\n" + driver.UNDERLINE);
			
			for(Node_get_service_sid node : tree.values())
			{
				jta.append(node.toString());
			}
			
			
		}
		catch(Exception e)
		{
			driver.eop(identifier, "write_report_get_service_sid", e);
		}
		
		return count_differences;
	}
	
	public int write_report_tree_SESSIONS(String identifier, TreeMap<String, LinkedList<String>> tree, PrintWriter pw, JTextArea_Solomon jta)
	{
		int count_differences = 0;
		
		try
		{
			if(tree == null || tree.isEmpty())
				return 0;
			
			//otw, process the differences
			count_differences = tree.size();
			
			jta.append(identifier + ": [" + count_differences + "]\n" + driver.UNDERLINE);
			
			for(String session_container : tree.keySet())
			{
				if(session_container == null || session_container.trim().equals(""))
					continue;
				
				jta.append(session_container);
				
				LinkedList<String> list = tree.get(session_container);
				
				if(list == null || list.isEmpty())
					continue;				
				
				for(String entry : list)
				{
					if(entry == null || entry.trim().equals(""))
						continue;
					
					jta.append("\t"+entry);
				}								
			}
			
			
		}
		catch(Exception e)
		{
			driver.eop(identifier, "write_report_get_service_sid", e);
		}
		
		return count_differences;
	}
	
	
	
	public int write_report_dll(String identifier, TreeMap<String, Node_DLL> tree, PrintWriter pw, JTextArea_Solomon jta)
	{
		int count_differences = 0;
		
		try
		{
			if(tree == null || tree.isEmpty())
				return 0;
			
			//otw, process the differences
			count_differences = tree.size();
			
			jta.append(identifier + ": [" + count_differences + "]\n" + driver.UNDERLINE);
			
			for(Node_DLL node : tree.values())
			{
				jta.append(node.toString());
			}
			
			
		}
		catch(Exception e)
		{
			driver.eop(identifier, "write_report_dll", e);
		}
		
		return count_differences;
	}
	
	public int write_report_tree_string(String identifier, TreeMap<String, String> tree, PrintWriter pw, JTextArea_Solomon jta)
	{
		int count_differences = 0;
		
		try
		{
			if(tree == null || tree.isEmpty())
				return 0;
			
			//otw, process the differences
			count_differences = tree.size();
			
			jta.append(identifier + ": [" + count_differences + "]\n" + driver.UNDERLINE);
			
			for(String key : tree.keySet())
			{
				if(tree.get(key) == null)
					jta.append(key);
				else
					jta.append("key: [" + key + "] " + tree.get(key));
			}
			
			
		}
		catch(Exception e)
		{
			driver.eop(identifier, "write_report_tree_string", e);
		}
		
		return count_differences;
	}

	
	public int write_report_investigation_particulars(PrintWriter pw, JTextArea_Solomon jta)
	{
		int difference_count = 0;
		
		if(this.lst_investigation_particulars == null || this.lst_investigation_particulars.isEmpty())
			return 0;
		
		//
		//preprocessing is needed here first... 
		//
		boolean found_modifications = false;
		
		for(Node_Generic node : this.lst_investigation_particulars)
		{
			if(node == null || node.snapshot_manifest_DIFFERENCE_value == null || node.snapshot_manifest_DIFFERENCE_value.length() < 1)
				continue;
			
			//otw, a difference was found, print it out
			found_modifications = true;
		}
		
		if(!found_modifications)
			return 0;
						
		try
		{						
			if(intrface != null)
			{
				jta.append("\n" + "INVESTIGATION PARTICULARS\n" + driver.UNDERLINE);
				
				for(Node_Generic node : this.lst_investigation_particulars)
				{
					if(node == null)
						continue;
					
					difference_count += node.write_snapshot_report(pw, jta);
					
				}															
			}
			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_report", e, true);
		}
		
		return difference_count;
	}
	
	
	public boolean populate_analysis_of_file_attributes(String identifier, FileAttributeData attr_1, FileAttributeData attr_2, LinkedList<Node_Generic> lst)
	{
		try
		{
			if(attr_1 == null && attr_2 != null)
			{				
				lst.add(new Node_Generic(identifier + "_file_name", null, attr_2.file_name));
				lst.add(new Node_Generic(identifier + "_size", null, attr_2.size));
//				lst.add(new Node_Generic(identifier + "_creation", null, attr_2.creation_date));
//				lst.add(new Node_Generic(identifier + "_last_access", null, attr_2.last_accessed));
//				lst.add(new Node_Generic(identifier + "_last_modified", null, attr_2.last_modified));
				lst.add(new Node_Generic(identifier + "_md5", null, attr_2.hash_md5));
				lst.add(new Node_Generic(identifier + "_sha256", null, attr_2.hash_sha256));
				
			}
			
			else if(attr_2 == null && attr_1 != null)
			{				
				lst.add(new Node_Generic(identifier + "_file_name", attr_1.file_name, null));
				lst.add(new Node_Generic(identifier + "_size", attr_1.size, null));
//				lst.add(new Node_Generic(identifier + "_creation", attr_1.creation_date, null));
//				lst.add(new Node_Generic(identifier + "_last_access", attr_1.last_accessed, null));
//				lst.add(new Node_Generic(identifier + "_last_modified", attr_1.last_modified, null));
				lst.add(new Node_Generic(identifier + "_md5", attr_1.hash_md5, null));
				lst.add(new Node_Generic(identifier + "_sha256", attr_1.hash_sha256, null));
				
			}
			else
			{
				lst.add(new Node_Generic(identifier + "_file_name", attr_1.file_name, attr_2.file_name));
				lst.add(new Node_Generic(identifier + "_size", attr_1.size, attr_2.size));
//				lst.add(new Node_Generic(identifier + "_creation", attr_1.creation_date, attr_2.creation_date));
//				lst.add(new Node_Generic(identifier + "_last_access", attr_1.last_accessed, attr_2.last_accessed));
//				lst.add(new Node_Generic(identifier + "_last_modified", attr_1.last_modified, attr_2.last_modified));
				lst.add(new Node_Generic(identifier + "_md5", attr_1.hash_md5, attr_2.hash_md5));
				lst.add(new Node_Generic(identifier + "_sha256", attr_1.hash_sha256, attr_2.hash_sha256));
			}
			
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "populate_analysis_of_file_attributes", e);
		}
		
		return false;
	}
	
	/**
	 * for addition and missing Trees, the key is the Registry_Hive, and the value under each key is a LinkedList that stores a series of reg_binary	 %windir%\explorer.exe (for user assist), or key_name	 CMI-CreateHive{D43B12B8-09B5-40DB-B4F6-F6DFEB78DAEC} (S) (for print_key) 
	 * @param description
	 * @param tree_1
	 * @param tree_2
	 * @param tree_addition_results
	 * @param tree_missing_results
	 * @param tree_MODIFIED_results
	 * @return
	 */
	public boolean analysis_check_REGISTRY(String description, TreeMap<String, Node_Registry_Hive> tree_1, TreeMap<String, Node_Registry_Hive> tree_2, TreeMap<String, Node_Registry_Hive> tree_addition_results, TreeMap<String, Node_Registry_Hive> tree_missing_results, TreeMap<String, Node_Registry_Hive> tree_MODIFIED_results)
	{
		try
		{				
			////////////////////////////////////////////////////////////////////////////////////
			// first determine if snapshot 1 is empty -> add every process from snapshot 2
			///////////////////////////////////////////////////////////////////////////////////
			
			if((tree_1 == null || tree_1.isEmpty()) && tree_2 != null) 
			{
				//everything is an addition
				for(String key : tree_2.keySet())
				{
					if(key == null || key.trim().equals(""))
						continue;	
													
					tree_addition_results.put(key, tree_2.get(key));
				}								
			}

			
			////////////////////////////////////////////////////////////////////////////////////
			// Check absolute missing: ensure snapshot 2 is not blank
			///////////////////////////////////////////////////////////////////////////////////
			
			else if((tree_2 == null || tree_2.isEmpty()) && tree_1 != null)
			{
				//everything is missing from snapshot 2
				for(String key : tree_1.keySet())
				{
					if(key == null || key.trim().equals(""))
						continue;	
															
					tree_missing_results.put(key, tree_1.get(key));
				}
			}

			else
			{
				Node_Registry_Hive hive_1 = null, hive_2 = null;
				
				/////////////////////////////////////////
				// CHECK ADDITIONS
				////////////////////////////////////////	
				
				
				//
				//outter loop for each registry hive
				//
				for(String registry_hive_description : tree_2.keySet())
				{
					if(registry_hive_description == null || registry_hive_description.trim().equals(""))
						continue;
					
					//if tree_1 does not contain a node present in tree_2, this is an addition
					if(!tree_1.containsKey(registry_hive_description))
					{												
						try	{	tree_addition_results.put(registry_hive_description, tree_2.get(registry_hive_description));	} catch(Exception e) {driver.directive("Error! I encountered difficulties trying to retrieve key [" + registry_hive_description + "] for ADDITIONS results tree");}
					}
					else
					{
						//both tree 1 and tree 2 contain the key, now iterate through the sukeys to idenify additions
						hive_1 = tree_1.get(registry_hive_description);
						hive_2 = tree_2.get(registry_hive_description);
																		
						if(hive_1 == null && hive_2 == null)
							continue;
						
						//reject additions if the tree is null
						if(hive_2 == null)
							continue;
						
						if(hive_1 == null && hive_2 != null && !tree_addition_results.containsKey(registry_hive_description))
						{
							
							
							try	{	tree_addition_results.put(registry_hive_description, hive_2);	} catch(Exception e) {driver.directive("Error! I encountered difficulties trying to retrieve key [" + registry_hive_description + "] for ADDITIONS results tree");}
							
							continue;
						}
						
						//skip if this Hive's tree is empty
						if(hive_2.tree_registry_key == null)
							continue;
						
						//otw, iterate through both containers
						
						//
						//inner loop for each key under each container hive						
						//
						Node_Registry_Hive hive = null;
						Node_Registry_Key registry_key = null;
						
						Node_Registry_Key registry_key_1 = null, registry_key_2 = null;
						
						for(String registry_key_description : hive_2.tree_registry_key.keySet())
						{
							if(registry_key_description == null || registry_key_description.trim().equals(""))
								continue;														
							
							//search through the lists
							registry_key_1 = hive_1.tree_registry_key.get(registry_key_description);
							registry_key_2 = hive_2.tree_registry_key.get(registry_key_description);
														
							if(registry_key_2 == null)
								continue;
							
							//
							//list_sub_key_names
							//
							if(registry_key_2.list_sub_key_names != null)
							{
								for(String sub_key : registry_key_2.list_sub_key_names)
								{
									if(sub_key == null || sub_key.trim().equals(""))
										continue;
									
									if(registry_key_1 == null || registry_key_1.list_sub_key_names == null || registry_key_1.list_sub_key_names.isEmpty() || !registry_key_1.list_sub_key_names.contains(sub_key))
									{
										//sub_key is an addition!!!
										
										//get the hive to store this key's subkey
										hive = tree_addition_results.get(registry_hive_description); 
										
										if(hive == null)
										{
											hive = new Node_Registry_Hive ();
											hive.registry_hive = registry_hive_description;
											tree_addition_results.put(registry_hive_description, hive);
											//hive.tree_registry_key.put(registry_key_description,  hive_2.tree_registry_key.get(registry_key_description));
										}	
										
										registry_key = hive.tree_registry_key.get(registry_key_description);
										
										if(registry_key == null)
										{
											registry_key = new Node_Registry_Key(hive, registry_key_description);
											registry_key.key_name = registry_key_description;
											registry_key.path = registry_key_description;
											hive.tree_registry_key.put(registry_key_description, registry_key);
										}
										
										//create the list
										if(registry_key.list_sub_key_names == null)
											registry_key.list_sub_key_names = new LinkedList<String>();
										
										//store the key
										if(!registry_key.list_sub_key_names.contains(sub_key))
											registry_key.list_sub_key_names.add(sub_key);
									}
									
								}
							}
							
							//
							//list_values
							//
							if(registry_key_2.list_values != null)
							{
								for(String value : registry_key_2.list_values)
								{
									if(value == null || value.trim().equals(""))
										continue;
									
									if(registry_key_1 == null || registry_key_1.list_values == null || registry_key_1.list_values.isEmpty() || !registry_key_1.list_values.contains(value))
									{
										//value is an addition!!!
										
										//get the hive to store this key's subkey
										hive = tree_addition_results.get(registry_hive_description); 
										
										if(hive == null)
										{
											hive = new Node_Registry_Hive ();
											hive.registry_hive = registry_hive_description;
											tree_addition_results.put(registry_hive_description, hive);
											//hive.tree_registry_key.put(registry_key_description,  hive_2.tree_registry_key.get(registry_key_description));
										}	
										
										registry_key = hive.tree_registry_key.get(registry_key_description);
										
										if(registry_key == null)
										{
											registry_key = new Node_Registry_Key(hive, registry_key_description);
											registry_key.key_name = registry_key_description;
											registry_key.path = registry_key_description;
											hive.tree_registry_key.put(registry_key_description, registry_key);
										}
										
										//create the list
										if(registry_key.list_values == null)
											registry_key.list_values = new LinkedList<String>();
										
										//store the value!
										if(!registry_key.list_values.contains(value))
											registry_key.list_values.add(value);
									}
									
								}
							}
							
							//
							//tree
							//
							if(registry_key_2.tree_reg_subkey != null)
							{
								for(String sub_key : registry_key_2.tree_reg_subkey.keySet())
								{
									if(sub_key == null || sub_key.trim().equals(""))
										continue;
									
									if(registry_key_1 == null || registry_key_1.tree_reg_subkey == null || registry_key_1.tree_reg_subkey.isEmpty() || !registry_key_1.tree_reg_subkey.containsKey(sub_key))
									{

										//subkey is an addition!!!
										
										//get the hive to store this key's subkey
										hive = tree_addition_results.get(registry_hive_description); 
										
										if(hive == null)
										{
											hive = new Node_Registry_Hive ();
											hive.registry_hive = registry_hive_description;
											tree_addition_results.put(registry_hive_description, hive);											
										}	
										
										registry_key = hive.tree_registry_key.get(registry_key_description);
										
										if(registry_key == null)
										{
											registry_key = new Node_Registry_Key(hive, registry_key_description);
											registry_key.key_name = registry_key_description;
											registry_key.path = registry_key_description;
											hive.tree_registry_key.put(registry_key_description, registry_key);
										}
										
										//create the tree
										if(registry_key.tree_reg_subkey == null)
											registry_key.tree_reg_subkey = new TreeMap<String, Node_Generic>();
										
											
											
										//store the key
										if(!registry_key.tree_reg_subkey.containsKey(sub_key))
											registry_key.tree_reg_subkey.put(sub_key, registry_key_2.tree_reg_subkey.get(sub_key));
									}
									
								}
								
							}
							
							
							
						}
						
					}
				}


				/////////////////////////////////////////
				// CHECK MISSING
				////////////////////////////////////////
				//
				//outter loop for each registry hive
				//
				for(String registry_hive_description : tree_1.keySet())
				{
					if(registry_hive_description == null || registry_hive_description.trim().equals(""))
						continue;
					
					//if tree_2 does not contain a node present in tree_1, this is an missing
					if(!tree_2.containsKey(registry_hive_description))
					{												
						try	{	tree_missing_results.put(registry_hive_description, tree_1.get(registry_hive_description));	} catch(Exception e) {driver.directive("Error! I encountered difficulties trying to retrieve key [" + registry_hive_description + "] for missingS results tree");}
					}
					else
					{
						//both tree 1 and tree 2 contain the key, now iterate through the sukeys to idenify missings
						hive_2 = tree_2.get(registry_hive_description);
						hive_1 = tree_1.get(registry_hive_description);
																		
						if(hive_2 == null && hive_1 == null)
							continue;
						
						//reject missings if the tree is null
						if(hive_1 == null)
							continue;
						
						if(hive_2 == null && hive_1 != null && !tree_missing_results.containsKey(registry_hive_description))
						{
							
							
							try	{	tree_missing_results.put(registry_hive_description, hive_1);	} catch(Exception e) {driver.directive("Error! I encountered difficulties trying to retrieve key [" + registry_hive_description + "] for missingS results tree");}
							
							continue;
						}
						
						//skip if this Hive's tree is empty
						if(hive_1.tree_registry_key == null)
							continue;
						
						//otw, iterate through both containers
						
						//
						//inner loop for each key under each container hive						
						//
						Node_Registry_Hive hive = null;
						Node_Registry_Key registry_key = null;
						
						Node_Registry_Key registry_key_2 = null, registry_key_1 = null;
						
						for(String registry_key_description : hive_1.tree_registry_key.keySet())
						{
							if(registry_key_description == null || registry_key_description.trim().equals(""))
								continue;														
							
							//search through the lists
							registry_key_2 = hive_2.tree_registry_key.get(registry_key_description);
							registry_key_1 = hive_1.tree_registry_key.get(registry_key_description);
														
							if(registry_key_1 == null)
								continue;
							
							//
							//list_sub_key_names
							//
							if(registry_key_1.list_sub_key_names != null)
							{
								for(String sub_key : registry_key_1.list_sub_key_names)
								{
									if(sub_key == null || sub_key.trim().equals(""))
										continue;
									
									if(registry_key_2 == null || registry_key_2.list_sub_key_names == null || registry_key_2.list_sub_key_names.isEmpty() || !registry_key_2.list_sub_key_names.contains(sub_key))
									{
										//sub_key is an missing!!!
										
										//get the hive to store this key's subkey
										hive = tree_missing_results.get(registry_hive_description); 
										
										if(hive == null)
										{
											hive = new Node_Registry_Hive ();
											hive.registry_hive = registry_hive_description;
											tree_missing_results.put(registry_hive_description, hive);
											//hive.tree_registry_key.put(registry_key_description,  hive_1.tree_registry_key.get(registry_key_description));
										}	
										
										registry_key = hive.tree_registry_key.get(registry_key_description);
										
										if(registry_key == null)
										{
											registry_key = new Node_Registry_Key(hive, registry_key_description);
											registry_key.key_name = registry_key_description;
											registry_key.path = registry_key_description;
											hive.tree_registry_key.put(registry_key_description, registry_key);
										}
										
										//create the list
										if(registry_key.list_sub_key_names == null)
											registry_key.list_sub_key_names = new LinkedList<String>();
										
										//store the key
										if(!registry_key.list_sub_key_names.contains(sub_key))
											registry_key.list_sub_key_names.add(sub_key);
									}
									
								}
							}
							
							//
							//list_values
							//
							if(registry_key_1.list_values != null)
							{
								for(String value : registry_key_1.list_values)
								{
									if(value == null || value.trim().equals(""))
										continue;
									
									if(registry_key_2 == null || registry_key_2.list_values == null || registry_key_2.list_values.isEmpty() || !registry_key_2.list_values.contains(value))
									{
										//value is an missing!!!
										
										//get the hive to store this key's subkey
										hive = tree_missing_results.get(registry_hive_description); 
										
										if(hive == null)
										{
											hive = new Node_Registry_Hive ();
											hive.registry_hive = registry_hive_description;
											tree_missing_results.put(registry_hive_description, hive);
											//hive.tree_registry_key.put(registry_key_description,  hive_1.tree_registry_key.get(registry_key_description));
										}	
										
										registry_key = hive.tree_registry_key.get(registry_key_description);
										
										if(registry_key == null)
										{
											registry_key = new Node_Registry_Key(hive, registry_key_description);
											registry_key.key_name = registry_key_description;
											registry_key.path = registry_key_description;
											hive.tree_registry_key.put(registry_key_description, registry_key);
										}
										
										//create the list
										if(registry_key.list_values == null)
											registry_key.list_values = new LinkedList<String>();
										
										//store the value!
										if(!registry_key.list_values.contains(value))
											registry_key.list_values.add(value);
									}
									
								}
							}
							
							//
							//tree
							//
							if(registry_key_1.tree_reg_subkey != null)
							{
								for(String sub_key : registry_key_1.tree_reg_subkey.keySet())
								{
									if(sub_key == null || sub_key.trim().equals(""))
										continue;
									
									if(registry_key_2 == null || registry_key_2.tree_reg_subkey == null || registry_key_2.tree_reg_subkey.isEmpty() || !registry_key_2.tree_reg_subkey.containsKey(sub_key))
									{

										//subkey is an missing!!!
										
										//get the hive to store this key's subkey
										hive = tree_missing_results.get(registry_hive_description); 
										
										if(hive == null)
										{
											hive = new Node_Registry_Hive ();
											hive.registry_hive = registry_hive_description;
											tree_missing_results.put(registry_hive_description, hive);											
										}	
										
										registry_key = hive.tree_registry_key.get(registry_key_description);
										
										if(registry_key == null)
										{
											registry_key = new Node_Registry_Key(hive, registry_key_description);
											registry_key.key_name = registry_key_description;
											registry_key.path = registry_key_description;
											hive.tree_registry_key.put(registry_key_description, registry_key);
										}
										
										//create the tree
										if(registry_key.tree_reg_subkey == null)
											registry_key.tree_reg_subkey = new TreeMap<String, Node_Generic>();
										
											
											
										//store the key
										if(!registry_key.tree_reg_subkey.containsKey(sub_key))
											registry_key.tree_reg_subkey.put(sub_key, registry_key_1.tree_reg_subkey.get(sub_key));
									}
									
								}
								
							}
							
							
							
						}
						
					}
				}

				/////////////////////////////////////////
				// CHECK MODIFIED
				////////////////////////////////////////


			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analysis_check_REGISTRY", e);
		}
		
		return false;
	}

	public boolean analysis_check_Tree_Node_Generic(String description, TreeMap<String, Node_Generic> tree_1, TreeMap<String, Node_Generic> tree_2, TreeMap<String, Node_Generic> tree_addition_results, TreeMap<String, Node_Generic> tree_missing_results, TreeMap<String, Node_Generic> tree_MODIFIED_results)
	{
		try
		{				
			////////////////////////////////////////////////////////////////////////////////////
			// first determine if snapshot 1 is empty -> add every process from snapshot 2
			///////////////////////////////////////////////////////////////////////////////////
			
			if((tree_1 == null || tree_1.isEmpty()) && tree_2 != null) 
			{
				//everything is an addition
				for(String key : tree_2.keySet())
				{
					if(key == null || key.trim().equals(""))
						continue;										

					tree_addition_results.put(key, tree_2.get(key));
				}								
			}

			
			////////////////////////////////////////////////////////////////////////////////////
			// Check absolute missing: ensure snapshot 2 is not blank
			///////////////////////////////////////////////////////////////////////////////////
			
			else if((tree_2 == null || tree_2.isEmpty()) && tree_1 != null)
			{
				//everything is missing from snapshot 2
				for(String key : tree_1.keySet())
				{
					if(key == null || key.trim().equals(""))
						continue;															
					
					tree_missing_results.put(key,  tree_1.get(key));
				}
			}

			else
			{
				/////////////////////////////////////////
				// CHECK ADDITIONS
				////////////////////////////////////////					
				for(String key : tree_2.keySet())
				{
					//if tree_1 does not contain a node present in tree_2, this is an addition
					if(!tree_1.containsKey(key))
						try	{	tree_addition_results.put(key, tree_2.get(key));	} catch(Exception e) {driver.directive("Error! I encountered difficulties trying to retrieve key [" + key + "] for ADDITIONS results tree");}
				}


				/////////////////////////////////////////
				// CHECK MISSING
				////////////////////////////////////////
				for(String key : tree_1.keySet())
				{
					//if tree_2 does not contain a node present in tree_1, this is a missing value
					if(!tree_2.containsKey(key))
						try	{	tree_missing_results.put(key, tree_1.get(key));	} catch(Exception e) {driver.directive("Error! I encountered difficulties trying to retrieve key [" + key + "] for MISSING results tree");}
				}

				/////////////////////////////////////////
				// CHECK MODIFIED
				////////////////////////////////////////


			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analysis_check_Tree_Node_Generic", e);
		}
		
		return false;
	}
	
	
	public boolean analysis_check_DRIVER_Node_Generic(String description, TreeMap<String, Node_Driver> tree_1, TreeMap<String, Node_Driver> tree_2, TreeMap<String, Node_Driver> tree_addition_results, TreeMap<String, Node_Driver> tree_missing_results, TreeMap<String, Node_Driver> tree_MODIFIED_results, int index_load_tree)
	{
		try
		{				
			////////////////////////////////////////////////////////////////////////////////////
			// first determine if snapshot 1 is empty -> add every process from snapshot 2
			///////////////////////////////////////////////////////////////////////////////////
			
			TreeMap<String, Node_Generic> tree_generic_1 = null;
			TreeMap<String, Node_Generic> tree_generic_2 = null;
			
			
			if(tree_1 == null || tree_1.isEmpty() && tree_2 != null)
			{
				for(String key : tree_2.keySet())
				{
					if(tree_addition_results.containsKey(key))
						continue;
					
					tree_addition_results.put(key,  tree_2.get(key));
				}
					
			}
			
			else if(tree_2 == null || tree_2.isEmpty() && tree_1 != null)
			{
				for(String key : tree_1.keySet())
				{
					if(tree_missing_results.containsKey(key))
						continue;
					
					tree_missing_results.put(key,  tree_1.get(key));
				}
					
			}
			
			else
			{
				Node_Driver node_1 = null;
				Node_Driver node_2 = null;
				
				for(String key : tree_1.keySet())
				{
					node_1 = tree_1.get(key);
					node_2 = tree_2.get(key);
					
					if(node_1 == null && node_2 != null)
					{
						if(!tree_addition_results.containsValue(node_2))
							tree_addition_results.put(key,  node_2);
						
						continue;
					}
					
					else if(node_1 != null && node_2 == null)
					{
						if( !tree_missing_results.containsValue(node_1))
								tree_missing_results.put(key,  node_1);
						continue;
					}
					
					//just check if the keys are different, if so, add the driver
					switch(index_load_tree)
					{
						case index_callbacks:
						{
							tree_generic_1 = node_1.tree_callbacks;
							tree_generic_2 = node_2.tree_callbacks;
							break;
						}
						case index_timers:
						{
							tree_generic_1 = node_1.tree_timers;
							tree_generic_2 = node_2.tree_timers;
							break;
						}
						
						case index_unloaded_modules:
						{
							tree_generic_1 = node_1.tree_unloaded_modules;
							tree_generic_2 = node_2.tree_unloaded_modules;
							break;
						}
					}
					
					if((tree_generic_1 == null || tree_generic_1.isEmpty()) && tree_generic_2 != null && !tree_addition_results.containsValue(node_2))
					{
						tree_addition_results.put(key,  node_2);
					}
					
					else if((tree_generic_2 == null || tree_generic_2.isEmpty()) && tree_generic_1 != null && !tree_addition_results.containsValue(node_1))
					{
						tree_missing_results.put(key,  node_1);
					}
					else
					{
						//iterate through generic keys
						for(String generic_key : tree_generic_1.keySet())
						{
							if(!tree_generic_2.containsKey(generic_key))
								tree_missing_results.put(key,  node_1);
								
						}
					}					
				}//end for
				
				
				for(String key : tree_2.keySet())
				{
					node_1 = tree_1.get(key);
					node_2 = tree_2.get(key);
					
					if(node_2 == null && node_1 != null )
					{
						if(!tree_missing_results.containsValue(node_1))
							tree_missing_results.put(key,  node_1);
						
						continue;
					}
					
					else if(node_1 == null && node_2 != null )
					{
						if(!tree_addition_results.containsValue(node_2))
							tree_addition_results.put(key,  node_2);
						
						continue;
					}
					
					//just check if the keys are different, if so, add the driver
					switch(index_load_tree)
					{
						case index_callbacks:
						{
							tree_generic_1 = node_1.tree_callbacks;
							tree_generic_2 = node_2.tree_callbacks;
							break;
						}
						case index_timers:
						{
							tree_generic_1 = node_1.tree_timers;
							tree_generic_2 = node_2.tree_timers;
							break;
						}
						
						case index_unloaded_modules:
						{
							tree_generic_1 = node_1.tree_unloaded_modules;
							tree_generic_2 = node_2.tree_unloaded_modules;
							break;
						}
					}
					
					if((tree_generic_2 == null || tree_generic_2.isEmpty()) && tree_generic_1 != null && !tree_missing_results.containsValue(node_1))
					{
						tree_missing_results.put(key,  node_1);
					}
					
					else if((tree_generic_1 == null || tree_generic_1.isEmpty()) && tree_generic_2 != null && !tree_addition_results.containsValue(node_2))
					{
						tree_addition_results.put(key,  node_2);
					}
					else
					{
						//iterate through generic keys
						for(String generic_key : tree_generic_2.keySet())
						{
							if(!tree_generic_1.containsKey(generic_key))
								tree_addition_results.put(key,  node_2);
								
						}
					}					
				}//end for
				
				
			}
			
			
			
			
			
			
			//try	{	tree_missing_results.put(key, tree_1.get(key));	} catch(Exception e) {driver.directive("Error! I encountered difficulties trying to retrieve key [" + key + "] for MISSING results tree");}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analysis_check_DRIVER_Node_Generic", e, true);
		}
		
		return false;
	}
	
	
	public boolean analysis_check_analysis_check_HIVELIST(String description, TreeMap<String, Node_Envar> tree_1, TreeMap<String, Node_Envar> tree_2, TreeMap<String, Node_Envar> tree_addition_results, TreeMap<String, Node_Envar> tree_missing_results, TreeMap<String, Node_Envar> tree_MODIFIED_results)
	{
		try
		{				
			////////////////////////////////////////////////////////////////////////////////////
			// first determine if snapshot 1 is empty -> add every process from snapshot 2
			///////////////////////////////////////////////////////////////////////////////////
			
			if((tree_1 == null || tree_1.isEmpty()) && tree_2 != null) 
			{
				//everything is an addition
				for(String key : tree_2.keySet())
				{
					if(key == null || key.trim().equals(""))
						continue;										

					tree_addition_results.put(key, tree_2.get(key));
				}								
			}

			
			////////////////////////////////////////////////////////////////////////////////////
			// Check absolute missing: ensure snapshot 2 is not blank
			///////////////////////////////////////////////////////////////////////////////////
			
			else if((tree_2 == null || tree_2.isEmpty()) && tree_1 != null)
			{
				//everything is missing from snapshot 2
				for(String key : tree_1.keySet())
				{
					if(key == null || key.trim().equals(""))
						continue;															
					
					tree_missing_results.put(key,  tree_1.get(key));
				}
			}

			else
			{
				/////////////////////////////////////////
				// CHECK ADDITIONS
				////////////////////////////////////////					
				for(String key : tree_2.keySet())
				{
					//if tree_1 does not contain a node present in tree_2, this is an addition
					if(!tree_1.containsKey(key))
						try	{	tree_addition_results.put(key, tree_2.get(key));	} catch(Exception e) {driver.directive("Error! I encountered difficulties trying to retrieve key [" + key + "] for ADDITIONS results tree");}
				}


				/////////////////////////////////////////
				// CHECK MISSING
				////////////////////////////////////////
				for(String key : tree_1.keySet())
				{
					//if tree_2 does not contain a node present in tree_1, this is a missing value
					if(!tree_2.containsKey(key))
						try	{	tree_missing_results.put(key, tree_1.get(key));	} catch(Exception e) {driver.directive("Error! I encountered difficulties trying to retrieve key [" + key + "] for MISSING results tree");}
				}

				/////////////////////////////////////////
				// CHECK MODIFIED
				////////////////////////////////////////


			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analysis_check_HIVELIST", e);
		}
		
		return false;
	}
	
	public boolean analysis_check_HIVELIST(String description, TreeMap<String, Node_hivelist> tree_1, TreeMap<String, Node_hivelist> tree_2, TreeMap<String, Node_hivelist> tree_addition_results, TreeMap<String, Node_hivelist> tree_missing_results, TreeMap<String, Node_hivelist> tree_MODIFIED_results)
	{
		try
		{				
			////////////////////////////////////////////////////////////////////////////////////
			// first determine if snapshot 1 is empty -> add every process from snapshot 2
			///////////////////////////////////////////////////////////////////////////////////
			
			if((tree_1 == null || tree_1.isEmpty()) && tree_2 != null) 
			{
				//everything is an addition
				for(String key : tree_2.keySet())
				{
					if(key == null || key.trim().equals(""))
						continue;										

					tree_addition_results.put(key, tree_2.get(key));
				}								
			}

			
			////////////////////////////////////////////////////////////////////////////////////
			// Check absolute missing: ensure snapshot 2 is not blank
			///////////////////////////////////////////////////////////////////////////////////
			
			else if((tree_2 == null || tree_2.isEmpty()) && tree_1 != null)
			{
				//everything is missing from snapshot 2
				for(String key : tree_1.keySet())
				{
					if(key == null || key.trim().equals(""))
						continue;															
					
					tree_missing_results.put(key,  tree_1.get(key));
				}
			}

			else
			{
				/////////////////////////////////////////
				// CHECK ADDITIONS
				////////////////////////////////////////					
				for(String key : tree_2.keySet())
				{
					//if tree_1 does not contain a node present in tree_2, this is an addition
					if(!tree_1.containsKey(key))
						try	{	tree_addition_results.put(key, tree_2.get(key));	} catch(Exception e) {driver.directive("Error! I encountered difficulties trying to retrieve key [" + key + "] for ADDITIONS results tree");}
				}


				/////////////////////////////////////////
				// CHECK MISSING
				////////////////////////////////////////
				for(String key : tree_1.keySet())
				{
					//if tree_2 does not contain a node present in tree_1, this is a missing value
					if(!tree_2.containsKey(key))
						try	{	tree_missing_results.put(key, tree_1.get(key));	} catch(Exception e) {driver.directive("Error! I encountered difficulties trying to retrieve key [" + key + "] for MISSING results tree");}
				}

				/////////////////////////////////////////
				// CHECK MODIFIED
				////////////////////////////////////////


			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analysis_check_HIVELIST", e);
		}
		
		return false;
	}
	
	
	public boolean analysis_check_GET_SERVICE_SID(String description, TreeMap<String, Node_get_service_sid> tree_1, TreeMap<String, Node_get_service_sid> tree_2, TreeMap<String, Node_get_service_sid> tree_addition_results, TreeMap<String, Node_get_service_sid> tree_missing_results, TreeMap<String, Node_get_service_sid> tree_MODIFIED_results)
	{
		try
		{				
			////////////////////////////////////////////////////////////////////////////////////
			// first determine if snapshot 1 is empty -> add every process from snapshot 2
			///////////////////////////////////////////////////////////////////////////////////
			
			if((tree_1 == null || tree_1.isEmpty()) && tree_2 != null) 
			{
				//everything is an addition
				for(String key : tree_2.keySet())
				{
					if(key == null || key.trim().equals(""))
						continue;										

					tree_addition_results.put(key, tree_2.get(key));
				}								
			}

			
			////////////////////////////////////////////////////////////////////////////////////
			// Check absolute missing: ensure snapshot 2 is not blank
			///////////////////////////////////////////////////////////////////////////////////
			
			else if((tree_2 == null || tree_2.isEmpty()) && tree_1 != null)
			{
				//everything is missing from snapshot 2
				for(String key : tree_1.keySet())
				{
					if(key == null || key.trim().equals(""))
						continue;															
					
					tree_missing_results.put(key,  tree_1.get(key));
				}
			}

			else
			{
				/////////////////////////////////////////
				// CHECK ADDITIONS
				////////////////////////////////////////					
				for(String key : tree_2.keySet())
				{
					//if tree_1 does not contain a node present in tree_2, this is an addition
					if(!tree_1.containsKey(key))
						try	{	tree_addition_results.put(key, tree_2.get(key));	} catch(Exception e) {driver.directive("Error! I encountered difficulties trying to retrieve key [" + key + "] for ADDITIONS results tree");}
				}


				/////////////////////////////////////////
				// CHECK MISSING
				////////////////////////////////////////
				for(String key : tree_1.keySet())
				{
					//if tree_2 does not contain a node present in tree_1, this is a missing value
					if(!tree_2.containsKey(key))
						try	{	tree_missing_results.put(key, tree_1.get(key));	} catch(Exception e) {driver.directive("Error! I encountered difficulties trying to retrieve key [" + key + "] for MISSING results tree");}
				}

				/////////////////////////////////////////
				// CHECK MODIFIED
				////////////////////////////////////////
				

			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analysis_check_GET_SERVICE_SID", e);
		}
		
		return false;
	}
	
	
	
	public boolean snapshot_analysis_director_check_SESSIONS(Advanced_Analysis_Director director_1, Advanced_Analysis_Director director_2)
	{
		try
		{
			//("tree_session_entries", director_1.tree_session_entries, director_2.tree_session_entries, this.tree_addition_SESSION_ENTRIES, this.tree_missing_SESSION_ENTRIES, this.tree_MODIFIED_SESSION_ENTRIES);
			
			if(director_1 == null && director_2 == null)
				return false;
			
			if(director_1.tree_session_entries == null && director_2.tree_session_entries == null)
				return false;
			
			if(director_1.tree_session_entries.isEmpty() && director_2.tree_session_entries.isEmpty())
				return false;
			
			if((director_1 == null || director_1.tree_session_entries == null || director_1.tree_session_entries.isEmpty()) && director_2 != null && director_2.tree_session_entries != null && !director_2.tree_session_entries.isEmpty())
			{
				this.tree_addition_SESSION_ENTRIES = director_2.tree_session_entries;
				return true;
			}
			
			else if((director_2 == null || director_2.tree_session_entries == null || director_2.tree_session_entries.isEmpty()) && director_1 != null && director_1.tree_session_entries != null && !director_1.tree_session_entries.isEmpty())
			{
				this.tree_missing_SESSION_ENTRIES = director_1.tree_session_entries;
				return true;
			}			
			
			LinkedList<String> list_1 = null, list_2 = null;
			
			//
			//ADDITION
			//
			for(String session_container : director_2.tree_session_entries.keySet())				
			{
				try
				{
					if(session_container == null || session_container.trim().equals(""))
						continue;
					
					list_1 = director_1.tree_session_entries.get(session_container);
					list_2 = director_2.tree_session_entries.get(session_container);
					
					if((list_1 == null || list_1.isEmpty()) && (list_2 == null || list_2.isEmpty()))
						continue;
					
					//entire session addition
					if((list_1 == null || list_1.isEmpty()) && (list_2 != null && list_2.size() > 0))
					{
						this.tree_addition_SESSION_ENTRIES.put(session_container, list_2);
						continue;
					}
					
					//entire missing
					else if((list_2 == null || list_2.size() < 1) && list_1 != null && list_1.size() > 0)
					{
						this.tree_missing_SESSION_ENTRIES.put(session_container, list_1);
						continue;
					}
					
					//
					//check each entry - populate tree_ADDITIONAL
					//
					for(String entry_2 : list_2)
					{
						if(list_1.contains(entry_2))
							continue;
						
						//otw, we have an additional value!
						LinkedList<String> list_additional = null;
						
						if(this.tree_addition_SESSION_ENTRIES.containsKey(session_container))
						{
							list_additional = tree_addition_SESSION_ENTRIES.get(session_container);
							
							if(list_additional == null)
							{
								list_additional = new LinkedList<String>();
								tree_addition_SESSION_ENTRIES.put(session_container, list_additional);
							}
						}
						
						if(list_additional == null)
						{
							list_additional = new LinkedList<String>();
							tree_addition_SESSION_ENTRIES.put(session_container, list_additional);
						}
						
						//store the value!
						if(!list_additional.contains(entry_2))
							list_additional.add(entry_2);
					}
					
					//
					//check each entry - populate tree_MISSING
					//
					for(String entry_1 : list_1)
					{
						if(list_2.contains(entry_1))
							continue;
						
						//otw, we have a missing value!
						LinkedList<String> list_missing = null;
						
						if(this.tree_missing_SESSION_ENTRIES.containsKey(session_container))
						{
							list_missing = tree_missing_SESSION_ENTRIES.get(session_container);
							
							if(list_missing == null)
							{
								list_missing = new LinkedList<String>();
								tree_missing_SESSION_ENTRIES.put(session_container, list_missing);
							}
						}
						
						if(list_missing == null)
						{
							list_missing = new LinkedList<String>();
							tree_missing_SESSION_ENTRIES.put(session_container, list_missing);
						}
						
						//store the value!
						if(!list_missing.contains(entry_1))
							list_missing.add(entry_1);
					}
					
				}
				catch(Exception e)
				{
					driver.directive("Error caught in snapshot_analysis_director_check_SESSIONS mtd on director_1 session_container: " + session_container);
					continue;
				}
				
			}
			
			//
			//MISSING
			//
			for(String session_container : director_1.tree_session_entries.keySet())				
			{
				try
				{
					if(session_container == null || session_container.trim().equals(""))
						continue;
					
					list_1 = director_1.tree_session_entries.get(session_container);
					list_2 = director_2.tree_session_entries.get(session_container);
					
					if((list_1 == null || list_1.isEmpty()) && (list_2 == null || list_2.isEmpty()))
						continue;
					
					//entire session addition
					if((list_1 == null || list_1.isEmpty()) && (list_2 != null && list_2.size() > 0))
					{
						this.tree_addition_SESSION_ENTRIES.put(session_container, list_2);
						continue;
					}
					
					//entire missing
					else if((list_2 == null || list_2.size() < 1) && list_1 != null && list_1.size() > 0)
					{
						this.tree_missing_SESSION_ENTRIES.put(session_container, list_1);
						continue;
					}
					
					//
					//check each entry - populate tree_ADDITIONAL
					//
					for(String entry_2 : list_2)
					{
						if(list_1.contains(entry_2))
							continue;
						
						//otw, we have an additional value!
						LinkedList<String> list_additional = null;
						
						if(this.tree_addition_SESSION_ENTRIES.containsKey(session_container))
						{
							list_additional = tree_addition_SESSION_ENTRIES.get(session_container);
							
							if(list_additional == null)
							{
								list_additional = new LinkedList<String>();
								tree_addition_SESSION_ENTRIES.put(session_container, list_additional);
							}
						}
						
						if(list_additional == null)
						{
							list_additional = new LinkedList<String>();
							tree_addition_SESSION_ENTRIES.put(session_container, list_additional);
						}
						
						//store the value!
						if(!list_additional.contains(entry_2))
							list_additional.add(entry_2);
					}
					
					//
					//check each entry - populate tree_MISSING
					//
					for(String entry_1 : list_1)
					{
						if(list_2.contains(entry_1))
							continue;
						
						//otw, we have a missing value!
						LinkedList<String> list_missing = null;
						
						if(this.tree_missing_SESSION_ENTRIES.containsKey(session_container))
						{
							list_missing = tree_missing_SESSION_ENTRIES.get(session_container);
							
							if(list_missing == null)
							{
								list_missing = new LinkedList<String>();
								tree_missing_SESSION_ENTRIES.put(session_container, list_missing);
							}
						}
						
						if(list_missing == null)
						{
							list_missing = new LinkedList<String>();
							tree_missing_SESSION_ENTRIES.put(session_container, list_missing);
						}
						
						//store the value!
						if(!list_missing.contains(entry_1))
							list_missing.add(entry_1);
					}
					
				}
				catch(Exception e)
				{
					driver.directive("Error caught in snapshot_analysis_director_check_SESSIONS mtd on director_1 session_container: " + session_container);
					continue;
				}
				
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "snapshot_analysis_director_check_HIVELIST", e);
		}
		
		return false;
	}
	
	/**
	 * continuation mtd - assumes process 1 and 2 are NOT NULL!
	 * @param process_1
	 * @param process_2
	 * @param INITIALIZATION_INDEX
	 * @param tree
	 * @param key
	 * @param ARTIFACT_TYPE
	 * @return
	 */
	public boolean analyze_process_NETSTAT(Node_Process process_1, Node_Process process_2, int INITIALIZATION_INDEX, TreeMap<String, Node_Snapshot_Analysis_Artifact> tree, String node_key, String ARTIFACT_TYPE)
	{
		try
		{						
			//
			//procure
			//
			Node_Snapshot_Analysis_Artifact node = tree.get(node_key);		
			
			//
			//initialize if necessary
			//
			if(node == null)
			{
				//use the instances to handle the comparison and building of the trees
				node = new Node_Snapshot_Analysis_Artifact(this, process_2.get_process_html_header(), ARTIFACT_TYPE);
				
				//adjust name if needed
				try
				{
					if(node.descriptor == null || node.descriptor.toLowerCase().trim().endsWith("unknown") && !process_1.get_process_html_header().toLowerCase().trim().endsWith("unknown"))
						node.descriptor = process_1.get_process_html_header();	
				}catch(Exception e){}				
				
				//set processes
				node.process_1 = process_1; 
				node.proces_2 = process_2;
				
				//init structures
				node.initialize_structures(INITIALIZATION_INDEX);
				
				//link node!
				tree.put(node_key,  node);				
			}

			//
			//update node's initialization vector
			//
			node.set_my_tree_pointers(INITIALIZATION_INDEX);
				
			//
			//initialize structure
			//
			String VARIABLE_NAME = "Netstat";
			TreeMap<String, Node_Netstat_Entry> tree_1 = process_1.tree_netstat, tree_2 = process_2.tree_netstat;
			Node_Netstat_Entry entry_1 = null, entry_2 = null;
			
			//
			//* * * ENSURE THESE VALUES ARE SET PROPERLY BELOW! * * * 
			//
			String comparator_value_1 = null, comparator_value_2 = null;
			String unique_key_1 = null, unique_key_2 = null;
			
						
			//
			//compsre structures
			//
			if(tree_1 == null && tree_2 == null)
				return false;
			
			//
			//check addition
			//
			if(tree_1 == null && tree_2 != null)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data NOT specified", "[+] ENTIRE NEW " + VARIABLE_NAME + " STRUCTURE  ADDED!", null);				
				return true;
			}
			
			//
			//check missing
			//
			else if(tree_1 != null && tree_2 == null)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data specified", "[-] ENTIRE " + VARIABLE_NAME + " STRUCTURE MISSING!", null);				
				return true;
			}
			
			//at this point, both trees are not null, check sizes for additional and missing
			
			//
			//check addition
			//
			if(tree_1.size() < 1 && tree_2.size() > 0)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data NOT specified", "[+] ENTIRE NEW " + VARIABLE_NAME + " STRUCTURE ADDED!", null);					
				return true;
			}
			
			//
			//check missing
			//
			else if(tree_1.size() > 0 && tree_2.size() < 1)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data specified", "[-] ENTIRE " + VARIABLE_NAME + " STRUCTURE MISSING!", null);				
				return true;
			}
			
			//
			//check structure entries
			//
			else
			{								
				///////////////////////////////////////////////////////////////////////
				// check for addition and modified
				///////////////////////////////////////////////////////////////////////
				for(String key : tree_2.keySet())
				{
					if(key == null || key.trim().equals(""))
						continue;
															
					//
					//procure nodes
					//
					entry_1 = tree_1.get(key);
					entry_2 = tree_2.get(key);  	 								

					//
					//validate entry
					//
					if(entry_1 == null && entry_2 == null)
						continue;
											
								
					
					//
					//set unique_storage_key and comparator values
					//
/* modify ----> */	try	{	unique_key_1 = entry_1.get_snapshot_analysis_key();	} catch(Exception e){unique_key_1 = null;}
/* modify ----> */	try	{	unique_key_2 = entry_2.get_snapshot_analysis_key();	} catch(Exception e){unique_key_2 = null;}
					
/* modify ----> */ 	try	{	comparator_value_1 = entry_1.get_snapshot_analysis_COMPARATOR_VALUE();	} catch(Exception e){comparator_value_1 = null;}
/* modify ----> */ 	try	{	comparator_value_2 = entry_2.get_snapshot_analysis_COMPARATOR_VALUE();	} catch(Exception e){comparator_value_2 = null;}
	



					//
					//check addition
					//
					if(entry_1 == null && entry_2 != null)
					{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " entry " +unique_key_2, null, comparator_value_2, null);
					}
					
					//
					//check missing
					//
					else if(entry_1 != null && entry_2 == null)
					{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " entry " + unique_key_1, comparator_value_1, null, null);
					}
					
					//
					//else, iterate and check each value
					//
					else
					{
						//
						//specify unique key
						//
						String variable_key_identifier = VARIABLE_NAME + " entry " + unique_key_1 ;
						
						//
						//invoke compare routine on the data-transform
						//
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, comparator_value_1, comparator_value_2, null);
					}														
				}
				
				///////////////////////////////////////////////////////////////////////
				// check for missing and modified
				///////////////////////////////////////////////////////////////////////
				for(String key : tree_1.keySet())
				{
					if(key == null || key.trim().equals(""))
						continue;
															
					//
					//procure nodes
					//
					entry_1 = tree_1.get(key);
					entry_2 = tree_2.get(key);  	 								

					//
					//validate entry
					//
					if(entry_1 == null && entry_2 == null)
						continue;
											
					
					//
					//set unique_storage_key and comparator values
					//
					try	{	unique_key_1 = entry_1.get_snapshot_analysis_key();	} catch(Exception e){unique_key_1 = null;}
					try	{	unique_key_2 = entry_2.get_snapshot_analysis_key();	} catch(Exception e){unique_key_2 = null;}
					
					try	{	comparator_value_1 = entry_1.get_snapshot_analysis_COMPARATOR_VALUE();	} catch(Exception e){comparator_value_1 = null;}
					try	{	comparator_value_2 = entry_2.get_snapshot_analysis_COMPARATOR_VALUE();	} catch(Exception e){comparator_value_2 = null;}
													
					//
					//check addition
					//
					if(entry_1 == null && entry_2 != null)
					{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " entry " + unique_key_2, null, comparator_value_2, null);
					}
					
					//
					//check missing
					//
					else if(entry_1 != null && entry_2 == null)
					{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " entry " + unique_key_1, comparator_value_1, null, null);						
					}
					
					//
					//else, iterate and check each value
					//
					else
					{
						//
						//specify unique key
						//
						String variable_key_identifier = VARIABLE_NAME + " entry " + unique_key_1 ;
												
						//
						//invoke compare routine on the data-transform
						//
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, comparator_value_1, comparator_value_2, null);
					}														
				}
			}
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_process_NETSTAT", e);
		}
		
		return false;
	}
	
	
	
	//////////////////////////////
	//////////////////
	//////////
	
	/**
	 * continuation mtd - assumes process 1 and 2 are NOT NULL!
	 * @param process_1
	 * @param process_2
	 * @param INITIALIZATION_INDEX
	 * @param tree
	 * @param key
	 * @param ARTIFACT_TYPE
	 * @return
	 */
	public boolean analyze_process_PRIVILEGE(Node_Process process_1, Node_Process process_2, int INITIALIZATION_INDEX, TreeMap<String, Node_Snapshot_Analysis_Artifact> tree, String node_key, String ARTIFACT_TYPE)
	{
		try
		{						
			//
			//procure
			//
			Node_Snapshot_Analysis_Artifact node = tree.get(node_key);
			
			//
			//initialize if necessary
			//
			if(node == null)
			{
				//use the instances to handle the comparison and building of the trees
				node = new Node_Snapshot_Analysis_Artifact(this, process_2.get_process_html_header(), ARTIFACT_TYPE);
				
				//adjust name if needed
				try
				{
					if(node.descriptor == null || node.descriptor.toLowerCase().trim().endsWith("unknown") && !process_1.get_process_html_header().toLowerCase().trim().endsWith("unknown"))
						node.descriptor = process_1.get_process_html_header();	
				}catch(Exception e){}				
				
				//set processes
				node.process_1 = process_1; 
				node.proces_2 = process_2;
				
				//init structures
				node.initialize_structures(INITIALIZATION_INDEX);
				
				//link node!
				tree.put(node_key,  node);				
			}

			//
			//update node's initialization vector
			//
			node.set_my_tree_pointers(INITIALIZATION_INDEX);
				
			//
			//initialize structure
			//
			String VARIABLE_NAME = "Privilege";
			TreeMap<String, Node_Privs> tree_1 = process_1.tree_privs, tree_2 = process_2.tree_privs;
			Node_Privs entry_1 = null, entry_2 = null;
			
			//
			//* * * ENSURE THESE VALUES ARE SET PROPERLY BELOW! * * * 
			//
			String comparator_value_1 = null, comparator_value_2 = null;
			String unique_key_1 = null, unique_key_2 = null;
			
						
			//
			//compsre structures
			//
			if(tree_1 == null && tree_2 == null)
				return false;
			
			//
			//check addition
			//
			if(tree_1 == null && tree_2 != null)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data NOT specified", "[+] ENTIRE NEW " + VARIABLE_NAME + " STRUCTURE  ADDED!", null);				
				return true;
			}
			
			//
			//check missing
			//
			else if(tree_1 != null && tree_2 == null)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data specified", "[-] ENTIRE " + VARIABLE_NAME + " STRUCTURE MISSING!", null);				
				return true;
			}
			
			//at this point, both trees are not null, check sizes for additional and missing
			
			//
			//check addition
			//
			if(tree_1.size() < 1 && tree_2.size() > 0)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data NOT specified", "[+] ENTIRE NEW " + VARIABLE_NAME + " STRUCTURE ADDED!", null);					
				return true;
			}
			
			//
			//check missing
			//
			else if(tree_1.size() > 0 && tree_2.size() < 1)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data specified", "[-] ENTIRE " + VARIABLE_NAME + " STRUCTURE MISSING!", null);				
				return true;
			}
			
			//
			//check structure entries
			//
			else
			{								
				///////////////////////////////////////////////////////////////////////
				// check for addition and modified
				///////////////////////////////////////////////////////////////////////
				for(String key : tree_2.keySet())
				{
					if(key == null || key.trim().equals(""))
						continue;
															
					//
					//procure nodes
					//
					entry_1 = tree_1.get(key);
					entry_2 = tree_2.get(key);  	 								

					//
					//validate entry
					//
					if(entry_1 == null && entry_2 == null)
						continue;
											
								
					
					//
					//set unique_storage_key and comparator values
					//
					try	{	unique_key_1 = entry_1.get_snapshot_analysis_key();	} catch(Exception e){}
					try	{	unique_key_2 = entry_2.get_snapshot_analysis_key();	} catch(Exception e){}
					
					try	{	comparator_value_1 = entry_1.get_snapshot_analysis_COMPARATOR_VALUE();	} catch(Exception e){}
					try	{	comparator_value_2 = entry_2.get_snapshot_analysis_COMPARATOR_VALUE();	} catch(Exception e){}
					
					//
					//check addition
					//
					if(entry_1 == null && entry_2 != null)
					{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " entry [" +unique_key_2 + "]", null, comparator_value_2, null);
					}
					
					//
					//check missing
					//
					else if(entry_1 != null && entry_2 == null)
					{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " entry [" + unique_key_1 + "]", comparator_value_1, null, null);
					}
					
					//
					//else, iterate and check each value
					//
					else
					{
						//
						//specify unique key
						//
						String variable_key_identifier = VARIABLE_NAME + " entry [" + unique_key_2 + "]" ;
						
						if(unique_key_2 == null || unique_key_2.toLowerCase().equals("not specified") || unique_key_2.toLowerCase().equals("unknown"))
							variable_key_identifier = VARIABLE_NAME + " entry [" + unique_key_1 + "]";
						
						//
						//invoke compare routine on the data-transform
						//
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, comparator_value_1, comparator_value_2, null);
					}														
				}
				
				///////////////////////////////////////////////////////////////////////
				// check for missing and modified
				///////////////////////////////////////////////////////////////////////
				for(String key : tree_1.keySet())
				{
					if(key == null || key.trim().equals(""))
						continue;
															
					//
					//procure nodes
					//
					entry_1 = tree_1.get(key);
					entry_2 = tree_2.get(key);  	 								

					//
					//validate entry
					//
					if(entry_1 == null && entry_2 == null)
						continue;
											
													
					//
					//set unique_storage_key and comparator values
					//
					try	{	unique_key_1 = entry_1.get_snapshot_analysis_key();	} catch(Exception e){unique_key_1 = null;}
					try	{	unique_key_2 = entry_2.get_snapshot_analysis_key();	} catch(Exception e){unique_key_2 = null;}
					
					try	{	comparator_value_1 = entry_1.get_snapshot_analysis_COMPARATOR_VALUE();	} catch(Exception e){comparator_value_1 = null;}
					try	{	comparator_value_2 = entry_2.get_snapshot_analysis_COMPARATOR_VALUE();	} catch(Exception e){comparator_value_2 = null;}
					
					//
					//check addition
					//
					if(entry_1 == null && entry_2 != null)
					{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " entry [" + unique_key_2 + "]", null, comparator_value_2, null);
					}
					
					//
					//check missing
					//
					else if(entry_1 != null && entry_2 == null)
					{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " entry [" + unique_key_1 + "]", comparator_value_1, null, null);
					}
					
					//
					//else, iterate and check each value
					//
					else
					{
						//
						//specify unique key
						//
						String variable_key_identifier = VARIABLE_NAME + " entry " + unique_key_1 ;
						
						if(unique_key_1 == null || unique_key_1.toLowerCase().equals("not specified") || unique_key_1.toLowerCase().equals("unknown"))
							variable_key_identifier = VARIABLE_NAME + " entry [" + unique_key_2 + "]";
												
						//
						//invoke compare routine on the data-transform
						//
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, comparator_value_1, comparator_value_2, null);
					}														
				}
			}
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_process_PRIVILEGE", e);
		}
		
		return false;
	}
	
	/////////////////////////////////////////
	/////////////////////////
	///////////////
	/////
	
	
	public boolean analyze_process_SERVICE_SCAN(Node_Process process_1, Node_Process process_2, int INITIALIZATION_INDEX, TreeMap<String, Node_Snapshot_Analysis_Artifact> tree, String node_key, String ARTIFACT_TYPE)
	{
		try
		{						
			//
			//procure
			//
			Node_Snapshot_Analysis_Artifact node = tree.get(node_key);
			
			//
			//initialize if necessary
			//
			if(node == null)
			{
				//use the instances to handle the comparison and building of the trees
				node = new Node_Snapshot_Analysis_Artifact(this, process_2.get_process_html_header(), ARTIFACT_TYPE);
				
				//adjust name if needed
				try
				{
					if(node.descriptor == null || node.descriptor.toLowerCase().trim().endsWith("unknown") && !process_1.get_process_html_header().toLowerCase().trim().endsWith("unknown"))
						node.descriptor = process_1.get_process_html_header();	
				}catch(Exception e){}				
				
				//set processes
				node.process_1 = process_1; 
				node.proces_2 = process_2;
				
				//init structures
				node.initialize_structures(INITIALIZATION_INDEX);
				
				//link node!
				tree.put(node_key,  node);				
			}

			
			
			//
			//update node's initialization vector
			//
			node.set_my_tree_pointers(INITIALIZATION_INDEX);
				
			//
			//initialize structure
			//
			String VARIABLE_NAME = "Service Scan";
			TreeMap<String, Node_svcscan> tree_1 = process_1.tree_services_svcscan, tree_2 = process_2.tree_services_svcscan;
			Node_svcscan entry_1 = null, entry_2 = null;
			
			//
			//* * * ENSURE THESE VALUES ARE SET PROPERLY BELOW! * * * 
			//
			String comparator_value_1 = null, comparator_value_2 = null;
			String unique_key_1 = null, unique_key_2 = null;
			
						
			//
			//compsre structures
			//
			if(tree_1 == null && tree_2 == null)
				return false;
			
			//
			//check addition
			//
			if(tree_1 == null && tree_2 != null)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data NOT specified", "[+] ENTIRE NEW " + VARIABLE_NAME + " STRUCTURE  ADDED!", null);				
				return true;
			}
			
			//
			//check missing
			//
			else if(tree_1 != null && tree_2 == null)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data specified", "[-] ENTIRE " + VARIABLE_NAME + " STRUCTURE MISSING!", null);				
				return true;
			}
			
			//at this point, both trees are not null, check sizes for additional and missing
			
			//
			//check addition
			//
			if(tree_1.size() < 1 && tree_2.size() > 0)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data NOT specified", "[+] ENTIRE NEW " + VARIABLE_NAME + " STRUCTURE ADDED!", null);					
				return true;
			}
			
			//
			//check missing
			//
			else if(tree_1.size() > 0 && tree_2.size() < 1)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data specified", "[-] ENTIRE " + VARIABLE_NAME + " STRUCTURE MISSING!", null);				
				return true;
			}
			
			//
			//check structure entries
			//
			else
			{								
				///////////////////////////////////////////////////////////////////////
				// check for addition and modified
				///////////////////////////////////////////////////////////////////////
				for(String key : tree_2.keySet())
				{
					if(key == null || key.trim().equals(""))
						continue;
															
					//
					//procure nodes
					//
					entry_1 = tree_1.get(key);
					entry_2 = tree_2.get(key); 	 	 								

					//
					//validate entry
					//
					if(entry_1 == null && entry_2 == null)
						continue;
																		
					
					//
					//set unique_storage_key and comparator values
					//
					try	{	unique_key_1 = entry_1.get_snapshot_analysis_key();	} catch(Exception e){unique_key_1 = null;}
					try	{	unique_key_2 = entry_2.get_snapshot_analysis_key();	} catch(Exception e){unique_key_2 = null;}
					
					try	{	comparator_value_1 = entry_1.get_snapshot_analysis_COMPARATOR_VALUE();	} catch(Exception e){comparator_value_1 = null;}
					try	{	comparator_value_2 = entry_2.get_snapshot_analysis_COMPARATOR_VALUE();	} catch(Exception e){comparator_value_2 = null;}
					
					//
					//check addition
					//
					if(entry_1 == null && entry_2 != null)
					{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " entry [" +unique_key_2 + "]", null, comparator_value_2, null);
					}
					
					//
					//check missing
					//
					else if(entry_1 != null && entry_2 == null)
					{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " entry [" + unique_key_1 + "]", comparator_value_1, null, null);
					}
					
					//
					//else, iterate and check each value
					//
					else
					{
						//
						//specify unique key
						//
						String variable_key_identifier = VARIABLE_NAME + " entry [" + unique_key_2 + "]" ;
						
						if(unique_key_2 == null || unique_key_2.toLowerCase().equals("not specified") || unique_key_2.toLowerCase().equals("unknown"))
							variable_key_identifier = VARIABLE_NAME + " entry [" + unique_key_1 + "]";
						
						//
						//invoke compare routine on the data-transform
						//
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, comparator_value_1, comparator_value_2, null);
					}														
				}
				
				///////////////////////////////////////////////////////////////////////
				// check for missing and modified
				///////////////////////////////////////////////////////////////////////
				for(String key : tree_1.keySet())
				{
					if(key == null || key.trim().equals(""))
						continue;
					
										
					//
					//procure nodes
					//
					entry_1 = tree_1.get(key);
					entry_2 = tree_2.get(key);  	 								

					//
					//validate entry
					//
					if(entry_1 == null && entry_2 == null)
						continue;
											
					
					//
					//set unique_storage_key and comparator values
					//
					try	{	unique_key_1 = entry_1.get_snapshot_analysis_key();	} catch(Exception e){unique_key_1 = null;}
					try	{	unique_key_2 = entry_2.get_snapshot_analysis_key();	} catch(Exception e){unique_key_2 = null;}
					
					try	{	comparator_value_1 = entry_1.get_snapshot_analysis_COMPARATOR_VALUE();	} catch(Exception e){comparator_value_1 = null;}
					try	{	comparator_value_2 = entry_2.get_snapshot_analysis_COMPARATOR_VALUE();	} catch(Exception e){comparator_value_2 = null;}
																							
					//
					//check addition
					//
					if(entry_1 == null && entry_2 != null)
					{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " entry [" + unique_key_2 + "]", null, comparator_value_2, null);
					}
					
					//
					//check missing
					//
					else if(entry_1 != null && entry_2 == null)
					{						
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " entry [" + unique_key_1 + "]", comparator_value_1, null, null);
					}
					
					//
					//else, iterate and check each value
					//
					else
					{
						//
						//specify unique key
						//
						String variable_key_identifier = VARIABLE_NAME + " entry " + unique_key_1 ;
						
						if(unique_key_1 == null || unique_key_1.toLowerCase().equals("not specified") || unique_key_1.toLowerCase().equals("unknown"))
							variable_key_identifier = VARIABLE_NAME + " entry [" + unique_key_2 + "]";
												
						//
						//invoke compare routine on the data-transform
						//
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, comparator_value_1, comparator_value_2, null);
					}														
				}
			}
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_process_SERVICE_SCAN", e);
		}
		
		return false;
	}
	
	
	
	/////////////////////////////////////////
	/////////////////////////
	///////////////
	/////
	
	
	public boolean analyze_process_SIDS(Node_Process process_1, Node_Process process_2, int INITIALIZATION_INDEX, TreeMap<String, Node_Snapshot_Analysis_Artifact> tree, String node_key, String ARTIFACT_TYPE)
	{
		try
		{						
			//
			//procure
			//
			Node_Snapshot_Analysis_Artifact node = tree.get(node_key);
	
			//
			//initialize if necessary
			//
			if(node == null)
			{
				//use the instances to handle the comparison and building of the trees
				node = new Node_Snapshot_Analysis_Artifact(this, process_2.get_process_html_header(), ARTIFACT_TYPE);
	
				//adjust name if needed
				try
				{
					if(node.descriptor == null || node.descriptor.toLowerCase().trim().endsWith("unknown") && !process_1.get_process_html_header().toLowerCase().trim().endsWith("unknown"))
						node.descriptor = process_1.get_process_html_header();	
				}catch(Exception e){}				
	
				//set processes
				node.process_1 = process_1; 
				node.proces_2 = process_2;
	
				//init structures
				node.initialize_structures(INITIALIZATION_INDEX);
	
				//link node!
				tree.put(node_key,  node);				
			}
	
	
	
			//
			//update node's initialization vector
			//
			node.set_my_tree_pointers(INITIALIZATION_INDEX);
	
			//
			//initialize structure
			//
			String VARIABLE_NAME = "SIDS";
			TreeMap<String, String> tree_1 = process_1.tree_sids, tree_2 = process_2.tree_sids;
			String entry_1 = null, entry_2 = null;
	
			//
			//* * * ENSURE THESE VALUES ARE SET PROPERLY BELOW! * * * 
			//
			String comparator_value_1 = null, comparator_value_2 = null;
			String unique_key_1 = null, unique_key_2 = null;
	
	
			//
			//compsre structures
			//
			if(tree_1 == null && tree_2 == null)
				return false;
	
			//
			//check addition
			//
			if(tree_1 == null && tree_2 != null)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data NOT specified", "[+] ENTIRE NEW " + VARIABLE_NAME + " STRUCTURE  ADDED!", null);				
				return true;
			}
	
			//
			//check missing
			//
			else if(tree_1 != null && tree_2 == null)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data specified", "[-] ENTIRE " + VARIABLE_NAME + " STRUCTURE MISSING!", null);				
				return true;
			}
	
			//at this point, both trees are not null, check sizes for additional and missing
	
			//
			//check addition
			//
			if(tree_1.size() < 1 && tree_2.size() > 0)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data NOT specified", "[+] ENTIRE NEW " + VARIABLE_NAME + " STRUCTURE ADDED!", null);					
				return true;
			}
	
			//
			//check missing
			//
			else if(tree_1.size() > 0 && tree_2.size() < 1)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data specified", "[-] ENTIRE " + VARIABLE_NAME + " STRUCTURE MISSING!", null);				
				return true;
			}
	
			//
			//check structure entries
			//
			else
			{								
				///////////////////////////////////////////////////////////////////////
				// check for addition and modified
				///////////////////////////////////////////////////////////////////////
				for(String key : tree_2.keySet())
				{
					if(key == null || key.trim().equals(""))
						continue;
	
					//
					//procure nodes
					//
					entry_1 = tree_1.get(key);
					entry_2 = tree_2.get(key);  	 								

					//
					//validate entry
					//
					if(entry_1 == null && entry_2 == null)
						continue;
																			
	
					//
					//set unique_storage_key and comparator values
					//
					try	{	unique_key_1 = key + "\t" + entry_1.trim();	} catch(Exception e){unique_key_1 = null;}
					try	{	unique_key_2 = key + "\t" + entry_2.trim();	} catch(Exception e){unique_key_2 = null;}
	
					try	{	comparator_value_1 = unique_key_1;	} catch(Exception e){comparator_value_1 = null;}
					try	{	comparator_value_2 = unique_key_2;	} catch(Exception e){comparator_value_2 = null;}
	
					//
					//check addition
					//
					if(entry_1 == null && entry_2 != null)
					{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " entry [" +unique_key_2 + "]", null, comparator_value_2, null);
					}
	
					//
					//check missing
					//
					else if(entry_1 != null && entry_2 == null)
					{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " entry [" + unique_key_1 + "]", comparator_value_1, null, null);
					}
	
					//
					//else, iterate and check each value
					//
					else
					{
						//
						//specify unique key
						//
						String variable_key_identifier = VARIABLE_NAME + " entry [" + unique_key_2 + "]" ;
	
						if(unique_key_2 == null || unique_key_2.toLowerCase().equals("not specified") || unique_key_2.toLowerCase().equals("unknown"))
							variable_key_identifier = VARIABLE_NAME + " entry [" + unique_key_1 + "]";
	
						//
						//invoke compare routine on the data-transform
						//
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, comparator_value_1, comparator_value_2, null);
					}														
				}
	
				///////////////////////////////////////////////////////////////////////
				// check for missing and modified
				///////////////////////////////////////////////////////////////////////
				for(String key : tree_1.keySet())
				{
					if(key == null || key.trim().equals(""))
						continue;
	
	
					//
					//procure nodes
					//
					entry_1 = tree_1.get(key);
					entry_2 = tree_2.get(key);  	 								

					//
					//validate entry
					//
					if(entry_1 == null && entry_2 == null)
						continue;
											
	
					//
					//set unique_storage_key and comparator values
					//
					try	{	unique_key_1 = key + "\t" + entry_1.trim();	} catch(Exception e){unique_key_1 = null;}
					try	{	unique_key_2 = key + "\t" + entry_2.trim();	} catch(Exception e){unique_key_2 = null;}
	
					try	{	comparator_value_1 = unique_key_1;	} catch(Exception e){comparator_value_1 = null;}
					try	{	comparator_value_2 = unique_key_2;	} catch(Exception e){comparator_value_2 = null;}
	
	
					//
					//check addition
					//
					if(entry_1 == null && entry_2 != null)
					{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " entry [" + unique_key_2 + "]", null, comparator_value_2, null);
					}
	
					//
					//check missing
					//
					else if(entry_1 != null && entry_2 == null)
					{						
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " entry [" + unique_key_1 + "]", comparator_value_1, null, null);
					}
	
					//
					//else, iterate and check each value
					//
					else
					{
						//
						//specify unique key
						//
						String variable_key_identifier = VARIABLE_NAME + " entry " + unique_key_1 ;
	
						if(unique_key_1 == null || unique_key_1.toLowerCase().equals("not specified") || unique_key_1.toLowerCase().equals("unknown"))
							variable_key_identifier = VARIABLE_NAME + " entry [" + unique_key_2 + "]";
	
						//
						//invoke compare routine on the data-transform
						//
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, comparator_value_1, comparator_value_2, null);
					}														
				}
			}
	
	
	
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_process_SIDS", e);
		}
	
		return false;
	}
	
		
		
	
	/////////////////////////////////////////
	/////////////////////////
	///////////////
	/////
	
	
	public boolean analyze_process_GDI_TIMERS(Node_Process process_1, Node_Process process_2, int INITIALIZATION_INDEX, TreeMap<String, Node_Snapshot_Analysis_Artifact> tree, String node_key, String ARTIFACT_TYPE)
	{
		try
		{						
			//
			//procure
			//
			Node_Snapshot_Analysis_Artifact node = tree.get(node_key);
			
			//
			//initialize if necessary
			//
			if(node == null)
			{
				//use the instances to handle the comparison and building of the trees
				node = new Node_Snapshot_Analysis_Artifact(this, process_2.get_process_html_header(), ARTIFACT_TYPE);
				
				//adjust name if needed
				try
				{
					if(node.descriptor == null || node.descriptor.toLowerCase().trim().endsWith("unknown") && !process_1.get_process_html_header().toLowerCase().trim().endsWith("unknown"))
						node.descriptor = process_1.get_process_html_header();	
				}catch(Exception e){}				
				
				//set processes
				node.process_1 = process_1; 
				node.proces_2 = process_2;
				
				//init structures
				node.initialize_structures(INITIALIZATION_INDEX);
				
				//link node!
				tree.put(node_key,  node);				
			}

			
			
			//
			//update node's initialization vector
			//
			node.set_my_tree_pointers(INITIALIZATION_INDEX);
				
			//
			//initialize structure
			//
			String VARIABLE_NAME = "GDI Timer";
			TreeMap<String, Node_Generic> tree_1 = process_1.tree_gdi_timers, tree_2 = process_2.tree_gdi_timers;
			Node_Generic entry_1 = null, entry_2 = null;
			
			//
			//* * * ENSURE THESE VALUES ARE SET PROPERLY BELOW! * * * 
			//
			String comparator_value_1 = null, comparator_value_2 = null;
			String unique_key_1 = null, unique_key_2 = null;
			
						
			//
			//compsre structures
			//
			if(tree_1 == null && tree_2 == null)
				return false;
			
			//
			//check addition
			//
			if(tree_1 == null && tree_2 != null)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data NOT specified", "[+] ENTIRE NEW " + VARIABLE_NAME + " STRUCTURE  ADDED!", null);				
				return true;
			}
			
			//
			//check missing
			//
			else if(tree_1 != null && tree_2 == null)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data specified", "[-] ENTIRE " + VARIABLE_NAME + " STRUCTURE MISSING!", null);				
				return true;
			}
			
			//at this point, both trees are not null, check sizes for additional and missing
			
			//
			//check addition
			//
			if(tree_1.size() < 1 && tree_2.size() > 0)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data NOT specified", "[+] ENTIRE NEW " + VARIABLE_NAME + " STRUCTURE ADDED!", null);					
				return true;
			}
			
			//
			//check missing
			//
			else if(tree_1.size() > 0 && tree_2.size() < 1)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data specified", "[-] ENTIRE " + VARIABLE_NAME + " STRUCTURE MISSING!", null);				
				return true;
			}
			
			//
			//check structure entries
			//
			else
			{								
				///////////////////////////////////////////////////////////////////////
				// check for addition and modified
				///////////////////////////////////////////////////////////////////////
				for(String key : tree_2.keySet())
				{
					if(key == null || key.trim().equals(""))
						continue;
															
					//
					//procure nodes
					//
					entry_1 = tree_1.get(key);
					entry_2 = tree_2.get(key); 		 	 								

					//
					//validate entry
					//
					if(entry_1 == null && entry_2 == null)
						continue;
																	
					
					//
					//set unique_storage_key and comparator values
					//
					try	{	unique_key_1 = entry_1.object;	} catch(Exception e){unique_key_1 = null;}
					try	{	unique_key_2 = entry_2.object;	} catch(Exception e){unique_key_2 = null;}
					
					try	{	comparator_value_1 = entry_1.write_manifest_as_single_line(null, "", "\t").trim();	} catch(Exception e){comparator_value_1 = null;}
					try	{	comparator_value_2 = entry_2.write_manifest_as_single_line(null, "", "\t").trim();	} catch(Exception e){comparator_value_2 = null;}
					
					//
					//check addition
					//
					if(entry_1 == null && entry_2 != null)
					{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " entry [" +unique_key_2 + "]", null, comparator_value_2, null);
					}
					
					//
					//check missing
					//
					else if(entry_1 != null && entry_2 == null)
					{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " entry [" + unique_key_1 + "]", comparator_value_1, null, null);
					}
					
					//
					//else, iterate and check each value
					//
					else
					{
						//
						//specify unique key
						//
						String variable_key_identifier = VARIABLE_NAME + " entry [" + unique_key_2 + "]" ;
						
						if(unique_key_2 == null || unique_key_2.toLowerCase().equals("not specified") || unique_key_2.toLowerCase().equals("unknown"))
							variable_key_identifier = VARIABLE_NAME + " entry [" + unique_key_1 + "]";
						
						//
						//invoke compare routine on the data-transform
						//
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, comparator_value_1, comparator_value_2, null);
					}														
				}
				
				///////////////////////////////////////////////////////////////////////
				// check for missing and modified
				///////////////////////////////////////////////////////////////////////
				for(String key : tree_1.keySet())
				{
					if(key == null || key.trim().equals(""))
						continue;
					
										
					//
					//procure nodes
					//
					entry_1 = tree_1.get(key);
					entry_2 = tree_2.get(key);  	 								

					//
					//validate entry
					//
					if(entry_1 == null && entry_2 == null)
						continue;
											
					
					//
					//set unique_storage_key and comparator values
					//
					try	{	unique_key_1 = entry_1.object;	} catch(Exception e){unique_key_1 = null;}
					try	{	unique_key_2 = entry_2.object;	} catch(Exception e){unique_key_2 = null;}
					
					try	{	comparator_value_1 = entry_1.write_manifest_as_single_line(null, "", "\t").trim();	} catch(Exception e){comparator_value_1 = null;}
					try	{	comparator_value_2 = entry_2.write_manifest_as_single_line(null, "", "\t").trim();	} catch(Exception e){comparator_value_2 = null;}
																							
					//
					//check addition
					//
					if(entry_1 == null && entry_2 != null)
					{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " entry [" + unique_key_2 + "]", null, comparator_value_2, null);
					}
					
					//
					//check missing
					//
					else if(entry_1 != null && entry_2 == null)
					{						
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " entry [" + unique_key_1 + "]", comparator_value_1, null, null);
					}
					
					//
					//else, iterate and check each value
					//
					else
					{
						//
						//specify unique key
						//
						String variable_key_identifier = VARIABLE_NAME + " entry " + unique_key_1 ;
						
						if(unique_key_1 == null || unique_key_1.toLowerCase().equals("not specified") || unique_key_1.toLowerCase().equals("unknown"))
							variable_key_identifier = VARIABLE_NAME + " entry [" + unique_key_2 + "]";
												
						//
						//invoke compare routine on the data-transform
						//
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, comparator_value_1, comparator_value_2, null);
					}														
				}
			}
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_process_GDI_TIMERS", e);
		}
		
		return false;
	}
	

	/////////////////////////////////////////
	/////////////////////////
	///////////////
	/////

	
	public boolean analyze_process_ENVARS(Node_Process process_1, Node_Process process_2, int INITIALIZATION_INDEX, TreeMap<String, Node_Snapshot_Analysis_Artifact> tree, String node_key, String ARTIFACT_TYPE)
	{
		try
		{						
			//
			//procure
			//
			Node_Snapshot_Analysis_Artifact node = tree.get(node_key);
					
			//
			//initialize if necessary
			//
			if(node == null)
			{
				//use the instances to handle the comparison and building of the trees
				node = new Node_Snapshot_Analysis_Artifact(this, process_2.get_process_html_header(), ARTIFACT_TYPE);

				//adjust name if needed
				try
				{
					if(node.descriptor == null || node.descriptor.toLowerCase().trim().endsWith("unknown") && !process_1.get_process_html_header().toLowerCase().trim().endsWith("unknown"))
						node.descriptor = process_1.get_process_html_header();	
				}catch(Exception e){}				

				//set processes
				node.process_1 = process_1; 
				node.proces_2 = process_2;

				//init structures
				node.initialize_structures(INITIALIZATION_INDEX);

				//link node!
				tree.put(node_key,  node);				
			}
			
			//
			//update node's initialization vector
			//
			node.set_my_tree_pointers(INITIALIZATION_INDEX);

			//
			//initialize structure
			//
			String VARIABLE_NAME = "Environment Variables";
			TreeMap<String, Node_Envar> tree_1 = process_1.tree_environment_vars, tree_2 = process_2.tree_environment_vars;
			Node_Envar entry_1 = null, entry_2 = null;

			//
			//* * * ENSURE THESE VALUES ARE SET PROPERLY BELOW! * * * 
			//
			String comparator_value_1 = null, comparator_value_2 = null;
			String unique_key_1 = null, unique_key_2 = null;


			//
			//compsre structures
			//
			if(tree_1 == null && tree_2 == null)
				return false;

			//
			//check addition
			//
			if(tree_1 == null && tree_2 != null)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data NOT specified", "[+] ENTIRE NEW " + VARIABLE_NAME + " STRUCTURE  ADDED!", null);				
				return true;
			}

			//
			//check missing
			//
			else if(tree_1 != null && tree_2 == null)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data specified", "[-] ENTIRE " + VARIABLE_NAME + " STRUCTURE MISSING!", null);				
				return true;
			}

			//at this point, both trees are not null, check sizes for additional and missing

			//
			//check addition
			//
			if(tree_1.size() < 1 && tree_2.size() > 0)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data NOT specified", "[+] ENTIRE NEW " + VARIABLE_NAME + " STRUCTURE ADDED!", null);					
				return true;
			}

			//
			//check missing
			//
			else if(tree_1.size() > 0 && tree_2.size() < 1)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data specified", "[-] ENTIRE " + VARIABLE_NAME + " STRUCTURE MISSING!", null);				
				return true;
			}

			//
			//check structure entries
			//
			else
			{								
				///////////////////////////////////////////////////////////////////////
				// check for addition and modified
				///////////////////////////////////////////////////////////////////////
				for(String key : tree_2.keySet())
				{
					if(key == null || key.trim().equals(""))
						continue;

					//
					//procure nodes
					//
					entry_1 = tree_1.get(key);
					entry_2 = tree_2.get(key); 		 	 								

					//
					//validate entry
					//
					if(entry_1 == null && entry_2 == null)
						continue;
											
								
					//
					//set unique_storage_key and comparator values
					//
					try	{	unique_key_1 = entry_1.get_snapshot_analysis_key();	} catch(Exception e){unique_key_1 = null;}
					try	{	unique_key_2 = entry_2.get_snapshot_analysis_key();	} catch(Exception e){unique_key_2 = null;}

					try	{	comparator_value_1 = entry_1.get_snapshot_analysis_COMPARATOR_VALUE();	} catch(Exception e){comparator_value_1 = null;}
					try	{	comparator_value_2 = entry_2.get_snapshot_analysis_COMPARATOR_VALUE();	} catch(Exception e){comparator_value_2 = null;}
										
					//
					//check addition
					//
					if(entry_1 == null && entry_2 != null)
					{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " entry [" +unique_key_2 + "]", null, comparator_value_2, null);
					}

					//
					//check missing
					//
					else if(entry_1 != null && entry_2 == null)
					{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " entry [" + unique_key_1 + "]", comparator_value_1, null, null);
					}

					//
					//else, iterate and check each value
					//
					else
					{
						//
						//specify unique key
						//
						String variable_key_identifier = VARIABLE_NAME + " entry [" + unique_key_2 + "]" ;

						if(unique_key_2 == null || unique_key_2.toLowerCase().equals("not specified") || unique_key_2.toLowerCase().equals("unknown"))
							variable_key_identifier = VARIABLE_NAME + " entry [" + unique_key_1 + "]";

						//
						//invoke compare routine on the data-transform
						//
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, comparator_value_1, comparator_value_2, null);
					}														
				}

				///////////////////////////////////////////////////////////////////////
				// check for missing and modified
				///////////////////////////////////////////////////////////////////////
				for(String key : tree_1.keySet())
				{
					if(key == null || key.trim().equals(""))
						continue;


					//
					//procure nodes
					//
					entry_1 = tree_1.get(key);
					entry_2 = tree_2.get(key);  	 								

					//
					//validate entry
					//
					if(entry_1 == null && entry_2 == null)
						continue;
											

					//
					//set unique_storage_key and comparator values
					//
					try	{	unique_key_1 = entry_1.get_snapshot_analysis_key();	} catch(Exception e){unique_key_1 = null;}
					try	{	unique_key_2 = entry_2.get_snapshot_analysis_key();	} catch(Exception e){unique_key_2 = null;}

					try	{	comparator_value_1 = entry_1.get_snapshot_analysis_COMPARATOR_VALUE();	} catch(Exception e){comparator_value_1 = null;}
					try	{	comparator_value_2 = entry_2.get_snapshot_analysis_COMPARATOR_VALUE();	} catch(Exception e){comparator_value_2 = null;}

					//
					//check addition
					//
					if(entry_1 == null && entry_2 != null)
					{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " entry [" + unique_key_2 + "]", null, comparator_value_2, null);
					}

					//
					//check missing
					//
					else if(entry_1 != null && entry_2 == null)
					{						
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " entry [" + unique_key_1 + "]", comparator_value_1, null, null);
					}

					//
					//else, iterate and check each value
					//
					else
					{
						//
						//specify unique key
						//
						String variable_key_identifier = VARIABLE_NAME + " entry " + unique_key_1 ;

						if(unique_key_1 == null || unique_key_1.toLowerCase().equals("not specified") || unique_key_1.toLowerCase().equals("unknown"))
							variable_key_identifier = VARIABLE_NAME + " entry [" + unique_key_2 + "]";

						//
						//invoke compare routine on the data-transform
						//
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, comparator_value_1, comparator_value_2, null);
					}														
				}
			}



			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_process_ENVARS", e);
		}

		return false;
	}



	/////////////////////////////////////////
	/////////////////////////
	///////////////
	/////

	
	public boolean analyze_process_THREADS_All_Entries_As_Entire_Line_DEPRECATED(Node_Process process_1, Node_Process process_2, int INITIALIZATION_INDEX, TreeMap<String, Node_Snapshot_Analysis_Artifact> tree, String node_key, String ARTIFACT_TYPE)
	{
		try
		{						
			//
			//procure
			//
			Node_Snapshot_Analysis_Artifact node = tree.get(node_key);

			//
			//initialize if necessary
			//
			if(node == null)
			{
				//use the instances to handle the comparison and building of the trees
				node = new Node_Snapshot_Analysis_Artifact(this, process_2.get_process_html_header(), ARTIFACT_TYPE);

				//adjust name if needed
				try
				{
					if(node.descriptor == null || node.descriptor.toLowerCase().trim().endsWith("unknown") && !process_1.get_process_html_header().toLowerCase().trim().endsWith("unknown"))
						node.descriptor = process_1.get_process_html_header();	
				}catch(Exception e){}				

				//set processes
				node.process_1 = process_1; 
				node.proces_2 = process_2;

				//init structures
				node.initialize_structures(INITIALIZATION_INDEX);

				//link node!
				tree.put(node_key,  node);				
			}



			//
			//update node's initialization vector
			//
			node.set_my_tree_pointers(INITIALIZATION_INDEX);

			//
			//initialize structure
			//
			String VARIABLE_NAME = "Thread";
			TreeMap<String, Node_Threads> tree_1 = process_1.tree_threads, tree_2 = process_2.tree_threads;
			Node_Threads entry_1 = null, entry_2 = null;

			//
			//* * * ENSURE THESE VALUES ARE SET PROPERLY BELOW! * * * 
			//
			String comparator_value_1 = null, comparator_value_2 = null;
			String unique_key_1 = null, unique_key_2 = null;


			//
			//compsre structures
			//
			if(tree_1 == null && tree_2 == null)
				return false;

			//
			//check addition
			//
			if(tree_1 == null && tree_2 != null)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data NOT specified", "[+] ENTIRE NEW " + VARIABLE_NAME + " STRUCTURE  ADDED!", null);				
				return true;
			}

			//
			//check missing
			//
			else if(tree_1 != null && tree_2 == null)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data specified", "[-] ENTIRE " + VARIABLE_NAME + " STRUCTURE MISSING!", null);				
				return true;
			}

			//at this point, both trees are not null, check sizes for additional and missing

			//
			//check addition
			//
			if(tree_1.size() < 1 && tree_2.size() > 0)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data NOT specified", "[+] ENTIRE NEW " + VARIABLE_NAME + " STRUCTURE ADDED!", null);					
				return true;
			}

			//
			//check missing
			//
			else if(tree_1.size() > 0 && tree_2.size() < 1)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data specified", "[-] ENTIRE " + VARIABLE_NAME + " STRUCTURE MISSING!", null);				
				return true;
			}

			//
			//check structure entries
			//
			else
			{								
				///////////////////////////////////////////////////////////////////////
				// check for addition and modified
				///////////////////////////////////////////////////////////////////////
				for(String key : tree_2.keySet())
				{
					if(key == null || key.trim().equals(""))
						continue;

					//
					//procure nodes
					//
					entry_1 = tree_1.get(key);
					entry_2 = tree_2.get(key); 	 	 								

					//
					//validate entry
					//
					if(entry_1 == null && entry_2 == null)
						continue;
																		

					//
					//set unique_storage_key and comparator values
					//
					try	{	unique_key_1 = entry_1.get_snapshot_analysis_key();	} catch(Exception e){unique_key_1 = null;}
					try	{	unique_key_2 = entry_2.get_snapshot_analysis_key();	} catch(Exception e){unique_key_2 = null;}

					try	{	comparator_value_1 = entry_1.get_snapshot_analysis_COMPARATOR_VALUE();	} catch(Exception e){comparator_value_1 = null;}
					try	{	comparator_value_2 = entry_2.get_snapshot_analysis_COMPARATOR_VALUE();	} catch(Exception e){comparator_value_2 = null;}

					//
					//check addition
					//
					if(entry_1 == null && entry_2 != null)
					{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " entry [" +unique_key_2 + "]", null, comparator_value_2, null);
					}

					//
					//check missing
					//
					else if(entry_1 != null && entry_2 == null)
					{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " entry [" + unique_key_1 + "]", comparator_value_1, null, null);
					}

					//
					//else, iterate and check each value
					//
					else
					{
						//
						//specify unique key
						//
						String variable_key_identifier = VARIABLE_NAME + " entry [" + unique_key_2 + "]" ;

						if(unique_key_2 == null || unique_key_2.toLowerCase().equals("not specified") || unique_key_2.toLowerCase().equals("unknown"))
							variable_key_identifier = VARIABLE_NAME + " entry [" + unique_key_1 + "]";

						//
						//invoke compare routine on the data-transform
						//
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, comparator_value_1, comparator_value_2, null);
					}														
				}

				///////////////////////////////////////////////////////////////////////
				// check for missing and modified
				///////////////////////////////////////////////////////////////////////
				for(String key : tree_1.keySet())
				{
					if(key == null || key.trim().equals(""))
						continue;


					//
					//procure nodes
					//
					entry_1 = tree_1.get(key);
					entry_2 = tree_2.get(key);  	 								

					//
					//validate entry
					//
					if(entry_1 == null && entry_2 == null)
						continue;
											

					//
					//set unique_storage_key and comparator values
					//
					try	{	unique_key_1 = entry_1.get_snapshot_analysis_key();	} catch(Exception e){unique_key_1 = null;}
					try	{	unique_key_2 = entry_2.get_snapshot_analysis_key();	} catch(Exception e){unique_key_2 = null;}

					try	{	comparator_value_1 = entry_1.get_snapshot_analysis_COMPARATOR_VALUE();	} catch(Exception e){comparator_value_1 = null;}
					try	{	comparator_value_2 = entry_2.get_snapshot_analysis_COMPARATOR_VALUE();	} catch(Exception e){comparator_value_2 = null;}

					//
					//check addition
					//
					if(entry_1 == null && entry_2 != null)
					{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " entry [" + unique_key_2 + "]", null, comparator_value_2, null);
					}

					//
					//check missing
					//
					else if(entry_1 != null && entry_2 == null)
					{						
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " entry [" + unique_key_1 + "]", comparator_value_1, null, null);
					}

					//
					//else, iterate and check each value
					//
					else
					{
						//
						//specify unique key
						//
						String variable_key_identifier = VARIABLE_NAME + " entry " + unique_key_1 ;

						if(unique_key_1 == null || unique_key_1.toLowerCase().equals("not specified") || unique_key_1.toLowerCase().equals("unknown"))
							variable_key_identifier = VARIABLE_NAME + " entry [" + unique_key_2 + "]";

						//
						//invoke compare routine on the data-transform
						//
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, comparator_value_1, comparator_value_2, null);
					}														
				}
			}



			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_process_THREADS_All_Entries_As_Entire_Line_DEPRECATED", e);
		}

		return false;
	}



	/////////////////////////////////////////
	/////////////////////////
	///////////////
	/////


	public boolean analyze_process_THREADS(Node_Process process_1, Node_Process process_2, int INITIALIZATION_INDEX, TreeMap<String, Node_Snapshot_Analysis_Artifact> tree, String node_key, String ARTIFACT_TYPE)
	{
		try
		{						
			//
			//procure
			//
			Node_Snapshot_Analysis_Artifact node = tree.get(node_key);

			//
			//initialize if necessary
			//
			if(node == null)
			{
				//use the instances to handle the comparison and building of the trees
				node = new Node_Snapshot_Analysis_Artifact(this, process_2.get_process_html_header(), ARTIFACT_TYPE);

				//adjust name if needed
				try
				{
					if(node.descriptor == null || node.descriptor.toLowerCase().trim().endsWith("unknown") && !process_1.get_process_html_header().toLowerCase().trim().endsWith("unknown"))
						node.descriptor = process_1.get_process_html_header();	
				}catch(Exception e){}				

				//set processes
				node.process_1 = process_1; 
				node.proces_2 = process_2;

				//init structures
				node.initialize_structures(INITIALIZATION_INDEX);

				//link node!
				tree.put(node_key,  node);				
			}



			//
			//update node's initialization vector
			//
			node.set_my_tree_pointers(INITIALIZATION_INDEX);

			//
			//initialize structure
			//
			String VARIABLE_NAME = "Thread";
			TreeMap<String, Node_Threads> tree_1 = process_1.tree_threads, tree_2 = process_2.tree_threads;
			Node_Threads entry_1 = null, entry_2 = null;

			//
			//* * * ENSURE THESE VALUES ARE SET PROPERLY BELOW! * * * 
			//
			String comparator_value_1 = null, comparator_value_2 = null;
			String unique_key_1 = null, unique_key_2 = null;


			//
			//compsre structures
			//
			if(tree_1 == null && tree_2 == null)
				return false;

			//
			//check addition
			//
			if(tree_1 == null && tree_2 != null)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data NOT specified", "[+] ENTIRE NEW " + VARIABLE_NAME + " STRUCTURE  ADDED!", null);				
				return true;
			}

			//
			//check missing
			//
			else if(tree_1 != null && tree_2 == null)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data specified", "[-] ENTIRE " + VARIABLE_NAME + " STRUCTURE MISSING!", null);				
				return true;
			}

			//at this point, both trees are not null, check sizes for additional and missing

			//
			//check addition
			//
			if(tree_1.size() < 1 && tree_2.size() > 0)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data NOT specified", "[+] ENTIRE NEW " + VARIABLE_NAME + " STRUCTURE ADDED!", null);					
				return true;
			}

			//
			//check missing
			//
			else if(tree_1.size() > 0 && tree_2.size() < 1)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data specified", "[-] ENTIRE " + VARIABLE_NAME + " STRUCTURE MISSING!", null);				
				return true;
			}
			
			

			//
			//check structure entries
			//
			
			
			
			
			else
			{								
				///////////////////////////////////////////////////////////////////////
				// check for addition and modified
				///////////////////////////////////////////////////////////////////////
				for(String key : tree_2.keySet())
				{
					if(key == null || key.trim().equals(""))
						continue;

					//
					//procure nodes
					//
					entry_1 = tree_1.get(key);
					entry_2 = tree_2.get(key); 			 	 								

					//
					//validate entry
					//
					if(entry_1 == null && entry_2 == null)
						continue;
																

					//
					//set unique_storage_key and comparator values
					//
					try	{	unique_key_1 = entry_1.get_snapshot_analysis_key();	} catch(Exception e){unique_key_1 = null;}
					try	{	unique_key_2 = entry_2.get_snapshot_analysis_key();	} catch(Exception e){unique_key_2 = null;}

					try	{	comparator_value_1 = entry_1.get_snapshot_analysis_COMPARATOR_VALUE();	} catch(Exception e){comparator_value_1 = null;}
					try	{	comparator_value_2 = entry_2.get_snapshot_analysis_COMPARATOR_VALUE();	} catch(Exception e){comparator_value_2 = null;}

					//
					//check addition
					//
					if(entry_1 == null && entry_2 != null)
					{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " @ ethread address [" +unique_key_2 + "]", null, comparator_value_2, null);
					}

					//
					//check missing
					//
					else if(entry_1 != null && entry_2 == null)
					{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " @ ethread address [" + unique_key_1 + "]", comparator_value_1, null, null);
					}

					//
					//else, iterate and check each value
					//
					else
					{
						//
						//specify unique key
						//
						String variable_key_identifier = VARIABLE_NAME + " @ ethread address " + unique_key_2 + "" ;

						if(unique_key_2 == null || unique_key_2.toLowerCase().equals("not specified") || unique_key_2.toLowerCase().equals("unknown"))
							variable_key_identifier = VARIABLE_NAME + " @ ethread address " + unique_key_1 + "";

						//
						//invoke compare routine on the data-transform
						//
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.TID, entry_2.TID, "TID");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.TID, entry_2.TID, "TID");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.ethread_address, entry_2.ethread_address, "ethread_address");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.pid, entry_2.pid, "pid");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.tags, entry_2.tags, "tags");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.created, entry_2.created, "created");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.exited, entry_2.exited, "exited");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.owning_process_name, entry_2.owning_process_name, "owning_process_name");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.attached_process_name, entry_2.attached_process_name, "attached_process_name");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.state, entry_2.state, "state");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.base_priority, entry_2.base_priority, "base_priority");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.priority, entry_2.priority, "priority");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.TEB, entry_2.TEB, "TEB");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.start_address, entry_2.start_address, "start_address");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.service_table_address, entry_2.service_table_address, "service_table_address");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.service_table_0, entry_2.service_table_0, "service_table_0");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.service_table_1, entry_2.service_table_1, "service_table_1");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.service_table_2, entry_2.service_table_2, "service_table_2");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.service_table_3, entry_2.service_table_3, "service_table_3");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.win32thread, entry_2.win32thread, "win32thread");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.crossThreadFlags, entry_2.crossThreadFlags, "crossThreadFlags");


					}														
				}

				///////////////////////////////////////////////////////////////////////
				// check for missing and modified
				///////////////////////////////////////////////////////////////////////
				for(String key : tree_1.keySet())
				{
					if(key == null || key.trim().equals(""))
						continue;


					//
					//procure nodes
					//
					entry_1 = tree_1.get(key);
					entry_2 = tree_2.get(key);  	 								

					//
					//validate entry
					//
					if(entry_1 == null && entry_2 == null)
						continue;
											

					//
					//set unique_storage_key and comparator values
					//
					try	{	unique_key_1 = entry_1.get_snapshot_analysis_key();	} catch(Exception e){unique_key_1 = null;}
					try	{	unique_key_2 = entry_2.get_snapshot_analysis_key();	} catch(Exception e){unique_key_2 = null;}

					try	{	comparator_value_1 = entry_1.get_snapshot_analysis_COMPARATOR_VALUE();	} catch(Exception e){comparator_value_1 = null;}
					try	{	comparator_value_2 = entry_2.get_snapshot_analysis_COMPARATOR_VALUE();	} catch(Exception e){comparator_value_2 = null;}

					//
					//check addition
					//
					if(entry_1 == null && entry_2 != null)
					{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " @ ethread address [" + unique_key_2 + "]", null, comparator_value_2, null);
					}

					//
					//check missing
					//
					else if(entry_1 != null && entry_2 == null)
					{						
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " @ ethread address [" + unique_key_1 + "]", comparator_value_1, null, null);
					}

					//
					//else, iterate and check each value
					//
					else
					{
						//
						//specify unique key
						//
						String variable_key_identifier = VARIABLE_NAME + " @ ethread address " + unique_key_1 ;

						if(unique_key_1 == null || unique_key_1.toLowerCase().equals("not specified") || unique_key_1.toLowerCase().equals("unknown"))
							variable_key_identifier = VARIABLE_NAME + " @ ethread address " + unique_key_2 + "";

						//
						//invoke compare routine on the data-transform
						//
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.TID, entry_2.TID, "TID");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.TID, entry_2.TID, "TID");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.ethread_address, entry_2.ethread_address, "ethread_address");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.pid, entry_2.pid, "pid");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.tags, entry_2.tags, "tags");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.created, entry_2.created, "created");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.exited, entry_2.exited, "exited");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.owning_process_name, entry_2.owning_process_name, "owning_process_name");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.attached_process_name, entry_2.attached_process_name, "attached_process_name");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.state, entry_2.state, "state");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.base_priority, entry_2.base_priority, "base_priority");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.priority, entry_2.priority, "priority");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.TEB, entry_2.TEB, "TEB");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.start_address, entry_2.start_address, "start_address");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.service_table_address, entry_2.service_table_address, "service_table_address");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.service_table_0, entry_2.service_table_0, "service_table_0");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.service_table_1, entry_2.service_table_1, "service_table_1");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.service_table_2, entry_2.service_table_2, "service_table_2");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.service_table_3, entry_2.service_table_3, "service_table_3");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.win32thread, entry_2.win32thread, "win32thread");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.crossThreadFlags, entry_2.crossThreadFlags, "crossThreadFlags");
					}														
				}
			}



			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_process_THREADS", e);
		}

		return false;
	}
	
	
	
	/////////////////////////////////////////
	/////////////////////////
	///////////////
	/////

	/**
	 * special note: these API values are the dll	 api_hooks and not the API Hooks under each PROCESS
	 * @param process_1
	 * @param process_2
	 * @param INITIALIZATION_INDEX
	 * @param tree
	 * @param node_key
	 * @param ARTIFACT_TYPE
	 * @return
	 */
	public boolean analyze_process_API_HOOKS(Node_Process process_1, Node_Process process_2, int INITIALIZATION_INDEX, TreeMap<String, Node_Snapshot_Analysis_Artifact> tree, String node_key, String ARTIFACT_TYPE)
	{
		try
		{						
			//
			//procure
			//
			Node_Snapshot_Analysis_Artifact node = tree.get(node_key);

			//
			//initialize if necessary
			//
			if(node == null)
			{
				//use the instances to handle the comparison and building of the trees
				node = new Node_Snapshot_Analysis_Artifact(this, process_2.get_process_html_header(), ARTIFACT_TYPE);

				//adjust name if needed
				try
				{
					if(node.descriptor == null || node.descriptor.toLowerCase().trim().endsWith("unknown") && !process_1.get_process_html_header().toLowerCase().trim().endsWith("unknown"))
						node.descriptor = process_1.get_process_html_header();	
				}catch(Exception e){}				

				//set processes
				node.process_1 = process_1; 
				node.proces_2 = process_2;

				//init structures
				node.initialize_structures(INITIALIZATION_INDEX);

				//link node!
				tree.put(node_key,  node);				
			}



			//
			//update node's initialization vector
			//
			node.set_my_tree_pointers(INITIALIZATION_INDEX);

			//
			//initialize structure
			//
			String VARIABLE_NAME = "API Hook";
			TreeMap<String, Node_ApiHook> tree_1 = process_1.tree_api_hook, tree_2 = process_2.tree_api_hook;
			Node_ApiHook entry_1 = null, entry_2 = null;

			//
			//* * * ENSURE THESE VALUES ARE SET PROPERLY BELOW! * * * 
			//
			String comparator_value_1 = null, comparator_value_2 = null;
			String unique_key_1 = null, unique_key_2 = null;


			//
			//compsre structures
			//
			if(tree_1 == null && tree_2 == null)
				return false;

			//
			//check addition
			//
			if(tree_1 == null && tree_2 != null)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data NOT specified", "[+] ENTIRE NEW " + VARIABLE_NAME + " STRUCTURE  ADDED!", null);				
				return true;
			}

			//
			//check missing
			//
			else if(tree_1 != null && tree_2 == null)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data specified", "[-] ENTIRE " + VARIABLE_NAME + " STRUCTURE MISSING!", null);				
				return true;
			}

			//at this point, both trees are not null, check sizes for additional and missing

			//
			//check addition
			//
			if(tree_1.size() < 1 && tree_2.size() > 0)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data NOT specified", "[+] ENTIRE NEW " + VARIABLE_NAME + " STRUCTURE ADDED!", null);					
				return true;
			}

			//
			//check missing
			//
			else if(tree_1.size() > 0 && tree_2.size() < 1)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data specified", "[-] ENTIRE " + VARIABLE_NAME + " STRUCTURE MISSING!", null);				
				return true;
			}
			
			

			//
			//check structure entries
			//
			
			
			
			
			else
			{								
				///////////////////////////////////////////////////////////////////////
				// check for addition and modified
				///////////////////////////////////////////////////////////////////////
				for(String key : tree_2.keySet())
				{
					if(key == null || key.trim().equals(""))
						continue;

					//
					//procure nodes
					//
					entry_1 = tree_1.get(key);
					entry_2 = tree_2.get(key); 			 	 								

					//
					//validate entry
					//
					if(entry_1 == null && entry_2 == null)
						continue;
																

					//
					//set unique_storage_key and comparator values
					//
					try	{	unique_key_1 = entry_1.get_snapshot_analysis_key();	} catch(Exception e){unique_key_1 = null;}
					try	{	unique_key_2 = entry_2.get_snapshot_analysis_key();	} catch(Exception e){unique_key_2 = null;}

					try	{	comparator_value_1 = entry_1.get_snapshot_analysis_COMPARATOR_VALUE();	} catch(Exception e){comparator_value_1 = null;}
					try	{	comparator_value_2 = entry_2.get_snapshot_analysis_COMPARATOR_VALUE();	} catch(Exception e){comparator_value_2 = null;}

					//
					//check addition
					//
					if(entry_1 == null && entry_2 != null)
					{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " @ hook address [" +unique_key_2 + "]", null, comparator_value_2, null);
					}

					//
					//check missing
					//
					else if(entry_1 != null && entry_2 == null)
					{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " @ hook address [" + unique_key_1 + "]", comparator_value_1, null, null);
					}

					//
					//else, iterate and check each value
					//
					else
					{
						//
						//specify unique key
						//
						String variable_key_identifier = VARIABLE_NAME + " @ hook address " + unique_key_2 + "" ;

						if(unique_key_2 == null || unique_key_2.toLowerCase().equals("not specified") || unique_key_2.toLowerCase().equals("unknown"))
							variable_key_identifier = VARIABLE_NAME + " @ hook address " + unique_key_1 + "";

						//
						//invoke compare routine on the data-transform
						//
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.hook_mode, entry_2.hook_mode, "hook_mode");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.hook_type, entry_2.hook_type, "hook_type");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.process_line, entry_2.process_line, "process_line");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.pid, entry_2.pid, "pid");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.process_name, entry_2.process_name, "process_name");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, ""+entry_1.PID, ""+entry_2.PID, "PID");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.victim_module_line, entry_2.victim_module_line, "victim_module_line");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.victim_module_name, entry_2.victim_module_name, "victim_module_name");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.victim_module_base_address, entry_2.victim_module_base_address, "victim_module_base_address");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.function, entry_2.function, "function");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.hook_address, entry_2.hook_address, "hook_address");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.hooking_module, entry_2.hooking_module, "hooking_module");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, ""+entry_1.MZ_Detected, ""+entry_2.MZ_Detected, "MZ_Detected");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, ""+entry_1.Trampoline_Initial_JMP_Detected, ""+entry_2.Trampoline_Initial_JMP_Detected, "Trampoline_Initial_JMP_Detected");
						
						
						///////////////////////////////////////////////////////////////////////
						// check lists
						///////////////////////////////////////////////////////////////////////
						this.check_lists(INITIALIZATION_INDEX, variable_key_identifier, node, entry_1.list_dissassembly_0, entry_2.list_dissassembly_0, "list_dissassembly_0", false);
						this.check_lists(INITIALIZATION_INDEX, variable_key_identifier, node, entry_1.list_dissassembly_1, entry_2.list_dissassembly_1, "list_dissassembly_1", false);
						this.check_lists(INITIALIZATION_INDEX, variable_key_identifier, node, entry_1.list_dissassembly_2, entry_2.list_dissassembly_2, "list_dissassembly_2", false);
						this.check_lists(INITIALIZATION_INDEX, variable_key_identifier, node, entry_1.list_dissassembly_3, entry_2.list_dissassembly_3, "list_dissassembly_3", false);

					}
					
					
															
				}

				///////////////////////////////////////////////////////////////////////
				// check for missing and modified
				///////////////////////////////////////////////////////////////////////
				for(String key : tree_1.keySet())
				{
					if(key == null || key.trim().equals(""))
						continue;


					//
					//procure nodes
					//
					entry_1 = tree_1.get(key);
					entry_2 = tree_2.get(key);  	 								

					//
					//validate entry
					//
					if(entry_1 == null && entry_2 == null)
						continue;
											

					//
					//set unique_storage_key and comparator values
					//
					try	{	unique_key_1 = entry_1.get_snapshot_analysis_key();	} catch(Exception e){unique_key_1 = null;}
					try	{	unique_key_2 = entry_2.get_snapshot_analysis_key();	} catch(Exception e){unique_key_2 = null;}

					try	{	comparator_value_1 = entry_1.get_snapshot_analysis_COMPARATOR_VALUE();	} catch(Exception e){comparator_value_1 = null;}
					try	{	comparator_value_2 = entry_2.get_snapshot_analysis_COMPARATOR_VALUE();	} catch(Exception e){comparator_value_2 = null;}

					//
					//check addition
					//
					if(entry_1 == null && entry_2 != null)
					{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " @ hook address [" + unique_key_2 + "]", null, comparator_value_2, null);
					}

					//
					//check missing
					//
					else if(entry_1 != null && entry_2 == null)
					{						
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " @ hook address [" + unique_key_1 + "]", comparator_value_1, null, null);
					}

					//
					//else, iterate and check each value
					//
					else
					{
						//
						//specify unique key
						//
						String variable_key_identifier = VARIABLE_NAME + " @ hook address " + unique_key_1 ;

						if(unique_key_1 == null || unique_key_1.toLowerCase().equals("not specified") || unique_key_1.toLowerCase().equals("unknown"))
							variable_key_identifier = VARIABLE_NAME + " @ hook address " + unique_key_2 + "";

						//
						//invoke compare routine on the data-transform
						//
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.hook_mode, entry_2.hook_mode, "hook_mode");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.hook_type, entry_2.hook_type, "hook_type");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.process_line, entry_2.process_line, "process_line");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.pid, entry_2.pid, "pid");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.process_name, entry_2.process_name, "process_name");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, ""+entry_1.PID, ""+entry_2.PID, "PID");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.victim_module_line, entry_2.victim_module_line, "victim_module_line");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.victim_module_name, entry_2.victim_module_name, "victim_module_name");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.victim_module_base_address, entry_2.victim_module_base_address, "victim_module_base_address");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.function, entry_2.function, "function");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.hook_address, entry_2.hook_address, "hook_address");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.hooking_module, entry_2.hooking_module, "hooking_module");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, ""+entry_1.MZ_Detected, ""+entry_2.MZ_Detected, "MZ_Detected");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, ""+entry_1.Trampoline_Initial_JMP_Detected, ""+entry_2.Trampoline_Initial_JMP_Detected, "Trampoline_Initial_JMP_Detected");

						///////////////////////////////////////////////////////////////////////
						// check lists
						///////////////////////////////////////////////////////////////////////
						this.check_lists(INITIALIZATION_INDEX, variable_key_identifier, node, entry_1.list_dissassembly_0, entry_2.list_dissassembly_0, "list_dissassembly_0", true);
						this.check_lists(INITIALIZATION_INDEX, variable_key_identifier, node, entry_1.list_dissassembly_1, entry_2.list_dissassembly_1, "list_dissassembly_1", true);
						this.check_lists(INITIALIZATION_INDEX, variable_key_identifier, node, entry_1.list_dissassembly_2, entry_2.list_dissassembly_2, "list_dissassembly_2", true);
						this.check_lists(INITIALIZATION_INDEX, variable_key_identifier, node, entry_1.list_dissassembly_3, entry_2.list_dissassembly_3, "list_dissassembly_3", true);
						
					}														
				}
				
					
			}



			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_process_API_HOOKS", e);
		}

		return false;
	}
	
	
	/**
	 * 
	 * @param INITIALIZATION_INDEX
	 * @param VARIABLE_NAME
	 * @param node
	 * @param list_1
	 * @param list_2
	 * @param specific_variable_description
	 * @param omit_adding_to_tree_if_deviation_detected - only set this to true after you are running through for the second batch. i.e. if you ran for loop to check for additions (set this to false), and now you're running the for loop for the second time (looking for missing values) - set this to true to not do the same thing if we've already identified deviations
	 * @return
	 */
	public boolean check_lists(int INITIALIZATION_INDEX, String VARIABLE_NAME, Node_Snapshot_Analysis_Artifact node, LinkedList<String> list_1, LinkedList<String> list_2, String specific_variable_description, boolean omit_adding_to_tree_if_deviation_detected)
	{
		try
		{
			if(list_1 == null && list_2 == null)
				return false;
			
			if(list_1.isEmpty() && list_2.isEmpty())
				return false;
			
			//ensure we have identified this value yet						
			
			if(list_1 == null && list_2 != null)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, null, "Entire [" + specific_variable_description + "] structure", null);
			}

			//
			//check missing
			//
			else if(list_1 != null && list_2 == null)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "Entire [" + specific_variable_description + "] structure", null, null);
			}
			
			else
			{
				
				//
				//check added
				//			
				int i = -1;
				for(String value : list_2)
				{
					++i;
					
					if(value == null || value.trim().equals(""))
						continue;
					
					//match found!
					if(list_1.contains(value))
						continue;
					
					try
					{
						if(omit_adding_to_tree_if_deviation_detected && node != null)
						{
							String key = VARIABLE_NAME;
							
							if(specific_variable_description != null && specific_variable_description.length() > 0)
								key = specific_variable_description + " index " + (i);
							
							if(node.tree_addition != null && node.tree_addition.containsKey(key))
								return true;
							
							else if(node.tree_missing != null && node.tree_missing.containsKey(key))
								return true;
							
							else if(node.tree_MODIFIED != null && node.tree_MODIFIED.containsKey(key))
								return true;								
						}
					}catch(Exception e){}
					
					//otw, this is an added value!
					node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, null, value, specific_variable_description + " index " + (i));
					
				}
				
				//
				//check missing
				//				
				i = -1;
				for(String value : list_1)
				{
					++i;
					
					if(value == null || value.trim().equals(""))
						continue;
					
					//match found!
					if(list_2.contains(value))
						continue;
					
					try
					{
						if(omit_adding_to_tree_if_deviation_detected && node != null)
						{
							String key = VARIABLE_NAME;
							
							if(specific_variable_description != null && specific_variable_description.length() > 0)
								key = specific_variable_description + " index " + (i);
							
							if(node.tree_addition != null && node.tree_addition.containsKey(key))
								return true;
							
							else if(node.tree_missing != null && node.tree_missing.containsKey(key))
								return true;
							
							else if(node.tree_MODIFIED != null && node.tree_MODIFIED.containsKey(key))
								return true;								
						}
					}catch(Exception e){}
					
					//otw, this is an missing value!
					node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, value, null, specific_variable_description+ " index " + (i));
					
				}


			}	
			
			
			//node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, ""+entry_1.Trampoline_Initial_JMP_Detected, ""+entry_2.Trampoline_Initial_JMP_Detected, specific_variable_description);
			
			return true;			
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "check_lists", e);
		}
		
		return false;
	}

	/////////////////////////////////////////
	/////////////////////////
	///////////////
	/////
	
	/**
	 * special note: these API values are the dll	 api_hooks and not the API Hooks under each PROCESS
	 * @param process_1
	 * @param process_2
	 * @param INITIALIZATION_INDEX
	 * @param tree
	 * @param node_key
	 * @param ARTIFACT_TYPE
	 * @return
	 */
	public boolean analyze_process_MALFIND(Node_Process process_1, Node_Process process_2, int INITIALIZATION_INDEX, TreeMap<String, Node_Snapshot_Analysis_Artifact> tree, String node_key, String ARTIFACT_TYPE)
	{
		try
		{						
			//
			//procure
			//
			Node_Snapshot_Analysis_Artifact node = tree.get(node_key);

			//
			//initialize if necessary
			//
			if(node == null)
			{
				//use the instances to handle the comparison and building of the trees
				node = new Node_Snapshot_Analysis_Artifact(this, process_2.get_process_html_header(), ARTIFACT_TYPE);

				//adjust name if needed
				try
				{
					if(node.descriptor == null || node.descriptor.toLowerCase().trim().endsWith("unknown") && !process_1.get_process_html_header().toLowerCase().trim().endsWith("unknown"))
						node.descriptor = process_1.get_process_html_header();	
				}catch(Exception e){}				

				//set processes
				node.process_1 = process_1; 
				node.proces_2 = process_2;

				//init structures
				node.initialize_structures(INITIALIZATION_INDEX);

				//link node!
				tree.put(node_key,  node);				
			}



			//
			//update node's initialization vector
			//
			node.set_my_tree_pointers(INITIALIZATION_INDEX);

			//
			//initialize structure
			//
			String VARIABLE_NAME = "Malfind";
			TreeMap<String, Node_Malfind> tree_1 = process_1.tree_malfind, tree_2 = process_2.tree_malfind;
			Node_Malfind entry_1 = null, entry_2 = null;

			//
			//* * * ENSURE THESE VALUES ARE SET PROPERLY BELOW! * * * 
			//
			String comparator_value_1 = null, comparator_value_2 = null;
			String unique_key_1 = null, unique_key_2 = null;


			//
			//compsre structures
			//
			if(tree_1 == null && tree_2 == null)
				return false;

			//
			//check addition
			//
			if(tree_1 == null && tree_2 != null)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data NOT specified", "[+] ENTIRE NEW " + VARIABLE_NAME + " STRUCTURE  ADDED!", null);				
				return true;
			}

			//
			//check missing
			//
			else if(tree_1 != null && tree_2 == null)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data specified", "[-] ENTIRE " + VARIABLE_NAME + " STRUCTURE MISSING!", null);				
				return true;
			}

			//at this point, both trees are not null, check sizes for additional and missing

			//
			//check addition
			//
			if(tree_1.size() < 1 && tree_2.size() > 0)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data NOT specified", "[+] ENTIRE NEW " + VARIABLE_NAME + " STRUCTURE ADDED!", null);					
				return true;
			}

			//
			//check missing
			//
			else if(tree_1.size() > 0 && tree_2.size() < 1)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data specified", "[-] ENTIRE " + VARIABLE_NAME + " STRUCTURE MISSING!", null);				
				return true;
			}
			
			

			//
			//check structure entries
			//
			else
			{								
				///////////////////////////////////////////////////////////////////////
				// check for addition and modified
				///////////////////////////////////////////////////////////////////////
				for(String key : tree_2.keySet())
				{
					if(key == null || key.trim().equals(""))
						continue;

					//
					//procure nodes
					//
					entry_1 = tree_1.get(key);
					entry_2 = tree_2.get(key); 			 	 								

					//
					//validate entry
					//
					if(entry_1 == null && entry_2 == null)
						continue;
																

					//
					//set unique_storage_key and comparator values
					//
					try	{	unique_key_1 = entry_1.get_snapshot_analysis_key();	} catch(Exception e){unique_key_1 = null;}
					try	{	unique_key_2 = entry_2.get_snapshot_analysis_key();	} catch(Exception e){unique_key_2 = null;}

					try	{	comparator_value_1 = entry_1.get_snapshot_analysis_COMPARATOR_VALUE();	} catch(Exception e){comparator_value_1 = null;}
					try	{	comparator_value_2 = entry_2.get_snapshot_analysis_COMPARATOR_VALUE();	} catch(Exception e){comparator_value_2 = null;}

					//
					//check entire addition
					//
					if(entry_1 == null && entry_2 != null)
					{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " @ address [" +unique_key_2 + "]", null, comparator_value_2, null);
					}

					//
					//check entire missing
					//
					else if(entry_1 != null && entry_2 == null)
					{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " @ address [" + unique_key_1 + "]", comparator_value_1, null, null);
					}

					//
					//else, iterate and check each value
					//
					else
					{
						//
						//specify unique key
						//
						String variable_key_identifier = VARIABLE_NAME + " @ address " + unique_key_2 + "" ;

						if(unique_key_2 == null || unique_key_2.toLowerCase().equals("not specified") || unique_key_2.toLowerCase().equals("unknown"))
							variable_key_identifier = VARIABLE_NAME + " @ address " + unique_key_1 + "";

						//
						//invoke compare routine on the data-transform
						//
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.pid, entry_2.pid, "pid");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.process_name, entry_2.process_name, "process_name");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.address, entry_2.address, "address");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.vad_tag, entry_2.vad_tag, "vad_tag");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.protection, entry_2.protection, "protection");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.flags, entry_2.flags, "flags");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, ""+entry_1.MZ_present, ""+entry_2.MZ_present, "MZ_present");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, ""+entry_1.Trampoline_initial_JMP_Detected, ""+entry_2.Trampoline_initial_JMP_Detected, "Trampoline_initial_JMP_Detected");
						
									
						///////////////////////////////////////////////////////////////////////
						// File Attribute!
						///////////////////////////////////////////////////////////////////////
						this.compare_file_attributes(node, INITIALIZATION_INDEX, entry_1.fle_attributes, entry_2.fle_attributes, VARIABLE_NAME + " - FILE ATTRIBUTE ");
						
						///////////////////////////////////////////////////////////////////////
						// check lists
						///////////////////////////////////////////////////////////////////////
						this.check_lists(INITIALIZATION_INDEX, variable_key_identifier, node, entry_1.list_details, entry_2.list_details, "list_details", false);

					}
					
					
															
				}

				///////////////////////////////////////////////////////////////////////
				// check for missing and modified
				///////////////////////////////////////////////////////////////////////
				for(String key : tree_1.keySet())
				{
					if(key == null || key.trim().equals(""))
						continue;


					//
					//procure nodes
					//
					entry_1 = tree_1.get(key);
					entry_2 = tree_2.get(key);  	 								

					//
					//validate entry
					//
					if(entry_1 == null && entry_2 == null)
						continue;
											

					//
					//set unique_storage_key and comparator values
					//
					try	{	unique_key_1 = entry_1.get_snapshot_analysis_key();	} catch(Exception e){unique_key_1 = null;}
					try	{	unique_key_2 = entry_2.get_snapshot_analysis_key();	} catch(Exception e){unique_key_2 = null;}

					try	{	comparator_value_1 = entry_1.get_snapshot_analysis_COMPARATOR_VALUE();	} catch(Exception e){comparator_value_1 = null;}
					try	{	comparator_value_2 = entry_2.get_snapshot_analysis_COMPARATOR_VALUE();	} catch(Exception e){comparator_value_2 = null;}

					//
					//check addition
					//
					if(entry_1 == null && entry_2 != null)
					{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " @ address [" + unique_key_2 + "]", null, comparator_value_2, null);
					}

					//
					//check missing
					//
					else if(entry_1 != null && entry_2 == null)
					{						
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " @ address [" + unique_key_1 + "]", comparator_value_1, null, null);
					}

					//
					//else, iterate and check each value
					//
					else
					{
						//
						//specify unique key
						//
						String variable_key_identifier = VARIABLE_NAME + " @ address " + unique_key_1 ;

						if(unique_key_1 == null || unique_key_1.toLowerCase().equals("not specified") || unique_key_1.toLowerCase().equals("unknown"))
							variable_key_identifier = VARIABLE_NAME + " @ address " + unique_key_2 + "";

						//
						//invoke compare routine on the data-transform
						//
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.pid, entry_2.pid, "pid");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.process_name, entry_2.process_name, "process_name");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.address, entry_2.address, "address");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.vad_tag, entry_2.vad_tag, "vad_tag");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.protection, entry_2.protection, "protection");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.flags, entry_2.flags, "flags");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, ""+entry_1.MZ_present, ""+entry_2.MZ_present, "MZ_present");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, ""+entry_1.Trampoline_initial_JMP_Detected, ""+entry_2.Trampoline_initial_JMP_Detected, "Trampoline_initial_JMP_Detected");
						
						
						///////////////////////////////////////////////////////////////////////
						// File Attribute!
						///////////////////////////////////////////////////////////////////////
						//this.compare_file_attributes(node, INITIALIZATION_INDEX, process_1.fle_attributes, process_2.fle_attributes, VARIABLE_NAME + " - FILE ATTRIBUTE");
						
						
						///////////////////////////////////////////////////////////////////////
						// check lists
						///////////////////////////////////////////////////////////////////////
						this.check_lists(INITIALIZATION_INDEX, variable_key_identifier, node, entry_1.list_details, entry_2.list_details, "list_details", true);						
					}														
				}
				
					
			}



			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_process_MALFIND", e);
		}

		return false;
	}


	/////////////////////////////////////////
	/////////////////////////
	///////////////
	/////


	/**
	 * special note: these API values are the dll	 api_hooks and not the API Hooks under each PROCESS
	 * @param process_1
	 * @param process_2
	 * @param INITIALIZATION_INDEX
	 * @param tree
	 * @param node_key
	 * @param ARTIFACT_TYPE
	 * @return
	 */
	public boolean analyze_process_NODE_GENERIC(Node_Process process_1, Node_Process process_2, int INITIALIZATION_INDEX, TreeMap<String, Node_Snapshot_Analysis_Artifact> tree, String node_key, String ARTIFACT_TYPE, String VARIABLE_NAME)
	{ 
		try
		{						
			//
			//procure
			//
			Node_Snapshot_Analysis_Artifact node = tree.get(node_key);

			//
			//initialize if necessary
			//
			if(node == null)
			{
				//use the instances to handle the comparison and building of the trees
				node = new Node_Snapshot_Analysis_Artifact(this, process_2.get_process_html_header(), ARTIFACT_TYPE);

				//adjust name if needed
				try
				{
					if(node.descriptor == null || node.descriptor.toLowerCase().trim().endsWith("unknown") && !process_1.get_process_html_header().toLowerCase().trim().endsWith("unknown"))
						node.descriptor = process_1.get_process_html_header();	
				}catch(Exception e){}				

				//set processes
				node.process_1 = process_1; 
				node.proces_2 = process_2;

				//init structures
				node.initialize_structures(INITIALIZATION_INDEX);

				//link node!
				tree.put(node_key,  node);				
			}



			//
			//update node's initialization vector
			//
			node.set_my_tree_pointers(INITIALIZATION_INDEX);

			//
			//initialize structure
			//			
			TreeMap<String, Node_Generic> tree_1 = process_1.tree_vad_info, tree_2 = process_2.tree_vad_info;
			Node_Generic entry_1 = null, entry_2 = null;

			//
			//* * * ENSURE THESE VALUES ARE SET PROPERLY BELOW! * * * 
			//
			String comparator_value_1 = null, comparator_value_2 = null;
			String unique_key_1 = null, unique_key_2 = null;


			//
			//compsre structures
			//
			if(tree_1 == null && tree_2 == null)
				return false;

			//
			//check addition
			//
			if(tree_1 == null && tree_2 != null)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data NOT specified", "[+] ENTIRE NEW " + VARIABLE_NAME + " STRUCTURE  ADDED!", null);				
				return true;
			}

			//
			//check missing
			//
			else if(tree_1 != null && tree_2 == null)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data specified", "[-] ENTIRE " + VARIABLE_NAME + " STRUCTURE MISSING!", null);				
				return true;
			}

			//at this point, both trees are not null, check sizes for additional and missing

			//
			//check addition
			//
			if(tree_1.size() < 1 && tree_2.size() > 0)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data NOT specified", "[+] ENTIRE NEW " + VARIABLE_NAME + " STRUCTURE ADDED!", null);					
				return true;
			}

			//
			//check missing
			//
			else if(tree_1.size() > 0 && tree_2.size() < 1)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data specified", "[-] ENTIRE " + VARIABLE_NAME + " STRUCTURE MISSING!", null);				
				return true;
			}
			
			

			//
			//check structure entries
			//
			else
			{								
				///////////////////////////////////////////////////////////////////////
				// check for addition and modified
				///////////////////////////////////////////////////////////////////////
				for(String key : tree_2.keySet())
				{
					if(key == null || key.trim().equals(""))
						continue;

					//
					//procure nodes
					//
					entry_1 = tree_1.get(key);
					entry_2 = tree_2.get(key); 	 	 								

					//
					//validate entry
					//
					if(entry_1 == null && entry_2 == null)
						continue;
																		

					//
					//set unique_storage_key and comparator values
					//
					try	{	unique_key_1 = entry_1.get_snapshot_analysis_key_VAD();	} catch(Exception e){unique_key_1 = null;}
					try	{	unique_key_2 = entry_2.get_snapshot_analysis_key_VAD();	} catch(Exception e){unique_key_2 = null;}

					try	{	comparator_value_1 = entry_1.get_snapshot_analysis_COMPARATOR_VALUE().trim();	} catch(Exception e){comparator_value_1 = null;}
					try	{	comparator_value_2 = entry_2.get_snapshot_analysis_COMPARATOR_VALUE().trim();	} catch(Exception e){comparator_value_2 = null;}

					//
					//check entire addition
					//
					if(entry_1 == null && entry_2 != null)
					{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " @ address [" +unique_key_2 + "]", null, comparator_value_2, null);
					}

					//
					//check entire missing
					//
					else if(entry_1 != null && entry_2 == null)
					{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " @ address [" + unique_key_1 + "]", comparator_value_1, null, null);
					}

					//
					//else, iterate and check each value
					//
					else
					{
						//
						//specify unique key
						//
						String variable_key_identifier = VARIABLE_NAME + " @ address " + unique_key_2 + "" ;

						if(unique_key_2 == null || unique_key_2.toLowerCase().equals("not specified") || unique_key_2.toLowerCase().equals("unknown"))
							variable_key_identifier = VARIABLE_NAME + " @ address " + unique_key_1 + "";

						//
						//invoke compare routine on the data-transform
						//
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.session, entry_2.session, "session");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.handle, entry_2.handle, "handle");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.object, entry_2.object, "object");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.thread, entry_2.thread, "thread");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.process_details, entry_2.process_details, "process_details");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.nID, entry_2.nID, "nID");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.rate_ms, entry_2.rate_ms, "rate_ms");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.countdown_ms, entry_2.countdown_ms, "countdown_ms");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.function, entry_2.function, "function");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.type, entry_2.type, "type");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.callback, entry_2.callback, "callback");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.module_name, entry_2.module_name, "module_name");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.details, entry_2.details, "details");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.offset_v, entry_2.offset_v, "offset_v");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.due_time, entry_2.due_time, "due_time");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.period_ms, entry_2.period_ms, "period_ms");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.signaled, entry_2.signaled, "signaled");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.routine, entry_2.routine, "routine");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.start_address, entry_2.start_address, "start_address");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.end_address, entry_2.end_address, "end_address");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.date, entry_2.date, "date");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.time, entry_2.time, "time");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.reg_binary, entry_2.reg_binary, "reg_binary");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.raw_data_first_line, entry_2.raw_data_first_line, "raw_data_first_line");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.id, entry_2.id, "id");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.count, entry_2.count, "count");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.focus_count, entry_2.focus_count, "focus_count");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.time_focused, entry_2.time_focused, "time_focused");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.last_updated, entry_2.last_updated, "last_updated");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.offset, entry_2.offset, "offset");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.name, entry_2.name, "name");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.path, entry_2.path, "path");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.desktop_offset, entry_2.desktop_offset, "desktop_offset");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.next, entry_2.next, "next");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.session_id, entry_2.session_id, "session_id");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.desktop_info, entry_2.desktop_info, "desktop_info");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.size, entry_2.size, "size");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.fshooks, entry_2.fshooks, "fshooks");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.spwnd, entry_2.spwnd, "spwnd");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.windows, entry_2.windows, "windows");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.heap, entry_2.heap, "heap");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.limit, entry_2.limit, "limit");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.base, entry_2.base, "base");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.impscan_start_address, entry_2.impscan_start_address, "impscan_start_address");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.impscan_end_address, entry_2.impscan_end_address, "impscan_end_address");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.IAT, entry_2.IAT, "IAT");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.call, entry_2.call, "call");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.function_name_lower, entry_2.function_name_lower, "function_name_lower");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.offset_p, entry_2.offset_p, "offset_p");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.num_ptr, entry_2.num_ptr, "num_ptr");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.num_hnd, entry_2.num_hnd, "num_hnd");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.access, entry_2.access, "access");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.path_name, entry_2.path_name, "path_name");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.file_name, entry_2.file_name, "file_name");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.process_offset_V, entry_2.process_offset_V, "process_offset_V");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.module_base_address, entry_2.module_base_address, "module_base_address");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.process_offset_P_trimmed, entry_2.process_offset_P_trimmed, "process_offset_P_trimmed");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.module_base_address_trimmed, entry_2.module_base_address_trimmed, "module_base_address_trimmed");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.module_basse_address_trimmed, entry_2.module_basse_address_trimmed, "module_basse_address_trimmed");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, ""+entry_1.PID, ""+entry_2.PID, "PID");

									
						///////////////////////////////////////////////////////////////////////
						// File Attribute!
						///////////////////////////////////////////////////////////////////////
						//this.compare_file_attributes(node, INITIALIZATION_INDEX, entry_1.fle_attributes, entry_2.fle_attributes, VARIABLE_NAME + " - FILE ATTRIBUTE ");
						
						///////////////////////////////////////////////////////////////////////
						// check lists
						///////////////////////////////////////////////////////////////////////
						this.check_lists(INITIALIZATION_INDEX, variable_key_identifier, node, entry_1.list_details, entry_2.list_details, "list_details", false);
						this.check_lists(INITIALIZATION_INDEX, variable_key_identifier, node, entry_1.list_session_entries, entry_2.list_session_entries, "list_session_entries", false);

					}
					
					
															
				}

				///////////////////////////////////////////////////////////////////////
				// check for missing and modified
				///////////////////////////////////////////////////////////////////////
				for(String key : tree_1.keySet())
				{
					if(key == null || key.trim().equals(""))
						continue;


					//
					//procure nodes
					//
					entry_1 = tree_1.get(key);
					entry_2 = tree_2.get(key);  	 								

					//
					//validate entry
					//
					if(entry_1 == null && entry_2 == null)
						continue;
											

					//
					//set unique_storage_key and comparator values
					//
					try	{	unique_key_1 = entry_1.get_snapshot_analysis_key_VAD();	} catch(Exception e){unique_key_1 = null;}
					try	{	unique_key_2 = entry_2.get_snapshot_analysis_key_VAD();	} catch(Exception e){unique_key_2 = null;}

					try	{	comparator_value_1 = entry_1.get_snapshot_analysis_COMPARATOR_VALUE();	} catch(Exception e){comparator_value_1 = null;}
					try	{	comparator_value_2 = entry_2.get_snapshot_analysis_COMPARATOR_VALUE();	} catch(Exception e){comparator_value_2 = null;}

					//
					//check addition
					//
					if(entry_1 == null && entry_2 != null)
					{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " @ address [" + unique_key_2 + "]", null, comparator_value_2, null);
					}

					//
					//check missing
					//
					else if(entry_1 != null && entry_2 == null)
					{						
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " @ address [" + unique_key_1 + "]", comparator_value_1, null, null);
					}

					//
					//else, iterate and check each value
					//
					else
					{
						//
						//specify unique key
						//
						String variable_key_identifier = VARIABLE_NAME + " @ address " + unique_key_1 ;

						if(unique_key_1 == null || unique_key_1.toLowerCase().equals("not specified") || unique_key_1.toLowerCase().equals("unknown"))
							variable_key_identifier = VARIABLE_NAME + " @ address " + unique_key_2 + "";

						//
						//invoke compare routine on the data-transform
						//
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.session, entry_2.session, "session");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.handle, entry_2.handle, "handle");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.object, entry_2.object, "object");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.thread, entry_2.thread, "thread");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.process_details, entry_2.process_details, "process_details");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.nID, entry_2.nID, "nID");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.rate_ms, entry_2.rate_ms, "rate_ms");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.countdown_ms, entry_2.countdown_ms, "countdown_ms");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.function, entry_2.function, "function");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.type, entry_2.type, "type");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.callback, entry_2.callback, "callback");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.module_name, entry_2.module_name, "module_name");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.details, entry_2.details, "details");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.offset_v, entry_2.offset_v, "offset_v");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.due_time, entry_2.due_time, "due_time");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.period_ms, entry_2.period_ms, "period_ms");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.signaled, entry_2.signaled, "signaled");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.routine, entry_2.routine, "routine");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.start_address, entry_2.start_address, "start_address");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.end_address, entry_2.end_address, "end_address");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.date, entry_2.date, "date");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.time, entry_2.time, "time");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.reg_binary, entry_2.reg_binary, "reg_binary");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.raw_data_first_line, entry_2.raw_data_first_line, "raw_data_first_line");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.id, entry_2.id, "id");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.count, entry_2.count, "count");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.focus_count, entry_2.focus_count, "focus_count");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.time_focused, entry_2.time_focused, "time_focused");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.last_updated, entry_2.last_updated, "last_updated");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.offset, entry_2.offset, "offset");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.name, entry_2.name, "name");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.path, entry_2.path, "path");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.desktop_offset, entry_2.desktop_offset, "desktop_offset");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.next, entry_2.next, "next");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.session_id, entry_2.session_id, "session_id");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.desktop_info, entry_2.desktop_info, "desktop_info");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.size, entry_2.size, "size");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.fshooks, entry_2.fshooks, "fshooks");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.spwnd, entry_2.spwnd, "spwnd");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.windows, entry_2.windows, "windows");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.heap, entry_2.heap, "heap");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.limit, entry_2.limit, "limit");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.base, entry_2.base, "base");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.impscan_start_address, entry_2.impscan_start_address, "impscan_start_address");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.impscan_end_address, entry_2.impscan_end_address, "impscan_end_address");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.IAT, entry_2.IAT, "IAT");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.call, entry_2.call, "call");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.function_name_lower, entry_2.function_name_lower, "function_name_lower");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.offset_p, entry_2.offset_p, "offset_p");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.num_ptr, entry_2.num_ptr, "num_ptr");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.num_hnd, entry_2.num_hnd, "num_hnd");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.access, entry_2.access, "access");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.path_name, entry_2.path_name, "path_name");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.file_name, entry_2.file_name, "file_name");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.process_offset_V, entry_2.process_offset_V, "process_offset_V");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.module_base_address, entry_2.module_base_address, "module_base_address");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.process_offset_P_trimmed, entry_2.process_offset_P_trimmed, "process_offset_P_trimmed");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.module_base_address_trimmed, entry_2.module_base_address_trimmed, "module_base_address_trimmed");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.module_basse_address_trimmed, entry_2.module_basse_address_trimmed, "module_basse_address_trimmed");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, ""+entry_1.PID, ""+entry_2.PID, "PID");
						
						///////////////////////////////////////////////////////////////////////
						// File Attribute!
						///////////////////////////////////////////////////////////////////////
						//this.compare_file_attributes(node, INITIALIZATION_INDEX, process_1.fle_attributes, process_2.fle_attributes, VARIABLE_NAME + " - FILE ATTRIBUTE");
						
						
						///////////////////////////////////////////////////////////////////////
						// check lists
						///////////////////////////////////////////////////////////////////////
						this.check_lists(INITIALIZATION_INDEX, variable_key_identifier, node, entry_1.list_details, entry_2.list_details, "list_details", true);
						this.check_lists(INITIALIZATION_INDEX, variable_key_identifier, node, entry_1.list_session_entries, entry_2.list_session_entries, "list_session_entries", true);
					}														
				}
				
					
			}



			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_process_NODE_GENERIC", e);
		}

		return false;
	}




	/////////////////////////////////////////
	/////////////////////////
	///////////////
	/////


	/**
	 * special note: these API values are the dll	 api_hooks and not the API Hooks under each PROCESS
	 * @param process_1
	 * @param process_2
	 * @param INITIALIZATION_INDEX
	 * @param tree
	 * @param node_key
	 * @param ARTIFACT_TYPE
	 * @return
	 */
	public boolean analyze_process_my_VAD_INFO(Node_Process process_1, Node_Process process_2, int INITIALIZATION_INDEX, TreeMap<String, Node_Snapshot_Analysis_Artifact> tree, String node_key, String ARTIFACT_TYPE, String VARIABLE_NAME)
	{ 
		try
		{						
			//
			//procure
			//
			Node_Snapshot_Analysis_Artifact node = tree.get(node_key);

			//
			//initialize if necessary
			//
			if(node == null)
			{
				//use the instances to handle the comparison and building of the trees
				node = new Node_Snapshot_Analysis_Artifact(this, process_2.get_process_html_header(), ARTIFACT_TYPE);

				//adjust name if needed
				try
				{
					if(node.descriptor == null || node.descriptor.toLowerCase().trim().endsWith("unknown") && !process_1.get_process_html_header().toLowerCase().trim().endsWith("unknown"))
						node.descriptor = process_1.get_process_html_header();	
				}catch(Exception e){}				

				//set processes
				node.process_1 = process_1; 
				node.proces_2 = process_2;

				//init structures
				node.initialize_structures(INITIALIZATION_INDEX);

				//link node!
				tree.put(node_key,  node);				
			}



			//
			//update node's initialization vector
			//
			node.set_my_tree_pointers(INITIALIZATION_INDEX);

			//
			//initialize structure
			//			
			Node_Generic entry_1 = null, entry_2 = null;

			//
			//* * * ENSURE THESE VALUES ARE SET PROPERLY BELOW! * * * 
			//
			String comparator_value_1 = null, comparator_value_2 = null;
			String unique_key_1 = null, unique_key_2 = null;

			///////////////////////////////////////////////////////////////////////
			// check for addition and modified
			///////////////////////////////////////////////////////////////////////

			//
			//procure nodes
			//
			entry_1 = process_1.VAD;
			entry_2 = process_2.VAD; 								

			//
			//validate entry
			//
			if(entry_1 == null && entry_2 == null)
				return false;
			
			
			
			//
			//set unique_storage_key and comparator values
			//
			try	{	unique_key_1 = entry_1.get_snapshot_analysis_key_VAD();	} catch(Exception e){unique_key_1 = null;}
			try	{	unique_key_2 = entry_2.get_snapshot_analysis_key_VAD();	} catch(Exception e){unique_key_2 = null;}

			try	{	comparator_value_1 = entry_1.get_snapshot_analysis_COMPARATOR_VALUE().trim();	} catch(Exception e){comparator_value_1 = null;}
			try	{	comparator_value_2 = entry_2.get_snapshot_analysis_COMPARATOR_VALUE().trim();	} catch(Exception e){comparator_value_2 = null;}

			//
			//check entire addition
			//
			if(entry_1 == null && entry_2 != null)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " @ address [" +unique_key_2 + "]", null, comparator_value_2, null);
			}

			//
			//check entire missing
			//
			else if(entry_1 != null && entry_2 == null)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " @ address [" + unique_key_1 + "]", comparator_value_1, null, null);
			}

			//
			//else, iterate and check each value
			//
			else
			{
				//
				//specify unique key
				//
				String variable_key_identifier = VARIABLE_NAME + " @ address " + unique_key_2 + "" ;

				if(unique_key_2 == null || unique_key_2.toLowerCase().equals("not specified") || unique_key_2.toLowerCase().equals("unknown"))
					variable_key_identifier = VARIABLE_NAME + " @ address " + unique_key_1 + "";

				//
				//invoke compare routine on the data-transform
				//
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.session, entry_2.session, "session");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.handle, entry_2.handle, "handle");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.object, entry_2.object, "object");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.thread, entry_2.thread, "thread");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.process_details, entry_2.process_details, "process_details");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.nID, entry_2.nID, "nID");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.rate_ms, entry_2.rate_ms, "rate_ms");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.countdown_ms, entry_2.countdown_ms, "countdown_ms");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.function, entry_2.function, "function");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.type, entry_2.type, "type");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.callback, entry_2.callback, "callback");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.module_name, entry_2.module_name, "module_name");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.details, entry_2.details, "details");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.offset_v, entry_2.offset_v, "offset_v");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.due_time, entry_2.due_time, "due_time");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.period_ms, entry_2.period_ms, "period_ms");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.signaled, entry_2.signaled, "signaled");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.routine, entry_2.routine, "routine");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.start_address, entry_2.start_address, "start_address");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.end_address, entry_2.end_address, "end_address");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.date, entry_2.date, "date");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.time, entry_2.time, "time");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.reg_binary, entry_2.reg_binary, "reg_binary");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.raw_data_first_line, entry_2.raw_data_first_line, "raw_data_first_line");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.id, entry_2.id, "id");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.count, entry_2.count, "count");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.focus_count, entry_2.focus_count, "focus_count");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.time_focused, entry_2.time_focused, "time_focused");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.last_updated, entry_2.last_updated, "last_updated");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.offset, entry_2.offset, "offset");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.name, entry_2.name, "name");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.path, entry_2.path, "path");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.desktop_offset, entry_2.desktop_offset, "desktop_offset");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.next, entry_2.next, "next");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.session_id, entry_2.session_id, "session_id");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.desktop_info, entry_2.desktop_info, "desktop_info");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.size, entry_2.size, "size");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.fshooks, entry_2.fshooks, "fshooks");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.spwnd, entry_2.spwnd, "spwnd");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.windows, entry_2.windows, "windows");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.heap, entry_2.heap, "heap");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.limit, entry_2.limit, "limit");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.base, entry_2.base, "base");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.impscan_start_address, entry_2.impscan_start_address, "impscan_start_address");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.impscan_end_address, entry_2.impscan_end_address, "impscan_end_address");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.IAT, entry_2.IAT, "IAT");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.call, entry_2.call, "call");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.function_name_lower, entry_2.function_name_lower, "function_name_lower");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.offset_p, entry_2.offset_p, "offset_p");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.num_ptr, entry_2.num_ptr, "num_ptr");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.num_hnd, entry_2.num_hnd, "num_hnd");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.access, entry_2.access, "access");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.path_name, entry_2.path_name, "path_name");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.file_name, entry_2.file_name, "file_name");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.process_offset_V, entry_2.process_offset_V, "process_offset_V");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.module_base_address, entry_2.module_base_address, "module_base_address");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.process_offset_P_trimmed, entry_2.process_offset_P_trimmed, "process_offset_P_trimmed");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.module_base_address_trimmed, entry_2.module_base_address_trimmed, "module_base_address_trimmed");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.module_basse_address_trimmed, entry_2.module_basse_address_trimmed, "module_basse_address_trimmed");
				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, ""+entry_1.PID, ""+entry_2.PID, "PID");


				///////////////////////////////////////////////////////////////////////
				// File Attribute!
				///////////////////////////////////////////////////////////////////////
				//this.compare_file_attributes(node, INITIALIZATION_INDEX, entry_1.fle_attributes, entry_2.fle_attributes, VARIABLE_NAME + " - FILE ATTRIBUTE ");

				///////////////////////////////////////////////////////////////////////
				// check lists
				///////////////////////////////////////////////////////////////////////
				this.check_lists(INITIALIZATION_INDEX, variable_key_identifier, node, entry_1.list_details, entry_2.list_details, "list_details", false);
				this.check_lists(INITIALIZATION_INDEX, variable_key_identifier, node, entry_1.list_session_entries, entry_2.list_session_entries, "list_session_entries", false);
			}

			
			///////////////////////////////////////////////////////////////////////
			// check for missing and modified
			///////////////////////////////////////////////////////////////////////
//
//			//
//			//procure nodes
//			//
//			entry_1 = process_1.VAD;
//			entry_2 = process_2.VAD; 
			
				

//			//
//			//validate entry
//			//
//			if(entry_1 == null && entry_2 == null)
//			return false;;

//
//			//
//			//set unique_storage_key and comparator values
//			//
//			try	{	unique_key_1 = entry_1.get_snapshot_analysis_key_VAD();	} catch(Exception e){unique_key_1 = null;}
//			try	{	unique_key_2 = entry_2.get_snapshot_analysis_key_VAD();	} catch(Exception e){unique_key_2 = null;}
//
//			try	{	comparator_value_1 = entry_1.get_snapshot_analysis_COMPARATOR_VALUE();	} catch(Exception e){comparator_value_1 = null;}
//			try	{	comparator_value_2 = entry_2.get_snapshot_analysis_COMPARATOR_VALUE();	} catch(Exception e){comparator_value_2 = null;}
//
//			//
//			//check addition
//			//
//			if(entry_1 == null && entry_2 != null)
//			{
//				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " @ address [" + unique_key_2 + "]", null, comparator_value_2, null);
//			}
//
//			//
//			//check missing
//			//
//			else if(entry_1 != null && entry_2 == null)
//			{						
//				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " @ address [" + unique_key_1 + "]", comparator_value_1, null, null);
//			}
//
//			//
//			//else, iterate and check each value
//			//
//			else
//			{
//				//
//				//specify unique key
//				//
//				String variable_key_identifier = VARIABLE_NAME + " @ address " + unique_key_1 ;
//
//				if(unique_key_1 == null || unique_key_1.toLowerCase().equals("not specified") || unique_key_1.toLowerCase().equals("unknown"))
//					variable_key_identifier = VARIABLE_NAME + " @ address " + unique_key_2 + "";
//
//				//
//				//invoke compare routine on the data-transform
//				//
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.session, entry_2.session, "session");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.handle, entry_2.handle, "handle");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.object, entry_2.object, "object");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.thread, entry_2.thread, "thread");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.process_details, entry_2.process_details, "process_details");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.nID, entry_2.nID, "nID");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.rate_ms, entry_2.rate_ms, "rate_ms");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.countdown_ms, entry_2.countdown_ms, "countdown_ms");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.function, entry_2.function, "function");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.type, entry_2.type, "type");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.callback, entry_2.callback, "callback");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.module_name, entry_2.module_name, "module_name");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.details, entry_2.details, "details");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.offset_v, entry_2.offset_v, "offset_v");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.due_time, entry_2.due_time, "due_time");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.period_ms, entry_2.period_ms, "period_ms");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.signaled, entry_2.signaled, "signaled");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.routine, entry_2.routine, "routine");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.start_address, entry_2.start_address, "start_address");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.end_address, entry_2.end_address, "end_address");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.date, entry_2.date, "date");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.time, entry_2.time, "time");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.reg_binary, entry_2.reg_binary, "reg_binary");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.raw_data_first_line, entry_2.raw_data_first_line, "raw_data_first_line");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.id, entry_2.id, "id");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.count, entry_2.count, "count");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.focus_count, entry_2.focus_count, "focus_count");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.time_focused, entry_2.time_focused, "time_focused");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.last_updated, entry_2.last_updated, "last_updated");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.offset, entry_2.offset, "offset");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.name, entry_2.name, "name");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.path, entry_2.path, "path");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.desktop_offset, entry_2.desktop_offset, "desktop_offset");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.next, entry_2.next, "next");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.session_id, entry_2.session_id, "session_id");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.desktop_info, entry_2.desktop_info, "desktop_info");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.size, entry_2.size, "size");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.fshooks, entry_2.fshooks, "fshooks");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.spwnd, entry_2.spwnd, "spwnd");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.windows, entry_2.windows, "windows");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.heap, entry_2.heap, "heap");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.limit, entry_2.limit, "limit");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.base, entry_2.base, "base");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.impscan_start_address, entry_2.impscan_start_address, "impscan_start_address");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.impscan_end_address, entry_2.impscan_end_address, "impscan_end_address");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.IAT, entry_2.IAT, "IAT");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.call, entry_2.call, "call");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.function_name_lower, entry_2.function_name_lower, "function_name_lower");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.offset_p, entry_2.offset_p, "offset_p");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.num_ptr, entry_2.num_ptr, "num_ptr");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.num_hnd, entry_2.num_hnd, "num_hnd");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.access, entry_2.access, "access");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.path_name, entry_2.path_name, "path_name");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.file_name, entry_2.file_name, "file_name");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.process_offset_V, entry_2.process_offset_V, "process_offset_V");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.module_base_address, entry_2.module_base_address, "module_base_address");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.process_offset_P_trimmed, entry_2.process_offset_P_trimmed, "process_offset_P_trimmed");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.module_base_address_trimmed, entry_2.module_base_address_trimmed, "module_base_address_trimmed");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.module_basse_address_trimmed, entry_2.module_basse_address_trimmed, "module_basse_address_trimmed");
//				node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, ""+entry_1.PID, ""+entry_2.PID, "PID");
//
//				///////////////////////////////////////////////////////////////////////
//				// File Attribute!
//				///////////////////////////////////////////////////////////////////////
//				//this.compare_file_attributes(node, INITIALIZATION_INDEX, process_1.fle_attributes, process_2.fle_attributes, VARIABLE_NAME + " - FILE ATTRIBUTE");
//
//
//				///////////////////////////////////////////////////////////////////////
//				// check lists
//				///////////////////////////////////////////////////////////////////////
//				this.check_lists(INITIALIZATION_INDEX, variable_key_identifier, node, entry_1.list_details, entry_2.list_details, "list_details", true);
//				this.check_lists(INITIALIZATION_INDEX, variable_key_identifier, node, entry_1.list_session_entries, entry_2.list_session_entries, "list_session_entries", true);
//			}														
//

			



			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_process_MY_VAD_INFO", e, true);
		}

		return false;
	}




	/**
	 * special note: these API values are the dll	 api_hooks and not the API Hooks under each PROCESS
	 * @param process_1
	 * @param process_2
	 * @param INITIALIZATION_INDEX
	 * @param tree
	 * @param node_key
	 * @param ARTIFACT_TYPE
	 * @return
	 */
	public boolean analyze_process_DESKSCAN_PART_1(Node_Process process_1, Node_Process process_2, int INITIALIZATION_INDEX, TreeMap<String, Node_Snapshot_Analysis_Artifact> tree, String node_key, String ARTIFACT_TYPE, String VARIABLE_NAME)
	{ 
		try
		{						
			//
			//procure
			//
			Node_Snapshot_Analysis_Artifact node = tree.get(node_key);

			//
			//initialize if necessary
			//
			if(node == null)
			{
				//use the instances to handle the comparison and building of the trees
				node = new Node_Snapshot_Analysis_Artifact(this, process_2.get_process_html_header(), ARTIFACT_TYPE);

				//adjust name if needed
				try
				{
					if(node.descriptor == null || node.descriptor.toLowerCase().trim().endsWith("unknown") && !process_1.get_process_html_header().toLowerCase().trim().endsWith("unknown"))
						node.descriptor = process_1.get_process_html_header();	
				}catch(Exception e){}				

				//set processes
				node.process_1 = process_1; 
				node.proces_2 = process_2;

				//init structures
				node.initialize_structures(INITIALIZATION_INDEX);

				//link node!
				tree.put(node_key,  node);				
			}



			//
			//update node's initialization vector
			//
			node.set_my_tree_pointers(INITIALIZATION_INDEX);
			
			//
			//first, check overall deskscan structures
			//
			TreeMap<String, TreeMap<String, Node_Generic>> tree_1 = process_1.tree_deskscan;
			TreeMap<String, TreeMap<String, Node_Generic>> tree_2 = process_2.tree_deskscan; 
			
			
			//
			//compsre structures
			//
			if(tree_1 == null && tree_2 == null)
				return false;

			//
			//check addition
			//
			if(tree_1 == null && tree_2 != null)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data NOT specified", "[+] ENTIRE NEW " + VARIABLE_NAME + " STRUCTURE  ADDED!", null);				
				return true;
			}

			//
			//check missing
			//
			else if(tree_1 != null && tree_2 == null)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data specified", "[-] ENTIRE " + VARIABLE_NAME + " STRUCTURE MISSING!", null);				
				return true;
			}
			
			//
			//scan for additions
			//
			for(String key : tree_2.keySet())
			{
				TreeMap<String, Node_Generic> tree_deskscan_1 = tree_1.get(key);
				TreeMap<String, Node_Generic> tree_deskscan_2 = tree_2.get(key);
				
				this.analyze_process_DESKSCAN_PART_2(process_1, process_2, INITIALIZATION_INDEX, tree, node_key, ARTIFACT_TYPE, VARIABLE_NAME, node, tree_deskscan_1, tree_deskscan_2);
			}
			
			//
			//scan for missing
			//
			for(String key : tree_1.keySet())
			{
				TreeMap<String, Node_Generic> tree_deskscan_1 = tree_1.get(key);
				TreeMap<String, Node_Generic> tree_deskscan_2 = tree_2.get(key);
				
				this.analyze_process_DESKSCAN_PART_2(process_1, process_2, INITIALIZATION_INDEX, tree, node_key, ARTIFACT_TYPE, VARIABLE_NAME, node, tree_deskscan_1, tree_deskscan_2);
			}
			
			

			


			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_process_DESKSCAN_PART_1", e);
		}

		return false;
	}



	
	///////////////////////////////
	///////////////////
	///////////
	/**
	 * continuation mtd
	 * @param process_1
	 * @param process_2
	 * @param INITIALIZATION_INDEX
	 * @param tree
	 * @param node_key
	 * @param ARTIFACT_TYPE
	 * @param VARIABLE_NAME
	 * @param node
	 * @param tree_1
	 * @param tree_2
	 * @return
	 */
	public boolean analyze_process_DESKSCAN_PART_2(Node_Process process_1, Node_Process process_2, int INITIALIZATION_INDEX, TreeMap<String, Node_Snapshot_Analysis_Artifact> tree, String node_key, String ARTIFACT_TYPE, String VARIABLE_NAME, Node_Snapshot_Analysis_Artifact node, TreeMap<String, Node_Generic> tree_1, TreeMap<String, Node_Generic> tree_2)
	{
		try
		{
			//
			//initialize structure
			//			
			Node_Generic entry_1 = null, entry_2 = null;

			//
			//* * * ENSURE THESE VALUES ARE SET PROPERLY BELOW! * * * 
			//
			String comparator_value_1 = null, comparator_value_2 = null;
			String unique_key_1 = null, unique_key_2 = null;


			//
			//compsre structures
			//
			if(tree_1 == null && tree_2 == null)
				return false;

			//
			//check addition
			//
			if(tree_1 == null && tree_2 != null)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data NOT specified", "[+] ENTIRE NEW " + VARIABLE_NAME + " STRUCTURE  ADDED!", null);				
				return true;
			}

			//
			//check missing
			//
			else if(tree_1 != null && tree_2 == null)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data specified", "[-] ENTIRE " + VARIABLE_NAME + " STRUCTURE MISSING!", null);				
				return true;
			}

			//at this point, both trees are not null, check sizes for additional and missing

			//
			//check addition
			//
			if(tree_1.size() < 1 && tree_2.size() > 0)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data NOT specified", "[+] ENTIRE NEW " + VARIABLE_NAME + " STRUCTURE ADDED!", null);					
				return true;
			}

			//
			//check missing
			//
			else if(tree_1.size() > 0 && tree_2.size() < 1)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data specified", "[-] ENTIRE " + VARIABLE_NAME + " STRUCTURE MISSING!", null);				
				return true;
			}
			
			

			//
			//check structure entries
			//
			else
			{								
				///////////////////////////////////////////////////////////////////////
				// check for addition and modified
				///////////////////////////////////////////////////////////////////////
				for(String key : tree_2.keySet())
				{
					if(key == null || key.trim().equals(""))
						continue;

					//
					//procure nodes
					//
					entry_1 = tree_1.get(key);
					entry_2 = tree_2.get(key); 	 								

					//
					//validate entry
					//
					if(entry_1 == null && entry_2 == null)
						continue;
												

					//
					//set unique_storage_key and comparator values
					//
					try	{	unique_key_1 = entry_1.get_snapshot_analysis_key_DESKSCAN();	} catch(Exception e){unique_key_1 = null;}
					try	{	unique_key_2 = entry_2.get_snapshot_analysis_key_DESKSCAN();	} catch(Exception e){unique_key_2 = null;}

					try	{	comparator_value_1 = entry_1.get_snapshot_analysis_COMPARATOR_VALUE().trim();	} catch(Exception e){comparator_value_1 = null;}
					try	{	comparator_value_2 = entry_2.get_snapshot_analysis_COMPARATOR_VALUE().trim();	} catch(Exception e){comparator_value_2 = null;}

					
					if(unique_key_2 == null)
						unique_key_2 = unique_key_1;
					
					//
					//check entire addition
					//
					if(entry_1 == null && entry_2 != null)
					{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " @ address [" +unique_key_2 + "]", null, comparator_value_2, null);
					}

					//
					//check entire missing
					//
					else if(entry_1 != null && entry_2 == null)
					{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " @ address [" + unique_key_1 + "]", comparator_value_1, null, null);
					}

					//
					//else, iterate and check each value
					//
					else
					{
						//
						//specify unique key
						//
						String variable_key_identifier = VARIABLE_NAME + " @ address " + unique_key_2 + "" ;

						if(unique_key_2 == null || unique_key_2.toLowerCase().equals("not specified") || unique_key_2.toLowerCase().equals("unknown"))
							variable_key_identifier = VARIABLE_NAME + " @ address " + unique_key_1 + "";

						//
						//invoke compare routine on the data-transform
						//
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.session, entry_2.session, "session");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.handle, entry_2.handle, "handle");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.object, entry_2.object, "object");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.thread, entry_2.thread, "thread");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.process_details, entry_2.process_details, "process_details");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.nID, entry_2.nID, "nID");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.rate_ms, entry_2.rate_ms, "rate_ms");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.countdown_ms, entry_2.countdown_ms, "countdown_ms");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.function, entry_2.function, "function");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.type, entry_2.type, "type");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.callback, entry_2.callback, "callback");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.module_name, entry_2.module_name, "module_name");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.details, entry_2.details, "details");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.offset_v, entry_2.offset_v, "offset_v");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.due_time, entry_2.due_time, "due_time");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.period_ms, entry_2.period_ms, "period_ms");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.signaled, entry_2.signaled, "signaled");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.routine, entry_2.routine, "routine");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.start_address, entry_2.start_address, "start_address");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.end_address, entry_2.end_address, "end_address");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.date, entry_2.date, "date");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.time, entry_2.time, "time");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.reg_binary, entry_2.reg_binary, "reg_binary");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.raw_data_first_line, entry_2.raw_data_first_line, "raw_data_first_line");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.id, entry_2.id, "id");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.count, entry_2.count, "count");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.focus_count, entry_2.focus_count, "focus_count");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.time_focused, entry_2.time_focused, "time_focused");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.last_updated, entry_2.last_updated, "last_updated");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.offset, entry_2.offset, "offset");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.name, entry_2.name, "name");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.path, entry_2.path, "path");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.desktop_offset, entry_2.desktop_offset, "desktop_offset");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.next, entry_2.next, "next");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.session_id, entry_2.session_id, "session_id");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.desktop_info, entry_2.desktop_info, "desktop_info");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.size, entry_2.size, "size");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.fshooks, entry_2.fshooks, "fshooks");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.spwnd, entry_2.spwnd, "spwnd");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.windows, entry_2.windows, "windows");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.heap, entry_2.heap, "heap");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.limit, entry_2.limit, "limit");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.base, entry_2.base, "base");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.impscan_start_address, entry_2.impscan_start_address, "impscan_start_address");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.impscan_end_address, entry_2.impscan_end_address, "impscan_end_address");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.IAT, entry_2.IAT, "IAT");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.call, entry_2.call, "call");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.function_name_lower, entry_2.function_name_lower, "function_name_lower");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.offset_p, entry_2.offset_p, "offset_p");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.num_ptr, entry_2.num_ptr, "num_ptr");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.num_hnd, entry_2.num_hnd, "num_hnd");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.access, entry_2.access, "access");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.path_name, entry_2.path_name, "path_name");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.file_name, entry_2.file_name, "file_name");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.process_offset_V, entry_2.process_offset_V, "process_offset_V");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.module_base_address, entry_2.module_base_address, "module_base_address");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.process_offset_P_trimmed, entry_2.process_offset_P_trimmed, "process_offset_P_trimmed");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.module_base_address_trimmed, entry_2.module_base_address_trimmed, "module_base_address_trimmed");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.module_basse_address_trimmed, entry_2.module_basse_address_trimmed, "module_basse_address_trimmed");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, ""+entry_1.PID, ""+entry_2.PID, "PID");

									
						///////////////////////////////////////////////////////////////////////
						// File Attribute!
						///////////////////////////////////////////////////////////////////////
						//this.compare_file_attributes(node, INITIALIZATION_INDEX, entry_1.fle_attributes, entry_2.fle_attributes, VARIABLE_NAME + " - FILE ATTRIBUTE ");
						
						///////////////////////////////////////////////////////////////////////
						// check lists
						///////////////////////////////////////////////////////////////////////
						this.check_lists(INITIALIZATION_INDEX, variable_key_identifier, node, entry_1.list_details, entry_2.list_details, "list_details", false);
						this.check_lists(INITIALIZATION_INDEX, variable_key_identifier, node, entry_1.list_session_entries, entry_2.list_session_entries, "list_session_entries", false);

					}
					
					
															
				}

				///////////////////////////////////////////////////////////////////////
				// check for missing and modified
				///////////////////////////////////////////////////////////////////////
				for(String key : tree_1.keySet())
				{
					if(key == null || key.trim().equals(""))
						continue;


					//
					//procure nodes
					//
					entry_1 = tree_1.get(key);
					entry_2 = tree_2.get(key);  	 								

					//
					//validate entry
					//
					if(entry_1 == null && entry_2 == null)
						continue;
											

					//
					//set unique_storage_key and comparator values
					//
					try	{	unique_key_1 = entry_1.get_snapshot_analysis_key_VAD();	} catch(Exception e){unique_key_1 = null;}
					try	{	unique_key_2 = entry_2.get_snapshot_analysis_key_VAD();	} catch(Exception e){unique_key_2 = null;}

					try	{	comparator_value_1 = entry_1.get_snapshot_analysis_COMPARATOR_VALUE();	} catch(Exception e){comparator_value_1 = null;}
					try	{	comparator_value_2 = entry_2.get_snapshot_analysis_COMPARATOR_VALUE();	} catch(Exception e){comparator_value_2 = null;}

					//
					//check addition
					//
					if(entry_1 == null && entry_2 != null)
					{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " @ address [" + unique_key_2 + "]", null, comparator_value_2, null);
					}

					//
					//check missing
					//
					else if(entry_1 != null && entry_2 == null)
					{						
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " @ address [" + unique_key_1 + "]", comparator_value_1, null, null);
					}

					//
					//else, iterate and check each value
					//
					else
					{
						//
						//specify unique key
						//
						String variable_key_identifier = VARIABLE_NAME + " @ address " + unique_key_1 ;

						if(unique_key_1 == null || unique_key_1.toLowerCase().equals("not specified") || unique_key_1.toLowerCase().equals("unknown"))
							variable_key_identifier = VARIABLE_NAME + " @ address " + unique_key_2 + "";

						//
						//invoke compare routine on the data-transform
						//
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.session, entry_2.session, "session");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.handle, entry_2.handle, "handle");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.object, entry_2.object, "object");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.thread, entry_2.thread, "thread");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.process_details, entry_2.process_details, "process_details");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.nID, entry_2.nID, "nID");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.rate_ms, entry_2.rate_ms, "rate_ms");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.countdown_ms, entry_2.countdown_ms, "countdown_ms");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.function, entry_2.function, "function");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.type, entry_2.type, "type");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.callback, entry_2.callback, "callback");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.module_name, entry_2.module_name, "module_name");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.details, entry_2.details, "details");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.offset_v, entry_2.offset_v, "offset_v");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.due_time, entry_2.due_time, "due_time");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.period_ms, entry_2.period_ms, "period_ms");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.signaled, entry_2.signaled, "signaled");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.routine, entry_2.routine, "routine");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.start_address, entry_2.start_address, "start_address");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.end_address, entry_2.end_address, "end_address");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.date, entry_2.date, "date");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.time, entry_2.time, "time");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.reg_binary, entry_2.reg_binary, "reg_binary");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.raw_data_first_line, entry_2.raw_data_first_line, "raw_data_first_line");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.id, entry_2.id, "id");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.count, entry_2.count, "count");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.focus_count, entry_2.focus_count, "focus_count");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.time_focused, entry_2.time_focused, "time_focused");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.last_updated, entry_2.last_updated, "last_updated");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.offset, entry_2.offset, "offset");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.name, entry_2.name, "name");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.path, entry_2.path, "path");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.desktop_offset, entry_2.desktop_offset, "desktop_offset");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.next, entry_2.next, "next");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.session_id, entry_2.session_id, "session_id");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.desktop_info, entry_2.desktop_info, "desktop_info");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.size, entry_2.size, "size");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.fshooks, entry_2.fshooks, "fshooks");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.spwnd, entry_2.spwnd, "spwnd");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.windows, entry_2.windows, "windows");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.heap, entry_2.heap, "heap");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.limit, entry_2.limit, "limit");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.base, entry_2.base, "base");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.impscan_start_address, entry_2.impscan_start_address, "impscan_start_address");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.impscan_end_address, entry_2.impscan_end_address, "impscan_end_address");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.IAT, entry_2.IAT, "IAT");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.call, entry_2.call, "call");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.function_name_lower, entry_2.function_name_lower, "function_name_lower");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.offset_p, entry_2.offset_p, "offset_p");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.num_ptr, entry_2.num_ptr, "num_ptr");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.num_hnd, entry_2.num_hnd, "num_hnd");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.access, entry_2.access, "access");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.path_name, entry_2.path_name, "path_name");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.file_name, entry_2.file_name, "file_name");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.process_offset_V, entry_2.process_offset_V, "process_offset_V");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.module_base_address, entry_2.module_base_address, "module_base_address");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.process_offset_P_trimmed, entry_2.process_offset_P_trimmed, "process_offset_P_trimmed");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.module_base_address_trimmed, entry_2.module_base_address_trimmed, "module_base_address_trimmed");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, entry_1.module_basse_address_trimmed, entry_2.module_basse_address_trimmed, "module_basse_address_trimmed");
						node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, ""+entry_1.PID, ""+entry_2.PID, "PID");
						
						///////////////////////////////////////////////////////////////////////
						// File Attribute!
						///////////////////////////////////////////////////////////////////////
						//this.compare_file_attributes(node, INITIALIZATION_INDEX, process_1.fle_attributes, process_2.fle_attributes, VARIABLE_NAME + " - FILE ATTRIBUTE");
						
						
						///////////////////////////////////////////////////////////////////////
						// check lists
						///////////////////////////////////////////////////////////////////////
						this.check_lists(INITIALIZATION_INDEX, variable_key_identifier, node, entry_1.list_details, entry_2.list_details, "list_details", true);
						this.check_lists(INITIALIZATION_INDEX, variable_key_identifier, node, entry_1.list_session_entries, entry_2.list_session_entries, "list_session_entries", true);
					}														
				}
				
					
			}

			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_process_DESKSCAN_PART_2", e);
		}
		
		return false;
	}




	
	public boolean analyze_process_IMPSCAN(Node_Process process_1, Node_Process process_2, int INITIALIZATION_INDEX, TreeMap<String, Node_Snapshot_Analysis_Artifact> tree, String node_key, String ARTIFACT_TYPE)
	{
		try
		{						
			//
			//procure
			//
			Node_Snapshot_Analysis_Artifact node = tree.get(node_key);
			
			//
			//initialize if necessary
			//
			if(node == null)
			{
				//use the instances to handle the comparison and building of the trees
				node = new Node_Snapshot_Analysis_Artifact(this, process_2.get_process_html_header(), ARTIFACT_TYPE);
				
				//adjust name if needed
				try
				{
					if(node.descriptor == null || node.descriptor.toLowerCase().trim().endsWith("unknown") && !process_1.get_process_html_header().toLowerCase().trim().endsWith("unknown"))
						node.descriptor = process_1.get_process_html_header();	
				}catch(Exception e){}				
				
				//set processes
				node.process_1 = process_1; 
				node.proces_2 = process_2;
				
				//init structures
				node.initialize_structures(INITIALIZATION_INDEX);
				
				//link node!
				tree.put(node_key,  node);				
			}

			
			
			//
			//update node's initialization vector
			//
			node.set_my_tree_pointers(INITIALIZATION_INDEX);
				
			//
			//initialize structure
			//
			String VARIABLE_NAME = "ImpScan";
			TreeMap<String, Node_DLL_Container_Impscan> tree_1 = process_1.tree_impscan_DLL_containers, tree_2 = process_2.tree_impscan_DLL_containers;
			Node_DLL_Container_Impscan container_1 = null, container_2 = null;
			
			//
			//* * * ENSURE THESE VALUES ARE SET PROPERLY BELOW! * * * 
			//
			String comparator_value_1 = null, comparator_value_2 = null;
			String module_name_1 = null, module_name_2 = null;
			
						
			//
			//compsre structures
			//
			if(tree_1 == null && tree_2 == null)
				return false;
			
			//
			//check addition
			//
			if(tree_1 == null && tree_2 != null)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data NOT specified", "[+] ENTIRE NEW " + VARIABLE_NAME + " STRUCTURE  ADDED!", null);				
				return true;
			}
			
			//
			//check missing
			//
			else if(tree_1 != null && tree_2 == null)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data specified", "[-] ENTIRE " + VARIABLE_NAME + " STRUCTURE MISSING!", null);				
				return true;
			}
			
			//at this point, both trees are not null, check sizes for additional and missing
			
			//
			//check addition
			//
			if(tree_1.size() < 1 && tree_2.size() > 0)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data NOT specified", "[+] ENTIRE NEW " + VARIABLE_NAME + " STRUCTURE ADDED!", null);					
				return true;
			}
			
			//
			//check missing
			//
			else if(tree_1.size() > 0 && tree_2.size() < 1)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "entry data specified", "[-] ENTIRE " + VARIABLE_NAME + " STRUCTURE MISSING!", null);				
				return true;
			}
			
			//
			//check structure entries
			//
			else
			{								
				///////////////////////////////////////////////////////////////////////
				// check for addition and modified
				///////////////////////////////////////////////////////////////////////
				for(String module_name : tree_2.keySet())
				{
					if(module_name == null || module_name.trim().equals(""))
						continue;
															
					//
					//procure nodes
					//
					container_1 = tree_1.get(module_name);
					container_2 = tree_2.get(module_name); 	 	 								

					//
					//validate entry
					//
					if(container_1 == null && container_2 == null)
						continue;
																		
					
					//
					//set unique_storage_key and comparator values
					//
					try	{	module_name_1 = container_1.get_snapshot_analysis_key();	} catch(Exception e){module_name_1 = null;}
					try	{	module_name_2 = container_2.get_snapshot_analysis_key();	} catch(Exception e){module_name_2 = null;}
															
					//
					//check addition
					//
					if(container_1 == null && container_2 != null)
					{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " module [" +module_name_2 + "]", null, comparator_value_2, null);
					}
					
					//
					//check missing
					//
					else if(container_1 != null && container_2 == null)
					{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " module [" + module_name_1 + "]", comparator_value_1, null, null);
					}
					
					//
					//else, iterate and check each value 
					//
					else
					{
						
						///////////////////////////////////////////////////////////////////////
						// check for ADDITION and modified
						///////////////////////////////////////////////////////////////////////		
						
						TreeMap<String, Node_Generic> tree_import_functions = container_2.tree_impscan_functions;						
						Node_Generic import_function_1 = null, import_function_2 = null;
						int index = -1;
						
						if(tree_import_functions != null && tree_import_functions.size() > 0)
						{
							//we have module, now iterate through the IAT values
							for(String iat_address : tree_import_functions.keySet())
							{
								
								++index;
								
								if(iat_address == null || iat_address.trim().equals(""))
									continue;
								
								try	{	import_function_1 = container_1.tree_impscan_functions.get(iat_address);	} catch(Exception e){comparator_value_1 = null;}
								try	{	import_function_2 = container_2.tree_impscan_functions.get(iat_address);	} catch(Exception e){comparator_value_1 = null;}
								
								try	{	comparator_value_1 = import_function_1.get_snapshot_analysis_COMPARATOR_VALUE_IMPSCAN();	} catch(Exception e){comparator_value_1 = null;}
								try	{	comparator_value_2 = import_function_2.get_snapshot_analysis_COMPARATOR_VALUE_IMPSCAN();	} catch(Exception e){comparator_value_2 = null;}
								
								//
								//specify unique key
								//
								String variable_key_identifier = VARIABLE_NAME + " module " + module_name_2 + "" ;
								
								if(module_name_2 == null || module_name_2.toLowerCase().equals("not specified") || module_name_2.toLowerCase().equals("unknown"))
									variable_key_identifier = VARIABLE_NAME + " module " + module_name_1 + "";
								
								String function_name = "";
								
								try	{	function_name = import_function_2.get_comparator_key().trim();	}	catch(Exception e){	try	{ function_name = import_function_1.get_comparator_key().trim();	} catch(Exception ee){function_name = "index: " + index;}}	
								
								//
								//invoke compare routine on the data-transform
								//
								node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, comparator_value_1, comparator_value_2, function_name);
							}
						}//end if
						
						
						///////////////////////////////////////////////////////////////////////
						// check for missing and modified
						///////////////////////////////////////////////////////////////////////						
						
						tree_import_functions = container_1.tree_impscan_functions;						
						index = -1;
						
						if(tree_import_functions != null && tree_import_functions.size() > 0)
						{
							//we have module, now iterate through the IAT values
							for(String iat_address : tree_import_functions.keySet())
							{
								
								++index;
								
								if(iat_address == null || iat_address.trim().equals(""))
									continue;
								
								try	{	import_function_1 = container_1.tree_impscan_functions.get(iat_address);	} catch(Exception e){comparator_value_1 = null;}
								try	{	import_function_2 = container_2.tree_impscan_functions.get(iat_address);	} catch(Exception e){comparator_value_1 = null;}
								
								try	{	comparator_value_1 = import_function_1.get_snapshot_analysis_COMPARATOR_VALUE_IMPSCAN();	} catch(Exception e){comparator_value_1 = null;}
								try	{	comparator_value_2 = import_function_2.get_snapshot_analysis_COMPARATOR_VALUE_IMPSCAN();	} catch(Exception e){comparator_value_2 = null;}
								
								//
								//specify unique key
								//
								String variable_key_identifier = VARIABLE_NAME + " module " + module_name_1 + "" ;
								
								if(module_name_1 == null || module_name_1.toLowerCase().equals("not specified") || module_name_2.toLowerCase().equals("unknown"))
									variable_key_identifier = VARIABLE_NAME + " module " + module_name_2 + "";
								
								String function_name = "";
								
								try	{	function_name = import_function_1.get_comparator_key().trim();	}	catch(Exception e){	try	{ function_name = import_function_2.get_comparator_key().trim();	} catch(Exception ee){function_name = "index: " + index;}}	
								
								//
								//invoke compare routine on the data-transform
								//
								node.compare_artifacts(INITIALIZATION_INDEX, variable_key_identifier, comparator_value_1, comparator_value_2, function_name);
							}
						}//end if
						
						
						
					}//end else														
				}
				
				
			}
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_process_IMPSCAN", e);
		}
		
		return false;
	}



	
	
	public boolean compare_file_description_DEEP_INSPECTION(Node_Snapshot_Analysis_Artifact node, int INITIALIZATION_INDEX, Node_Generic node_1, Node_Generic node_2, String VARIABLE_NAME)
	{
		try
		{
			if((node_1 == null && node_2 == null) || node == null)
				return false;
			
			//initialize respective tree structure
			node.set_my_tree_pointers(INITIALIZATION_INDEX);
			
			if(node_1 == null && node_2 != null)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "file data NOT specified", "[+] ENTIRE NEW STRUCTURE ADDED!", null);				
				return true;
			}
			
			else if(node_1 != null && node_2 == null)
			{
				node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME, "file data specified", "[-] ENTIRE STRUCTURE MISSING!", null);				
				return true;
			}
			
			else//check each data point
			{				
				switch(INITIALIZATION_INDEX)
				{
				 	case Node_Snapshot_Analysis_Artifact.initialization_index_filescan:
				 	{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [offset_p]",  node_1.offset_p, node_2.offset_p, null);
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [num_ptr]",  node_1.num_ptr, node_2.num_ptr, null);
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [num_hnd]",  node_1.num_hnd, node_2.num_hnd, null);
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [access]",  node_1.access, node_2.access, null);
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [path]",  node_1.path, node_2.path, null);
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [additional_details]",  node_1.additional_details, node_2.additional_details, null);
	
						break;
				 	}
				 	
				 	case Node_Snapshot_Analysis_Artifact.initialization_index_mftparser:
				 	{
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [create_date]",  node_1.create_date, node_2.create_date, null);
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [modified_date]",  node_1.modified_date, node_2.modified_date, null);
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [mft_altered_date]",  node_1.mft_altered_date, node_2.mft_altered_date, null);
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [access_date]",  node_1.access_date, node_2.access_date, null);
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [path]",  node_1.path, node_2.path, null);
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [entry_attr]",  node_1.entry_attr, node_2.entry_attr, null);
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [extension]",  node_1.extension, node_2.extension, null);
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [additional_details]",  node_1.additional_details, node_2.additional_details, null);
						
						break;
				 	}
				 	
				 	case Node_Snapshot_Analysis_Artifact.initialization_index_shellbags:
				 	{
				 		node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [modified_date]",  node_1.modified_date, node_2.modified_date, null);
				 		node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [create_date]",  node_1.create_date, node_2.create_date, null);
				 		node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [access_date]",  node_1.access_date, node_2.access_date, null);
				 		node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [last_updated]",  node_1.last_updated, node_2.last_updated, null);
				 		node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [file_name]",  node_1.file_name, node_2.file_name, null);
				 		node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [unicode_name]",  node_1.unicode_name, node_2.unicode_name, null);
				 		node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [file_attr]",  node_1.file_attr, node_2.file_attr, null);
				 		node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [shellbag_value]",  node_1.shellbag_value, node_2.shellbag_value, null);
				 		node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [registry_name]",  node_1.registry_name, node_2.registry_name, null);
				 		node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [registry_key_name]",  node_1.registry_key_name, node_2.registry_key_name, null);
				 		node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [shellbag_type]",  node_1.shellbag_type, node_2.shellbag_type, null);
				 		node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [additional_details]",  node_1.additional_details, node_2.additional_details, null);
				 		node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [guid_description]",  node_1.guid_description, node_2.guid_description, null);
				 		node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [guid]",  node_1.guid, node_2.guid, null);
				 		node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [folder_ids]",  node_1.folder_ids, node_2.folder_ids, null);
				 		node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [entry_type]",  node_1.entry_type, node_2.entry_type, null);
				 		node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [mru]",  node_1.mru, node_2.mru, null);
				 		node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [path]",  node_1.path, node_2.path, null);

				 		break;
				 	}
	
				 	case Node_Snapshot_Analysis_Artifact.initialization_index_shimcache:
				 	{
				 		node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [last_updated]",  node_1.last_updated, node_2.last_updated, null);
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [path]",  node_1.path, node_2.path, null);
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [additional_details]",  node_1.additional_details, node_2.additional_details, null);
		
						break;
				 	}
						
				 	case Node_Snapshot_Analysis_Artifact.initialization_index_timeliner:
				 	{
				 		node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [time]",  node_1.time, node_2.time, null);
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [key_name]",  node_1.key_name, node_2.key_name, null);
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [value]",  node_1.value, node_2.value, null);
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [details]",  node_1.details, node_2.details, null);
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [additional_details]",  node_1.additional_details, node_2.additional_details, null);
						
				 		break;
				 	}

				 	case Node_Snapshot_Analysis_Artifact.initialization_index_userassist_specific_entries:
				 	{
				 		node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [last_updated]",  node_1.last_updated, node_2.last_updated, null);
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [reg_binary]",  node_1.reg_binary, node_2.reg_binary, null);
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [time_focused]",  node_1.time_focused, node_2.time_focused, null);
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [count]",  node_1.count, node_2.count, null);
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [focus_count]",  node_1.focus_count, node_2.focus_count, null);
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [registry_name]",  node_1.registry_name, node_2.registry_name, null);
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [path]",  node_1.path, node_2.path, null);
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [reg_data_first_line]",  node_1.reg_data_first_line, node_2.reg_data_first_line, null);
						node.compare_artifacts(INITIALIZATION_INDEX, VARIABLE_NAME + " [additional_details]",  node_1.additional_details, node_2.additional_details, null);
				 	
				 		break;
				 	}
	
					default:
					{
						driver.directive("Unknown initialization vector received in compare_file_description_DEEP_INSPECTION mtd in " + this.myClassName);
						break;
					}
					
				}
			
				
				
			}
			
			
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "compare_file_description_DEEP_INSPECTION", e);
		}				
		
		return false;
	}
	



	public boolean analyze_structure_mftparser(int INITIALIZATION_INDEX, String type, TreeMap<String, Node_Generic> tree_1, TreeMap<String, Node_Generic> tree_2, TreeMap<String, String> tree_addition, TreeMap<String, String> tree_missing, TreeMap<String, String> tree_MODIFIED)
	{
		try
		{
			TreeMap<String, String>tree_KEY_SET = new TreeMap<String, String>();
			
			String key = "";
			
			if((tree_1 == null || tree_1.size() < 1) && tree_2 != null && tree_2.size() > 0)
			{
				tree_addition.put(type, "Entirely new " + type + " detected!");
				return true;
			}
			
			else if((tree_1 != null && tree_1.size() > 0) && (tree_2 == null || tree_2.size() < 0))
			{
				tree_missing.put(type, "Entirely missing " + type + " detected!");
				return true;
			}
			
			TreeMap<String, Node_Generic> tree_analysis_1 = new TreeMap<String, Node_Generic>();
			TreeMap<String, Node_Generic> tree_analysis_2 = new TreeMap<String, Node_Generic>();
			
			for(Node_Generic generic : tree_1.values())
			{
				try
				{
					//
					//identify key
					//
					key = generic.path;
					
					//populate keyset
					tree_KEY_SET.put(key, null);
					
					//populate tree via new index
					tree_analysis_1.put(key, generic);
				}
				catch(Exception e)
				{
					continue;
				}								
			}
			
			for(Node_Generic generic : tree_2.values())
			{
				try
				{
					//
					//identify key
					//
					key = generic.path;
					
					//populate keyset
					tree_KEY_SET.put(key, null);
					
					//populate tree via new index
					tree_analysis_2.put(key, generic);
				}
				catch(Exception e)
				{
					continue;
				}								
			}
			
			Node_Generic node_1 = null, node_2 = null;
			String value_1 = null, value_2 = null;
			
			for(String key_name : tree_KEY_SET.keySet())
			{
				value_1 = null;
				value_2 = null;		
				
				node_1 = null; 
				node_2 = null;
				
				try	{	node_1 = tree_analysis_1.get(key_name);  value_1 = node_1.path;}	catch(Exception e ) { value_1 = null;	}
				try	{	node_2 = tree_analysis_2.get(key_name);  value_2 = node_2.path;}	catch(Exception e ) { value_2 = null;	}
				
				if(value_1 == null && value_2 == null)
					continue;
								
				
				//addition
				if((value_1 == null || value_1.length() < 1) && (value_2 != null && value_2.length() > 0))					
				{
					tree_addition.put(key_name, "Entirely new entry detected");
					continue;
				}
				
				//missing
				else if((value_1 != null && value_1.length() > 0) && (value_2 == null || value_2.length() < 0))					
				{
					tree_missing.put(key_name, "Entire entry is missing");
					continue;
				}
				else
				{
					//iterate through the values					
					compare_artifacts(INITIALIZATION_INDEX, type, key_name, "create_date",  node_1.create_date, node_2.create_date, tree_addition, tree_missing, tree_MODIFIED);
					compare_artifacts(INITIALIZATION_INDEX, type, key_name, "modified_date",  node_1.modified_date, node_2.modified_date, tree_addition, tree_missing, tree_MODIFIED);
					compare_artifacts(INITIALIZATION_INDEX, type, key_name, "mft_altered_date",  node_1.mft_altered_date, node_2.mft_altered_date, tree_addition, tree_missing, tree_MODIFIED);
					compare_artifacts(INITIALIZATION_INDEX, type, key_name, "access_date",  node_1.access_date, node_2.access_date, tree_addition, tree_missing, tree_MODIFIED);
					//compare_artifacts(INITIALIZATION_INDEX, type, key_name, "path",  node_1.path, node_2.path, tree_addition, tree_missing, tree_MODIFIED);
					compare_artifacts(INITIALIZATION_INDEX, type, key_name, "entry_attr",  node_1.entry_attr, node_2.entry_attr, tree_addition, tree_missing, tree_MODIFIED);
					compare_artifacts(INITIALIZATION_INDEX, type, key_name, "extension",  node_1.extension, node_2.extension, tree_addition, tree_missing, tree_MODIFIED);
					compare_artifacts(INITIALIZATION_INDEX, type, key_name, "additional_details",  node_1.additional_details, node_2.additional_details, tree_addition, tree_missing, tree_MODIFIED);

				}
				
				
				
			}
				
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_structure_mftparser", e);
		}
		
		return false;
	}
	
	
	public boolean analyze_structure_shellbags(int INITIALIZATION_INDEX, String type, TreeMap<String, Node_Generic> tree_1, TreeMap<String, Node_Generic> tree_2, TreeMap<String, String> tree_addition, TreeMap<String, String> tree_missing, TreeMap<String, String> tree_MODIFIED)
	{
		try
		{
			TreeMap<String, String>tree_KEY_SET = new TreeMap<String, String>();
			
			String key = "";
			
			if((tree_1 == null || tree_1.size() < 1) && tree_2 != null && tree_2.size() > 0)
			{
				tree_addition.put(type, "Entirely new " + type + " detected!");
				return true;
			}
			
			else if((tree_1 != null && tree_1.size() > 0) && (tree_2 == null || tree_2.size() < 0))
			{
				tree_missing.put(type, "Entirely missing " + type + " detected!");
				return true;
			}
			
			TreeMap<String, Node_Generic> tree_analysis_1 = new TreeMap<String, Node_Generic>();
			TreeMap<String, Node_Generic> tree_analysis_2 = new TreeMap<String, Node_Generic>();
			
			int shellbag_type = 0;
			
			//determine type!
			for(Node_Generic no : tree_1.values())
			{
				try
				{
					shellbag_type = Integer.parseInt(no.shellbag_type.trim());
					break;
				}
				catch(Exception e)
				{
					continue;
				}							
			}
			
			for(Node_Generic generic : tree_1.values())
			{
				try
				{
					//
					//identify key
					//
					switch(shellbag_type)
					{
						case 1:
						{
							key = generic.unicode_name;
							break;
						}
						case 2:
						{
							key = generic.guid_description;
							break;
						}
						case 3:
						{
							key = generic.path;
							break;
						}
						
						case 4:
						{
							key = generic.path;
							break;
						}
						default:
						{
							driver.directive("NOTE: I was not able to determine shellbag type in " + myClassName + " analyze_structure_shellbags mtd");
							break;
						}
					}
					
					
					//populate keyset
					tree_KEY_SET.put(key, null);
					
					//populate tree via new index
					tree_analysis_1.put(key, generic);
				}
				catch(Exception e)
				{
					continue;
				}								
			}
			
			for(Node_Generic generic : tree_2.values())
			{
				try
				{
					//
					//identify key
					//
					switch(shellbag_type)
					{
						case 1:
						{
							key = generic.unicode_name;
							break;
						}
						case 2:
						{
							key = generic.guid_description;
							break;
						}
						case 3:
						{
							key = generic.path;
							break;
						}
						
						case 4:
						{
							key = generic.path;
							break;
						}
						default:
						{
							driver.directive("NOTE: I was not able to determine shellbag type in " + myClassName + " analyze_structure_shellbags mtd");
							break;
						}
					}
					
					//populate keyset
					tree_KEY_SET.put(key, null);
					
					//populate tree via new index
					tree_analysis_2.put(key, generic);
				}
				catch(Exception e)
				{
					continue;
				}								
			}
			
			Node_Generic node_1 = null, node_2 = null;
			String value_1 = null, value_2 = null;
			
			for(String key_name : tree_KEY_SET.keySet())
			{
				value_1 = null;
				value_2 = null;		
				
				node_1 = null; 
				node_2 = null;
				
				try	{	node_1 = tree_analysis_1.get(key_name);  value_1 = node_1.value;}	catch(Exception e ) { value_1 = null;	}
				try	{	node_2 = tree_analysis_2.get(key_name);  value_2 = node_2.value;}	catch(Exception e ) { value_2 = null;	}
				
				if(value_1 == null && value_2 == null)
					continue;
								
				
				//addition
				if((value_1 == null || value_1.length() < 1) && (value_2 != null && value_2.length() > 0))					
				{
					tree_addition.put(key_name, "Entirely new [shellbag type " + shellbag_type + "] entry detected");
					continue;
				}
				
				//missing
				else if((value_1 != null && value_1.length() > 0) && (value_2 == null || value_2.length() < 0))					
				{
					tree_missing.put(key_name, "Entire [shellbag type " + shellbag_type + "] entry is missing");
					continue;
				}
				else
				{
					//iterate through the values					
					compare_artifacts(INITIALIZATION_INDEX, type, key_name, "modified_date [type " + shellbag_type + "]",  node_1.modified_date, node_2.modified_date, tree_addition, tree_missing, tree_MODIFIED);
					compare_artifacts(INITIALIZATION_INDEX, type, key_name, "create_date [type " + shellbag_type + "]",  node_1.create_date, node_2.create_date, tree_addition, tree_missing, tree_MODIFIED);
					compare_artifacts(INITIALIZATION_INDEX, type, key_name, "access_date [type " + shellbag_type + "]",  node_1.access_date, node_2.access_date, tree_addition, tree_missing, tree_MODIFIED);
					compare_artifacts(INITIALIZATION_INDEX, type, key_name, "last_updated [type " + shellbag_type + "]",  node_1.last_updated, node_2.last_updated, tree_addition, tree_missing, tree_MODIFIED);
					compare_artifacts(INITIALIZATION_INDEX, type, key_name, "file_name [type " + shellbag_type + "]",  node_1.file_name, node_2.file_name, tree_addition, tree_missing, tree_MODIFIED);
					compare_artifacts(INITIALIZATION_INDEX, type, key_name, "unicode_name [type " + shellbag_type + "]",  node_1.unicode_name, node_2.unicode_name, tree_addition, tree_missing, tree_MODIFIED);
					compare_artifacts(INITIALIZATION_INDEX, type, key_name, "file_attr [type " + shellbag_type + "]",  node_1.file_attr, node_2.file_attr, tree_addition, tree_missing, tree_MODIFIED);
					compare_artifacts(INITIALIZATION_INDEX, type, key_name, "shellbag_value [type " + shellbag_type + "]",  node_1.shellbag_value, node_2.shellbag_value, tree_addition, tree_missing, tree_MODIFIED);
					compare_artifacts(INITIALIZATION_INDEX, type, key_name, "registry_name [type " + shellbag_type + "]",  node_1.registry_name, node_2.registry_name, tree_addition, tree_missing, tree_MODIFIED);
					compare_artifacts(INITIALIZATION_INDEX, type, key_name, "registry_key_name [type " + shellbag_type + "]",  node_1.registry_key_name, node_2.registry_key_name, tree_addition, tree_missing, tree_MODIFIED);
					compare_artifacts(INITIALIZATION_INDEX, type, key_name, "shellbag_type [type " + shellbag_type + "]",  node_1.shellbag_type, node_2.shellbag_type, tree_addition, tree_missing, tree_MODIFIED);
					compare_artifacts(INITIALIZATION_INDEX, type, key_name, "additional_details [type " + shellbag_type + "]",  node_1.additional_details, node_2.additional_details, tree_addition, tree_missing, tree_MODIFIED);
					compare_artifacts(INITIALIZATION_INDEX, type, key_name, "guid_description [type " + shellbag_type + "]",  node_1.guid_description, node_2.guid_description, tree_addition, tree_missing, tree_MODIFIED);
					compare_artifacts(INITIALIZATION_INDEX, type, key_name, "guid [type " + shellbag_type + "]",  node_1.guid, node_2.guid, tree_addition, tree_missing, tree_MODIFIED);
					compare_artifacts(INITIALIZATION_INDEX, type, key_name, "folder_ids [type " + shellbag_type + "]",  node_1.folder_ids, node_2.folder_ids, tree_addition, tree_missing, tree_MODIFIED);
					compare_artifacts(INITIALIZATION_INDEX, type, key_name, "entry_type [type " + shellbag_type + "]",  node_1.entry_type, node_2.entry_type, tree_addition, tree_missing, tree_MODIFIED);
					compare_artifacts(INITIALIZATION_INDEX, type, key_name, "mru [type " + shellbag_type + "]",  node_1.mru, node_2.mru, tree_addition, tree_missing, tree_MODIFIED);
					compare_artifacts(INITIALIZATION_INDEX, type, key_name, "path [type " + shellbag_type + "]",  node_1.path, node_2.path, tree_addition, tree_missing, tree_MODIFIED);
				}
				
				
				
			}
				
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_structure_shellbags", e);
		}
		
		return false;
	}
	
	public boolean analyze_structure_shimcache(int INITIALIZATION_INDEX, String type, TreeMap<String, Node_Generic> tree_1, TreeMap<String, Node_Generic> tree_2, TreeMap<String, String> tree_addition, TreeMap<String, String> tree_missing, TreeMap<String, String> tree_MODIFIED)
	{
		try
		{
			TreeMap<String, String>tree_KEY_SET = new TreeMap<String, String>();
			
			String key = "";
			
			if((tree_1 == null || tree_1.size() < 1) && tree_2 != null && tree_2.size() > 0)
			{
				tree_addition.put(type, "Entirely new " + type + " detected!");
				return true;
			}
			
			else if((tree_1 != null && tree_1.size() > 0) && (tree_2 == null || tree_2.size() < 0))
			{
				tree_missing.put(type, "Entirely missing " + type + " detected!");
				return true;
			}
			
			TreeMap<String, Node_Generic> tree_analysis_1 = new TreeMap<String, Node_Generic>();
			TreeMap<String, Node_Generic> tree_analysis_2 = new TreeMap<String, Node_Generic>();
			
			for(Node_Generic generic : tree_1.values())
			{
				try
				{
					//
					//identify key
					//
					key = generic.path;
					
					//populate keyset
					tree_KEY_SET.put(key, null);
					
					//populate tree via new index
					tree_analysis_1.put(key, generic);
				}
				catch(Exception e)
				{
					continue;
				}								
			}
			
			for(Node_Generic generic : tree_2.values())
			{
				try
				{
					//
					//identify key
					//
					key = generic.path;
					
					//populate keyset
					tree_KEY_SET.put(key, null);
					
					//populate tree via new index
					tree_analysis_2.put(key, generic);
				}
				catch(Exception e)
				{
					continue;
				}								
			}
			
			Node_Generic node_1 = null, node_2 = null;
			String value_1 = null, value_2 = null;
			
			for(String key_name : tree_KEY_SET.keySet())
			{
				value_1 = null;
				value_2 = null;		
				
				node_1 = null; 
				node_2 = null;
				
				try	{	node_1 = tree_analysis_1.get(key_name);  value_1 = node_1.path;}	catch(Exception e ) { value_1 = null;	}
				try	{	node_2 = tree_analysis_2.get(key_name);  value_2 = node_2.path;}	catch(Exception e ) { value_2 = null;	}
				
				if(value_1 == null && value_2 == null)
					continue;
								
				
				//addition
				if((value_1 == null || value_1.length() < 1) && (value_2 != null && value_2.length() > 0))					
				{
					tree_addition.put(key_name, "Entirely new entry detected");
					continue;
				}
				
				//missing
				else if((value_1 != null && value_1.length() > 0) && (value_2 == null || value_2.length() < 0))					
				{
					tree_missing.put(key_name, "Entire entry is missing");
					continue;
				}
				else
				{
					//iterate through the values					
					compare_artifacts(INITIALIZATION_INDEX, type, key_name, "last_updated",  node_1.last_updated, node_2.last_updated, tree_addition, tree_missing, tree_MODIFIED);
					//compare_artifacts(INITIALIZATION_INDEX, type, key_name, "path",  node_1.path, node_2.path, tree_addition, tree_missing, tree_MODIFIED);
					compare_artifacts(INITIALIZATION_INDEX, type, key_name, "additional_details",  node_1.additional_details, node_2.additional_details, tree_addition, tree_missing, tree_MODIFIED);

				}
				
				
				
			}
				
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_structure_shimcache", e);
		}
		
		return false;
	}
	

	public boolean analyze_structure_timeliner(int INITIALIZATION_INDEX, String type, TreeMap<String, Node_Generic> tree_1, TreeMap<String, Node_Generic> tree_2, TreeMap<String, String> tree_addition, TreeMap<String, String> tree_missing, TreeMap<String, String> tree_MODIFIED)
	{
		try
		{
			TreeMap<String, String>tree_KEY_SET = new TreeMap<String, String>();
			
			String key = "";
			
			if((tree_1 == null || tree_1.size() < 1) && tree_2 != null && tree_2.size() > 0)
			{
				tree_addition.put(type, "Entirely new " + type + " detected!");
				return true;
			}
			
			else if((tree_1 != null && tree_1.size() > 0) && (tree_2 == null || tree_2.size() < 0))
			{
				tree_missing.put(type, "Entirely missing " + type + " detected!");
				return true;
			}
			
			TreeMap<String, Node_Generic> tree_analysis_1 = new TreeMap<String, Node_Generic>();
			TreeMap<String, Node_Generic> tree_analysis_2 = new TreeMap<String, Node_Generic>();
			
			for(Node_Generic generic : tree_1.values())
			{
				try
				{
					//
					//identify key
					//
					key = generic.key_name + " " + generic.value + " " + generic.details;
					
					//populate keyset
					tree_KEY_SET.put(key, null);
					
					//populate tree via new index
					tree_analysis_1.put(key, generic);
				}
				catch(Exception e)
				{
					continue;
				}								
			}
			
			for(Node_Generic generic : tree_2.values())
			{
				try
				{
					//
					//identify key
					//
					key = generic.key_name + " " + generic.value + " " + generic.details;
					
					//populate keyset
					tree_KEY_SET.put(key, null);
					
					//populate tree via new index
					tree_analysis_2.put(key, generic);
				}
				catch(Exception e)
				{
					continue;
				}								
			}
			
			Node_Generic node_1 = null, node_2 = null;
			String value_1 = null, value_2 = null;
			
			for(String key_name : tree_KEY_SET.keySet())
			{
				value_1 = null;
				value_2 = null;		
				
				node_1 = null; 
				node_2 = null;
				
				try	{	node_1 = tree_analysis_1.get(key_name);  value_1 = node_1.value;}	catch(Exception e ) { value_1 = null;	}
				try	{	node_2 = tree_analysis_2.get(key_name);  value_2 = node_2.value;}	catch(Exception e ) { value_2 = null;	}
				
				if(value_1 == null && value_2 == null)
					continue;
								
				
				//addition
				if((value_1 == null || value_1.length() < 1) && (value_2 != null && value_2.length() > 0))					
				{
					tree_addition.put(key_name, "Entirely new entry detected");
					continue;
				}
				
				//missing
				else if((value_1 != null && value_1.length() > 0) && (value_2 == null || value_2.length() < 0))					
				{
					tree_missing.put(key_name, "Entire entry is missing");
					continue;
				}
				else
				{										
					//iterate through the values
					
					String time_1 = null, time_2 = null;
					String additional_details_1 = null, additional_details_2 = null;
					
					if(node_1 != null)
					{
						time_1 = node_1.time;
						additional_details_1 = node_1.additional_details;
					}
					
					if(node_2 != null)
					{
						time_2 = node_2.time;
						additional_details_2 = node_2.additional_details;
					}
					
					compare_artifacts(INITIALIZATION_INDEX, type, key_name, "time",  time_1, time_2, tree_addition, tree_missing, tree_MODIFIED);
					//compare_artifacts(INITIALIZATION_INDEX, type, key_name, "key_name",  node_1.key_name, node_2.key_name, tree_addition, tree_missing, tree_MODIFIED);
					//compare_artifacts(INITIALIZATION_INDEX, type, key_name, "value",  node_1.value, node_2.value, tree_addition, tree_missing, tree_MODIFIED);
					//compare_artifacts(INITIALIZATION_INDEX, type, key_name, "details",  node_1.details, node_2.details, tree_addition, tree_missing, tree_MODIFIED);
					compare_artifacts(INITIALIZATION_INDEX, type, key_name, "additional_details",  additional_details_1, additional_details_2, tree_addition, tree_missing, tree_MODIFIED);
				}
				
				
				
			}
				
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_structure_timeliner", e, false);
		}
		
		return false;
	}
	
	public boolean analyze_structure_userassist_specific_entries(int INITIALIZATION_INDEX, String type, TreeMap<String, Node_Generic> tree_1, TreeMap<String, Node_Generic> tree_2, TreeMap<String, String> tree_addition, TreeMap<String, String> tree_missing, TreeMap<String, String> tree_MODIFIED)
	{
		try
		{
			TreeMap<String, String>tree_KEY_SET = new TreeMap<String, String>();
			
			String key = "";
			
			if((tree_1 == null || tree_1.size() < 1) && tree_2 != null && tree_2.size() > 0)
			{
				tree_addition.put(type, "Entirely new " + type + " detected!");
				return true;
			}
			
			else if((tree_1 != null && tree_1.size() > 0) && (tree_2 == null || tree_2.size() < 0))
			{
				tree_missing.put(type, "Entirely missing " + type + " detected!");
				return true;
			}
			
			TreeMap<String, Node_Generic> tree_analysis_1 = new TreeMap<String, Node_Generic>();
			TreeMap<String, Node_Generic> tree_analysis_2 = new TreeMap<String, Node_Generic>();
			
			for(Node_Generic generic : tree_1.values())
			{
				try
				{
					//
					//identify key
					//
					key = generic.reg_binary;
					
					//populate keyset
					tree_KEY_SET.put(key, null);
					
					//populate tree via new index
					tree_analysis_1.put(key, generic);
				}
				catch(Exception e)
				{
					continue;
				}								
			}
			
			for(Node_Generic generic : tree_2.values())
			{
				try
				{
					//
					//identify key
					//
					key = generic.reg_binary;
					
					//populate keyset
					tree_KEY_SET.put(key, null);
					
					//populate tree via new index
					tree_analysis_2.put(key, generic);
				}
				catch(Exception e)
				{
					continue;
				}								
			}
			
			Node_Generic node_1 = null, node_2 = null;
			String value_1 = null, value_2 = null;
			
			for(String key_name : tree_KEY_SET.keySet())
			{
				value_1 = null;
				value_2 = null;		
				
				node_1 = null; 
				node_2 = null;
				
				try	{	node_1 = tree_analysis_1.get(key_name);  value_1 = node_1.value;}	catch(Exception e ) { value_1 = null;	}
				try	{	node_2 = tree_analysis_2.get(key_name);  value_2 = node_2.value;}	catch(Exception e ) { value_2 = null;	}
				
				if(value_1 == null && value_2 == null)
					continue;
								
				
				//addition
				if((value_1 == null || value_1.length() < 1) && (value_2 != null && value_2.length() > 0))					
				{
					tree_addition.put(key_name, "Entirely new entry detected");
					continue;
				}
				
				//missing
				else if((value_1 != null && value_1.length() > 0) && (value_2 == null || value_2.length() < 0))					
				{
					tree_missing.put(key_name, "Entire entry is missing");
					continue;
				}
				else
				{										
					//iterate through the values			
					
					compare_artifacts(INITIALIZATION_INDEX, type, key_name, "last_updated",  node_1.last_updated, node_2.last_updated, tree_addition, tree_missing, tree_MODIFIED);
					//compare_artifacts(INITIALIZATION_INDEX, type, key_name, "reg_binary",  node_1.reg_binary, node_2.reg_binary, tree_addition, tree_missing, tree_MODIFIED);
					compare_artifacts(INITIALIZATION_INDEX, type, key_name, "time_focused",  node_1.time_focused, node_2.time_focused, tree_addition, tree_missing, tree_MODIFIED);
					compare_artifacts(INITIALIZATION_INDEX, type, key_name, "count",  node_1.count, node_2.count, tree_addition, tree_missing, tree_MODIFIED);
					compare_artifacts(INITIALIZATION_INDEX, type, key_name, "focus_count",  node_1.focus_count, node_2.focus_count, tree_addition, tree_missing, tree_MODIFIED);
					compare_artifacts(INITIALIZATION_INDEX, type, key_name, "registry_name",  node_1.registry_name, node_2.registry_name, tree_addition, tree_missing, tree_MODIFIED);
					compare_artifacts(INITIALIZATION_INDEX, type, key_name, "path",  node_1.path, node_2.path, tree_addition, tree_missing, tree_MODIFIED);
					compare_artifacts(INITIALIZATION_INDEX, type, key_name, "reg_data_first_line",  node_1.reg_data_first_line, node_2.reg_data_first_line, tree_addition, tree_missing, tree_MODIFIED);
					compare_artifacts(INITIALIZATION_INDEX, type, key_name, "additional_details",  node_1.additional_details, node_2.additional_details, tree_addition, tree_missing, tree_MODIFIED);
						

				}
				
				
				
			}
				
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_structure_userassist_specific_entries", e);
		}
		
		return false;
	}
	
	
	
	
	
	





}
