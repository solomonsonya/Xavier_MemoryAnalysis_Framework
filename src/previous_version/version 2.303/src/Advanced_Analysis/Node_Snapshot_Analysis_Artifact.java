/**
 * Purpose of this class is to capture an artifact type: e.g. Process  and the changes captured between the artifact type e.g. additional DLL detected, etc 
 * 
 * @author Solomon Sonya
 */

package Advanced_Analysis;

import Driver.*;
import java.util.*;

public class Node_Snapshot_Analysis_Artifact 
{
	public static volatile Driver driver = new Driver();
	public static final String myClassName = "Node_Snapshot_Analysis_Artifact";

	/**message a change occurred in this top node such that we will print entries for add, missing, and/or modified*/
	public volatile boolean MODIFICATION_DETECTED = false;
	
	public volatile Snapshot_Manifest_Analysis director = null;
	
	public volatile Node_Snapshot_Analysis_Artifact parent = null;
	
	public volatile int my_tree_initialization_index = -1;
	
	
	/**e.g., my_vad_info */
	public volatile String variable_name = null;
	
	/**e.g., [4] System Idle Process */
	public volatile String descriptor = null;		
	
	/**Given dll	 path	 C:\Windows\WinSxS\amd64_microsoft.windows.common-controls_6595b64144ccf1df_5.82.7601.17514_none_a4d6a923711520a9\COMCTL32.dll as key, short_descriptor == COMCTL32.dll*/
	public volatile String short_descriptor = null;
	
	/** this is the value from snapshot 1*/
	public volatile String value_1 = null;
	
	/** this is the value from snapshot 2*/
	public volatile String value_2 = null;
	
	/** this is how we'll know to store this artifact, e.g. 476 (i.e. PID 476) - the unique key for the tree*/
	public volatile String key = null;
		
	/**addition, missing, or modified tree dictated by the comparison function*/
	public volatile String tree = null;
	
	
	
	public volatile Node_Process 	process_1 = null, 	proces_2 = null;
	public volatile Node_DLL 		dll_1 = null, 		dll_2 = null;
	public volatile Node_Driver 	driver_1 = null, 	driver_2 = null;
	public volatile Node_Generic 	node_generic_file_1 = null, 	node_generic_file_2 = null;
	
	/**pointer to respective tree initialized by constructor*/
	public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_addition = null;
	
	/**pointer to respective tree initialized by constructor*/
	public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_missing = null;
	
	/**pointer to respective tree initialized by constructor*/
	public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_MODIFIED = null;
	
	//initialization indices
	public static final int initialization_index_process_particulars = 0;
	public static final int initialization_index_my_vad_info = 1;
	public static final int initialization_index_netstat = 2;
	public static final int initialization_index_handles = 3;
	public static final int initialization_index_privs = 4;
	public static final int initialization_index_svcscan = 5;
	public static final int initialization_index_sids = 6;
	public static final int initialization_index_malfind = 7;
	public static final int initialization_index_threads = 8;
	public static final int initialization_index_gdi_timers = 9;
	public static final int initialization_index_api_hooks = 10;
	public static final int initialization_index_vad_info = 11;
	public static final int initialization_index_deskscan = 12;
	public static final int initialization_index_list_cmd_scan = 13;
	public static final int initialization_index_tree_cmdscan_consoles = 14;
	public static final int initialization_index_envars = 15;
	public static final int initialization_index_import_functions = 16;
	public static final int initialization_index_my_module_description = 17;
	public static final int initialization_index_fle_attributes = 18;
	
	public static final int initialization_index_dll = 19;
	public static final int initialization_index_driver = 20;
	public static final int initialization_index_driver_irp = 21;
	public static final int initialization_index_callbacks = 22;
	public static final int initialization_index_timers = 23;
	public static final int initialization_index_unloaded_modules = 24;
	
	public static final int initialization_index_filescan = 25;
	public static final int initialization_index_mftparser = 26;
	public static final int initialization_index_timeliner = 27;
	public static final int initialization_index_userassist_specific_entries = 28;
	public static final int initialization_index_shellbags = 29;
	public static final int initialization_index_shimcache = 30;
	
	
	
	
	public static final String ARTIFACT_TYPE_PROCESS = "Process";
	public static final String ARTIFACT_TYPE_DLL = "DLL";
	public static final String ARTIFACT_TYPE_DRIVER = "Driver";
	public static final String ARTIFACT_TYPE_DRIVER_IRP = "Driver IRP";
	public static final String ARTIFACT_TYPE_CALLBACKS = "Callback";
	public static final String ARTIFACT_TYPE_TIMERS = "Timer";
	public static final String ARTIFACT_TYPE_UNLOADED_MODULES = "Unloaded Module"; 
	
	public static final String ARTIFACT_TYPE_filescan = "Files";
	public static final String ARTIFACT_TYPE_mftparser = "MFT Entries"; 
	public static final String ARTIFACT_TYPE_timeliner = "Timeliner"; 
	public static final String ARTIFACT_TYPE_userassist_specific_entries = "User Assist Specific Entries"; 
	public static final String ARTIFACT_TYPE_shellbags = "shellBags"; 
	public static final String ARTIFACT_TYPE_shimcache = "Shimcache"; 
	
	
	
	
	
	
	/**e.g., process, dll, driver, etc*/
	public volatile String my_artifact_type = null;

	
	public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_addition_process_particulars = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_missing_process_particulars = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_MODIFIED_process_particulars = null;
	public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_addition_my_module_description = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_missing_my_module_description = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_MODIFIED_my_module_description = null;
	public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_addition_fle_attributes = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_missing_fle_attributes = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_MODIFIED_fle_attributes = null;
	public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_addition_my_vad_info = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_missing_my_vad_info = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_MODIFIED_my_vad_info = null;
	public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_addition_netstat = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_missing_netstat = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_MODIFIED_netstat = null;
	public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_addition_handles = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_missing_handles = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_MODIFIED_handles = null;
	public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_addition_privs = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_missing_privs = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_MODIFIED_privs = null;
	public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_addition_svcscan = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_missing_svcscan = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_MODIFIED_svcscan = null;
	public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_addition_sids = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_missing_sids = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_MODIFIED_sids = null;
	public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_addition_malfind = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_missing_malfind = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_MODIFIED_malfind = null;
	public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_addition_threads = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_missing_threads = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_MODIFIED_threads = null;
	public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_addition_gdi_timers = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_missing_gdi_timers = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_MODIFIED_gdi_timers = null;
	public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_addition_api_hooks = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_missing_api_hooks = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_MODIFIED_api_hooks = null;
	public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_addition_vad_info = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_missing_vad_info = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_MODIFIED_vad_info = null;
	public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_addition_deskscan = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_missing_deskscan = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_MODIFIED_deskscan = null;
	public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_addition_list_cmd_scan = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_missing_list_cmd_scan = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_MODIFIED_list_cmd_scan = null;
	public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_addition_tree_cmdscan_consoles = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_missing_tree_cmdscan_consoles = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_MODIFIED_tree_cmdscan_consoles = null;
	public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_addition_envars = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_missing_envars = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_MODIFIED_envars = null;
	public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_addition_import_functions = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_missing_import_functions = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_MODIFIED_import_functions = null;

	public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_addition_dll = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_missing_dll = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_MODIFIED_dll = null;
	public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_addition_driver = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_missing_driver = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_MODIFIED_driver = null;
	public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_addition_driver_irp = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_missing_driver_irp = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_MODIFIED_driver_irp = null;
	public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_addition_callback = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_missing_callback = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_MODIFIED_callback = null;
	public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_addition_timers = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_missing_timers = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_MODIFIED_timers = null;
	public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_addition_unloaded_modules = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_missing_unloaded_modules = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_MODIFIED_unloaded_modules = null;
	
	public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_addition_filescan = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_missing_filescan = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_MODIFIED_filescan = null;
	public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_addition_mftparser = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_missing_mftparser = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_MODIFIED_mftparser = null;
	public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_addition_timeliner = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_missing_timeliner = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_MODIFIED_timeliner = null;
	public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_addition_userassist_specific_entries = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_missing_userassist_specific_entries = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_MODIFIED_userassist_specific_entries = null;
	public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_addition_shellbags = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_missing_shellbags = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_MODIFIED_shellbags = null;
	public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_addition_shimcache = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_missing_shimcache = null;  public volatile TreeMap<String, Node_Snapshot_Analysis_Artifact> tree_MODIFIED_shimcache = null;

	
	
	
	/**
	 * Use this one for a Process, DLL, Driver, etc that holds trees of other components to be compared.
	 * @param TREE_INITIALIZATION_INDEX - describes which trees to initialize and by nature, which ARTIFACT_TYPE this node belongs to e.g. process, dll,driver, etc 
	 * @param DESCRIPTOR - e.g., [4] System Idle Process 
	 * @param DIRECTOR - Analysis director
	 * @param ARTIFACT_TYPE - specifies if we're dealing with a process, dll, driver, etc
	 */
	public Node_Snapshot_Analysis_Artifact(Snapshot_Manifest_Analysis DIRECTOR, String DESCRIPTOR, String ARTIFACT_TYPE)
	{
		try
		{
			director = DIRECTOR;				
			descriptor = DESCRIPTOR;
			my_artifact_type = ARTIFACT_TYPE;
						
			//initialize_structures(TREE_INITIALIZATION_INDEX);
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1");
		}
		
	}
	
	
	/**
	 * Use this one to compare filescan, mftparser, timeliner, shimcache, shellbags, etc
	 * */
	public Node_Snapshot_Analysis_Artifact(Snapshot_Manifest_Analysis DIRECTOR, int initialization_vector, String ARTIFACT_TYPE)
	{
		try
		{
			director = DIRECTOR;	
			this.my_artifact_type = ARTIFACT_TYPE;
			
			this.my_tree_initialization_index = initialization_vector;
			
			this.set_my_tree_pointers(initialization_vector);						
						
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1");
		}
		
	}
	
	
	
	
	
	/**
	 * @param VARIABLE_NAME - e.g., my_vad_info 
	 * @param VALUE_1 - this is the value from snapshot 1
	 * @param VALUE_2- this is the value from snapshot 2
	 * @param KEY - this is how we'll know to store this artifact, e.g. 476 (i.e. PID 476) - the unique key for the tree
	 * @param TREE - this is the particular tree (addition, missin, or modified) to add these values to
	 */
	public Node_Snapshot_Analysis_Artifact(Node_Snapshot_Analysis_Artifact PARENT, String VARIABLE_NAME, String VALUE_1, String VALUE_2, String KEY, TreeMap<String, Node_Snapshot_Analysis_Artifact> TREE)
	{
		try
		{
			parent = PARENT;
			variable_name = VARIABLE_NAME; 
			value_1 = VALUE_1;
			value_2 = VALUE_2;						
			key = KEY;
						
			if(value_1 == null || value_1.trim().equals(""))
				value_1 = "not specified";
			
			if(value_2 == null || value_2.trim().equals(""))
				value_2 = "not specified";
			
			TREE.put(key,  this);
			
			//indicate modification occured (add, missing, modified)
			if(PARENT != null)
				PARENT.MODIFICATION_DETECTED = true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1");
		}
		
	}
	
	public boolean compare_artifacts(int INITIALIZATION_INDEX, String VARIABLE_NAME, String value_1, String value_2, String specific_variable_description)
	{
		try
		{
			if(value_1 == null && value_2 == null)
				return false;
									
			if(specific_variable_description != null && specific_variable_description.length() > 0)
				VARIABLE_NAME = VARIABLE_NAME + " variable name [" + specific_variable_description + "]";
			
			//initialize respective tree structure
			set_my_tree_pointers(INITIALIZATION_INDEX);
			
			//normalize
			if(value_1 == null)
				value_1 = "";
			if(value_2 == null)
				value_2 = "";
			
			//trim
			String value_1_lower = value_1.toLowerCase().trim();
			String value_2_lower = value_2.toLowerCase().trim();
			
			//addition
			if(value_2_lower.length() > 0 && value_1_lower.length() < 1)
			{
				Node_Snapshot_Analysis_Artifact add = new Node_Snapshot_Analysis_Artifact(this, VARIABLE_NAME, value_1, value_2, VARIABLE_NAME, this.tree_addition);				
				return true;
			}
			
			//missing
			else if(value_1_lower.length() > 0 && value_2_lower.length() < 1)
			{
				Node_Snapshot_Analysis_Artifact missing = new Node_Snapshot_Analysis_Artifact(this, VARIABLE_NAME, value_1, value_2, VARIABLE_NAME, this.tree_missing);				
				return true;
			}
			
			//modified
			else if(!value_1_lower.equals(value_2_lower))
			{
				Node_Snapshot_Analysis_Artifact MODIFIED = new Node_Snapshot_Analysis_Artifact(this, VARIABLE_NAME, value_1, value_2, VARIABLE_NAME, this.tree_MODIFIED);
				return true;
			}
			
			//owt, fall through, the values equaled each other
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "compare_artifacts", e);
		}
		
		return false;		
	}
	
	
	
	
	
	
	public boolean initialize_structures(int TREE_INITIALIZATION_INDEX)
	{
		try
		{
			switch(TREE_INITIALIZATION_INDEX)
			{
				case initialization_index_process_particulars:
				{
					if(tree_addition_process_particulars == null) tree_addition_process_particulars = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_process_particulars == null) tree_missing_process_particulars = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_process_particulars == null) tree_MODIFIED_process_particulars = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();
					
					//tree_addition_process_particulars = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_missing_process_particulars = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_MODIFIED_process_particulars = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();
					
					
					break;
				}
				
				case initialization_index_my_module_description:
				{
					if(tree_addition_my_module_description == null) tree_addition_my_module_description = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_my_module_description == null) tree_missing_my_module_description = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_my_module_description == null) tree_MODIFIED_my_module_description = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					//tree_addition_my_module_description = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_missing_my_module_description = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_MODIFIED_my_module_description = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();
					
					break;
				}
				
				case initialization_index_fle_attributes:
				{
					if(tree_addition_fle_attributes == null) tree_addition_fle_attributes = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_fle_attributes == null) tree_missing_fle_attributes = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_fle_attributes == null) tree_MODIFIED_fle_attributes = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					//tree_addition_fle_attributes = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_missing_fle_attributes = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_MODIFIED_fle_attributes = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					break;					
				}
	
				case initialization_index_my_vad_info:
				{
					if(tree_addition_my_vad_info == null) tree_addition_my_vad_info = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_my_vad_info == null) tree_missing_my_vad_info = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_my_vad_info == null) tree_MODIFIED_my_vad_info = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					//tree_addition_my_vad_info = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_missing_my_vad_info = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_MODIFIED_my_vad_info = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();


					break;
				}
	
				case initialization_index_netstat:
				{
					if(tree_addition_netstat == null) tree_addition_netstat = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_netstat == null) tree_missing_netstat = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_netstat == null) tree_MODIFIED_netstat = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					//tree_addition_netstat = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_missing_netstat = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_MODIFIED_netstat = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();
					
					
					break;
				}
	
				case initialization_index_handles:
				{
					if(tree_addition_handles == null) tree_addition_handles = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_handles == null) tree_missing_handles = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_handles == null) tree_MODIFIED_handles = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					//tree_addition_handles = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_missing_handles = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_MODIFIED_handles = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();
					
					
					break;
				}
	
				case initialization_index_privs:
				{
					if(tree_addition_privs == null) tree_addition_privs = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_privs == null) tree_missing_privs = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_privs == null) tree_MODIFIED_privs = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					//tree_addition_privs = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_missing_privs = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_MODIFIED_privs = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();
				
					
					break;
				}
	
				case initialization_index_svcscan:
				{
					if(tree_addition_svcscan == null) tree_addition_svcscan = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_svcscan == null) tree_missing_svcscan = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_svcscan == null) tree_MODIFIED_svcscan = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					//tree_addition_svcscan = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_missing_svcscan = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_MODIFIED_svcscan = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();
					
					
					break;
				}
	
				case initialization_index_sids:
				{
					if(tree_addition_sids == null) tree_addition_sids = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_sids == null) tree_missing_sids = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_sids == null) tree_MODIFIED_sids = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					//tree_addition_sids = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_missing_sids = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_MODIFIED_sids = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();
					
					
					break;
				}
	
				case initialization_index_malfind:
				{
					if(tree_addition_malfind == null) tree_addition_malfind = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_malfind == null) tree_missing_malfind = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_malfind == null) tree_MODIFIED_malfind = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					//tree_addition_malfind = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_missing_malfind = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_MODIFIED_malfind = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					
					break;
				}
	
				case initialization_index_threads:
				{
					if(tree_addition_threads == null) tree_addition_threads = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_threads == null) tree_missing_threads = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_threads == null) tree_MODIFIED_threads = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					//tree_addition_threads = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_missing_threads = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_MODIFIED_threads = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					
					break;
				}
	
				case initialization_index_gdi_timers:
				{
					if(tree_addition_gdi_timers == null) tree_addition_gdi_timers = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_gdi_timers == null) tree_missing_gdi_timers = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_gdi_timers == null) tree_MODIFIED_gdi_timers = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					//tree_addition_gdi_timers = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_missing_gdi_timers = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_MODIFIED_gdi_timers = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					
					break;
				}
	
				case initialization_index_api_hooks:
				{
					if(tree_addition_api_hooks == null) tree_addition_api_hooks = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_api_hooks == null) tree_missing_api_hooks = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_api_hooks == null) tree_MODIFIED_api_hooks = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					//tree_addition_api_hooks = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_missing_api_hooks = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_MODIFIED_api_hooks = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					
					break;
				}
	
				case initialization_index_vad_info:
				{
					if(tree_addition_vad_info == null) tree_addition_vad_info = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_vad_info == null) tree_missing_vad_info = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_vad_info == null) tree_MODIFIED_vad_info = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					//tree_addition_vad_info = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_missing_vad_info = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_MODIFIED_vad_info = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					
					break;
				}
	
				case initialization_index_deskscan:
				{
					if(tree_addition_deskscan == null) tree_addition_deskscan = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_deskscan == null) tree_missing_deskscan = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_deskscan == null) tree_MODIFIED_deskscan = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					//tree_addition_deskscan = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_missing_deskscan = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_MODIFIED_deskscan = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					
					break;
				}
	
				case initialization_index_list_cmd_scan:
				{
					if(tree_addition_list_cmd_scan == null) tree_addition_list_cmd_scan = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_list_cmd_scan == null) tree_missing_list_cmd_scan = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_list_cmd_scan == null) tree_MODIFIED_list_cmd_scan = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					//tree_addition_list_cmd_scan = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_missing_list_cmd_scan = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_MODIFIED_list_cmd_scan = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					
					break;
				}
	
				case initialization_index_tree_cmdscan_consoles:
				{
					if(tree_addition_tree_cmdscan_consoles == null) tree_addition_tree_cmdscan_consoles = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_tree_cmdscan_consoles == null) tree_missing_tree_cmdscan_consoles = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_tree_cmdscan_consoles == null) tree_MODIFIED_tree_cmdscan_consoles = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					//tree_addition_tree_cmdscan_consoles = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_missing_tree_cmdscan_consoles = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_MODIFIED_tree_cmdscan_consoles = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();
					
					break;
				}
	
				case initialization_index_envars:
				{
					if(tree_addition_envars == null) tree_addition_envars = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_envars == null) tree_missing_envars = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_envars == null) tree_MODIFIED_envars = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					//tree_addition_envars = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_missing_envars = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_MODIFIED_envars = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					break;
				}
				
				case initialization_index_import_functions:
				{
					if(tree_addition_import_functions == null) tree_addition_import_functions = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_import_functions == null) tree_missing_import_functions = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_import_functions == null) tree_MODIFIED_import_functions = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					//tree_addition_import_functions = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_missing_import_functions = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_MODIFIED_import_functions = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					break;
				}
	
				case initialization_index_dll:
				{
					if(tree_addition_dll == null) tree_addition_dll = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_dll == null) tree_missing_dll = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_dll == null) tree_MODIFIED_dll = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					
					break;
				}
				
				case initialization_index_driver:
				{
					if(tree_addition_driver == null) tree_addition_driver = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_driver == null) tree_missing_driver = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_driver == null) tree_MODIFIED_driver = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					//tree_addittion_import_functions = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_misssing_import_functions = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_MODFIED_import_functions = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					break;
				}
				
				case initialization_index_driver_irp:
				{
					if(tree_addition_driver_irp == null) tree_addition_driver_irp = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_driver_irp == null) tree_missing_driver_irp = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_driver_irp == null) tree_MODIFIED_driver_irp = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					//tree_addittion_import_functions = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_misssing_import_functions = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_MODFIED_import_functions = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					break;
				}
				
				case initialization_index_callbacks:
				{
					if(tree_addition_callback == null) tree_addition_callback = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_callback == null) tree_missing_callback = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_callback == null) tree_MODIFIED_callback = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					//tree_addittion_import_functions = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_misssing_import_functions = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_MODFIED_import_functions = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					break;
				}
				
				case initialization_index_timers:
				{
					if(tree_addition_timers == null) tree_addition_timers = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_timers == null) tree_missing_timers = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_timers == null) tree_MODIFIED_timers = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					//tree_addittion_import_functions = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_misssing_import_functions = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_MODFIED_import_functions = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					break;
				}
				
				case initialization_index_unloaded_modules:
				{
					if(tree_addition_unloaded_modules == null) tree_addition_unloaded_modules = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_unloaded_modules == null) tree_missing_unloaded_modules = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_unloaded_modules == null) tree_MODIFIED_unloaded_modules = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					//tree_addittion_import_functions = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_misssing_import_functions = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();  tree_MODFIED_import_functions = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					break;
				}
				
				case initialization_index_filescan:
				{
					if(tree_addition_filescan == null) tree_addition_filescan = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_filescan == null) tree_missing_filescan = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_filescan == null) tree_MODIFIED_filescan = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					tree_addition = tree_addition_filescan;
					tree_missing = tree_missing_filescan;
					tree_MODIFIED = tree_MODIFIED_filescan;
					
					break;
				}
				
				case initialization_index_mftparser:
				{
					if(tree_addition_mftparser == null) tree_addition_mftparser = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_mftparser == null) tree_missing_mftparser = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_mftparser == null) tree_MODIFIED_mftparser = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					tree_addition = tree_addition_mftparser;
					tree_missing = tree_missing_mftparser;
					tree_MODIFIED = tree_MODIFIED_mftparser;
					
					break;
				}
				
				case initialization_index_timeliner:
				{
					if(tree_addition_timeliner == null) tree_addition_timeliner = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_timeliner == null) tree_missing_timeliner = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_timeliner == null) tree_MODIFIED_timeliner = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					tree_addition = tree_addition_timeliner;
					tree_missing = tree_missing_timeliner;
					tree_MODIFIED = tree_MODIFIED_timeliner;
					
					break;
				}
				
				case initialization_index_userassist_specific_entries:
				{
					if(tree_addition_userassist_specific_entries == null) tree_addition_userassist_specific_entries = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_userassist_specific_entries == null) tree_missing_userassist_specific_entries = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_userassist_specific_entries == null) tree_MODIFIED_userassist_specific_entries = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					tree_addition = tree_addition_userassist_specific_entries;
					tree_missing = tree_missing_userassist_specific_entries;
					tree_MODIFIED = tree_MODIFIED_userassist_specific_entries;
					
					break;
				}
				
				case initialization_index_shellbags:
				{
					if(tree_addition_shellbags == null) tree_addition_shellbags = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_shellbags == null) tree_missing_shellbags = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_shellbags == null) tree_MODIFIED_shellbags = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					tree_addition = tree_addition_shellbags;
					tree_missing = tree_missing_shellbags;
					tree_MODIFIED = tree_MODIFIED_shellbags;
					
					break;
				}
				
				case initialization_index_shimcache:
				{
					if(tree_addition_shimcache == null) tree_addition_shimcache = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_shimcache == null) tree_missing_shimcache = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_shimcache == null) tree_MODIFIED_shimcache = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					tree_addition = tree_addition_shimcache;
					tree_missing = tree_missing_shimcache;
					tree_MODIFIED = tree_MODIFIED_shimcache;
					
					break;
				}
				
				
			
				
				default:
				{
					driver.directive("ERROR IN " + myClassName + " I did not know initialization index: [" + TREE_INITIALIZATION_INDEX + "]");
					break;
				}


			}
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "initialize_structures", e);
		}
		
		return false;
		
	}
	
	
	public boolean set_my_tree_pointers(int TREE_INITIALIZATION_INDEX)
	{
		try
		{
			switch(TREE_INITIALIZATION_INDEX)
			{
				case initialization_index_process_particulars:
				{
					if(tree_addition_process_particulars == null) tree_addition_process_particulars = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_process_particulars == null) tree_missing_process_particulars = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_process_particulars == null) tree_MODIFIED_process_particulars = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();
					
					tree_addition = tree_addition_process_particulars;
					tree_missing = tree_missing_process_particulars;
					tree_MODIFIED = tree_MODIFIED_process_particulars; 
					
					break;
				}
				
				case initialization_index_my_module_description:
				{
					if(tree_addition_my_module_description == null) tree_addition_my_module_description = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_my_module_description == null) tree_missing_my_module_description = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_my_module_description == null) tree_MODIFIED_my_module_description = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					
					tree_addition = tree_addition_my_module_description;
					tree_missing = tree_missing_my_module_description;
					tree_MODIFIED = tree_MODIFIED_my_module_description;
					
					break;
				}
				
				case initialization_index_fle_attributes:
				{
					if(tree_addition_fle_attributes == null) tree_addition_fle_attributes = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_fle_attributes == null) tree_missing_fle_attributes = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_fle_attributes == null) tree_MODIFIED_fle_attributes = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					
					tree_addition = tree_addition_fle_attributes;
					tree_missing = tree_missing_fle_attributes;
					tree_MODIFIED = tree_MODIFIED_fle_attributes;
					
					break;					
				}
	
				case initialization_index_my_vad_info:
				{
					if(tree_addition_my_vad_info == null) tree_addition_my_vad_info = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_my_vad_info == null) tree_missing_my_vad_info = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_my_vad_info == null) tree_MODIFIED_my_vad_info = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					tree_addition = tree_addition_my_vad_info;
					tree_missing = tree_missing_my_vad_info;
					tree_MODIFIED = tree_MODIFIED_my_vad_info;

					break;
				}
	
				case initialization_index_netstat:
				{
					if(tree_addition_netstat == null) tree_addition_netstat = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_netstat == null) tree_missing_netstat = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_netstat == null) tree_MODIFIED_netstat = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					tree_addition = tree_addition_netstat;
					tree_missing = tree_missing_netstat;
					tree_MODIFIED = tree_MODIFIED_netstat;
					
					break;
				}
	
				case initialization_index_handles:
				{
					if(tree_addition_handles == null) tree_addition_handles = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_handles == null) tree_missing_handles = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_handles == null) tree_MODIFIED_handles = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					tree_addition = tree_addition_handles;
					tree_missing = tree_missing_handles;
					tree_MODIFIED = tree_MODIFIED_handles;
					
					break;
				}
	
				case initialization_index_privs:
				{
					if(tree_addition_privs == null) tree_addition_privs = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_privs == null) tree_missing_privs = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_privs == null) tree_MODIFIED_privs = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					tree_addition = tree_addition_privs;
					tree_missing = tree_missing_privs;
					tree_MODIFIED = tree_MODIFIED_privs;
					
					break;
				}
	
				case initialization_index_svcscan:
				{
					if(tree_addition_svcscan == null) tree_addition_svcscan = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_svcscan == null) tree_missing_svcscan = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_svcscan == null) tree_MODIFIED_svcscan = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					tree_addition = tree_addition_svcscan;
					tree_missing = tree_missing_svcscan;
					tree_MODIFIED = tree_MODIFIED_svcscan;
					
					break;
				}
	
				case initialization_index_sids:
				{
					if(tree_addition_sids == null) tree_addition_sids = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_sids == null) tree_missing_sids = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_sids == null) tree_MODIFIED_sids = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					tree_addition = tree_addition_sids;
					tree_missing = tree_missing_sids;
					tree_MODIFIED = tree_MODIFIED_sids;
					
					break;
				}
	
				case initialization_index_malfind:
				{
					if(tree_addition_malfind == null) tree_addition_malfind = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_malfind == null) tree_missing_malfind = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_malfind == null) tree_MODIFIED_malfind = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					tree_addition = tree_addition_malfind;
					tree_missing = tree_missing_malfind;
					tree_MODIFIED = tree_MODIFIED_malfind;
					
					break;
				}
	
				case initialization_index_threads:
				{
					if(tree_addition_threads == null) tree_addition_threads = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_threads == null) tree_missing_threads = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_threads == null) tree_MODIFIED_threads = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					tree_addition = tree_addition_threads;
					tree_missing = tree_missing_threads;
					tree_MODIFIED = tree_MODIFIED_threads;
					
					break;
				}
	
				case initialization_index_gdi_timers:
				{
					if(tree_addition_gdi_timers == null) tree_addition_gdi_timers = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_gdi_timers == null) tree_missing_gdi_timers = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_gdi_timers == null) tree_MODIFIED_gdi_timers = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					tree_addition = tree_addition_gdi_timers;
					tree_missing = tree_missing_gdi_timers;
					tree_MODIFIED = tree_MODIFIED_gdi_timers;
					
					break;
				}
	
				case initialization_index_api_hooks:
				{
					if(tree_addition_api_hooks == null) tree_addition_api_hooks = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_api_hooks == null) tree_missing_api_hooks = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_api_hooks == null) tree_MODIFIED_api_hooks = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					tree_addition = tree_addition_api_hooks;
					tree_missing = tree_missing_api_hooks;
					tree_MODIFIED = tree_MODIFIED_api_hooks;
					
					break;
				}
	
				case initialization_index_vad_info:
				{
					if(tree_addition_vad_info == null) tree_addition_vad_info = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_vad_info == null) tree_missing_vad_info = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_vad_info == null) tree_MODIFIED_vad_info = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					tree_addition = tree_addition_vad_info;
					tree_missing = tree_missing_vad_info;
					tree_MODIFIED = tree_MODIFIED_vad_info;
					
					break;
				}
	
				case initialization_index_deskscan:
				{
					if(tree_addition_deskscan == null) tree_addition_deskscan = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_deskscan == null) tree_missing_deskscan = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_deskscan == null) tree_MODIFIED_deskscan = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					tree_addition = tree_addition_deskscan;
					tree_missing = tree_missing_deskscan;
					tree_MODIFIED = tree_MODIFIED_deskscan;
					
					break;
				}
	
				case initialization_index_list_cmd_scan:
				{
					if(tree_addition_list_cmd_scan == null) tree_addition_list_cmd_scan = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_list_cmd_scan == null) tree_missing_list_cmd_scan = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_list_cmd_scan == null) tree_MODIFIED_list_cmd_scan = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					tree_addition = tree_addition_list_cmd_scan;
					tree_missing = tree_missing_list_cmd_scan;
					tree_MODIFIED = tree_MODIFIED_list_cmd_scan;
					
					break;
				}
	
				case initialization_index_tree_cmdscan_consoles:
				{
					if(tree_addition_tree_cmdscan_consoles == null) tree_addition_tree_cmdscan_consoles = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_tree_cmdscan_consoles == null) tree_missing_tree_cmdscan_consoles = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_tree_cmdscan_consoles == null) tree_MODIFIED_tree_cmdscan_consoles = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					tree_addition = tree_addition_tree_cmdscan_consoles;
					tree_missing = tree_missing_tree_cmdscan_consoles;
					tree_MODIFIED = tree_MODIFIED_tree_cmdscan_consoles;
					
					break;
				}
	
				case initialization_index_envars:
				{
					if(tree_addition_envars == null) tree_addition_envars = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_envars == null) tree_missing_envars = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_envars == null) tree_MODIFIED_envars = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					tree_addition = tree_addition_envars;
					tree_missing = tree_missing_envars;
					tree_MODIFIED = tree_MODIFIED_envars;
					
					break;
				}
	
				case initialization_index_import_functions:
				{
					if(tree_addition_import_functions == null) tree_addition_import_functions = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_import_functions == null) tree_missing_import_functions = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_import_functions == null) tree_MODIFIED_import_functions = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					tree_addition = tree_addition_import_functions;
					tree_missing = tree_missing_import_functions;
					tree_MODIFIED = tree_MODIFIED_import_functions;
					
					break;
				}
				
				case initialization_index_dll:
				{
					if(tree_addition_dll == null) tree_addition_dll = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_dll == null) tree_missing_dll = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_dll == null) tree_MODIFIED_dll = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					tree_addition = tree_addition_dll;
					tree_missing = tree_missing_dll;
					tree_MODIFIED = tree_MODIFIED_dll;
					
					break;
				}
				
				case initialization_index_driver:
				{
					if(tree_addition_driver == null) tree_addition_driver = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_driver == null) tree_missing_driver = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_driver == null) tree_MODIFIED_driver = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					tree_addition = tree_addition_driver;
					tree_missing = tree_missing_driver;
					tree_MODIFIED = tree_MODIFIED_driver;
					
					break;
				}
				
				case initialization_index_driver_irp:
				{
					if(tree_addition_driver_irp == null) tree_addition_driver_irp = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_driver_irp == null) tree_missing_driver_irp = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_driver_irp == null) tree_MODIFIED_driver_irp = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					tree_addition = tree_addition_driver_irp;
					tree_missing = tree_missing_driver_irp;
					tree_MODIFIED = tree_MODIFIED_driver_irp;
					
					break;
				}
				
				case initialization_index_callbacks:
				{
					if(tree_addition_callback == null) tree_addition_callback = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_callback == null) tree_missing_callback = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_callback == null) tree_MODIFIED_callback = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					tree_addition = tree_addition_callback;
					tree_missing = tree_missing_callback;
					tree_MODIFIED = tree_MODIFIED_callback;
					
					break;
				}
				
				case initialization_index_timers:
				{
					if(tree_addition_timers == null) tree_addition_timers = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_timers == null) tree_missing_timers = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_timers == null) tree_MODIFIED_timers = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					tree_addition = tree_addition_timers;
					tree_missing = tree_missing_timers;
					tree_MODIFIED = tree_MODIFIED_timers;
					
					break;
				}
				
				case initialization_index_unloaded_modules:
				{
					if(tree_addition_unloaded_modules == null) tree_addition_unloaded_modules = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_unloaded_modules == null) tree_missing_unloaded_modules = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_unloaded_modules == null) tree_MODIFIED_unloaded_modules = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					tree_addition = tree_addition_unloaded_modules;
					tree_missing = tree_missing_unloaded_modules;
					tree_MODIFIED = tree_MODIFIED_unloaded_modules;
					
					break;
				}
				
				case initialization_index_filescan:
				{
					if(tree_addition_filescan == null) tree_addition_filescan = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_filescan == null) tree_missing_filescan = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_filescan == null) tree_MODIFIED_filescan = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					tree_addition = tree_addition_filescan;
					tree_missing = tree_missing_filescan;
					tree_MODIFIED = tree_MODIFIED_filescan;
					
					break;
				}
				
				case initialization_index_mftparser:
				{
					if(tree_addition_mftparser == null) tree_addition_mftparser = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_mftparser == null) tree_missing_mftparser = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_mftparser == null) tree_MODIFIED_mftparser = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					tree_addition = tree_addition_mftparser;
					tree_missing = tree_missing_mftparser;
					tree_MODIFIED = tree_MODIFIED_mftparser;
					
					break;
				}
				
				case initialization_index_timeliner:
				{
					if(tree_addition_timeliner == null) tree_addition_timeliner = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_timeliner == null) tree_missing_timeliner = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_timeliner == null) tree_MODIFIED_timeliner = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					tree_addition = tree_addition_timeliner;
					tree_missing = tree_missing_timeliner;
					tree_MODIFIED = tree_MODIFIED_timeliner;
					
					break;
				}
				
				case initialization_index_userassist_specific_entries:
				{
					if(tree_addition_userassist_specific_entries == null) tree_addition_userassist_specific_entries = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_userassist_specific_entries == null) tree_missing_userassist_specific_entries = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_userassist_specific_entries == null) tree_MODIFIED_userassist_specific_entries = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					tree_addition = tree_addition_userassist_specific_entries;
					tree_missing = tree_missing_userassist_specific_entries;
					tree_MODIFIED = tree_MODIFIED_userassist_specific_entries;
					
					break;
				}
				
				case initialization_index_shellbags:
				{
					if(tree_addition_shellbags == null) tree_addition_shellbags = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_shellbags == null) tree_missing_shellbags = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_shellbags == null) tree_MODIFIED_shellbags = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					tree_addition = tree_addition_shellbags;
					tree_missing = tree_missing_shellbags;
					tree_MODIFIED = tree_MODIFIED_shellbags;
					
					break;
				}
				
				case initialization_index_shimcache:
				{
					if(tree_addition_shimcache == null) tree_addition_shimcache = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_missing_shimcache == null) tree_missing_shimcache = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();     if(tree_MODIFIED_shimcache == null) tree_MODIFIED_shimcache = new TreeMap<String, Node_Snapshot_Analysis_Artifact>();

					tree_addition = tree_addition_shimcache;
					tree_missing = tree_missing_shimcache;
					tree_MODIFIED = tree_MODIFIED_shimcache;
					
					break;
				}
				
				
				default:
				{
					driver.directive("* * ERROR IN " + myClassName + " I did not know initialization index: [" + TREE_INITIALIZATION_INDEX + "]");
					break;
				}


			}
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "set_my_tree_pointers", e);
		}
		
		return false;
		
	}
	
	public boolean PRINT_REPORT()
	{
		try
		{
			String designator = "";
			
			print_report(tree_addition_process_particulars, "ADDITIONAL INVESTIGATION DETAIL ENTRIES DETECTED"); print_report(this.tree_missing_process_particulars, "MISSING INVESTIGATION DETAIL ENTRIES DETECTED");  print_report(this.tree_MODIFIED_process_particulars, "MODIFIED INVESTIGATION DETAIL ENTRIES DETECTED");
			print_report(tree_addition_my_module_description, "ADDITIONAL MODULE DESCRIPTION ENTRIES DETECTED"); print_report(this.tree_missing_my_module_description, "MISSING MODULE DESCRIPTION ENTRIES DETECTED");  print_report(this.tree_MODIFIED_my_module_description, "MODIFIED MODULE DESCRIPTION ENTRIES DETECTED");
			print_report(tree_addition_fle_attributes, "ADDITIONAL FILE ATTRIBUTE ENTRIES DETECTED"); print_report(this.tree_missing_fle_attributes, "MISSING FILE ATTRIBUTEENTRIES DETECTED");  print_report(this.tree_MODIFIED_fle_attributes, "MODIFIED FILE ATTRIBUTE ENTRIES DETECTED");
			print_report(tree_addition_my_vad_info, "ADDITIONAL VAD ENTRIES DETECTED"); print_report(this.tree_missing_my_vad_info, "MISSING VAD ENTRIES DETECTED");  print_report(this.tree_MODIFIED_my_vad_info, "MODIFIED VAD ENTRIES DETECTED");
			print_report(tree_addition_netstat, "ADDITIONAL NETSTAT ENTRIES DETECTED"); print_report(this.tree_missing_netstat, "MISSING NETSTAT ENTRIES DETECTED");  print_report(this.tree_MODIFIED_netstat, "MODIFIED NETSTAT ENTRIES DETECTED");
			print_report(tree_addition_handles, "ADDITIONAL HANDLE ENTRIES DETECTED"); print_report(this.tree_missing_handles, "MISSING HANDLE ENTRIES DETECTED");  print_report(this.tree_MODIFIED_handles, "MODIFIED HANDLE ENTRIES DETECTED");
			print_report(tree_addition_privs, "ADDITIONAL PRIVILEGE ENTRIES DETECTED"); print_report(this.tree_missing_privs, "MISSING PRIVILEGE ENTRIES DETECTED");  print_report(this.tree_MODIFIED_privs, "MODIFIED PRIVILEGE ENTRIES DETECTED");
			print_report(tree_addition_svcscan, "ADDITIONAL SERVICES ENTRIES DETECTED"); print_report(this.tree_missing_svcscan, "MISSING SERVICES ENTRIES DETECTED");  print_report(this.tree_MODIFIED_svcscan, "MODIFIED SERVICES ENTRIES DETECTED");
			print_report(tree_addition_sids, "ADDITIONAL SID ENTRIES DETECTED"); print_report(this.tree_missing_sids, "MISSING SID ENTRIES DETECTED");  print_report(this.tree_MODIFIED_sids, "MODIFIED SID ENTRIES DETECTED");
			print_report(tree_addition_malfind, "ADDITIONAL MALFIND ENTRIES DETECTED"); print_report(this.tree_missing_malfind, "MISSING MALFIND ENTRIES DETECTED");  print_report(this.tree_MODIFIED_malfind, "MODIFIED MALFIND ENTRIES DETECTED");
			print_report(tree_addition_threads, "ADDITIONAL THREAD ENTRIES DETECTED"); print_report(this.tree_missing_threads, "MISSING THREAD ENTRIES DETECTED");  print_report(this.tree_MODIFIED_threads, "MODIFIED THREAD ENTRIES DETECTED");
			print_report(tree_addition_gdi_timers, "ADDITIONAL GDI TIMER ENTRIES DETECTED"); print_report(this.tree_missing_gdi_timers, "MISSING GDI TIMER ENTRIES DETECTED");  print_report(this.tree_MODIFIED_gdi_timers, "MODIFIED GDI TIMER ENTRIES DETECTED");
			print_report(tree_addition_api_hooks, "ADDITIONAL APIHOOK ENTRIES DETECTED"); print_report(this.tree_missing_api_hooks, "MISSING APIHOOK ENTRIES DETECTED");  print_report(this.tree_MODIFIED_api_hooks, "MODIFIED APIHOOK ENTRIES DETECTED");
			print_report(tree_addition_vad_info, "ADDITIONAL VAD ENTRIES DETECTED"); print_report(this.tree_missing_vad_info, "MISSING VAD ENTRIES DETECTED");  print_report(this.tree_MODIFIED_vad_info, "MODIFIED VAD ENTRIES DETECTED");
			print_report(tree_addition_deskscan, "ADDITIONAL DESKSCAN ENTRIES DETECTED"); print_report(this.tree_missing_deskscan, "MISSING DESKSCAN ENTRIES DETECTED");  print_report(this.tree_MODIFIED_deskscan, "MODIFIED DESKSCAN ENTRIES DETECTED");
			print_report(tree_addition_list_cmd_scan, "ADDITIONAL CMDSCAN ENTRIES DETECTED"); print_report(this.tree_missing_list_cmd_scan, "MISSING CMDSCAN ENTRIES DETECTED");  print_report(this.tree_MODIFIED_list_cmd_scan, "MODIFIED CMDSCAN ENTRIES DETECTED");
			print_report(tree_addition_tree_cmdscan_consoles, "ADDITIONAL CONSOLE ENTRIES DETECTED"); print_report(this.tree_missing_tree_cmdscan_consoles, "MISSING CONSOLE ENTRIES DETECTED");  print_report(this.tree_MODIFIED_tree_cmdscan_consoles, "MODIFIED CONSOLE ENTRIES DETECTED");
			print_report(tree_addition_envars, "ADDITIONAL ENVIRONMENT VARIABLE ENTRIES DETECTED"); print_report(this.tree_missing_envars, "MISSING ENVIRONMENT VARIABLE ENTRIES DETECTED");  print_report(this.tree_MODIFIED_envars, "MODIFIED ENVIRONMENT VARIABLE ENTRIES DETECTED");
			print_report(tree_addition_import_functions, "ADDITIONAL IMPORT FUNCTION (IAT) ENTRIES DETECTED"); print_report(this.tree_missing_import_functions, "MISSING IMPORT FUNCTION (IAT) ENTRIES DETECTED");  print_report(this.tree_MODIFIED_import_functions, "MODIFIED IMPORT FUNCTION (IAT) ENTRIES DETECTED");
			
			print_report(tree_addition_dll, "ADDITIONAL DLL ENTRIES DETECTED"); print_report(tree_missing_dll, "MISSING DLL ENTRIES DETECTED");  print_report(tree_MODIFIED_dll, "MODIFIED DLL ENTRIES DETECTED");
			print_report(tree_addition_driver, "ADDITIONAL ENTRIES DETECTED"); print_report(tree_missing_driver, "MISSING ENTRIES DETECTED");  print_report(tree_MODIFIED_driver, "MODIFIED ENTRIES DETECTED");
			designator = "DRIVER IRP"; 		print_report(tree_addition_driver_irp, "ADDITIONAL " + designator + " ENTRIES DETECTED"); print_report(tree_missing_driver_irp, "MISSING " + designator + "  ENTRIES DETECTED");  print_report(tree_MODIFIED_driver_irp, "MODIFIED " + designator + "  ENTRIES DETECTED");
			designator = "CALLBACK";		print_report(tree_addition_callback, "ADDITIONAL " + designator + "  ENTRIES DETECTED"); print_report(tree_missing_callback, "MISSING " + designator + "  ENTRIES DETECTED");  print_report(tree_MODIFIED_callback, "MODIFIED " + designator + "  ENTRIES DETECTED");
			designator = "TIMER";			print_report(tree_addition_timers, "ADDITIONAL " + designator + "  ENTRIES DETECTED"); print_report(tree_missing_timers, "MISSING " + designator + "  ENTRIES DETECTED");  print_report(tree_MODIFIED_timers, "MODIFIED " + designator + "  ENTRIES DETECTED");
			designator = "UNLOADED MODULE";	print_report(tree_addition_unloaded_modules, "ADDITIONAL " + designator + "  ENTRIES DETECTED"); print_report(tree_missing_unloaded_modules, "MISSING " + designator + "  ENTRIES DETECTED");  print_report(tree_MODIFIED_unloaded_modules, "MODIFIED " + designator + "  ENTRIES DETECTED");
						
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "print_report", e);
		}
		
		return false; 
		
	}
	
	
	public boolean print_report(TreeMap<String, Node_Snapshot_Analysis_Artifact> tree, String description)
	{
		try
		{
			
			if(tree == null || tree.isEmpty())
				return false;
			
			director.sop("\n" + description);
			
			for(String key : tree.keySet())
			{
				if(key == null || key.trim().equals(""))
					continue;
				
				director.sop("\t" + key + ": \n\t\t" + tree.get(key).toString(true, "\t\t"));
			}
			
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "print_report - tree", e);
		}
		
		return false;		
	}
	
	
	
	
	
	
	
	
	/**override*/
	public String toString()
	{
		try
		{
			return "value_1: " + value_1 + "\tvalue_2: " + value_2;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "toString", e);
		}
		
		return "* * *";
	}
	
	public String toString(boolean use_new_line_to_separate_values, String delimiter)
	{
		try	
		{	
			if(use_new_line_to_separate_values)
			{
				return "value_1: " + value_1 + "\n" + delimiter + "value_2: " + value_2;
			}
			
			return toString();	
		}
		catch(Exception e)
		{
			return " * * *"; 
		}
	}
	
	
	
	
	
}
