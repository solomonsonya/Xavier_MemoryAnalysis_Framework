/**
 * Instantiated to iterate through indicated registry startup locations
 * @author Solomon Sonya
 */
package Advanced_Analysis.Analysis_Plugin;

import Advanced_Analysis.*;
import Driver.*;
import Interface.*;
import Plugin.*;
import Worker.*;
import java.awt.event.*;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.TreeMap;

import org.apache.commons.io.LineIterator;



public class Analysis_Plugin_Registry_Startup_Apps extends _Analysis_Plugin_Super_Class implements Runnable, ActionListener
{
	public static final String myClassName = "Analysis_Plugin_Registry_Startup_Apps";
	public static volatile Driver driver = new Driver();
	
	
	
	public volatile Advanced_Analysis_Director parent = null;
	
	
	public volatile Node_Registry_Hive registry_hive = null;
	public volatile Node_Registry_Key registry_key_name = null;
	public volatile LinkedList<String> list_to_store = null;
	
	
	public static volatile String [] array_registry_startup_locations = new String []
	{
			"Microsoft\\Windows\\CurrentVersion\\Run", 
			"Microsoft\\Windows\\CurrentVersion\\RunOnce", 
			"Microsoft\\Windows\\CurrentVersion\\RunServices", 
			"Microsoft\\Windows\\CurrentVersion\\RunServicesOnce", 
			"Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit", 
			"Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",

			"Microsoft\\Windows\\CurrentVersion\\Run", 
			"Microsoft\\Windows\\CurrentVersion\\RunOnce", 
			"Microsoft\\Windows\\CurrentVersion\\RunServices", 
			"Microsoft\\Windows\\CurrentVersion\\RunServicesOnce", 
			"Microsoft\\Windows NT\\CurrentVersion\\Windows",
			"Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
			
			//user logons
			"Microsoft\\Windows NT\\CurrentVersion\\Windows",
			"Microsoft\\Windows NT\\CurrentVersion\\Windows\\Run",
			
			"ControlSet001\\services",
			"Microsoft\\Security Center\\Svc",
			
	};
	
	//public static volatile LinkedList<String> list_registry_startup_locations = new LinkedList<String>(Arrays.asList(array_registry_startup_locations));

	public volatile String lower = "";
	
	public volatile Node_Process process = null;
	
	


	
	public Analysis_Plugin_Registry_Startup_Apps(File file, Advanced_Analysis_Director par, String PLUGIN_NAME, String PLUGIN_DESCRIPTION, boolean execute_via_thread, JTextArea_Solomon jta_OUTPUT)
	{
		try
		{
			fle_import = file;
			parent = par;
			plugin_name = PLUGIN_NAME;
			plugin_description = PLUGIN_DESCRIPTION;
			jta_console_output_execution_status = jta_OUTPUT;
			
			EXECUTION_TIME_STAMP = parent.EXECUTION_TIME_STAMP;
//			fle_volatility = parent.fle_volatility;
//			fle_memory_image = parent.fle_memory_image;
//			PROFILE = parent.PROFILE;
//			path_fle_analysis_directory = parent.path_fle_analysis_directory;
//			file_attr_volatility = parent.file_attr_volatility;
//			file_attr_memory_image = parent.file_attr_memory_image;
//			investigator_name = parent.investigator_name;
//			investigation_description = parent.investigation_description;
			EXECUTE_VIA_THREAD = execute_via_thread;
			
			if(execute_via_thread)
				this.start();
			else
				commence_action();
			
			
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

			///////////////////////////////////////////////////////////////////////////////////
			// IMPORT FILE
			//////////////////////////////////////////////////////////////////////////////////
			if(this.fle_import != null && this.fle_import.isFile() && this.fle_import.exists())
			{
				int line_num = 0;
				
				BufferedReader br = new BufferedReader(new FileReader(fle_import));
				
				Start.intface.sp("commencing import on file: " + fle_import.getName());
				
				String line = "";
				while((line = br.readLine()) != null)
				{
					if((line_num++) % 20 == 0)
						Start.intface.sp(".");
					
					if(line_num% Advanced_Analysis_Director.new_line_separator_count == 0)
						Start.intface.sp("\n");

					this.process_plugin_line(line);
				}
				
				try	{	br.close();} catch(Exception e){}
				
				Start.intface.sop(Advanced_Analysis_Director.import_complete_separator + "import complete on " + fle_import.getName());
				
				try	{ parent.tree_advanced_analysis_threads.put(this.plugin_name, this);	} catch(Exception e){}
				EXECUTION_STARTED = true;
				this.EXECUTION_COMPLETE = true;
				
				return true;
			}
			
			//////////////////////////////////////////////////////////////////////////////////////
			// EXECUTE PLUGIN CMD
			//////////////////////////////////////////////////////////////////////////////////////
			
			try	{ parent.tree_advanced_analysis_threads.put(this.plugin_name, this);	} catch(Exception e){}			EXECUTION_STARTED = true;

			
			try	{	Advanced_Analysis_Director.list_plugins_in_execution.add(this.plugin_name);	} catch(Exception e){}

			
			boolean status = false;
			
			for(String registry : array_registry_startup_locations)
			{
				status = execute_plugin(plugin_name, plugin_description, null, "", registry, true);	
			}
			
						
					
			try	{	Advanced_Analysis_Director.list_plugins_in_execution.remove(this.plugin_name);	} catch(Exception e){}
			
			this.EXECUTION_COMPLETE = true;

			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "run", e);
		}
		
		try	{	Advanced_Analysis_Director.list_plugins_in_execution.remove(this.plugin_name);	} catch(Exception e){}
		
		this.EXECUTION_COMPLETE = true;

		return false;
	}
	
	
	public boolean execute_plugin(String plugin_name, String plugin_description, String cmd, String additional_file_name_detail, String registry_name, boolean include_plugin_header)
	{
		try
		{							
			if(Interface.fle_volatility == null || !Interface.fle_volatility.exists() || !Interface.fle_volatility.isFile())
			{
				driver.sop("* * ERROR! Valid volatility executable binary has not been set. I cannot proceed with execution of plugin: [" + plugin_name + "]. * * ");
				return false;
			}
			
			if(Interface.fle_memory_image == null || !Interface.fle_memory_image.exists() || !Interface.fle_memory_image.isFile())
			{
				driver.sop("* * ERROR! Valid memory image for analysis has not been set. I cannot proceed with execution of plugin: [" + plugin_name + "]. * *");				
				return false;
			}
			
			//
			//INITIALIZE OUTPUT DIRECTORY
			//
			String time_stamp = driver.get_time_stamp("_");

			if(Advanced_Analysis_Director.DO_NOT_INCLUDE_TIME_STAMP_IN_FILE_NAME)
			{
				if(additional_file_name_detail == null || additional_file_name_detail.trim().equals(""))
					fleOutput = new File(Interface.path_fle_analysis_directory + plugin_name + File.separator + "_" + plugin_name + ".txt");
				else
					fleOutput = new File(Interface.path_fle_analysis_directory + plugin_name + File.separator + "_" + plugin_name + "_" + registry_name + ".txt");
			}
			else				
				fleOutput = new File(Interface.path_fle_analysis_directory + plugin_name + File.separator + "_" + plugin_name + "_" + registry_name + "_" + time_stamp + ".txt");
			
			
			
			try	
			{	
				if(!fleOutput.getParentFile().exists() || !fleOutput.getParentFile().isDirectory())
				fleOutput.getParentFile().mkdirs();	
			}	 catch(Exception e){}
			
			
			//
			//build cmd
			//
			if(cmd == null)
			{
				cmd = "\"" + Interface.fle_volatility.getCanonicalPath().trim() + "\" -f \"" + Interface.fle_memory_image.getCanonicalPath().trim() + "\" " + " --profile=" + Interface.PROFILE + " printkey -K \"" + registry_name;
			}						
						
			
			//
			//notify
			//
			if(parent.DEBUG)
				sop("\n* * * Processing plugin: [" + plugin_name + " - " + registry_name + "]\n");
			else
				sp("\nprocessing plugin: [" + plugin_name + " - " + registry_name + "]...");
								
			
			//split the command now into command and params
			String array [] = cmd.split("\\-f");
			
			String command = cmd;
			String params = "";
			String execution_command = "";
			
			
									
			execution_command = command + params;
			
			//
			//NOTIFY
			//
			if(parent.DEBUG)
				sop("[" + plugin_name + "]\t Executing command --> " + execution_command);
									
			//
			//EXECUTE COMMAND!
			//
			ProcessBuilder process_builder = null;	
			
			
			if(driver.isWindows)
			{
				process_builder = new ProcessBuilder("cmd.exe", "/C",  command +  params);
				execution_command = command +  params;								
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
			
			if(include_plugin_header)
				write_process_header(pw, plugin_name, plugin_description, execution_command);
			
			BufferedReader brIn = new BufferedReader(new InputStreamReader(process.getInputStream()));
			long line_count = 31;
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

		        	sp(".");
		        	
		        	if((++line_count) % 100 == 0)
		        		sp("\n");
		        	

		        	process_plugin_line(line);
		        	
		        	//log
		        	pw.println(line);
		        }		       	       		       		        	                		        		      
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
			//sop("\n\nExecution complete. If successful, output file has been written to --> " + fleOutput + "\n");
			sop("\n" + this.plugin_name + " - " + registry_name + " execution complete.");		
											
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "execute_plugin", e);
		}
		
		return false;
	}
	
	/**
	 * process list
	 * @param line
	 * @return
	 */
	public boolean process_plugin_line(String line)
	{
		try
		{			
			///////////////////////////////////////////////////////////////
			//
			// Solo, be sure to enable process_plugin_line!
			//
			/////////////////////////////////////////////////////////////
			
			if(line == null)
				return false;
			
			if(line.trim().startsWith("#"))
				return false;
			
			
			line = line.replace("	", " ").replace("\t", " ").replace("\\??\\", "").trim();
			
			if(parent.system_root != null)
				line = line.replace("\\Device\\HarddiskVolume1", parent.system_root).replace("\\SystemRoot", parent.system_root);
			
			if(line.equals(""))
				return false;
			
			lower = line.toLowerCase().trim();
									
			//skip if volatility header
			if(lower.startsWith("volatility foundation "))
				return false;
			else if(line.startsWith("ERROR "))
				return false;
			
			if(lower.startsWith("***"))
				return false;
			
			if(lower.startsWith("------"))
				return false;
			
			if(lower.startsWith("legend:"))
				return false;
			
			if(lower.startsWith("the requested key could not"))
				return false;
			
			//
			//remove errors
			//
			if(lower.startsWith("unable to read "))  //--> e.g., Unable to read PEB for task.
				return false;
			
			if(lower.startsWith("registry:"))
			{
				String registry = line.substring(9).trim();
				this.registry_hive = null;
				
				list_to_store = null;
				
				if(parent.tree_REGISTRY_HIVE_PRINTKEY.containsKey(registry))
					registry_hive = parent.tree_REGISTRY_HIVE_PRINTKEY.get(registry);
				
				if(registry_hive == null)
				{
					registry_hive = new Node_Registry_Hive(registry);
					parent.tree_REGISTRY_HIVE_PRINTKEY.put(registry,  registry_hive);
				}																									
			}
			
			else if(lower.startsWith("path:"))
			{
				registry_hive.path = line.substring(line.indexOf(":")+1).trim();
				
				if(this.registry_key_name != null)
					registry_key_name.path = line.substring(line.indexOf(":")+1).trim();
					
			}
			
			else if(lower.startsWith("last updated:"))
			{
				registry_hive.last_updated = line.substring(line.indexOf(":")+1).trim();
				
				if(this.registry_key_name != null)
					registry_key_name.last_updated = line.substring(line.indexOf(":")+1).trim();
					
			}
			
			else if(lower.startsWith("key name:"))
			{
				String key_name = line.substring(9).trim();
				registry_key_name = null;
				
				if(this.registry_hive.tree_registry_key.containsKey(key_name))
					registry_key_name = registry_hive.tree_registry_key.get(key_name);
				
				if(registry_key_name == null)
				{
					registry_key_name = new Node_Registry_Key(registry_hive, null);
					registry_key_name.key_name = key_name;
					registry_hive.tree_registry_key.put(key_name, registry_key_name);
				}					
			}
			
			else if(lower.startsWith("subkeys:"))
			{
				if(registry_key_name.list_sub_key_names == null)
					registry_key_name.list_sub_key_names = new LinkedList<String>();
											
				list_to_store = registry_key_name.list_sub_key_names;
			}
			
			else if(lower.startsWith("values:"))
			{
				if(registry_key_name.list_values == null)
					registry_key_name.list_values = new LinkedList<String>();
								
				list_to_store = registry_key_name.list_values;
			}
			
			else if(lower.startsWith("("))
			{
				if(registry_key_name.list_sub_key_names == null)
					registry_key_name.list_sub_key_names = new LinkedList<String>();
				
				line = line.replace("\"", "").trim();
				
				if(!registry_key_name.list_sub_key_names.contains(line))
					registry_key_name.list_sub_key_names.add(line);
				
				list_to_store = registry_key_name.list_sub_key_names;
			}
			
			else if(list_to_store != null)
			{
				line = line.replace("\"", "").trim();
				
				if(!list_to_store.contains(line))				
					list_to_store.add(line);
			}
			
			
			
			return true;
		
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_plugin_line", e);
		}
		
		return false;
	}
	
	
	
	
	
	public boolean error_processing_line(String line)
	{
		try
		{
			sop("plugin: [" + this.plugin_name + "] I was unable to process line -->" + line);
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "error_processing_line", e);
		}
		
		return false;
	}
	
	
	
	
	public void actionPerformed(ActionEvent ae)
	{
		try
		{
			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "ae", e);
		}
	}
	
	
	
	
	
	
	
	
		
	

	
	
	
	
	
	
	
	
	
}
