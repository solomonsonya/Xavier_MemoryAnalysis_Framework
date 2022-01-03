/**
 * Instantiated to execute plugin without any special processing
 * 
 * Special NOTE: we only store the first string of Raw Data - to not occupy too much memory storing the raw data contents...
 * 
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
import java.util.LinkedList;
import java.util.TreeMap;

import org.apache.commons.io.LineIterator;

public class Analysis_Plugin_user_assist extends _Analysis_Plugin_Super_Class implements Runnable, ActionListener
{
	public static final String myClassName = "Analysis_Plugin_user_assist";
	public static volatile Driver driver = new Driver();
	

	
	public volatile Advanced_Analysis_Director director = null;
	

	public volatile String lower = "";
	
	public volatile Node_Process process = null;
	
	public volatile Node_Registry_Hive registry_hive = null;
	public volatile Node_Registry_Key registry_path = null;
	public volatile Node_Generic reg_binary = null;
	
	public volatile File fleUserAssist_focus_time = null;
	
	

	
	public Analysis_Plugin_user_assist(File file, Advanced_Analysis_Director par, String PLUGIN_NAME, String PLUGIN_DESCRIPTION, boolean execute_via_thread, JTextArea_Solomon jta_OUTPUT)
	{
		try
		{
			fle_import = file;
			director = par;
			plugin_name = PLUGIN_NAME;
			plugin_description = PLUGIN_DESCRIPTION;
			jta_console_output_execution_status = jta_OUTPUT;
			
			EXECUTION_TIME_STAMP = director.EXECUTION_TIME_STAMP;
			fle_volatility = director.fle_volatility;
			fle_memory_image = director.fle_memory_image;
			PROFILE = director.PROFILE;
			path_fle_analysis_directory = director.path_fle_analysis_directory;
			file_attr_volatility = director.file_attr_volatility;
			file_attr_memory_image = director.file_attr_memory_image;
			investigator_name = director.investigator_name;
			investigation_description = director.investigation_description;
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
				
				try	{ director.tree_advanced_analysis_threads.put(this.plugin_name, this);	} catch(Exception e){}
				EXECUTION_STARTED = true;
				this.EXECUTION_COMPLETE = true;
				
				this.analyze_user_agent();
				
				return true;
			}
			
			//////////////////////////////////////////////////////////////////////////////////////
			// EXECUTE PLUGIN CMD
			//////////////////////////////////////////////////////////////////////////////////////
			
			try	{ director.tree_advanced_analysis_threads.put(this.plugin_name, this);	} catch(Exception e){}			EXECUTION_STARTED = true;

			
			try	{	Advanced_Analysis_Director.list_plugins_in_execution.add(this.plugin_name);	} catch(Exception e){}

			
			boolean status = false;
			
			status = execute_plugin(plugin_name, plugin_description, null, "");			
					
			try	{	Advanced_Analysis_Director.list_plugins_in_execution.remove(this.plugin_name);	} catch(Exception e){}
			
			analyze_user_agent();
			
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
	
	public boolean analyze_user_agent()
	{
		try
		{
			if(director.tree_user_assist_linked_by_time_focused == null || director.tree_user_assist_linked_by_time_focused.isEmpty())
				return false;
			
			if(Advanced_Analysis_Director.jtaUserAssistConsole == null)
			{
				Advanced_Analysis_Director.jtaUserAssistConsole = new JTextArea_Solomon("", true, "User Assist Entries", false);				
				Start.intface.populate_export_btn(Advanced_Analysis_Director.jtaUserAssistConsole);
				Start.intface.jtabbedpane_AdvancedAnalysis.addTab("User Assist Entries", Advanced_Analysis_Director.jtaUserAssistConsole);
				
				//prevent additional executions of this action since it is automatic from here on (i.e., after this class is called to execute the function
				try	{	Start.intface.jmnuitm_AnalyseUserAssist.setEnabled(false);} catch(Exception e){}
			}
						
			
			Advanced_Analysis_Director.jtaUserAssistConsole.clear();
			
			String delimiter = "\t ";
			String header = "registry_hive" + delimiter + "path" + delimiter + "reg_binary" + delimiter + "time_focused" + delimiter + "last_updated" + delimiter + "count" + delimiter + "focus_count" + delimiter + "reg_data_first_line";
			
			//create output file as well
			PrintWriter pw = null;
			if(fleUserAssist_focus_time == null || !fleUserAssist_focus_time.exists() || !fleUserAssist_focus_time.isFile())
			{
				try
				{
					if((fleOutput == null || !fleOutput.isFile()) && this.fle_import != null && this.fle_import.isFile())
							fleOutput = this.fle_import;
					
					String path = this.fleOutput.getParentFile().getCanonicalPath().trim();
					
					if(!path.endsWith(File.separator))
						path = path + File.separator;
					
					this.fleUserAssist_focus_time = new File(path + "_user_assist_entries.txt");
					
					//ensure not to overwrite previous file if present
					if(!fleUserAssist_focus_time.exists() && !fleUserAssist_focus_time.isFile())
					{
						pw = new PrintWriter(new FileWriter(fleUserAssist_focus_time));
						pw.println(header);
					}
					
					
				}
				catch(Exception e)
				{
					driver.directive("Exception handled in " + this.myClassName + " attempting to create User Assist sorted output file");
				}
			}
			
			Advanced_Analysis_Director.jtaUserAssistConsole.append(header);
			
			String registry_hive = "";
			String path = "";
			String line = "";
			
			for(LinkedList<Node_Generic> list_keys : director.tree_user_assist_linked_by_time_focused.values())
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
					
					if(pw != null)
						pw.println(line);
				}
			}
			
			
			if(pw != null)
			{
				try	{	pw.flush();	}	catch(Exception e){}
				try	{	pw.close();	}	catch(Exception e){}
				
				sop("If successful, user_assist focus file has been written to " + this.fleUserAssist_focus_time.getCanonicalPath());
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_user_agent", e);
		}
		
		return false;
	}
	
	public boolean execute_plugin(String plugin_name, String plugin_description, String cmd, String additional_file_name_detail)
	{
		try
		{							
			if(fle_volatility == null || !fle_volatility.exists() || !fle_volatility.isFile())
			{
				driver.sop("* * ERROR! Valid volatility executable binary has not been set. I cannot proceed with execution of plugin: [" + plugin_name + "]. * * ");
				return false;
			}
			
			if(fle_memory_image == null || !fle_memory_image.exists() || !fle_memory_image.isFile())
			{
				driver.sop("* * ERROR! Valid memory image for analysis has not been set. I cannot proceed with execution of plugin: [" + plugin_name + "]. * *");				
				return false;
			}
			
			//
			//INITIALIZE OUTPUT DIRECTORY
			//
			String time_stamp = driver.get_time_stamp("_");

			fleOutput = new File(path_fle_analysis_directory + plugin_name + File.separator + "_" + plugin_name + "_" + additional_file_name_detail + time_stamp + ".txt");
			
			
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
				cmd = "\"" + fle_volatility.getCanonicalPath().trim() + "\" -f \"" + fle_memory_image.getCanonicalPath().trim() + "\" " + plugin_name + " --profile=" + PROFILE;
			}						
			
			
			//
			//notify
			//
			if(director.DEBUG)
				sop("\n* * * Processing plugin: [" + plugin_name + "]\n");
			else
				sp("\nprocessing plugin: [" + plugin_name + "]...");
								
			
			//split the command now into command and params
			String array [] = cmd.split("\\-f");
			
			String command = cmd;
			String params = "";
			String execution_command = "";
			
			
									
			execution_command = command + params;
			
			//
			//NOTIFY
			//
			if(director.DEBUG)
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
			
			if(command.toLowerCase().contains("volatility") || params.toLowerCase().contains("volatility"))
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
			sop("\n" + this.plugin_name + " execution complete.");		
											
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "execute_plugin", e);
		}
		
		return false;
	}
	
	/**
	 * process dll list
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
			
			if(director.system_drive != null)
				line = line.replace("\\Device\\HarddiskVolume1", director.system_root).replace("\\SystemRoot", director.system_root);
			
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
			
			//
			//remove errors
			//
			if(lower.startsWith("unable to read "))  //--> e.g., Unable to read PEB for task.
				return false;
			
			if(lower.startsWith("registry:"))
			{
				String registry = line.substring(9).trim();
				this.registry_hive = null;
				
				if(director.tree_REGISTRY_KEY_USER_ASSIST.containsKey(registry))
					registry_hive = director.tree_REGISTRY_KEY_USER_ASSIST.get(registry);
				
				if(registry_hive == null)
				{
					registry_hive = new Node_Registry_Hive(registry);
					director.tree_REGISTRY_KEY_USER_ASSIST.put(registry,  registry_hive);
				}																									
			}
			
			else if(lower.startsWith("path:"))
			{
				String path = line.substring(5).trim();
				registry_path = null;
				
				if(this.registry_hive.tree_registry_key.containsKey(path))
					registry_path = registry_hive.tree_registry_key.get(path);
				
				if(registry_path == null)
				{
					registry_path = new Node_Registry_Key(registry_hive, path);
					registry_hive.tree_registry_key.put(path, registry_path);
				}	
				
				//added this part later... - Solo
				if(registry_hive != null && registry_hive.path == null)
					registry_hive.path = line.substring(5).trim();
			}
			
			else if(lower.startsWith("last updated:"))
			{
				if(registry_hive != null && registry_hive.last_updated == null)
					registry_hive.last_updated = line.substring(14).trim();
				
				if(registry_path != null && registry_path.last_updated == null)
					registry_path.last_updated = line.substring(14).trim();
				
				if(reg_binary != null && reg_binary.last_updated == null)
					reg_binary.last_updated = line.substring(14).trim();
			}
			
			else if(lower.startsWith("reg_binary"))
			{
				reg_binary = null;				
				
				//REG_BINARY    UEME_CTLSESSION : Raw Data:
				String reg_binary_value = line.substring(11).trim();
				
				//normalize
				if(reg_binary_value.toLowerCase().trim().endsWith(": raw data:"))
					reg_binary_value = reg_binary_value.substring(0, reg_binary_value.length()-12).trim();
				
				if(reg_binary_value.toLowerCase().trim().endsWith(": raw data"))
					reg_binary_value = reg_binary_value.substring(0, reg_binary_value.length()-11).trim();
				
				if(reg_binary_value.toLowerCase().trim().endsWith(":"))
					reg_binary_value = reg_binary_value.substring(0, reg_binary_value.length()-2).trim();
				
				String reg_binary_value_lower = reg_binary_value.toLowerCase().trim();
				
				//get node
				if(this.registry_path.tree_reg_binary.containsKey(reg_binary_value_lower))
					reg_binary = registry_path.tree_reg_binary.get(reg_binary_value_lower);
				
				if(reg_binary == null)					
				{
					reg_binary = new Node_Generic(this.plugin_name);
					reg_binary.reg_binary = reg_binary_value;
					this.registry_path.tree_reg_binary.put(reg_binary_value_lower, reg_binary);	
					
					reg_binary.registry_hive = registry_hive;
					reg_binary.registry_key = registry_path;
				}													
			}
			
			else if(lower.startsWith("0x"))
			{
				if(reg_binary.raw_data_first_line == null)
					reg_binary.raw_data_first_line = line;
												
				if(Advanced_Analysis_Director.STORE_REGISTRY_RAW_DATA)
				{
					if(reg_binary.list_details == null)
						reg_binary.list_details = new LinkedList<String>();
					
					reg_binary.list_details.add(line);
				}
			}
			
			else if(lower.startsWith("id:"))
				reg_binary.id = line.substring(line.indexOf(":")+1).trim();
			
			else if(lower.startsWith("count:"))
				reg_binary.count = line.substring(line.indexOf(":")+1).trim();
			
			else if(lower.startsWith("focus count:"))
				reg_binary.focus_count = line.substring(line.indexOf(":")+1).trim();
			
			else if(lower.startsWith("time focused:"))
			{
				reg_binary.time_focused = line.substring(line.indexOf(":")+1).trim();
				
				//store this key by the time it has been focused
				if(reg_binary.time_focused != null && !reg_binary.time_focused.trim().equals(""))
				{
					try
					{
						LinkedList<Node_Generic> list = null;
						
						if(director.tree_user_assist_linked_by_time_focused.containsKey(reg_binary.time_focused))
							list = director.tree_user_assist_linked_by_time_focused.get(reg_binary.time_focused);
						
						//create new list if necessary
						if(list == null)
						{
							list = new LinkedList<Node_Generic>();
							director.tree_user_assist_linked_by_time_focused.put(reg_binary.time_focused, list);
						}
						
						//link!
						list.add(reg_binary);
						 
					}
					catch(Exception e)
					{
						driver.sop("In " + this.myClassName + " I had trouble locating linked list for focussed time [" + reg_binary.time_focused + "]");
					}
				}
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
