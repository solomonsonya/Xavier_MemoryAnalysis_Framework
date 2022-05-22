/**
 * Instantiated to execute plugin without any special processing
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

public class Analysis_Plugin_driverscan extends _Analysis_Plugin_Super_Class implements Runnable, ActionListener
{
	public static final String myClassName = "Analysis_Plugin_drivermodule";
	public static volatile Driver driver = new Driver();
	

	
	public volatile Advanced_Analysis_Director parent = null;
	

	public volatile String lower = "";
	
	public volatile Node_Process process = null;
	
	 


	
	public Analysis_Plugin_driverscan(File file,Advanced_Analysis_Director par, String PLUGIN_NAME, String PLUGIN_DESCRIPTION, boolean execute_via_thread, JTextArea_Solomon jta_OUTPUT)
	{
		try
		{
			fle_import = file;
			parent = par;
			plugin_name = PLUGIN_NAME;
			plugin_description = PLUGIN_DESCRIPTION;
			jta_console_output_execution_status = jta_OUTPUT;
			
			EXECUTION_TIME_STAMP = parent.EXECUTION_TIME_STAMP;
			fle_volatility = parent.fle_volatility;
			fle_memory_image = parent.fle_memory_image;
			PROFILE = parent.PROFILE;
			path_fle_analysis_directory = parent.path_fle_analysis_directory;
			file_attr_volatility = parent.file_attr_volatility;
			file_attr_memory_image = parent.file_attr_memory_image;
			investigator_name = parent.investigator_name;
			investigation_description = parent.investigation_description;
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
			
			status = execute_plugin(plugin_name, plugin_description, null, "", true);			
					
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
	
	
	public boolean execute_plugin(String plugin_name, String plugin_description, String cmd, String additional_file_name_detail, boolean include_plugin_header)
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

			if(Advanced_Analysis_Director.DO_NOT_INCLUDE_TIME_STAMP_IN_FILE_NAME)
			{
				if(additional_file_name_detail == null || additional_file_name_detail.trim().equals(""))
					fleOutput = new File(path_fle_analysis_directory + plugin_name + File.separator + "_" + plugin_name + ".txt");
				else
					fleOutput = new File(path_fle_analysis_directory + plugin_name + File.separator + "_" + plugin_name + "_" + additional_file_name_detail + "" + ".txt");
			}
			else
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
			
//			if(cmd.toLowerCase().contains("dump") && (!cmd.toLowerCase().contains("hashdump") || !cmd.toLowerCase().contains("evtlogs") || cmd.toLowerCase().contains("lsadump")))
//				cmd = cmd + " --dump-dir " + "\"" + fleOutput.getParentFile().getCanonicalPath(); //leave final " off
			
			//
			//notify
			//
			if(parent.DEBUG)
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
			
			line = line.replace("	", " ").replace("\t", " ").replace("\\??\\", "").trim();
			
			if(parent.system_drive != null)
				line = line.replace("\\Device\\HarddiskVolume1", parent.system_root).replace("\\SystemRoot", parent.system_root);
			
			if(line.equals(""))
				return false;
			
			if(line.trim().startsWith("#"))
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
			
			//
			//remove errors
			//
			if(lower.startsWith("unable to read "))  //--> e.g., Unable to read PEB for task.
				return false;
			
			String offset_driverscan = null;
			String num_ptr = null;
			String num_handle = null;
			String start = null;
			String size = null;
			String service_key = null;
			String module_name = null;			
			String driver_path = null;
			
			String [] arr = line.split("  ");
			
			for(String value : arr)
			{
				if(value == null)
					continue;
				
				value = value.trim();
				
				if(value.equals(""))
					continue;
				
				if(offset_driverscan == null)
					offset_driverscan = value;
				
				else if(num_ptr == null)
					num_ptr = value;
				
				else if(num_handle == null)
				{
					String [] array = value.split(" ");
					num_handle = array[0].trim();
					start = array[1].trim();
				}
				
				else if(size == null)
				{
					String [] array = value.split(" ");
					size = array[0].trim();
					service_key = array[1].trim();
				}
				
				else if(module_name == null)
					module_name = value;
				
				else if(driver_path == null)
					driver_path = value;
				
				
			}
			
			//remove \Driver\PptpMiniport --> PptpMiniport
			if(module_name != null && module_name.contains("\\"))
			{
				String array [] = module_name.split("\\");
				
				if(array != null)
				{
					module_name = array[array.length -1].trim();
				}
			}
			
			String original_module_name = module_name;
			
			if(module_name != null && !module_name.contains(".") && !module_name.toLowerCase().trim().endsWith(".sys"))
				module_name = module_name.trim() + ".sys";
			
			//   \Driver\kmixer     --> \SystemRoot\System32\Drivers\kmixer
			//	 \FileSystem\MRxDAV --> \SystemRoot\system32\DRIVERS\MRxDAV
			
			if(parent.system_root != null && driver_path != null && driver_path.toLowerCase().trim().startsWith("\\driver\\"))
				driver_path = parent.system_root + driver_path;
			if(parent.system_root != null && driver_path != null && driver_path.toLowerCase().trim().startsWith("\\filesystem\\"))
				driver_path = parent.system_root + driver_path.substring(12).trim();
			
			String module_name_without_extension = module_name.toLowerCase().trim();
			
			try
			{
				if(module_name_without_extension.endsWith(".sys"))
					module_name_without_extension =module_name_without_extension.substring(0, module_name_without_extension.lastIndexOf(".sys")).trim();
					
				if(module_name_without_extension.length() < 1)
					module_name_without_extension = module_name.toLowerCase().trim();
			}
			catch(Exception e)
			{
				module_name_without_extension = module_name.toLowerCase().trim();
			}
			
			
			Node_Driver node = null;
			
			if(parent.tree_DRIVERS.containsKey(module_name.toLowerCase().trim()))
				node = parent.tree_DRIVERS.get(module_name.toLowerCase().trim());
			
			if(node == null && parent.tree_DRIVERS.containsKey(module_name_without_extension))
				node = parent.tree_DRIVERS.get(module_name_without_extension);
									
			if(node == null)			
			{
				node = new Node_Driver(null, module_name, null);
				
				//store
				parent.tree_DRIVERS.put(module_name_without_extension, node);
				
				//driver.directive("\nnew node --> " + module_name + "\n\n");
			}
			
			if(node.offset_driverscan == null || node.offset_driverscan.trim().equals("-") || node.offset_driverscan.trim().equals(""))
				node.offset_driverscan = offset_driverscan;
			
			if(node.num_ptr == null || node.num_ptr.trim().equals("-") || node.num_ptr.trim().equals(""))
				node.num_ptr = num_ptr;
			
			if(node.num_handle == null || node.num_handle.trim().equals("-") || node.num_handle.trim().equals(""))
				node.num_handle = num_handle;
			
			if(node.start == null || node.start.trim().equals("-") || node.start.trim().equals(""))
				node.start = start;
			
			if(node.size_P == null || node.size_P.trim().equals("-") || node.size_P.trim().equals(""))
				node.size_P = size;
			
			if(node.service_key == null || node.service_key.trim().equals("-") || node.service_key.trim().equals(""))
				node.service_key = service_key;					
			
			if(node.file_path_from_memory == null || node.file_path_from_memory.trim().equals("-") || node.file_path_from_memory.trim().equals(""))
				node.file_path_from_memory = driver_path;										
			
		}
		catch(Exception e)
		{
			driver.directive("[" + this.plugin_name + "]\t* NOTE: I had trouble processing line -->" + line);
			//driver.eop(myClassName, "process_plugin_line", e);
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
