/**
 * 
 * NOTE: base address extracted from dlllist == ldrmodules == start address from VAD (all point to the same module)
 * Thus use the same base address to reference the same module (exe or dll) from memory
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

public class Analysis_Plugin_impscan extends _Analysis_Plugin_Super_Class implements Runnable, ActionListener
{
	public static final String myClassName = "Analysis_Plugin_impscan";
	public static volatile Driver driver = new Driver();
	

	
	public volatile Advanced_Analysis_Director parent = null;
	
	
	
	/**e.g. 0x771b0000 from --> volatility_2.6_win64_standalone.exe -f mem_WinXPSP3x86 --profile=WinXPSP3x86 impscan -b 0x771b0000 -v  -p  2860*/
	public volatile String base_address = "";
	/**e.g. payload3.exe_2860_0x771b0000.txt*/
	public volatile String output_file_name = "";
		
	public int PID = -1;

	public volatile String lower = "";
	
	public volatile Node_Process process = null;
	
	
	
	public volatile TreeMap<String, Node_Generic> tree_import_functions = new TreeMap<String, Node_Generic>();
	
	
	public static volatile boolean EXECUTE_VIA_THREAD = true;

	
	public Analysis_Plugin_impscan(File file, Advanced_Analysis_Director par, String PLUGIN_NAME, String PLUGIN_DESCRIPTION, boolean execute_via_thread, JTextArea_Solomon jta_OUTPUT, Node_Process PROCESS)
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
			
			process = PROCESS;
			
			if(process != null)
				PID = process.PID;
			
			/*driver.directive("output_directory_top_folder_name: " + output_directory_top_folder_name);
			driver.directive("base_address: " + base_address);
			driver.directive("output_file_name: " + output_file_name);
			driver.directive("PID: " + PID);*/
			
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
			if(this.process != null)
				plugin_special_identifer = this.plugin_name + " " + process.get_process_html_header();
			

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
				
				if(plugin_special_identifer == null)
					plugin_special_identifer = this.plugin_name + "_" + getId();
				
				try	{ parent.tree_advanced_analysis_threads.put(this.plugin_special_identifer, this);	} catch(Exception e){}
				EXECUTION_STARTED = true;
				this.EXECUTION_COMPLETE = true;
				
				return true;
			}
			
			//////////////////////////////////////////////////////////////////////////////////////
			// EXECUTE PLUGIN CMD
			//////////////////////////////////////////////////////////////////////////////////////
			
			try	{ parent.tree_advanced_analysis_threads.put(plugin_special_identifer, this);	} catch(Exception e){}			EXECUTION_STARTED = true;

			
			try	{	if(!Advanced_Analysis_Director.list_plugins_in_execution.contains(this.plugin_name))
					Advanced_Analysis_Director.list_plugins_in_execution.add(this.plugin_name);	} catch(Exception e){}

			try
			{								
				if(PID < 0)
					throw new Exception("Invalid PID!");
				
				this.output_file_name = this.plugin_name + "_" + this.process.process_name + "_" + process.PID + ".txt";								 
			}
			catch(Exception e)
			{
				return false;
			}
			
			//ensure we haven't already executed
//solo, return here			if(parent.tree_executed_imports.containsKey(this.base_address))
//solo, return here				return false;
			
//solo, return here			parent.tree_executed_imports.put(base_address, this);
			
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

			fleOutput = new File(path_fle_analysis_directory + plugin_name + File.separator + File.separator + this.output_file_name);
			
			
			try	
			{	
				if(!fleOutput.getParentFile().exists() || !fleOutput.getParentFile().isDirectory())
				fleOutput.getParentFile().mkdirs();	
			}	 catch(Exception e){}
			
			
			//
			//build cmd --> volatility_2.6_win64_standalone.exe -f mem_WinXPSP3x86 --profile=WinXPSP3x86 impscan -b 0x771b0000 -v  -p  2860
			//
			//with base address:
			//cmd = "\"" + fle_volatility.getCanonicalPath().trim() + "\" -f \"" + fle_memory_image.getCanonicalPath().trim() + "\" " + "--profile=" + PROFILE + " " + plugin_name + " -b " + this.base_address + " -v -p " + PID;
			if(cmd == null)			
				cmd = "\"" + fle_volatility.getCanonicalPath().trim() + "\" -f \"" + fle_memory_image.getCanonicalPath().trim() + "\" " + "--profile=" + PROFILE + " " + plugin_name + " -v -p " + PID;
					
			
			
			//
			//notify
			//
			if(parent.DEBUG)
				sop("* * * Processing plugin: [" + plugin_name + "]\n");
			else
				sop("processing plugin: [" + plugin_name + " - " + this.output_file_name + "]...");
								
			
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
			long line_count = 0;
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
			sop("\n" + this.plugin_name + " " + this.output_file_name + " execution complete.");		
											
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
			
			if(lower.startsWith("iat") || lower.startsWith("call") || lower.startsWith("function"))
				return false;
			
			//
			//remove errors
			//
			if(lower.startsWith("unable to read "))  //--> e.g., Unable to read PEB for task.
				return false;
			
			//sop(line);
			
			if(lower.startsWith("0x"))
			{
				String IAT = null;
				String call = null;
				String module_name = null;
				String module_name_lower = null;
				String function = "";
				
				try
				{
					String arr [] = line.split(" ");
					
					for(String token : arr)
					{
						if(token == null)
							continue;
						
						token = token.trim();
						
						if(token.equals(""))
							continue;
						
						if(IAT == null)
							IAT = token;
						else if(call == null)
							call = token;
						else if(module_name == null)
						{
							module_name = token;
							try	{ module_name_lower = module_name.toLowerCase().trim();	} catch(Exception e){}
						}
						else
							function = function + " " + token;
					}
					
					
				}
				catch(Exception e)
				{
					//do n/t
				}
				
				function = function.trim();
				
				
				Node_DLL_Container_Impscan dll_container = null;
//driver.directive("Process: " + process.PID + "\t module: " + module_name + "\t IAT: " + IAT + "\tFunction: " + function);
				if(process.tree_impscan_DLL_containers.containsKey(module_name_lower))
					dll_container = process.tree_impscan_DLL_containers.get(module_name_lower);
				
				if(dll_container == null)
					dll_container = new Node_DLL_Container_Impscan(process, module_name, IAT, call, function);
				else
					dll_container.process_import_function(IAT, call, function, process);										
				
				
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
