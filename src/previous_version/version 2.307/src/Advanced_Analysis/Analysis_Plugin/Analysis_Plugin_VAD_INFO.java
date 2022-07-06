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

public class Analysis_Plugin_VAD_INFO extends _Analysis_Plugin_Super_Class implements Runnable, ActionListener
{
	public static final String myClassName = "Analysis_Plugin_VAD_INFO";
	public static volatile Driver driver = new Driver();
	

	
	public volatile Advanced_Analysis_Director parent = null;
	

	public volatile String lower = "";
	
	public volatile Node_Process process = null;
	public volatile Node_Generic vad = null;
	
	public volatile int PID = -1;	
	public volatile String impscan_output_file_name = null;
	public volatile String tree_storage_key_identifier = null;
	
	


	
	public Analysis_Plugin_VAD_INFO(File file, Advanced_Analysis_Director par, String PLUGIN_NAME, String PLUGIN_DESCRIPTION, boolean execute_via_thread, JTextArea_Solomon jta_OUTPUT)
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
					fleOutput = new File(Interface.path_fle_analysis_directory + plugin_name + File.separator + "_" + plugin_name + "_" + additional_file_name_detail + "" + ".txt");
			}
			else				
				fleOutput = new File(Interface.path_fle_analysis_directory + plugin_name + File.separator + "_" + plugin_name + "_" + additional_file_name_detail + time_stamp + ".txt");
			
			
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
				cmd = "\"" + Interface.fle_volatility.getCanonicalPath().trim() + "\" -f \"" + Interface.fle_memory_image.getCanonicalPath().trim() + "\" " + plugin_name + " --profile=" + Interface.PROFILE;
			}						
			
			
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
			
			if(line.trim().startsWith("#"))
				return false;
			
			
			line = line.replace("	", " ").replace("\t", " ").replace("\\??\\", "").trim();
			
			if(parent.system_drive != null)
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
			
			//
			//remove errors
			//
			if(lower.startsWith("unable to read "))  //--> e.g., Unable to read PEB for task.
				return false;
			
			//Pid:      4
			if(lower.startsWith("pid:"))
			{
				String pid = line.substring(line.indexOf(":")+1).trim();
				
				PID = Integer.parseInt(pid.trim());
				
				this.process = parent.tree_PROCESS.get(PID);
				
				if(process != null && process.tree_vad_info == null)
					process.tree_vad_info = new TreeMap<String, Node_Generic>();
					
				if(process != null)	
					parent.tree_VAD_INFO.put(process.PID,  process);
			}
			
			//VAD node @ 0x8601d470 Start 0x00100000 End 0x00100fff Tag Vad 
			else if(lower.startsWith("vad node"))
			{
				this.vad = new Node_Generic(this.plugin_name);
				vad.list_details = new LinkedList<String>();
				vad.process = process;
				
				//extract offset
				String offset = lower.substring(lower.indexOf("0x"), lower.indexOf(" ", lower.indexOf("0x"))).trim();
				
				vad.offset = offset;
				
				//link
				if(process != null)
					process.tree_vad_info.put(offset,  vad);
				
				if(vad != null)
					vad.list_details.add(line);
				
				//parse to extract start and end
				String arr [] = lower.split(" ");				 
				
				if(arr != null && arr.length > 0)
				{
					for(int i = 0; i < arr.length; i++)
					{
						try
						{
							if(arr[i] == null)
								continue;
							
							if(arr[i].trim().startsWith("start"))
								vad.start_address = arr[i+1].trim();
							
							if(arr[i].trim().startsWith("end"))
								vad.end_address = arr[i+1].trim();
							
						}
						catch(Exception e)
						{
							continue;
						}
						
					}
						
				}
			}
			
			//FileObject @854dbf80, Name: \Device\HarddiskVolume1\Windows\System32\ntdll.dll
			else if(lower.contains("name:"))
			{
				if(process != null && process.process_name != null && process.process_name.length() > 1 && lower.trim().endsWith(process.process_name.toLowerCase().trim()))
				{
					process.VAD = vad;
					
					//start impscan
					impscan_output_file_name = process.process_name + "_" + PID + "_" + vad.impscan_start_address + "_impscan.txt";
//process.impscan = new Analysis_Plugin_impscan(this.parent, "impscan", "Scan for calls to imported functions", false, "process", vad.impscan_start_address, impscan_output_file_name, PID, process);
				}
				
				String path = line.substring(lower.indexOf("name:")+5).trim();
				
				String name = path;
				
				if(name.contains("\\"))
					name = name.substring(name.lastIndexOf("\\")+1).trim();
				
				vad.path = path;
				vad.name = name;
				
				vad.list_details.add(line);
			}
			else
				vad.list_details.add(line);
			
			
			//conduct separate if statement to determine page protection
			if(lower.startsWith("protection:") && process != null && vad != null)
			{
				try
				{
					//ensure structure exists
					if(process.tree_vad_page_protection == null)
						process.tree_vad_page_protection = new TreeMap<String, LinkedList<Node_Generic>>();
					
					String protection = line.substring(11).toLowerCase().trim();
					
					if(protection.length() < 2)
						throw new Exception("Unable to procure proper page protection. [" + protection + "] appears invalid...");
					
					TreeMap<Integer, Node_Process> tree_VAD_PAGE_PROTECTION = null;
					
					if(parent.tree_VAD_PAGE_PROTECTION.containsKey(protection))
						tree_VAD_PAGE_PROTECTION = parent.tree_VAD_PAGE_PROTECTION.get(protection);
					
					//link process to parent
					if(tree_VAD_PAGE_PROTECTION == null)
					{
						tree_VAD_PAGE_PROTECTION = new TreeMap<Integer, Node_Process>();
						
						parent.tree_VAD_PAGE_PROTECTION.put(protection, tree_VAD_PAGE_PROTECTION);
					}
					
					if(!tree_VAD_PAGE_PROTECTION.containsKey(process.PID))
						tree_VAD_PAGE_PROTECTION.put(process.PID, process);
					
					//link this vad to process
					LinkedList<Node_Generic> list_vad_protection = null;
															
					if(process.tree_vad_page_protection != null && process.tree_vad_page_protection.containsKey(protection))
						list_vad_protection = process.tree_vad_page_protection.get(protection);
					
					if(list_vad_protection == null)
					{
						list_vad_protection = new LinkedList<Node_Generic>();
						process.tree_vad_page_protection.put(protection,  list_vad_protection);
					}
						
					if(!list_vad_protection.contains(vad))
						list_vad_protection.add(vad);
					
				}
				catch(Exception e)
				{
					//do n/t
				}
			}

			
			
			return true;
		
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "*process_plugin_line", e, false);
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
