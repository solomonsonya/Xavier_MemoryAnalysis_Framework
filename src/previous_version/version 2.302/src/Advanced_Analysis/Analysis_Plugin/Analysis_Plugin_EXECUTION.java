/**
 *volatility_2.6_win64_standalone.exe -f .\MemoryDump_Lab1.raw --profile=Win7SP1x64 yarascan -Y "search_string" -C
 * 
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

import javax.swing.JCheckBox;

import org.apache.commons.io.LineIterator;

public class Analysis_Plugin_EXECUTION extends _Analysis_Plugin_Super_Class implements Runnable, ActionListener
{
	public static final String myClassName = "Analysis_Plugin_EXECUTION";
	public static volatile Driver driver = new Driver();
	

	
	public volatile Advanced_Analysis_Director parent = null;
	

	public volatile String lower = "";
	
	public volatile Node_Process process = null;
	
	//public volatile TreeMap<Integer, Node_ShellBag_Container> tree_shell_bags = null;
	
	
	boolean update_gui = false;

	/**otbn = "ok to be null"*/
	public Analysis_Plugin_EXECUTION(File file, Advanced_Analysis_Director par, String PLUGIN_NAME, String PLUGIN_DESCRIPTION, boolean execute_via_thread, JTextArea_Solomon jta_OUTPUT, String additional_file_name_DETAILS, String execution_command_override_otbn, JTextArea_Solomon jta_plugin_output)
	{
		try
		{
			fle_import = file;
			parent = par;
			plugin_name = PLUGIN_NAME;
			plugin_description = PLUGIN_DESCRIPTION;
			jta_console_output_execution_status = jta_OUTPUT;
			this.jta_plugin_output_lines = jta_plugin_output;
			this.additional_file_name_details = additional_file_name_DETAILS;
			this.EXECUTION_COMMAND_OVERRIDE = execution_command_override_otbn;
			
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
	
	public Analysis_Plugin_EXECUTION(File file, Advanced_Analysis_Director par, String PLUGIN_NAME, String PLUGIN_DESCRIPTION, boolean execute_via_thread, JTextArea_Solomon jta_OUTPUT)
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
			driver.eop(myClassName, "Constructor - 2", e);
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
						sp(".");
					
					if(line_num% Advanced_Analysis_Director.new_line_separator_count == 0)
						sp("\n");

					this.process_plugin_line(line);
				}
				
				try	{	br.close();} catch(Exception e){}
				
				if(fle_import != null)
					sop(Advanced_Analysis_Director.import_complete_separator + "import complete on " + fle_import.getName());
				
				try	{ parent.tree_advanced_analysis_threads.put(this.plugin_name, this);	} catch(Exception e){}
				EXECUTION_STARTED = true;
				this.EXECUTION_COMPLETE = true;
				
				if(update_gui && Start.intface.file_xref != null && Start.intface.file_xref.tree_dump_file_entries_FILEDUMP_XREF != null && Start.intface.file_xref.tree_dump_file_entries_FILEDUMP_XREF.size() > 0)
	        	{
					Start.intface.file_xref.intrface.populate_dump_files_FILESCAN_XREF(Start.intface.file_xref.tree_dump_file_entries_FILEDUMP_XREF);
	        	}
				
				return true;
			}
			
			//////////////////////////////////////////////////////////////////////////////////////
			// EXECUTE PLUGIN CMD
			//////////////////////////////////////////////////////////////////////////////////////
			
			try	{ parent.tree_advanced_analysis_threads.put(this.plugin_name, this);	} catch(Exception e){}			EXECUTION_STARTED = true;

			
			try	{	Advanced_Analysis_Director.list_plugins_in_execution.add(this.plugin_name);	} catch(Exception e){}

			
			boolean status = false;
			
			status = execute_plugin(plugin_name, plugin_description, EXECUTION_COMMAND_OVERRIDE, this.additional_file_name_details, true);			
					
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
			
			if(additional_file_name_detail == null)
				additional_file_name_detail = "";
			
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
			
			//update if other filename is provided
//			if(output_directory_specification != null)
//				fleOutput = new File(path_fle_analysis_directory + plugin_name + File.separator + "_" + plugin_name + "_" + additional_file_name_detail + time_stamp + ".txt");
			
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
			
			if((plugin_name.toLowerCase().contains("dump") || plugin_name.toLowerCase().contains("evtlogs")) && !(plugin_name.toLowerCase().contains("hashdump") || plugin_name.toLowerCase().contains("lsadump")))
			{
				//return here and specify which plugins require dumpdir from the class instantiation
				cmd = cmd + " --dump-dir " + "\"" + fleOutput.getParentFile().getCanonicalPath(); //leave final " off
			}
			//+ " --dump-dir \"" + fle_dump_directory.getCanonicalPath();
			
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
//			if(lower.startsWith("unable to read "))  //--> e.g., Unable to read PEB for task.
//				return false;
			
			if(jta_plugin_output_lines != null)
				jta_plugin_output_lines.append(line);
			
			if(Start.intface.file_xref != null && this.plugin_name != null && this.plugin_name.equalsIgnoreCase("yarascan"))
				process_yarascan_line_from_XREF(line);
			
			return true;
		
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_plugin_line", e);
		}
		
		return false;
	}
	
	public boolean process_yarascan_line_from_XREF(String line)
	{
		try
		{
			//search for processes --> Owner: Process explorer.exe Pid 604
        	if(lower.startsWith("owner:") && lower.contains("pid "))
        	{
        		try
        		{
        			String [] arr = line.trim().split(" ");
        			
        			int PID = Integer.parseInt(arr[arr.length-1].trim());
        					        					        			
        			String process_line = line.trim();
        			
        			if(line.startsWith("Owner: Process "))
        				process_line = line.substring(15).replaceFirst("Pid", "PID").trim();
        					        			
        			//create dump process node
        			if(Start.intface.file_xref != null && Start.intface.file_xref.tree_dump_file_entries_FILEDUMP_XREF != null)
        			{		        				
        				Node_Generic node_mem_dump = new Node_Generic("yarascan");		        				
        				node_mem_dump.jcb = new JCheckBox("memdump - " + process_line);
        				node_mem_dump.jcb.setToolTipText("memdump - " + process_line);
        				node_mem_dump.pid = ""+PID;
        				Start.intface.file_xref.tree_dump_file_entries_FILEDUMP_XREF.put("memdump - " + process_line.toLowerCase().trim(), node_mem_dump);								
						update_gui = true;																
        			}
        		}
        		catch(Exception e){}
        	}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_yarascan_line_from_XREF", e);
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
	
	
	
	/**
	 * continuation mtd
	 * @param pw
	 * @param key
	 * @param value
	 * @return
	 */
	public boolean write_filescan_manifest(PrintWriter pw, String header, String delimiter)
	{
		try
		{
			if(pw == null)
				return false;	
			
			delimiter = delimiter + " ";
			
			File fle = this.fleOutput; 
			
			if(fle == null)
				fle = this.fle_import;
			
			if(fle == null || fle.length() < 10)
			{
				driver.sop("NOTE: I am omitting filescan - I can not seem to locate valid filescan.txt file to analyze");
				return false;
			}
			
			BufferedReader br = null;
			
			//open the file
			try
			{
				br = new BufferedReader(new FileReader(fle));
			}
			catch(Exception ee)
			{
				driver.directive("Exception caught in write_filescan_manifest mtd in " + this.myClassName + " --> I couldnot open the output file in order to write contents to manifest file!");
				return false;
			}
							 			
			driver.directivesp("\nwriting filescan contents to manifest file");
			
			//write file header
			pw.println("#" + header + delimiter + Advanced_Analysis_Director.get_header(delimiter, false, header, null));
			
			//write contents
			String line = "", lower = "";
			String offset_p = "", ptr = "", hnd = "", access = "", path = "";
			int line_number = -1;
			String [] arr = null;
			
			
			while((line = br.readLine()) != null)
			{								
				if(line_number %10000 == 0)
					driver.directive("");
				if(line_number %30 == 0)
					driver.directivesp(".");
				
				++line_number;
				
				try
				{
					if(line == null)
						continue;
					
					line = line.trim();
					
					//normalize entry
					line = driver.normalize_system_root_and_device_hardrivedisk_volume(line, parent);
					
					lower = line.toLowerCase().trim();
					
					if(lower.equals("") || lower.startsWith("#") || !lower.startsWith("0x"))
						continue;
					
					//re-init
					offset_p = "";
					ptr = "";
					hnd = "";
					access = "";
					path = "";
					
					//tokenize line
					arr = line.split(" ");
					
					//Offset(P)            #Ptr   #Hnd Access Name
					//------------------ ------ ------ ------ ----
					//0x0000000000a51690      8      0 R--r-d \Device\HarddiskVolume1\Windows\System32\en-US\autoplay.dll.mui
					//0x0000000000a51b40      1      1 R--rw- \Device\HarddiskVolume1\Windows\System32
					String token = "";
					for(int i = 0; i < arr.length; i++)
					{
						token = arr[i].replace("\t",  " ").trim();
						
						if(token.equals(""))
							continue;
						
						if(offset_p.length() < 1)
							offset_p = token;
						else if(ptr.length() < 1)
							ptr = token;
						else if(hnd.length() < 1)
							hnd = token;
						else if(access.length() < 1)
							access = token;
						else 
							path = path + token + " ";
					}
					
//					offset_p = arr[0].replaceAll("\t", " ").trim();
//					ptr = arr[1].replaceAll("\t", " ").trim();
//					hnd = arr[2].replaceAll("\t", " ").trim();
//					access = arr[3].replaceAll("\t", " ").trim();
//					name_path = arr[4].replaceAll("\t", " ").trim();								
//					for(int i = 5; i < arr.length; i++)
//					{
//						name_path = name_path + " " + arr[i].replaceAll("\t", " ").trim();
//					}
					
					path = path.trim();
					
					//write entries out!
					pw.println(header + delimiter + offset_p + delimiter + ptr + delimiter + hnd + delimiter + access + delimiter + path);
					
				}
				catch(Exception ee)
				{
					driver.directive(" Error! I had trouble processing line on file " + fle + " at line [" + line_number + "] entry --> " + line);
					continue;
				}
				
				
			}
			
			try	{	br.close();}  catch(Exception e){}
			
			
			


			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_filescan_manifest", e, false);
		}
		
		return false;
	}
	
	
	/**
	 * continuation mtd
	 * @param pw
	 * @param key
	 * @param value
	 * @return
	 */
	public boolean write_shimcache_manifest(PrintWriter pw, String header, String delimiter, PrintWriter pw_manifest_super_timeline)
	{
		try
		{
			if(pw == null)
				return false;	
			
			delimiter = delimiter + " ";
			
			File fle = this.fleOutput; 
			
			if(fle == null)
				fle = this.fle_import;
			
			if(fle == null || fle.length() < 10)
			{
				driver.sop("NOTE: I am omitting " + header + " - I can not seem to locate valid data text file file to analyze");
				return false;
			}
			
			BufferedReader br = null;
			
			//open the file
			try
			{
				br = new BufferedReader(new FileReader(fle));
			}
			catch(Exception ee)
			{
				driver.directive("Exception caught in write_" + header + "_manifest mtd in " + this.myClassName + " --> I could not open the output file in order to write contents to manifest file!");
				return false;
			}
			
			//notify
			driver.directivesp("\nwriting " + header + " contents to manifest file...");
				
			//write header
			pw.println("#" + header + delimiter + Advanced_Analysis_Director.get_header(delimiter, false, header, null));
			
			pw_manifest_super_timeline.println(Advanced_Analysis_Director.get_header(delimiter, true, header, null));
			
			//write contents
			String line = "", lower = "";
			
			int line_number = 0;
			String [] arr = null;
			String token = null;
			
			String year = null;
			String time = null;
			String utc = null;
			String path = null;
			
			while((line = br.readLine()) != null)
			{
				++line_number;	
				
				if(line_number %10000 == 0)
					driver.directive("");
				if(line_number %30 == 0)
					driver.directivesp(".");
																		
				try
				{
					if(line == null)
						continue;
					
					line = line.trim();
					
					lower = line.toLowerCase().trim();
					
					if(lower.equals(""))
						continue;
					
					if(lower.equals(""))
						continue;
					
					if(lower.startsWith("#"))
						continue;
					
					if(lower.startsWith("volatility"))
						continue;
					
					if(lower.startsWith("last"))
						continue;
					
					if(lower.startsWith("-"))
						continue;
					
					//parse 2009-07-14 01:14:18 UTC+0000   \??\C:\Windows\system32\DllHost.exe
					arr = line.split(" ");
					
					year = null;
					time = null;
					utc = null;
					path = "";
					
					for(int i = 0; i < arr.length; i++)
					{
						token = arr[i].trim();
						
						if(token.equals(""))
							continue;
						
						if(year == null)
							year = token;
						else if(time == null)
							time = token;
						else if(utc == null)
							utc = token;
						else
							path = path + " " + token;
					}
					
					//trim
					path = path.trim();
					
					//normalize
					try
					{
						String temp_path = path;
						
						if(temp_path.startsWith("\\??\\"))
							path = path.substring(4).trim();
						
					}
					catch(Exception e)
					{
						//do n/t
					}
					
					//normalize entry
					line = driver.normalize_system_root_and_device_hardrivedisk_volume(line, parent);
					
					//write entries out!
					pw.println(header + delimiter + year + " " + time + " " + utc + delimiter + path);
					
					pw_manifest_super_timeline.println(year + " " + time + " " + utc + delimiter + header + delimiter + "path" + delimiter + path);
					
				}
				catch(Exception ee)
				{
					driver.directive(" Error! I had trouble processing line on file " + fle + " at line [" + line_number + "] entry --> " + line);
					continue;
				}
				
				
			}
			
			try	{	br.close();}  catch(Exception e){}
			
			
			


			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_shimcache_manifest", e, false);
		}
		
		return false;
	}
	
	
	
	/**
	 * continuation mtd
	 * @param pw
	 * @param key
	 * @param value
	 * @return
	 */
	public boolean write_timeliner_manifest(PrintWriter pw, String header, String delimiter, PrintWriter pw_super_timeline)
	{
		try
		{
			if(pw == null)
				return false;	
			
			delimiter = delimiter + " ";
			
			File fle = this.fleOutput; 
			
			if(fle == null)
				fle = this.fle_import;
			
			if(fle == null || fle.length() < 10)
			{
				driver.sop("NOTE: I am omitting " + header + " - I can not seem to locate valid data text file file to analyze");
				return false;
			}
			
			BufferedReader br = null;
			
			//open the file
			try
			{
				br = new BufferedReader(new FileReader(fle));
			}
			catch(Exception ee)
			{
				driver.directive("Exception caught in write_" + header + "_manifest mtd in " + this.myClassName + " --> I could not open the output file in order to write contents to manifest file!");
				return false;
			}
			
			//notify
			driver.directivesp("\nwriting " + header + " contents to manifest file...");
				
			//write header
			pw.println("#" + header + delimiter + Advanced_Analysis_Director.get_header(delimiter, false, header, null));
			
			pw_super_timeline.println(Advanced_Analysis_Director.get_header(delimiter, true, header, null));
			
			//write contents
			String line = "", lower = "";
			
			int line_number = 0;
			String [] arr = null;
			String token = null;
			
			String time = null;
			String key = null;
			String value = null;
			String details = null;
			String additional_details = "";
			
			while((line = br.readLine()) != null)
			{
				++line_number;	
				
				if(line_number %10000 == 0)
					driver.directive("");
				if(line_number %30 == 0)
					driver.directivesp(".");
																		
				try
				{
					if(line == null)
						continue;
					
					line = line.trim();
					
					lower = line.toLowerCase().trim();
					
					if(lower.equals(""))
						continue;
										
					if(lower.startsWith("#"))
						continue;
					
					if(lower.startsWith("volatility"))
						continue;	
					
					//normalize
					try
					{
						if(lower.contains("\\??\\"))
							lower.replace("\\??\\", "");
						
						//if that didn't cause errors
						line = line.replace("\\??\\", "").trim();						
					}catch(Exception e){}
					
					//normalize
					try
					{
						if(lower.contains("["))
							lower.replace("[", "");
						
						//if that didn't cause errors
						line = line.replace("[", "").replace("]", "").trim();						
					}catch(Exception e){}
					
					line = line.replace("|", "\t");
					
					if(line == null)
						continue;
					
					//normalize entry
					line = driver.normalize_system_root_and_device_hardrivedisk_volume(line, parent);
					
					pw.println(header + delimiter + line);
					
					try
					{
						arr = line.split("\t");
						
						time = arr[0].trim();
						key = arr[1].trim();
						value = arr[2].trim();
						details = arr[3].trim();
						
						if(arr.length > 4)
							additional_details = arr[4];
						
						for(int i = 5; 5 < arr.length; i++)
							additional_details = additional_details + delimiter + arr[i].trim();
					}
					catch(Exception e)
					{
						//do n/t
					}
					
					pw_super_timeline.println(time + delimiter + header + delimiter + key + delimiter + value + delimiter + details + delimiter + additional_details);
					
				}
				catch(Exception ee)
				{
					driver.directive(" Error! I had trouble processing line on file " + fle + " at line [" + line_number + "] entry --> " + line);
					continue;
				}
				
				
			}//end while
			
			try	{	br.close();}  catch(Exception e){}
			
			
			


			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_timeliner_manifest", e, false);
		}
		
		return false;
	}
	
	
	/**
	 * continuation mtd
	 * @param pw
	 * @param key
	 * @param value
	 * @return
	 */
	public boolean write_shellbags_manifest(PrintWriter pw, String header, String delimiter, PrintWriter pw_manifest_super_timeline)
	{
		try
		{
			if(pw == null)
				return false;	
			
			delimiter = delimiter + " ";
			
			File fle = this.fleOutput; 
			
			if(fle == null)
				fle = this.fle_import;
			
			if(fle == null || fle.length() < 10)
			{
				driver.sop("NOTE: I am omitting " + header + " - I can not seem to locate valid data text file file to analyze");
				return false;
			}
			
			BufferedReader br = null;
			
			//tree_shell_bags = new TreeMap<Integer, Node_ShellBag_Container>();
			
			//open the file
			try
			{
				br = new BufferedReader(new FileReader(fle));
			}
			catch(Exception ee)
			{
				driver.directive("Exception caught in write_" + header + "_manifest mtd in " + this.myClassName + " --> I could not open the output file in order to write contents to manifest file!");
				return false;
			}
			
			//notify
			driver.directivesp("\nanalyzing " + header + " contents to tokenize and store into manifest");
			
			//
			//phase 1: analyze and populate tree!
			//
				
			//write header
			//pw.println("#" + header + "\tlast_updated\treg_binary\ttime_focused\tcount\t focus_count\tregistry_hive\tpath\treg_data_first_line");
			
			//write contents
			String line = "", lower = "";
			
			int line_number = 0;
			String [] arr = null;
			String token = null;
			
			String registry = "";
			String registry_key_name = "";
			String last_updated = "";
			int type = 0;
			
			String analysis_line = null;
			
			Node_ShellBag_Container container = null;
			
			while((line = br.readLine()) != null)
			{
				++line_number;	
				
				if(line_number %10000 == 0)
					driver.directive("");
				if(line_number %30 == 0)
					driver.directivesp(".");
																		
				try
				{
					if(line == null)
						continue;
					
					line = line.replace("\\??\\", "").trim();
					
					lower = line.toLowerCase().trim();
					
					if(lower.equals(""))
						continue;
					
					if(lower.equals(""))
						continue;
					
					if(lower.startsWith("#"))
						continue;
					
					if(lower.startsWith("volatility"))
						continue;
					
					if(lower.startsWith("scanning "))
						continue;
					
					if(lower.startsWith("gathering shellbag "))
						continue;
					
					if(lower.startsWith("*"))
						continue;
					
					if(lower.startsWith("--"))
						continue;
					
					
					
					if(lower.startsWith("registry:"))
						registry = line.substring(9).trim();
					else if(lower.startsWith("key:"))
						registry_key_name = line.substring(4).trim();
					else if(lower.startsWith("last updated:"))
						last_updated = line.substring(13).trim();
					else if(line.equals("Value                     File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Unicode Name"))
						type = Node_ShellBag_Container.TYPE_1;
					else if(line.equals("Value   Mru   Entry Type     GUID                                     GUID Description     Folder IDs"))
						type = Node_ShellBag_Container.TYPE_2;
					else if(line.equals("Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path"))
						type = Node_ShellBag_Container.TYPE_3;
					else if(line.equals("Value   Mru   Entry Type     Path"))
						type = Node_ShellBag_Container.TYPE_4;
					else if(line.startsWith("Value"))
					{
						driver.directive("Punt! While analyzing " + header + " I encountered an entry type that I am un familiar with and will have to omit line [" + line_number + "] --> " + line);
						continue;
					}
					
					else//analyze the line
					{
						switch(type)
						{
							case Node_ShellBag_Container.TYPE_1:
							{
								//
								//instantiate container
								//
								try	
								{	
									container  = parent.tree_shell_bags.get(type);	
									
									if(container == null || container.tree_shellbag_entries == null)
										throw new Exception("container did not exist for type [" + type + "] - need to create it first");								
								}	
								
								catch(Exception e)	
								{	
									container = new Node_ShellBag_Container(type, this, this.parent);
									
									parent.tree_shell_bags.put(type,  container);									
								}
								
								//
								//analyze and store the data
								//
								analysis_line = analyze_shellbags_entry_type_1(registry, registry_key_name, last_updated, line, type, line_number, container);																																															
								
								break;
							}
							
							case Node_ShellBag_Container.TYPE_2:
							{
								//
								//instantiate container
								//
								try	
								{	
									container  = parent.tree_shell_bags.get(type);	
									
									if(container == null || container.tree_shellbag_entries == null)
										throw new Exception("container did not exist for type [" + type + "] - need to create it first");								
								}	
								
								catch(Exception e)	
								{	
									container = new Node_ShellBag_Container(type, this, this.parent);
									
									parent.tree_shell_bags.put(type,  container);									
								}
								
								//
								//analyze and store the data
								//
								analysis_line = analyze_shellbags_entry_type_2(registry, registry_key_name, last_updated, line, type, line_number, container);
								break;
							}
							
							case Node_ShellBag_Container.TYPE_3:
							{
								//
								//instantiate container
								//
								try	
								{	
									container  = parent.tree_shell_bags.get(type);	
									
									if(container == null || container.tree_shellbag_entries == null)
										throw new Exception("container did not exist for type [" + type + "] - need to create it first");								
								}	
								
								catch(Exception e)	
								{	
									container = new Node_ShellBag_Container(type, this, this.parent);
									
									parent.tree_shell_bags.put(type,  container);									
								}
								
								//
								//analyze and store the data
								//
								analysis_line = analyze_shellbags_entry_type_3(registry, registry_key_name, last_updated, line, type, line_number, container);
								break;
							}
							
							case Node_ShellBag_Container.TYPE_4:
							{
								//
								//instantiate container
								//
								try	
								{	
									container  = parent.tree_shell_bags.get(type);	
									
									if(container == null || container.tree_shellbag_entries == null)
										throw new Exception("container did not exist for type [" + type + "] - need to create it first");								
								}	
								
								catch(Exception e)	
								{	
									container = new Node_ShellBag_Container(type, this, this.parent);
									
									parent.tree_shell_bags.put(type,  container);									
								}
								
								//
								//analyze and store the data
								//
								analysis_line = analyze_shellbags_entry_type_4(registry, registry_key_name, last_updated, line, type, line_number, container);
								break;
							}
							default:
							{
								analysis_line = null;
								driver.directive("* * * Punt! Analyzing " + header + " I encountered an entry type that I am un familiar with and will have to omit line [" + line_number + "] --> " + line);
								continue;
							}
						}
					}
					
										
				}
				catch(Exception ee)
				{
					driver.directive(" Error! I had trouble processing line on file " + fle + " at line [" + line_number + "] entry --> " + line);
					continue;
				}
				
				
			}//end while
			
			try	{	br.close();}  catch(Exception e){}
			
			//
			//Phase 3 - write entries
			//
			if(parent.tree_shell_bags != null && parent.tree_shell_bags.size() > 0)
			{								
				for(Node_ShellBag_Container shellbag_container : parent.tree_shell_bags.values())
				{
					if(shellbag_container == null || shellbag_container.tree_shellbag_entries == null || shellbag_container.tree_shellbag_entries.size() < 1)
						continue;
					
					//write header
					pw.println("#" + header + delimiter + shellbag_container.get_manifest_header(delimiter));
					pw_manifest_super_timeline.println(shellbag_container.get_timeliner_header(delimiter));
					
					//write entries
					for(Node_Generic node : shellbag_container.tree_shellbag_entries.values())
					{
						if(node == null || node.shell_bag_analysis_line == null || node.shell_bag_analysis_line.length() < 1)
							continue;
						
						pw.println(header + delimiter + node.shell_bag_analysis_line);
						pw_manifest_super_timeline.println(node.shell_bag_timeline);
					}
					
				}
			}
			


			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_shellbags_manifest", e, false);
		}
		
		return false;
	}
	
	
	
	public String analyze_shellbags_entry_type_1(String registry, String registry_key_name, String last_updated, String line, int type, int line_number, Node_ShellBag_Container container)
	{
		try
		{
			String delimiter = "\t";
			String header = "shellbags";
			
			if(line == null || line.trim().equals(""))
				return null;
			
			line = line.trim();
			
			//Value                     File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Unicode Name
			
			//Parse the data
			String arr [] = line.split("  ");
			
			//Create the new node
			Node_Generic node = new Node_Generic("shellbag_entry");
			
			node.registry_name = registry;
			node.registry_key_name = registry_key_name;
			node.last_updated = last_updated;
			node.shellbag_type = ""+type;
			
			for(String token : arr)
			{
				if(token == null)
					continue;
				
				token = token.trim();
				
				if(token.equals(""))
					continue;
				
				if(node.value == null)
					node.value = token;
				else if(node.file_name == null)
					node.file_name = token;
				else if(node.modified_date == null)
					node.modified_date = token;
				else if(node.create_date == null)
					node.create_date = token;
				else if(node.access_date == null)
					node.access_date = token;
				else if(node.file_attr == null)
					node.file_attr = token;
				else if(node.unicode_name == null)
					node.unicode_name = token;
				else 
					node.additional_details = node.additional_details + delimiter + token;				
			}
			
			try	{	node.additional_details = node.additional_details.trim();	} catch(Exception e){}				
					
			//
			//phase 2: store entries!
			//
			node.shell_bag_analysis_line = node.get_manifest_shellbags(type, delimiter);
			
			node.shell_bag_timeline = driver.get_latest_time(node.modified_date, node.create_date, node.access_date, null, 0) + delimiter + header + delimiter + "file name (unicode)" + delimiter + node.unicode_name + delimiter + node.shellbag_type + delimiter + node.file_name + delimiter + node.file_attr + delimiter + node.create_date + delimiter + node.modified_date + delimiter + node.access_date + delimiter + node.last_updated + delimiter + node.value + delimiter + node.registry_name + delimiter + node.registry_key_name + delimiter + node.additional_details;
			
			//link
			container.tree_shellbag_entries.put(node.shell_bag_analysis_line, node);
			
			return node.get_manifest_shellbags(type, "\t");
		}
		catch(Exception e)
		{
			driver.directive("Error analyzing analyze_shellbags_entry_type_1 at line [" + line_number + "] entry --> " + line);
		}
		
		return null;
	}
	
	
	public String analyze_shellbags_entry_type_2(String registry_name, String registry_key_name, String last_updated, String line, int type, int line_number, Node_ShellBag_Container container)
	{
		try
		{
			String header = "shellbags";
			String delimiter = "\t";
			
			if(line == null || line.trim().equals(""))
				return null;
			
			line = line.trim();
			
			//Value   Mru   Entry Type     GUID                                     GUID Description     Folder IDs
			
			//Parse the data
			String arr [] = line.split("  ");
			
			//Create the new node
			Node_Generic node = new Node_Generic("shellbag_entry");
			
			node.registry_name = registry_name;
			node.registry_key_name = registry_key_name;
			node.last_updated = last_updated;
			node.shellbag_type = ""+type;
			
			for(String token : arr)
			{
				if(token == null)
					continue;
				
				token = token.trim();
				
				if(token.equals(""))
					continue;
				
				if(node.value == null)
					node.value = token;
				else if(node.mru == null)
					node.mru = token;
				else if(node.entry_type == null)
					node.entry_type = token;
				else if(node.guid == null)
					node.guid = token;
				else if(node.guid_description == null)
					node.guid_description = token;
				else if(node.folder_ids == null)
					node.folder_ids = token;				
				else 
					node.additional_details = node.additional_details + "\t" + token;				
			}
			
			try	{	node.additional_details = node.additional_details.trim();	} catch(Exception e){}				
			
			
			//
			//phase 2: store entries!
			//
			node.shell_bag_analysis_line = node.get_manifest_shellbags(type, "\t");
			
			node.shell_bag_timeline = node.last_updated + delimiter + header + delimiter + "guid description" + delimiter + node.guid_description + delimiter + node.shellbag_type + delimiter + node.folder_ids + delimiter + node.entry_type + delimiter + node.guid + delimiter + node.value + delimiter + node.mru + delimiter + node.registry_name + delimiter + node.registry_key_name + delimiter + node.additional_details;
			
			
			//link
			container.tree_shellbag_entries.put(node.shell_bag_analysis_line, node);
			
			return node.get_manifest_shellbags(type, "\t");

		}
		catch(Exception e)
		{
			driver.directive("Error analyzing analyze_shellbags_entry_type_2 at line [" + line_number + "] entry --> " + line);
		}
		
		return null;
	}
	
	
	public String analyze_shellbags_entry_type_3(String registry, String registry_key_name, String last_updated, String line, int type, int line_number, Node_ShellBag_Container container)
	{
		try
		{
			if(line == null || line.trim().equals(""))
				return null;
			
			String header = "shellbags";
			String delimiter = "\t";
			
			line = line.trim();
			
			//Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path
			
			//Parse the data
			String arr [] = line.split("  ");
			
			//Create the new node
			Node_Generic node = new Node_Generic("shellbag_entry");
			
			node.registry_name = registry;
			node.registry_key_name = registry_key_name;
			node.last_updated = last_updated;
			node.shellbag_type = ""+type;
			
			for(String token : arr)
			{
				if(token == null)
					continue;
				
				token = token.trim();
				
				if(token.equals(""))
					continue;
				
				if(node.value == null)
					node.value = token;
				else if(node.mru == null)
					node.mru = token;
				else if(node.file_name == null)
					node.file_name = token;
				else if(node.modified_date == null)
					node.modified_date = token;
				else if(node.create_date == null)
					node.create_date = token;
				else if(node.access_date == null)
					node.access_date = token;	
				else if(node.file_attr == null)
					node.file_attr = token;	
				else if(node.path == null)
					node.path = token;	
				else 
					node.additional_details = node.additional_details + "\t" + token;				
			}
			
			try	{	node.additional_details = node.additional_details.trim();	} catch(Exception e){}				
			
			//
			//phase 2: store entries!
			//
			node.shell_bag_analysis_line = node.get_manifest_shellbags(type, "\t");
			
			node.shell_bag_timeline = driver.get_latest_time(node.modified_date, node.create_date, node.access_date, null, 0) + delimiter + header + delimiter + "path" + delimiter + node.path + delimiter + node.shellbag_type + delimiter + node.file_name + delimiter + node.file_attr + delimiter + node.create_date + delimiter + node.modified_date + delimiter + node.access_date + delimiter + node.last_updated + delimiter + node.value + delimiter + node.mru + delimiter + node.registry_name + delimiter + node.registry_key_name + delimiter + node.additional_details;
			
			//link
			container.tree_shellbag_entries.put(node.shell_bag_analysis_line, node);
			
			return node.get_manifest_shellbags(type, "\t");

		}
		catch(Exception e)
		{
			driver.directive("Error analyzing analyze_shellbags_entry_type_3 at line [" + line_number + "] entry --> " + line);
		}
		
		return null;
	}
	
	
	
	public String analyze_shellbags_entry_type_4(String registry, String registry_key_name, String last_updated, String line, int type, int line_number, Node_ShellBag_Container container)
	{
		try
		{
			if(line == null || line.trim().equals(""))
				return null;
			
			String delimiter = "\t";
			String header = "shellbags";
			
			line = line.trim();
			
			//Value   Mru   Entry Type     Path
			
			//Parse the data
			String arr [] = line.split("  ");
			
			//Create the new node
			Node_Generic node = new Node_Generic("shellbag_entry");
			
			node.registry_name = registry;
			node.registry_key_name = registry_key_name;
			node.last_updated = last_updated;
			node.shellbag_type = ""+type;
			
			for(String token : arr)
			{
				if(token == null)
					continue;
				
				token = token.trim();
				
				if(token.equals(""))
					continue;
				
				if(node.value == null)
					node.value = token;
				else if(node.mru == null)
					node.mru = token;
				else if(node.entry_type == null)
					node.entry_type = token;
				else if(node.path == null)
					node.path = token;
				
				else 
					node.additional_details = node.additional_details + "\t" + token;				
			}
			
			try	{	node.additional_details = node.additional_details.trim();	} catch(Exception e){}				
			
			//
			//phase 2: store entries!
			//
			node.shell_bag_analysis_line = node.get_manifest_shellbags(type, "\t");
			
			node.shell_bag_timeline = node.last_updated + delimiter + header + delimiter + "path" + delimiter + node.path + delimiter + node.shellbag_type + delimiter + node.entry_type + delimiter + node.value + delimiter + node.mru + delimiter + node.registry_name + delimiter + node.registry_key_name + delimiter + node.additional_details;
		
			//link
			container.tree_shellbag_entries.put(node.shell_bag_analysis_line, node);
			
			return node.get_manifest_shellbags(type, "\t");

		}
		catch(Exception e)
		{
			driver.directive("Error analyzing analyze_shellbags_entry_type_4 at line [" + line_number + "] entry --> " + line);
		}
		
		return null;
	}
	
	
	
	
	
	
		
	
	
	
	
	
	
	
	
	
}
