/**
 * procdump, dlldump, dumpcerts, dumpfiles, dumpregistry, memdump, moddump, evtlogs, vaddump
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

public class Analysis_Plugin_Dump extends _Analysis_Plugin_Super_Class implements Runnable, ActionListener
{
	public static final String myClassName = "Analysis_Plugin_Dump";
	public static volatile Driver driver = new Driver();
	
	
	public volatile Advanced_Analysis_Director director = null;
		
	
	
	public volatile File fle_dump_directory = null;
	
	public volatile TreeMap<String, String> tree_execution_output = null;
	
	public volatile File parent_directory_file_header = null;
	public volatile String path_parent_directory_file_header = null;
	
	/**take result e.g., module.248.3f68f040.77c90000.dll and convert to --> smss.exe_248_ntdll.dll_3f68f040_77c90000 */
	public volatile TreeMap<String, String> tree_DLL_result_to_file_name_conversion = new TreeMap<String, String>();
	
	/**take result e.g., module.248.3f68f040.77c90000.dll and store the process node it relates to */
	public volatile TreeMap<String, Node_Process> tree_DLL_result_to_Node_Process = new TreeMap<String, Node_Process>();
	
	/**take result e.g., module.248.3f68f040.77c90000.dll and store the DLL node it relates to */
	public volatile TreeMap<String, Node_DLL> tree_DLL_result_to_Node_DLL = new TreeMap<String, Node_DLL>();


	public Analysis_Plugin_Dump(File file, Advanced_Analysis_Director par, String PLUGIN_NAME, String PLUGIN_DESCRIPTION, boolean execute_via_thread, JTextArea_Solomon jta_OUTPUT, boolean store_execution_output_for_processing)
	{
		try
		{
			fle_import = file;
			director = par;
			plugin_name = PLUGIN_NAME;
			plugin_description = PLUGIN_DESCRIPTION;
			jta_console_output_execution_status = jta_OUTPUT;
			
			EXECUTION_TIME_STAMP = par.EXECUTION_TIME_STAMP;
			fle_volatility = par.fle_volatility;
			fle_memory_image = par.fle_memory_image;
			PROFILE = par.PROFILE;
			path_fle_analysis_directory = par.path_fle_analysis_directory;
			file_attr_volatility = par.file_attr_volatility;
			file_attr_memory_image = par.file_attr_memory_image;
			investigator_name = par.investigator_name;
			investigation_description = par.investigation_description;
			EXECUTE_VIA_THREAD = execute_via_thread;
			
			if(store_execution_output_for_processing)
				this.tree_execution_output = new TreeMap<String, String>();
			
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
				
				return true;
			}
			
			//////////////////////////////////////////////////////////////////////////////////////
			// EXECUTE PLUGIN CMD
			//////////////////////////////////////////////////////////////////////////////////////
			
			try	{ director.tree_advanced_analysis_threads.put(this.plugin_name, this);	} catch(Exception e){}			EXECUTION_STARTED = true;

			
			try	{	Advanced_Analysis_Director.list_plugins_in_execution.add(this.plugin_name);	} catch(Exception e){}

			
			boolean status = false;
			
			status = execute_plugin(plugin_name, plugin_description, null, "");							
					
			//File fle = new File(path_fle_analysis_directory + "file_attributes" + File.separator + "file_attributes_" + this.fle_memory_image.getName() + time_stamp + ".txt");
			
			
			
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
	
	public boolean write_file_imports()
	{
		try
		{
			File fleImports = new File(path_parent_directory_file_header + "_file_imports.txt");
			
			PrintWriter pw = new PrintWriter(new FileWriter(fleImports));
			
			for(Node_Process process : director.tree_PROCESS.values() )
				process.print_dll_import_table(pw);
			
			pw.flush();
			pw.close();
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_file_improrts", e);
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
			//specify dumpfile path
			//			
			fle_dump_directory = new File(path_fle_analysis_directory + plugin_name + File.separator);			
			try	{	fle_dump_directory.mkdirs();	}	catch(Exception e){sop("\n\nERROR: I could not make dump directory at " + path_fle_analysis_directory + plugin_name + File.separator);}
			
			//
			//build cmd
			//
			if(cmd == null)
			{
				//do not end the command with closing "
				cmd = "\"" + fle_volatility.getCanonicalPath().trim() + "\" -f \"" + fle_memory_image.getCanonicalPath().trim() + "\" " + plugin_name + " --profile=" + PROFILE + " --dump-dir \"" + fle_dump_directory.getCanonicalPath();
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
			if(director.DEBUG)
				sop("[" + plugin_name + "]\t Executing command --> " + command + params);
			
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
			
			if(command.toLowerCase().contains("volatility") || params.toLowerCase().contains("volatility"))
				write_process_header(pw, plugin_name, plugin_description, execution_command);
			
			BufferedReader brIn = new BufferedReader(new InputStreamReader(process.getInputStream()));
			
			//
			//process command output
			//
			LineIterator line_iterator = new LineIterator(brIn);
			String line = "";
			long line_count = 30;
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
		        	
		        	if(plugin_name != null && plugin_name.toLowerCase().trim().equals("dlldump"))
		        		process_plugin_line_DLLDUMP(line);
		        	
		        	if(tree_execution_output != null)
		        		process_plugin_line(line);
		        	
		        	//log
		        	pw.println(line);
		        }		       	       		       		        	                		        		      
		    }
		    catch(Exception e)
		    {
		    	driver.sop("check plugin process execution " + plugin_name + " - " + cmd);
		    }
		        
		      
		    if(plugin_name != null && plugin_name.toLowerCase().trim().equals("dlldump"))
		    	analyze_dlldump(this.fle_dump_directory, pw);
		    else
		    	analyze_dump_procdump(this.fle_dump_directory, pw);
		    
		   //clean up
		    try	{ 	brIn.close();       		}	catch(Exception e){}
		    try	{	process.destroy();			}	catch(Exception e){}
		    try	{ 	line_iterator.close();      }	catch(Exception e){}
		    
		    try	{	pw.flush();} catch(Exception e){}
			try	{	pw.close();} catch(Exception e){}
			
			
			
			//
			//NOTIFY
			//
			sop("\n" + this.plugin_name + " execution complete.");
			//sop("\n\nExecution complete. If successful, output file has been written to --> " + fleOutput + "\n");
				
						
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "execute_plugin", e);
		}
		
		return false;
	}
	
	
	/**
	 * Progress through this, analyze each line, input is similar to 0xfffffa800148f040 smss.exe             0x0000000047ef0000 smss.exe             OK: module.248.3f68f040.47ef0000.dll
	 * and convert and store the files to be renamed in analyze_dll dump 
	 * @return
	 */
	public boolean process_plugin_line_DLLDUMP(String line)
	{
		try
		{
			if(line == null)
				return false;
			
			String lower = line.toLowerCase().trim();
			
			if(lower.equals(""))
				return false;
			
			//0xfffffa8001c38580 svchost.exe          0x000007fefd8c0000 RpcRtRemote.dll      Error: DllBase is paged
			if(lower.contains("error: dllBase is paged") || !lower.contains("ok: module."))
				return false;
			
			//0xfffffa800148f040 smss.exe             0x0000000077c90000 ntdll.dll            OK: module.248.3f68f040.77c90000.dll

			//Bifurcate result and module info
			String arr[] = line.split("OK: ");
			
			if(arr == null || arr.length < 2)
				return false;
			
			//0xfffffa800148f040 smss.exe             0x0000000077c90000 ntdll.dll 
			String token_0 = arr[0].trim();

			
			//
			//token 0
			//
			//0xfffffa800148f040 smss.exe             0x0000000077c90000 ntdll.dll
			String [] arr_header = token_0.split(" ");
			
			String process_offset_V = arr_header[0].toLowerCase().trim();
			
			String name = arr_header[1].trim();
			
			int i = 2; 
			for(; i < arr_header.length; i++)
			{
				if(arr_header[i].toLowerCase().contains("0x"))
					break;
				else 
					name = name + " " + arr_header[i].trim();
			}
			
			String module_base_address = arr_header[i++].trim();
			
			String module_name = arr_header[i++].trim();
			
			for(; i < arr_header.length; i++)
				module_name = module_name + " " + arr_header[i].trim();
			
			name = name.trim();
			module_name = module_name.trim();
			
			//
			//token 1
			//
			
			//module.248.3f68f040.77c90000.dll --> module.PID.process_offset(P).image_base_address; 
			//note, if image_base_address starts with 7, it is a dll, or 4 and it is an exe
			String token_1 = arr[1].trim();
			
			//bifurcate module data
			String arr_module [] = token_1.split("\\.");
						
			//248
			int PID = Integer.parseInt(arr_module[1].trim());
			
			//3f68f040 --> trimmed, i.e., 	given 0x0000000047ef0000 --> 47ef0000	
			String process_offset_P_trimmed = arr_module[2].toLowerCase().trim();
			
			//77c90000
			String module_base_address_trimmed = arr_module[3].trim();
									
			Node_Generic node = new Node_Generic(this.plugin_name);
			node.process_offset_V = process_offset_V.toLowerCase().trim();
			node.name = name.trim();
			node.module_base_address = module_base_address.toLowerCase().trim();
			node.module_name = module_name.trim();
			node.PID = PID;
			node.pid = ""+PID;
			node.process_offset_P_trimmed = process_offset_P_trimmed.toLowerCase().trim();
			node.module_base_address_trimmed = module_base_address_trimmed.toLowerCase().trim();
			
			String conversion_name = name + "_" + PID + "_" + module_name + "_" + process_offset_P_trimmed + "_" + module_base_address_trimmed;
			
			//store name conversion
			tree_DLL_result_to_file_name_conversion.put(token_1.toLowerCase().trim(), conversion_name);
			
			//store the DLL node
			try	{this.tree_DLL_result_to_Node_DLL.put(token_1.toLowerCase().trim(), director.tree_DLL_MODULES_linked_by_VAD_base_start_address.get(module_base_address.toLowerCase().trim()).getFirst());	}	catch(Exception e){}
			
			//Store the Process node
			try	{this.tree_DLL_result_to_Node_Process.put(token_1.toLowerCase().trim(), director.tree_PROCESS.get(PID));	}	catch(Exception e){}
			
			
			//link
			director.tree_Module_Name_from_base_address_as_key.put(module_base_address, module_name);
			director.tree_Module_Name_from_base_address_trimmed_as_key.put(module_base_address_trimmed, module_name);
			director.tree_Process_Name_from_process_offset_V.put(process_offset_V, name);
			director.tree_Process_Name_from_process_offset_P_trimmed.put(process_offset_P_trimmed, name);
			
			//update Node_Process
			Node_Process process = director.tree_PROCESS.get(PID);
			
			if(process != null)
			{
				if(process.process_name.toLowerCase().trim().equals(module_name.toLowerCase().trim()))
				{
					//0xfffffa800148f040
					process.offset_V_dlldump = process_offset_V.toLowerCase().trim();
					
					//0x0000000047ef0000
					process.module_base_address_dlldump = module_base_address;
					
					//47ef0000
					process.module_base_address_dlldump_trimmed = module_base_address_trimmed;
					
					//3f68f040
					process.offset_P_dlldump_trimmed = process_offset_P_trimmed;
					
					//link
					director.tree_Process_from_offset_P_trimmed.put(process_offset_P_trimmed, process);
					director.tree_Process_from_offset_V.put(process_offset_V, process);
					director.tree_Process_from_module_base_address_trimmed.put(module_base_address_trimmed, process);
					director.tree_Process_from_module_base_address.put(module_base_address, process);
				}
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_plugin_line_DLLDUMP on line: " + line, e, true);
		}
		
		return false;
	}

	/**
	 * e.g. moddump - 0x0f82f0000 portcls.sys          OK: driver.f82f0000.sys
	 * Dumped file needs translation back to original file name
	 */
	public boolean process_plugin_line(String line)
	{
		try
		{
			if(line == null)
				return false;
			
			line = line.trim();
			
			if(line.equals(""))
				return false;
			
			if(line.trim().startsWith("#"))
				return false;
			
			
			//0x0f8bae000 swenum.sys           OK: driver.f8bae000.sys

			String array [] = line.split(" ");
			
			if(array == null || array.length < 2)
				return false;
			String lower = "";
			String name = "";
			String dumped_file_name = null;//use indication that is it no longer null to begin saving into the variable e.g.  driver.f82d9000.sys of line 0x0f82d9000 ndiswan.sys          OK: driver.f82d9000.sys

			for(String token : array)
			{
				if(token == null)
					continue;
				
				token = token.trim();
				
				if(token.equals(""))
					continue;
				
				lower = token.toLowerCase().trim();
				
				if(lower.startsWith("0x"))
					continue;
				
				//OK:
				if(token.contains(":"))
					dumped_file_name = "";
				
				if(dumped_file_name == null)//add data to name							
					name = name + token + " ";
				else//time to store the dumped file name
					dumped_file_name = dumped_file_name + token + " ";
			}
			
			if(dumped_file_name != null)
				dumped_file_name = dumped_file_name.trim();
			
			name = name.trim();
			
			if(name.equals("") || dumped_file_name.equals(""))
			{
				this.error_processing_line(line + " I could not determine name:[" + name + "] or dumped_file_name: [" + dumped_file_name + "]");
				return false;
			}
			
			this.tree_execution_output.put(dumped_file_name.toLowerCase().trim(), name);
			
			sop("Just stored dumped_file_name: [" + dumped_file_name + "] as key for name value: [" + name + "]");
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_plugin_line",  e);
		}
		
		return false; 		
	}
	
	public boolean analyze_dump_procdump(File dir, PrintWriter pw)
	{
		try
		{
			if(dir == null || !dir.exists())
				return false;
			
			LinkedList<File> list = new LinkedList<File>();
			
			if(dir.isDirectory())
				list = driver.getFileListing(dir, false, null, list);
			else
				list = driver.getFileListing(dir.getParentFile(), false, null, list);
				
			
			pw.println("\n\n\n#################################################################################################################");
			pw.println("# FILE DETAILS");
			pw.println("#################################################################################################################");
			
			
			//iterate through list
			String path = "";
			String [] array = null;
			
			for(File fle : list)
			{
				try
				{
					if(fle == null || !fle.exists() || !fle.isFile())
						continue;
					
					path = fle.getCanonicalPath().toLowerCase().trim();

					if(path.endsWith(".txt"))
						continue;
					
					array = path.split("\\.");
					
					//executable.4072.exe
					if(plugin_name.toLowerCase().equals("procdump"))
						process_procdump_file(array, fle, pw);
//					else if(plugin_name.toLowerCase().equals("dlldump"))
//						process_dlldump_file(array, fle, pw);
					
					
				}
				catch(Exception e)
				{
					continue;
				}
			}
			
			if(this.plugin_name.toLowerCase().trim().equals("procdump"))
				write_file_imports();
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_dump_procdump", e);
		}
		
		return false;
	}
	
	
	/**
	 * value is toLowerCase() already --> executable.4072.exe
	 * @param array
	 * @return
	 */
	public boolean process_procdump_file(String [] array, File fle, PrintWriter pw)
	{
		try
		{
			if(array == null)
				return false;
			
			
			if(array.length < 2)
				return false;
			
			String extention_from_header_in_case_missing_extension = "exe";
			
			int PID = -1;
			Node_Process process = null;
			
			//0x81fd0820 0x01000000 explorer.exe         OK: executable.888.exe --> <path>/executable.888.exe
			if(array[0].trim().startsWith("exe"))
				extention_from_header_in_case_missing_extension = "exe";

			//search for the first number, and we'll take that as the PID
			for(String value : array)
			{
				try
				{
					PID = Integer.parseInt(value.trim());
					break;
				}
				catch(Exception e)
				{
					continue;
				}
			}
			
			if(PID < 0)
				return false;
			
			String extension = array[array.length -1].trim();
			
			//ensure extension is not left off
			if(extension.equals(""+PID))
				extension = extention_from_header_in_case_missing_extension;
			else if(extension.equals(""))
				extension = extention_from_header_in_case_missing_extension;
			
			//get Process
			process = director.tree_PROCESS.get(PID);							
			
			//good process name, name the file!
			File fleNew = null;
			
			String path = fle.getParentFile().getCanonicalPath().trim();
			
			if(!path.endsWith(File.separator))
				path = path + File.separator;
			
			boolean process_file_name = true;
			
			if(director.INOCULATE_FILE_EXECUTABLE_EXTENSION)
			{
				if(process == null || process.process_name == null || process.process_name.trim().equals(""))
					fleNew = new File(fle.getCanonicalPath().replace(".exe", "_exe"));
				else
					fleNew = new File(path + process.process_name.replace(".exe", "") + "_" + PID + "_" + extension);
			}
			else if(process != null && process.process_name != null && !process.process_name.trim().equals(""))
				fleNew = new File(path + process.process_name + "_" + PID + "." + extension);
			else
			{
				process_file_name = false;
				fleNew = fle;
			}

			boolean status = false;
			
			if(process_file_name)
				status = fle.renameTo(fleNew);								

			process.fle = fleNew;
			try	{	process.file_name = fle.getName();	} catch(Exception e){}
			process.fle_attributes = new FileAttributeData(fleNew, process, null);
			process.fle_attributes.set_hash(false);
			process.fle_attributes.extension = extension;
			process.extension = extension;
			
			pw.println(process.fle_attributes.get_attributes("\t  "));
			
			//read PE Header and import information
			if(driver.isWindows)
				read_file_import_dependencies(fleNew, process, PID);
			else						
				;//Solo, return and process for Linux! - readpe
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_procdump_file", e);
		}
		
		return false;
	}
	
	/**
	 * process, read PECOFF header for imports, etc - this is only for WINDOWS! - I may return to make compatible with Linux
	 * @param pw
	 * @param fle
	 * @param process
	 * @param PID
	 * @return
	 */
	public boolean read_file_import_dependencies(File fle, Node_Process proc, int PID)
	{
		try
		{
			File fle_import_analyzer = Start.fle_dependencies;
			
			
			if(fle_import_analyzer == null || !fle_import_analyzer.exists() || !fle_import_analyzer.isFile())
				return false;
		
			if(fle == null || !fle.exists() || !fle.isFile())
				return false;
		
			//create parent directory if needed
			String path = fle.getParentFile().getCanonicalPath().trim();
			
			if(!path.endsWith(File.separator))
				path = path + File.separator;
			
			parent_directory_file_header = new File(path + "file_header");
			
			try	{	parent_directory_file_header.mkdirs();	} catch(Exception e){}
			
			path_parent_directory_file_header = parent_directory_file_header.getCanonicalPath().trim();
			
			if(!path_parent_directory_file_header.endsWith(File.separator))
				path_parent_directory_file_header = path_parent_directory_file_header + File.separator;
			
			File output = new File(path + "file_header" + File.separator + fle.getName() + "_dependencies.txt");
			
			
			
			PrintWriter pw = new PrintWriter(new FileWriter(output));
			
			//
			//EXECUTE COMMAND!
			//
			
			String command = "\"" + fle_import_analyzer.getCanonicalPath() + "\"";
			String params = " -imports \"" + fle.getCanonicalPath();//leave last " off
			
			String execution_command = "";
			ProcessBuilder process_builder = null;				
			
			if(driver.isWindows)
			{
				process_builder = new ProcessBuilder("cmd.exe", "/C",  command + params);
				execution_command = command +  params;							
			}
							
			//else if(driver.isLinux)
			else
			{
				process_builder = new ProcessBuilder("/bin/bash", "-c",  "readpe " +  "\" " + fle.getCanonicalPath() + "\"");				
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
														
			BufferedReader brIn = new BufferedReader(new InputStreamReader(process.getInputStream()));

//sop("Executing: " + execution_command);
			//
			//process command output
			//
			LineIterator line_iterator = new LineIterator(brIn);
			String line = "";
			String lower = "";
			long line_count = 30;
			Node_DLL dll = null;
		    try 
		    {
		        while (line_iterator.hasNext()) 
		        {	     		        	
		        	line = line_iterator.nextLine();
		        	
		        	if(line == null)
		        		continue;
		        	
		        	
		        	lower = line.toLowerCase().trim();
		        	
		        	
		        	//sop(line);
		        	
		        	//Import from module ADVAPI32.dll : --> from dependencies.exe
		        	if(lower.startsWith("import from module ") && lower.contains(":"))
		        		dll = Node_DLL.get_dll(line.trim().substring(18, line.lastIndexOf(":")).trim(), proc, director.tree_DLL_by_path);
		        	
		        	//Function SetSecurityDescriptorOwner --> from dependencies.exe
		        	else if(lower.startsWith("function ") && !lower.contains(":") && dll != null)
		        		dll.store_import_function(line.trim().substring(8).trim(), proc);

		        	

		        	
		        	//log
		        	pw.println(line);
		        	
		        	//analyze line
		        	
		        }		       	       		       		        	                		        		      
		    }
		    catch(Exception e)
		    {
		    	driver.eop(myClassName, "read_file_import_dependencies - loop", e);
		    }

			
			
			
			
			
			
			
			
			try	{	pw.flush();} catch(Exception e){}
			try	{	pw.close();} catch(Exception e){}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "read_file_import_dependencies", e);
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
	
	
	
	
	
	
	
	
	
	
		
	
//	/**
//	 * value is toLowerCase() already --> 0x822349f0 winlogon.exe         0x07c900000 ntdll.dll            OK: module.632.24349f0.7c900000.dll
//	 * @param array
//	 * @return
//	 */
//	public boolean process_dlldump_file(String [] array, File fle, PrintWriter pw)
//	{
//		try
//		{
//			if(array == null)
//				return false;
//			
//			
//			if(array.length < 4)
//				return false;
//			
//			String extention_from_header_in_case_missing_extension = "dll";
//						
//			
//			int PID = -1;
//			Node_Process process = null;
//			Node_DLL dll = null;
//			
//			if(fle == null || !fle.exists())
//				return false;
//			
//			//OK: module.632.24349f0.7c900000.dll
//			
//			String header = array[0].trim();			
//			try	{	PID = Integer.parseInt(array[1].trim());	} catch(Exception e){}
//			String function_address = array[2].trim();
//			String module_VAD_base_start_address = array[3].trim();
//			String extension = "dll";
//			try	{ extension = array[4].trim();}	catch(Exception e)	{ extension = "dll";}
//			
//			if(PID < 0)
//				return false;
//						
//			//get Process
//			process = director.tree_PROCESS.get(PID);
//			
//			//translate base address
//			
//			//pad module.1044.ccdbd.1090000 --> module.1044.ccdbd.01090000  
//			module_VAD_base_start_address = module_VAD_base_start_address.replace("0x",  "");//get rid of 0x for now...
//			for(int i = module_VAD_base_start_address.length(); i < 8; i++)
//				module_VAD_base_start_address = "0" + module_VAD_base_start_address;
//			
//			module_VAD_base_start_address = "0x" + module_VAD_base_start_address;
//			
//			//pad function_address
//			function_address = function_address.replace("0x",  "");//get rid of 0x for now...
//			for(int i = function_address.length(); i < 8; i++)
//				function_address = "0" + function_address;
//			
//			function_address = "0x" + function_address;
//			
//			//get DLL
//			try
//			{
//				LinkedList<Node_DLL> list = director.tree_DLL_MODULES_linked_by_VAD_base_start_address.get(module_VAD_base_start_address);
//												
//				if(list != null && list.size() < 2)
//					dll = list.getFirst();
//				else//extract dll name from the line
//				{
//					for(Node_DLL node : list)
//					{
//						if(node == null)
//							continue;
//						
//						if(process.tree_dll.containsValue(node));
//						{
//							dll = node;
//							break;
//						}
//					}
//				}
//				
//				
//			}
//			catch(Exception e){}
//									
//			//good process name, name the file!
//			File fleNew = null;
//			
//			
//			String dll_file_name = "_";
//			
//			if(dll != null)
//			{
//				try
//				{
//					if(dll.path.contains("\\"))
//						dll_file_name = dll.path.substring(dll.path.lastIndexOf("\\")+1).trim();
//					else
//						dll_file_name = dll.path.substring(dll.path.lastIndexOf("/")+1).trim();
//										
//				}
//				catch(Exception e){dll_file_name = "_";}				
//			}
//
//			String path = fle.getParentFile().getCanonicalPath().trim();
//			
//			if(!path.endsWith(File.separator))
//				path = path + File.separator;
//			
//			
//			try	  				{ path = path + dll_file_name + "_" + process.process_name.replace(".exe", "_exe").trim() + "_" + process.PID + "_" + function_address + "_" + module_VAD_base_start_address;	}
//			catch (Exception e)	{ path = fle.getCanonicalPath().replace("module.", dll_file_name + "." + process.process_name + ".").replace(".exe", "_exe").trim();}
//			
//			//fleNew = new File(fle.getCanonicalPath().replace("module.", dll_file_name + "." + process.process_name + ".").replace(".exe", "_exe").trim());
//			fleNew = new File(path);
//
//			boolean status = fle.renameTo(fleNew);								
//
//			if(dll != null)
//			{
//				dll.file_dump_name = dll_file_name;
//				
//				dll.fle = fleNew;
//				dll.fle_attributes = new FileAttributeData(fleNew, null, dll);
//				dll.fle_attributes.set_hash(false);		
//				dll.fle_attributes.short_file_name = dll_file_name;
//				
//				//multiple dll dumps could exist even for the same DLL - just different based on the Process. Store the attribute to PID as well
//				if(process != null)
//					dll.tree_file_dump_attributes.put(process.PID, dll.fle_attributes);
//				
//				pw.println(dll.fle_attributes.get_attributes("\t  "));
//			}
//			
//			
//			return true;
//		}
//		catch(Exception e)
//		{
//			driver.eop(myClassName, "process_dlldump_file", e, true);
//		}
//		
//		return false;
//	}
	
	
	public boolean analyze_dlldump(File dir, PrintWriter pw)
	{
		try
		{
			if(dir == null || !dir.exists())
				return false;
			
			LinkedList<File> list = new LinkedList<File>();
			
			if(dir.isDirectory())
				list = driver.getFileListing(dir, false, null, list);
			else
				list = driver.getFileListing(dir.getParentFile(), false, null, list);
				
			
			pw.println("\n\n\n#################################################################################################################");
			pw.println("# FILE DETAILS");
			pw.println("#################################################################################################################");
			
			
			//iterate through list
			String path = "", path_lower;
			String [] array = null;
			String file_name_lower = null;
			for(File fle : list)
			{
				try
				{
					if(fle == null || !fle.exists() || !fle.isFile())
						continue;
					
					path_lower = fle.getCanonicalPath().toLowerCase().trim();

					if(path_lower.endsWith(".txt"))
						continue;
					
					file_name_lower = fle.getName().toLowerCase().trim();
					
					String new_file_name = this.tree_DLL_result_to_file_name_conversion.get(file_name_lower);
					
					if(new_file_name == null)
						continue;
					
					path = fle.getParentFile().getCanonicalPath().trim();
					
					if(!path.endsWith(File.separator))
						path = path + File.separator;
					
					path = path + new_file_name;
					
					//change the name
					try	
					{							
						File new_file = new File(path);
						fle.renameTo(new File(path));
						FileAttributeData attr = new FileAttributeData(new_file, true, false);
						pw.println(attr.toString("", "\t ", false));
						
						//set attribute to process or dll node
						Node_Process process = null;
						Node_DLL DLL = null;
						
						if(this.tree_DLL_result_to_Node_DLL.containsKey(file_name_lower))
							DLL = this.tree_DLL_result_to_Node_DLL.get(file_name_lower);
						
						if(this.tree_DLL_result_to_Node_Process.containsKey(file_name_lower))
							process = this.tree_DLL_result_to_Node_Process.get(file_name_lower);
						
						//store the attribute
						if(process != null && process.fle_attributes == null)
							process.fle_attributes = attr;
						
						if(DLL != null && DLL.fle_attributes == null)
							DLL.fle_attributes = attr;
						
					} catch(Exception e){}
					
				}
				catch(Exception e)
				{
					continue;
				}
			}
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_dlldump", e);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	

}
