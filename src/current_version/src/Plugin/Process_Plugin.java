/**
 * Process thread created specifically to support each plugin requested by the user
 * 
 * @author Solomon Sonya
 */

package Plugin;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.io.*;
import java.util.*;
import java.util.LinkedList;

import org.apache.commons.io.LineIterator;

import Advanced_Analysis.Advanced_Analysis_Director;
import Driver.Driver;
import Driver.FileAttributeData;
import Driver.FilePrintWriter;
import Driver.Start;
import Interface.Interface;
import Interface.JTextArea_Solomon;

public class Process_Plugin extends Thread implements Runnable
{
	public static final String myClassName = "Process_Plugin";
	public volatile static Driver driver = new Driver();
	
	public static volatile boolean INOCULATE_FILE_EXECUTABLE_EXTENSION = true;
	
	public volatile Plugin parent = null;
	public volatile String cmd = "";
	public boolean set_canonical_paths = true;
	public String plugin_name = "not_specified";
	public String plugin_description = "not_specified";
	/**Useful in Snapshot_Plugin analysis, override enabled means no matter what, store the output and we'll process it later*/
	public boolean override_store_output = false;
	
	/**Allows us to add additional detail to the file name. e.g. psscan_PRE_<timestamp>.txt. It is ok to be null*/
	public String additional_file_name_detail = "";
	
	public volatile LinkedList<String> output = null;
	
	public static boolean hash_extracted_files = true;
	
	public static String EXECUTION_TIME_STAMP = driver.getTime_Specified_Hyphenated_with_seconds_using_colon(System.currentTimeMillis());
	
	public static volatile TreeMap<Integer, String> tree_PROCESS = new TreeMap<Integer, String>();
	public static volatile TreeMap<String, String> tree_dumpfiles_offsets = new TreeMap<String, String>();
	
	public volatile boolean EXECUTION_COMPLETE = false;
					
	public volatile File fleImage_file = null;
	
	/**if this is null, we'll default to Interface.file_attr_memory_image*/
	public volatile FileAttributeData file_attr_memory_image = null;
	
	public volatile String MFT_HEADER = null;
	public volatile LinkedList<String> list_prefetch = null;
	public volatile LinkedList<String> list_mft = null;
	
	/**For storing the Foreign IP address a connection could have been made to*/
	public volatile LinkedList<String> list_connections = null;
	
	 public volatile static LinkedList<Process_Plugin> list_plugin_in_execution = new LinkedList<Process_Plugin>();
	 
	 public volatile File fleOutput = null;
	 public volatile String path_to_output_directory = null;
			
	 public volatile String super_timeline_entry = null;
	 
	 /**Non-executing plugin*/
	 public Process_Plugin(Plugin par, String PLUGIN_NAME, String PLUGIN_DESCRIPTION)
		{
			try
			{
				parent = par;
				
				plugin_name = PLUGIN_NAME;
				plugin_description = PLUGIN_DESCRIPTION;
				
				if(file_attr_memory_image == null)
					file_attr_memory_image = Interface.file_attr_memory_image;
				
				try
				{
					if(parent == null)
						parent = Plugin.tree_plugins.get(PLUGIN_NAME);
				}
				catch(Exception e)
				{
					driver.directive("NOTE: I COULD NOT FIND SPECIFIC PLUGIN [" + PLUGIN_NAME + "] - This could provide unexpected runtime results...");
				}
				
			}
			catch(Exception e)
			{
				driver.eop(myClassName, "Constructor - 1");
			}		
			
		}
	 
	 /**
	  * Execution plugin
	  * @param par
	  * @param PLUGIN_NAME
	  * @param PLUGIN_DESCRIPTION
	  * @param image_file_ok_to_be_null
	  * @param file_attr_memory_img_ok_to_be_null
	  * @param execution_command
	  * @param SET_CANONICAL_PATHS
	  * @param OVERRIDE_STORE_OUTPUT
	  * @param ADDITIONAL_FILE_NAME_DETAIL
	  * @param execute_in_separate_thread
	  */
	public Process_Plugin(Plugin par, String PLUGIN_NAME, String PLUGIN_DESCRIPTION, File image_file_ok_to_be_null, FileAttributeData file_attr_memory_img_ok_to_be_null, String execution_command, boolean SET_CANONICAL_PATHS, boolean OVERRIDE_STORE_OUTPUT, String ADDITIONAL_FILE_NAME_DETAIL, boolean execute_in_separate_thread)
	{
		try
		{
			parent = par;
			cmd = execution_command;
			set_canonical_paths = SET_CANONICAL_PATHS;
			plugin_name = PLUGIN_NAME;
			plugin_description = PLUGIN_DESCRIPTION;
			override_store_output = OVERRIDE_STORE_OUTPUT;
			fleImage_file = image_file_ok_to_be_null;
			
			file_attr_memory_image = file_attr_memory_img_ok_to_be_null;
			
			if(file_attr_memory_image == null)
				file_attr_memory_image = Interface.file_attr_memory_image;
			
			try
			{
				if(parent == null)
					parent = Plugin.tree_plugins.get(PLUGIN_NAME);
			}
			catch(Exception e)
			{
				driver.directive("NOTE: I COULD NOT FIND SPECIFIC PLUGIN [" + PLUGIN_NAME + "] - This could provide unexpected runtime results...");
			}
			
			
			if(ADDITIONAL_FILE_NAME_DETAIL == null || ADDITIONAL_FILE_NAME_DETAIL.trim().equals(""))
				ADDITIONAL_FILE_NAME_DETAIL = "";
			else
			{
				additional_file_name_detail = ADDITIONAL_FILE_NAME_DETAIL.trim();
				
				if(!additional_file_name_detail.endsWith("_"))
					additional_file_name_detail = additional_file_name_detail + "_";							
			}
			
			
			if(execute_in_separate_thread)
				this.start();
			else
				execute_command();
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 2");
		}		
		
	}
	
	public void run()
	{
		try
		{
			execute_command();
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "run", e);
		}
	}

	
	public boolean execute_command()
	{
		try
		{
			//
			//VALIDATE WE'RE READY TO PROCEED
			//
			if(this.cmd == null || cmd.trim().equals(""))
			{
				driver.sop("ERROR! Empty command received for plugin: [" + plugin_name + "]. I will not be able to continue further for this execution plugin. ");
				return false;
			}
			
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
			//UPDATE CANONICAL PATHS IF REQUIRED
			//
			
			if(this.set_canonical_paths)
			{
				if(driver.isWindows)
				{
					if(!(cmd.contains("\\" + Interface.fle_volatility.getName()) || cmd.contains("/" + Interface.fle_volatility.getName().trim())))
					{
						cmd = cmd.replaceFirst(Interface.fle_volatility.getName().trim(), "\"" + Interface.fle_volatility.getCanonicalPath().replace("\\", "/") + "\"");
					}
					
					if(this.fleImage_file != null && this.fleImage_file.exists() && this.fleImage_file.isFile())
					{					
						//coming here, we could assume the execution command already contains the data parameters we're looking for
						//so do nothing besides convert the slashes if needed
						cmd = cmd.replace("\\", "/");					
					}
					else if(!(cmd.contains("\\" + Interface.fle_memory_image.getName()) || cmd.contains("/" + Interface.fle_memory_image.getName())))
					{
						cmd = cmd.replaceFirst(Interface.fle_memory_image.getName().trim(), "\"" + Interface.fle_memory_image.getCanonicalPath().replace("\\", "/") + "\"");
					}
				}
				else
				{
					if(!(cmd.contains("\\" + Interface.fle_volatility.getName()) || cmd.contains("/" + Interface.fle_volatility.getName().trim())))
					{
						cmd = cmd.replaceFirst(Interface.fle_volatility.getName().trim(), File.separator + Interface.fle_volatility.getCanonicalPath().replace("\\", "/") + File.separator);
					}
										
					if(!(cmd.contains("\\" + Interface.fle_memory_image.getName()) || cmd.contains("/" + Interface.fle_memory_image.getName())))
					{
						cmd = cmd.replaceFirst(Interface.fle_memory_image.getName().trim(), File.separator + Interface.fle_memory_image.getCanonicalPath().replace("\\", "/") + File.separator);
					}
				}
				
			}
			
			//split the command now into command and params
			String array [] = cmd.split("\\-f");
			
			String command = array[0].trim();
			String params = "";
			String execution_command = "";
			boolean store_output = override_store_output;
			boolean rename_files = false;
			output = null;
			
			for(int i = 1; array != null && i < array.length; i++)
			{
				params = params + " -f " + array[i].trim();
			}
			
			//cmd = Interface.fle_volatility.getCanonicalPath() + " –f " + Interface.fle_memory_mage.getCanonicalPath() + " " + plugin_name + " --profile=" + Interface.PROFILE;
			
			//
			//NOTIFY
			//
			if(parent != null && parent.jtaConsole != null)
        		parent.jtaConsole.append("[" + plugin_name + "]\t Executing command --> " + command + params + "\n");
			
			//
			//INITIALIZE OUTPUT DIRECTORY
			//
			String time_stamp = driver.get_time_stamp("_");
			//this.fleLog_Whois = new File(this.pathTopFolder_whois + DOMAIN_NAME + "_" + driver.get_time_stamp("_") + ".txt");
			
			if(Advanced_Analysis_Director.DO_NOT_INCLUDE_TIME_STAMP_IN_FILE_NAME)
			{
				if(additional_file_name_detail == null || additional_file_name_detail.trim().equals(""))
					fleOutput = new File(Interface.path_fle_analysis_directory + this.plugin_name + File.separator + "_" + plugin_name + ".txt");
				else
					fleOutput = new File(Interface.path_fle_analysis_directory + this.plugin_name + File.separator + "_" + plugin_name + "_" + additional_file_name_detail  + ".txt");
			}
			else
				fleOutput = new File(Interface.path_fle_analysis_directory + this.plugin_name + File.separator + "_" + plugin_name + "_" + additional_file_name_detail + time_stamp + ".txt");
			
			File fleOutput_connections = null;
			
			try	{	if(!fleOutput.getParentFile().exists() || !fleOutput.getParentFile().isDirectory())
				fleOutput.getParentFile().mkdirs();								
			}	 catch(Exception e){}
			
			
			//
			//EXECUTE COMMAND!
			//
			ProcessBuilder process_builder = null;	
			
			if(	parent != null &&
				   (parent.plugin_name.equalsIgnoreCase("mftparser") 	||
					parent.plugin_name.equalsIgnoreCase("pslist") 		||
					parent.plugin_name.equalsIgnoreCase("pstree") 		||
					parent.plugin_name.equalsIgnoreCase("psscan")))
				{
					store_output = true;
				}
			
			if(Plugin.list_include_tsv_data != null && Plugin.list_include_tsv_data.contains(plugin_name.toLowerCase().trim()))
					store_output = true;
			
			if(		parent != null &&
				   (parent.plugin_name.equalsIgnoreCase("procdump") 	||
					parent.plugin_name.equalsIgnoreCase("dlldump") 		||
					parent.plugin_name.equalsIgnoreCase("dumpcerts") 	||
					parent.plugin_name.equalsIgnoreCase("dumpfiles") 	||
					parent.plugin_name.equalsIgnoreCase("dumpregistry") ||
					parent.plugin_name.equalsIgnoreCase("memdump") 		||
					parent.plugin_name.equalsIgnoreCase("moddump")		||
					params.contains("--dump-dir")))
				{
					store_output = true;
					rename_files = true;
				}
			
			if(override_store_output)
				store_output = true;
			
			
			if(driver.isWindows)
			{
				if(	parent != null &&
				   (parent.plugin_name.equalsIgnoreCase("procdump") 	||
					parent.plugin_name.equalsIgnoreCase("dlldump") 		||
					parent.plugin_name.equalsIgnoreCase("dumpcerts") 	||
					parent.plugin_name.equalsIgnoreCase("dumpfiles") 	||
					parent.plugin_name.equalsIgnoreCase("dumpregistry") ||
					parent.plugin_name.equalsIgnoreCase("memdump") 		||
					parent.plugin_name.equalsIgnoreCase("moddump")		||
					parent.plugin_name.equalsIgnoreCase("evtlogs")		||
					parent.plugin_name.equalsIgnoreCase("vaddump")		||
					params.contains("--dump-dir")))
				{
					store_output = true;
					rename_files = true;
					
					if(params.contains("--dump-dir"))
						params = params.substring(0,params.indexOf("--dump-dir")).trim();					
					
					process_builder = new ProcessBuilder("cmd.exe", "/C",  command +  params, "--dump-dir", "./xavier_framework/export/memory_analysis/" + Interface.analysis_time_stamp + "/" + plugin_name);
					//process_builder = new ProcessBuilder("cmd.exe", "/C",  command +  params, "--dump-dir", "./");
					
					execution_command = command +  params + " " + "--dump-dir" +  " ./xavier_framework/export/memory_analysis/" + Interface.analysis_time_stamp + "/" + plugin_name;
				}
					
					
				else
				{
					process_builder = new ProcessBuilder("cmd.exe", "/C",  command +  params);
					execution_command = command +  params;
				}
			}
							
			else if(driver.isLinux)
			{
				process_builder = new ProcessBuilder("/bin/bash", "-c",  command +  params);
				
				execution_command = command +  params;
			}
			
			//
			//redirect error stream
			//
			process_builder.redirectErrorStream(true); 
					
			//notify
			driver.sop("Executing plugin: [" + this.plugin_name + "]...");
			
			//
			//setup
			//
			//instantiate new process
			Process process = process_builder.start();
			
			//
			//store in list
			//
			try	{	list_plugin_in_execution.add(this);	}	 catch(Exception ee){ driver.sop("Standby, currently executing plugin [" + this.plugin_name + "]");}
			
			//
			//process input
			//
			PrintWriter pw = new PrintWriter(new FileWriter(fleOutput), true);
			
			if(command.toLowerCase().contains("volatility") || params.toLowerCase().contains("volatility"))
				write_process_header(pw, execution_command);
			
			BufferedReader brIn = new BufferedReader(new InputStreamReader(process.getInputStream()));
			
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

		        	if(parent != null && parent.jtaConsole != null)
		        		parent.jtaConsole.append(line);
		        	

		        	if(store_output)
		        	{
		        		if(output == null)
		        			output = new LinkedList<String>();
		        		
		        		output.add(line);
		        	}
		        	
		        	//log
		        	pw.println(line);
		        }
		        
		        
		        //
		        //Check if we're providing output in TSV format as well
		        //
		        if(Plugin.list_include_tsv_data != null && Plugin.list_include_tsv_data.contains(plugin_name.toLowerCase().trim()))
		        	write_output_tsv(pw, output, "\t");
		        
		        //
		        //check if we're renaming the files
		        //
		        if(store_output && output != null && output.size() > 0)
		        {
		        	//process files for each plugin
		        	if(parent.plugin_name != null && parent.plugin_name.equalsIgnoreCase("dumpfiles"))
		        		process_plugin_dumpfiles(output, "./xavier_framework/export/memory_analysis/" + Interface.analysis_time_stamp + "/" + plugin_name, pw);
		        	else if(parent.plugin_name != null && parent.plugin_name.equalsIgnoreCase("psscan"))
		        		process_plugin_psscan(output);
		        	else if(parent.plugin_name != null && parent.plugin_name.equalsIgnoreCase("pslist"))
		        		process_plugin_pslist(output);
		        	else if(parent.plugin_name != null && parent.plugin_name.equalsIgnoreCase("pstree"))
		        		process_plugin_pstree(output);
		        	else if(parent.plugin_name != null && parent.plugin_name.equalsIgnoreCase("mftparser"))
		        		process_plugin_mftparser(output, pw, "\t", fleOutput);
		        	else if(rename_files)
		        		rename_files(output, "./xavier_framework/export/memory_analysis/" + Interface.analysis_time_stamp + "/" + plugin_name, pw);
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
			//process socket connections if applicable
			//
			try
			{
				if(this.plugin_name.equalsIgnoreCase("netscan"))
					store_connections(output, 3);
				else if(this.plugin_name.equalsIgnoreCase("connscan"))
					store_connections(output, 2);
				else if(this.plugin_name.equalsIgnoreCase("connections"))
					store_connections(output, 2);
				else if(this.plugin_name.equalsIgnoreCase("sockscan"))
					store_connections(output, 5);
				else if(this.plugin_name.equalsIgnoreCase("sockets"))
					store_connections(output, 5);
				
				if(list_connections != null && !list_connections.isEmpty())
				{
					//write contents to disk
					if(Advanced_Analysis_Director.DO_NOT_INCLUDE_TIME_STAMP_IN_FILE_NAME)
						fleOutput_connections = new File(Interface.path_fle_analysis_directory + this.plugin_name + File.separator + "_" + "connections" + "_" + additional_file_name_detail + ".txt");
					else				
						fleOutput_connections = new File(Interface.path_fle_analysis_directory + this.plugin_name + File.separator + "_" + "connections" + "_" + additional_file_name_detail + time_stamp + ".txt");
					
					
					PrintWriter pwOut_connections = new PrintWriter(new FileWriter(fleOutput_connections));
					
					for(String connection : this.list_connections)
					{
						pwOut_connections.println(connection);
					}
					
					try	{	pwOut_connections.flush();} catch(Exception e){}
					try	{	pwOut_connections.close();} catch(Exception e){}
				}
			}
			catch(Exception e){}
			
			//
			//NOTIFY
			//
			if(parent != null && parent.jtaConsole != null)
			{
				parent.jtaConsole.append("\n\nExecution complete. If successful, output file has been written to --> " + fleOutput + "\n");
				parent.jbtnOpenOutputFile.setEnabled(true);
				parent.jbtnOpenOutputDirectory.setEnabled(true);
				parent.fleOutput = fleOutput;
				
				if(fleOutput_connections != null && fleOutput_connections.exists())
					parent.jtaConsole.append("It appears I was able to extract specific foreign addresses from this plugin and write them to disk. If successful, connection information file has been written to --> " + fleOutput_connections + "\n");
			}
			
			if(parent != null)
			{
				driver.sop("[" + parent.plugin_name.toUpperCase() + "]\t Execution complete. If successful, output file has been written to --> " + fleOutput);
				
				if(fleOutput_connections != null && fleOutput_connections.exists())
					driver.sop("It appears I was able to extract specific foreign addresses from this plugin and write them to disk. If successful, connection information file has been written to --> " + fleOutput_connections + "\n");
				
			}
			else
			{
				driver.sop("Execution complete. If successful, output file has been written to --> " + fleOutput);
				
				if(fleOutput_connections != null && fleOutput_connections.exists())
					driver.sop("It appears I was able to extract specific foreign addresses from this plugin and write them to disk. If successful, connection information file has been written to --> " + fleOutput_connections + "\n");				
			}
			
			//
			//remove from in list
			//
			try	{	list_plugin_in_execution.remove(this);	}	 catch(Exception ee){ driver.sop("* * * Standby, currently executing plugin [" + this.plugin_name + "]");}
			
			
			EXECUTION_COMPLETE = true;
			
			System.gc();
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "execute_command", e, true);
		}
		
		EXECUTION_COMPLETE = true;
		
		return false;
	}
	
	
	public boolean store_connections(LinkedList<String> list, int foreign_address_index)
	{
		try
		{
			if(list == null || list.isEmpty())
				return false;
			
			list_connections = new LinkedList<String>();
			
			String [] array = null;
			String lower = "";
			
			int element_index = 0;
			
			for(String line : list)
			{
				if(line == null)
					continue;
				
				line = line.trim();
				
				if(line.equals(""))
					continue;
				
				lower = line.toLowerCase().trim();
				
				if(lower.contains("volatility"))
					continue;
				
				if(lower.contains("error"))
					continue;
				
				if(lower.contains("debug"))
					continue;
				
				if(lower.contains("offset"))
					continue;
				
				if(lower.startsWith("---"))
					continue;
				
				array = line.split(" ");
				
				if(array == null || array.length < 1)
					continue;
				
				element_index = 0;
				
				for(String element : array)
				{
					if(element == null)
						continue;
					
					element = element.trim();
					
					if(element.equals(""))
						continue;
					
					if(element_index++ == foreign_address_index)
					{
						if(element.startsWith("192"))
							continue;
						else if(element.startsWith("127"))
							continue;
						else if(element.startsWith("0"))
							continue;
						else if(element.startsWith("10"))
							continue;
						//will expand on this later...
						
						if(list_connections.contains(element))
							continue;
						
						list_connections.add(element);	
						
						break;
					}
				}
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "store_connections_netscan", e);
		}
		
		return false;
	}
	
	public boolean write_output_tsv(PrintWriter pw, LinkedList<String> output, String delimiter)
	{
		try
		{
			if(pw == null)
				return false;
			
			if(output == null || output.isEmpty())
				return false;
			
			if(pw != null)
			{
				pw.println("\n#################################################################################################################");
				pw.println("# OUTPUT - TSV");
				pw.println("#################################################################################################################");
				

				if(parent != null && parent.jtaConsole != null)
				{
					parent.jtaConsole.append("\n#################################################################################################################");
					parent.jtaConsole.append("# OUTPUT - TSV");
					parent.jtaConsole.append("#################################################################################################################");
				}
			}
			
			String [] array = null;
			String lower = "";
			
			for(String line : output)
			{
				if(line == null)
					continue;
				
				line = line.trim();
				
				if(line.trim().equals(""))
					continue;
				
				lower = line.toLowerCase().trim();
				
				//reject Volatility	Foundation	Volatility	Framework
				if(lower.contains("volatility") && lower.contains("foundation") && lower.contains("framework"))
					continue;
				
				array = line.split(" ");
				
				if(array == null || array.length < 1)
					continue;
				
				for(String token : array)
				{
					token = token.trim();
					
					if(token.length() < 1 || token.equals(""))
						continue;
					
					pw.print(token + delimiter);
					
					if(parent != null && parent.jtaConsole != null)
						parent.jtaConsole.append_sp(token + delimiter);
				}
				
				pw.println();
				
				if(parent != null && parent.jtaConsole != null)
					parent.jtaConsole.append("");
				
			}
			
			try	{pw.flush(); 	}	catch(Exception e){}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_output_tsv", e);
		}
		
		return false;
	}
	
	public boolean rename_files(LinkedList<String> output, String directory_path, PrintWriter pwOut)
	{
		try
		{
			if(output == null || output.size() < 1 || directory_path == null || directory_path.trim().equals(""))
				return false;
			
			//
			//IGNORE CERTAIN 
			//
						
			//
			//PROCESS
			//
			File fle_directory_path = new File(directory_path);
			
			if(fle_directory_path == null || !fle_directory_path.exists() || !fle_directory_path.isDirectory())
				return false;
			
			//good files --> 0x81a92728 0x4ad00000 cmd.exe              OK: executable.2972.exe
			//bad file --> 0x81fa7848 ---------- kolu.exe             Error: PEB at 0x7ffdf000 is unavailable (possibly due to paging)
			
			String path = fle_directory_path.getCanonicalPath().trim();
			
			if(!path.endsWith(File.separator))
				path = path + File.separator;
			
			String current_output_file_name = "";
			String process_name_from_memory = "";
			String array [] = null;
			String array_memaddress_name [] = null;
			String [] array_pid = null;
			String [] array_name = null;
			String value = "";
			String md5 = "";
			String sha256 = "";
			int PID = -1;
			
			File fleCurrent = null;
			File fleNew = null;
			
			if(pwOut != null)
			{
				pwOut.println("\n#################################################################################################################");
				pwOut.println("# FILE DETAILS");
				pwOut.println("#################################################################################################################");
				

				if(parent != null && parent.jtaConsole != null)
				{
					parent.jtaConsole.append("\n#################################################################################################################");
					parent.jtaConsole.append("# FILE DETAILS");
					parent.jtaConsole.append("#################################################################################################################");
				}
			}
			
			for(String line : output)
			{
				current_output_file_name = "";
				process_name_from_memory = "";
				array = null;
				array_name = null;
				array_memaddress_name = null;
				array_pid = null;
				value = "";
				fleCurrent = null;
				fleNew = null;
				md5 = "";
				sha256 = "";
				PID = -1;
				
				if(line == null || line.trim().equals(""))
					continue;
				
				
				
				
				//////////////////////////////////////////////////////////////////////
				//dumpfiles
				//                 
				//e.g. 	ImageSectionObject 0x81abd078   1080   \Device\HarddiskVolume1\WINDOWS\system32\rasdlg.dll
				//		DataSectionObject 0x81abd078   1080   \Device\HarddiskVolume1\WINDOWS\system32\rasdlg.dll
				//
				/////////////////////////////////////////////////////////////////////
//				if(line.toLowerCase().contains("imagesectionobject") || line.toLowerCase().contains("datasectionobject") )
//				{
//					try
//					{
//						array = line.trim().split(" ");
//						
//						PID = Integer.parseInt(array[0].trim());
//						process_name_from_memory = array[1].trim();
//						current_output_file_name = array[array.length-1].trim();						
//						
//					}
//					catch(Exception e)
//					{
//						continue;
//					}
//				}
				

				
				//////////////////////////////////////////////////////////////////////
				//dumpcerts
				//                 
				//e.g. dumpcerts -->632 winlogon.exe     0x000870c0 _X509_PUBLIC_CERT         791 632-870c0.crt
				//
				/////////////////////////////////////////////////////////////////////
				if(line.toLowerCase().contains("_cert") && (line.contains(".crt") || line.contains(".key")))
				{
					try
					{
						array = line.trim().split(" ");
						
						PID = Integer.parseInt(array[0].trim());
						process_name_from_memory = array[1].trim();
						current_output_file_name = array[array.length-1].trim();						
						
					}
					catch(Exception e)
					{
						continue;
					}
				}
				
				
				//////////////////////////////////////////////////////////////////////
				//
				//Writing cmd.exe [  2472] to 2472.dmp
				//e.g. memdump --> Writing cmd.exe [  2472] to 2472.dmp
				/////////////////////////////////////////////////////////////////////
				else if(line.toLowerCase().contains("writing ") && line.contains("[") && line.contains("]"))
				{
					array = line.trim().split("Writing");
					
					if(array == null || array.length < 1)
						array = line.toLowerCase().trim().split("writing");
						
					if(array == null || array.length < 1)
						continue;
					
					// explorer.exe [  1688] to 1688.dmp
					line = array[0].trim();
					
					if(line == null || line.trim().equals(""))
						line = array[1].trim();
							
					array = line.split("\\[");
					
					if(array == null || array.length < 1)
						continue;
					
					process_name_from_memory = array[0].trim();
					
					array = array[1].trim().split("\\]");
					
					try
					{
						PID = Integer.parseInt(array[0].trim());
						
						array = array[1].trim().split(" ");
						
						current_output_file_name = array[array.length-1].trim();																		
					}
					catch(Exception e)
					{
						continue;
					}
					
					
					
					 
				}
				
				/////////////////////////////////////////////////////////////////////
				//
				//0x82233660 0x01000000 services.exe         OK: executable.676.exe
				//e.g. procdump, moddump, dlldump
				////////////////////////////////////////////////////////////////////
				else if(line.toLowerCase().contains("ok:"))
				{

					//go from the reverse inwards... so start with OK: executable.2972.exe
					/*if(!line.toLowerCase().contains("ok:"))
						continue;*/


					array = line.split("OK:");

					if(array == null || array.length < 2)
						array = line.toLowerCase().split("ok:");

					if(array == null || array.length < 2)
						continue;



					//array[0]: 0x81f8fb80 mAgent.exe           0x07d1e0000 msi.dll               - - -  array[1]: module.2876.218fb80.7d1e0000.dll
					current_output_file_name = array[1].trim();

					//////////////////////////
					//extract PID
					////////////////////////
					if(current_output_file_name.toLowerCase().contains("module.") || current_output_file_name.toLowerCase().contains("executable.") )
					{
						array_pid = current_output_file_name.split("\\.");

						if(array_pid.length > 2)
						{
							try	{	PID = Integer.parseInt(array_pid[1].trim());	}	catch(Exception e){PID = -1;}
						}
					}
					else 
						PID = -1;


					//0x81f8fb80 mAgent.exe           0x07d1e0000 msi.dll               - - -  module.2876.218fb80.7d1e0000.dll

					//now start from the end, split based on the hex addressing [0x] and take the first value that does not parse to a number
					array_name = array[0].split("0x");

					//01000000 wscntfy.exe

					if(array_name == null || array_name.length < 1)
						continue;

					value = array_name[array_name.length-1].trim();

					process_name_from_memory = value.substring(value.indexOf(" "));

				}
				
				//driver.directive(file_name_from_memory + " --> " + current_output_file_name);
				
				//driver.directive("PID: [" + PID + "] Proc Name: [" + file_name_from_memory + "]");
				
				//
				//store pid
				//				
				try
				{
					if(PID > -1 && process_name_from_memory.trim().length() > 0)
						tree_PROCESS.put(PID, process_name_from_memory);
				}
				catch(Exception e){}//e.g. concurrentmodificationexception from another simultaneous process...	
				
				
				//
				//now attempt to rename the file
				//
				fleCurrent = new File(path + current_output_file_name);
				
				if(!fleCurrent.exists() || !fleCurrent.isFile())
					continue;
				
				//
				//attempt to rename!
				//
				try	
				{
					if(INOCULATE_FILE_EXECUTABLE_EXTENSION)
					{
						try
						{
							if(current_output_file_name.toLowerCase().trim().endsWith(".exe"))
								current_output_file_name = current_output_file_name.replace(".exe", "_exe");
						}
						catch(Exception e){driver.directive("check inoculation routine in " + myClassName + " for " + fleCurrent);}
					}
					
					fleNew = new File(path + process_name_from_memory + "." + current_output_file_name);
					fleCurrent.renameTo(fleNew);										
					
				}
				catch(Exception e)
				{
					
				}
				
				/*if(pwOut != null && this.hash_extracted_files && fleNew.exists() && fleNew.isFile())
				{
					FileAttributeData attr = new FileAttributeData(fleNew);
					attr.set_hash(false);
					pwOut.println(attr.get_attributes("\t  "));
					
					if(parent != null)
		        		parent.jtaConsole.append(attr.get_name_size_hash("\t  "));
				}*/
			
			}
			
			//finished, now read through the directory and create the file attributes to be standard for all files
			LinkedList<File> listing = new LinkedList<File>();
			listing = driver.getFileListing(new File(path), true, null, listing);
			
			if(listing != null && !listing.isEmpty())
			{				
				for(File fle : listing)
				{
					if(fle == null || !fle.exists() || !fle.isFile())
						continue;
					
					//skip output files
					if(fle.getCanonicalPath().toLowerCase().contains(parent.plugin_name) && fle.getCanonicalPath().toLowerCase().trim().endsWith(".txt"))
						continue;
					
					//otw, process file					
					FileAttributeData attr = new FileAttributeData(fle, null, null);
					attr.set_hash(false);
					pwOut.println(attr.get_attributes("\t  "));
					
					if(parent != null && parent.jtaConsole != null)
		        		parent.jtaConsole.append(attr.get_name_size_hash("\t  "));
				}
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "rename_files", e);
		}
		
		return false;
	}
	
	public boolean write_process_header(PrintWriter pw, String execution_command)
	{
		try
		{
			if(pw == null)
				return false;
			
			//
			//determine the number of hash signs we'll need
			//
			int size = 0;
			
			if(Interface.investigator_name != null && Interface.investigator_name.trim().length() > 0 && Interface.investigation_description != null && Interface.investigation_description.trim().length() > 0)
			{
				if(("# Investigator Name: " + Interface.investigator_name + "\t Investigation Description: " + Interface.investigation_description).length() > size);
					size = ("# Investigator Name: " + Interface.investigator_name + "\t Investigation Description: " + Interface.investigation_description).length();
				
			}
			else if(Interface.investigation_description != null && Interface.investigation_description.trim().length() > 0)
			{
				if(("# Investigation Description: " + Interface.investigation_description).length() > size)
					size = ("# Investigation Description: " + Interface.investigation_description).length();
			}
			
			if(("# Investigation Date: " + this.EXECUTION_TIME_STAMP).length() > size)
				size = ("# Investigation Date: " + this.EXECUTION_TIME_STAMP).length();
			
			
			if(Interface.file_attr_volatility != null)
			{
				if(("# Memory Analysis Binary: " + Interface.file_attr_volatility.get_attributes("\t ")).length() > size)
					size = ("# Memory Analysis Binary: " + Interface.file_attr_volatility.get_attributes("\t ")).length();
			}
			
			if(this.fleImage_file != null)
			{
				if(("# Memory Image Path: " + fleImage_file.getCanonicalPath()).length() > size)
					size = ("# Memory Image Path: " + fleImage_file.getCanonicalPath()).length();
			}
			else if(Interface.fle_memory_image != null)
			{
				if(("# Memory Image Path: " + Interface.fle_memory_image.getCanonicalPath()).length() > size)
					size = ("# Memory Image Path: " + Interface.fle_memory_image.getCanonicalPath()).length();
			}
			
			if(file_attr_memory_image != null)
			{
				if(("# Memory Image Attributes: " + file_attr_memory_image.get_attributes("\t ")).length() > size)
					size = ("# Memory Image Attributes: " + file_attr_memory_image.get_attributes("\t ")).length();
			}
			
			if(("# Plugin Name: " + this.plugin_name).length() > size)
				size = ("# Plugin Name: " + this.plugin_name).length();
			
			if(("# Plugin Description: " + this.plugin_description).length() > size)
				size = ("# Plugin Description: " + this.plugin_description).length();
			
			if(("# Execution Command: " + execution_command).length() > size)
				size = ("# Execution Command: " + execution_command).length();
			
			
			
			//
			//print data
			//
			for(int i = 0; i < size+8; i ++)
				pw.print("#");
			
			pw.print("\n");
			
			if(Interface.investigator_name != null && Interface.investigator_name.trim().length() > 0 && Interface.investigation_description != null && Interface.investigation_description.trim().length() > 0)
				pw.println("# Investigator Name: " + Interface.investigator_name + "\t Investigation Description: " + Interface.investigation_description);	
			else if(Interface.investigation_description != null && Interface.investigation_description.trim().length() > 0)
				pw.println("# Investigation Description: " + Interface.investigation_description);	
			
			pw.println("# Investigation Date: " + this.EXECUTION_TIME_STAMP);
			
			if(Interface.file_attr_volatility != null)
				pw.println("# Memory Analysis Binary: " + Interface.file_attr_volatility.get_attributes("\t "));
			
			if(fleImage_file != null)
				pw.println("# Memory Image Path: " + fleImage_file.getCanonicalPath());
			else if(Interface.fle_memory_image != null)
				pw.println("# Memory Image Path: " + Interface.fle_memory_image.getCanonicalPath());
			
			if(file_attr_memory_image != null)
				pw.println("# Memory Image Attributes: " + file_attr_memory_image.get_attributes("\t "));
			
			
			pw.println("# Plugin Name: " + this.plugin_name);
			pw.println("# Plugin Description: " + this.plugin_description);
			pw.println("# Execution Command: " + execution_command);
			
			for(int i = 0; i < size+8; i ++)
				pw.print("#");
			
			pw.println("\n");
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "write_process_header", e);
		}
		
		return false;
	}
	
	
	
	public boolean process_plugin_dumpfiles(LinkedList<String> output, String directory_path, PrintWriter pwOut)
	{
		try
		{
			if(output == null || output.size() < 1 || directory_path == null || directory_path.trim().equals(""))
				return false;
			
									
			//
			//PROCESS
			//
			File fle_directory_path = new File(directory_path);
			
			if(fle_directory_path == null || !fle_directory_path.exists() || !fle_directory_path.isDirectory())
				return false;
									
			String path = fle_directory_path.getCanonicalPath().trim();
			
			if(!path.endsWith(File.separator))
				path = path + File.separator;
									
			if(pwOut != null)
			{
				pwOut.println("\n#################################################################################################################");
				pwOut.println("# FILE DETAILS");
				pwOut.println("#################################################################################################################");
				

				if(parent != null && parent.jtaConsole != null)
				{
					parent.jtaConsole.append("\n#################################################################################################################");
					parent.jtaConsole.append("# FILE DETAILS");
					parent.jtaConsole.append("#################################################################################################################");
				}
			}
			
			//
			//first process each line to populate the output
			//
			
			String [] array = null;
			String memory_type = "";
			String offset = "";
			String PID = "";
			String path_from_memory = "";
			String resource_name = "";
			
			for(String line : output)
			{								
				if(line == null || line.trim().equals(""))
					continue;
				
				line = line.trim();
				
				memory_type = "";
				offset = "";
				PID = "";
				path_from_memory = "";
				resource_name = "";
				
//				SharedCacheMap 0x8227c178   4      \Device\HarddiskVolume1\Documents and Settings\Adham\Local Settings\Application Data\Microsoft\Windows\UsrClass.dat
//				ImageSectionObject 0x821e8198   4      \Device\HarddiskVolume1\WINDOWS\system32\ntdll.dll
//				DataSectionObject 0x821e8198   4      \Device\HarddiskVolume1\WINDOWS\system32\ntdll.dll
				
				array = line.split(" ");
				
				if(array == null || array.length < 4)
					continue;
				
				for(String token : array)
				{
					if(token == null || token.trim().length() < 1)
						continue;
					
					token = token.trim();
					
					if(token.equals(""))
						continue;
					
					if(memory_type.trim().equals(""))
						memory_type = token;
					else if(offset.trim().equals(""))
						offset = token;
					else if(PID.trim().equals(""))
						PID = token;
					else
						path_from_memory = path_from_memory + " " + token;
					
				}
				
				path_from_memory = path_from_memory.trim();
				
				try
				{
					resource_name = path_from_memory.substring(path_from_memory.lastIndexOf("\\")+1);
				}
				catch(Exception e){resource_name = "";}
				
				if(resource_name.trim().equals(""))
				{
					try
					{
						resource_name = path_from_memory.substring(path_from_memory.lastIndexOf("/")+1);
					}
					catch(Exception e){resource_name = "";}
				}

//				memory_type: DataSectionObject
//				offset: 0x81acbd00
//				PID: 1080
//				path_from_memory: \Device\HarddiskVolume1\WINDOWS\system32\wbem\wbemcore.dll
//				process_name: wbemcore.dll
								
//				driver.directive("memory_type: " + memory_type);
//				driver.directive("offset: " + offset);
//				driver.directive("PID: " + PID);
//				driver.directive("path_from_memory: " + path_from_memory);
//				driver.directive("resource_name: " + resource_name);
//				
				offset = offset.trim();
				PID = PID.trim();
				resource_name = resource_name.trim();
				
				//at this point, let's ensure pslist, psscan, and pstree have been executed. if so, they can populate the PID tree in order to let us know how to better
				//handle the PID and data for each saved image data file
				
				//here, if we have a good offset, pid, and resource name, store in the tree
				if(offset.length() > 0 &&  PID.length() > 0 && resource_name.length() > 0)
				{
					//file.288.0x81f2aba8.img
					try	{	tree_dumpfiles_offsets.put(PID + "." + offset, resource_name);	} catch(Exception e){}
					try	{	tree_dumpfiles_offsets.put(offset, resource_name);	} catch(Exception e){}
				}
				
			}//end for
			
			//now attempt to analyze the directory and renames the files based on the stored offsets
			rename_files_dumpfiles("./xavier_framework/export/memory_analysis/" + Interface.analysis_time_stamp + "/" + plugin_name, pwOut);
			
			return true;
			
		}//end try
		
		catch(Exception e)
		{
			driver.eop(myClassName, "process_plugin_dumpfiles", e);
		}
		
		return false;
	}
				
	
	
	
	public boolean process_plugin_pslist(LinkedList<String> output)
	{
		try
		{
			if(output == null || output.size() < 1)
				return false;
			
			String [] array = null;
			String offset = "";
			String process_name = "";
			int PID = -1;
			String PPID = "";
			String threads = "";
			String handles = "";
			String session = "";
			String wow64 = "";
			String start_exit = "";
			
			for(String line : output)
			{
				//pslist --> 0x822349f0 winlogon.exe            632    552     21      650      0      0 2016-11-29 06:44:45 UTC+0000                                 
				
				if(line == null)
					continue;
				
				line = line.trim();
				
				if(line.length() < 4)
					continue;
				
				if(!line.contains("0x"))
					continue;
				
				array = line.split(" ");
				offset = "";
				process_name = "";
				PID = -1;
				PPID = "";
				threads = "";
				handles = "";
				session = "";
				wow64 = "";
				start_exit = "";
				
				if(array == null || array.length < 3)
					continue;
				
				//Offset(V)  Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit                          
				for(String token : array)
				{
					if(token == null || token.trim().equals(" "))
						continue;
					
					
					if(offset == null || offset.equals(""))
						offset = token;
					else if(process_name == null || process_name.equals(""))
						process_name = token;
					
					//at this point, check if we're ready to store the PID. if not, add to the process name
					else if(offset != null && offset.length() > 0 && process_name != null && process_name.trim().length() > 0 && PID < 0)
					{
						try
						{
							PID = Integer.parseInt(token.trim());
							//break;
							
							//store the PID and process name
							if(PID > -1 && process_name.trim().length() > 0)
								tree_PROCESS.put(PID, process_name);//Solomon Sonya
						}
						catch(Exception e)
						{
							PID = -1;
							process_name = process_name + " " + token;
							continue;
						}
					}
					
					else if(PPID == null || PPID.equals(""))
						PPID = token;
					
					else if(threads == null || threads.equals(""))
						threads = token;
					
					else if(handles == null || handles.equals(""))
						handles = token;
					
					else if(session == null || session.equals(""))
						session = token;
					
					else if(wow64 == null || wow64.equals(""))
						wow64 = token;
					
					else
						start_exit = start_exit + " " + token;
					
					
				}
				
				//driver.directive(line);
				//driver.directive("\toffset: " + offset + "\t" + "process_name: " + process_name + " \tPID: " + PID + "\tPPID: " + PPID + "\thandles: " + handles + "\tthreads: " + threads + "\tsession: " + session + "\twow64: " + wow64 + "\tstart_exit: " + start_exit);
				
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_plugin_pslist", e);
		}
		
		return false;
		
	}
	
	////////////////////////////////
	/////////////////////
	/////////////////
	//////////
	public boolean process_plugin_psscan(LinkedList<String> output)
	{
		try
		{
			if(output == null || output.size() < 1)
				return false;
			
			String [] array = null;
			String offset = "";
			String process_name = "";
			int PID = -1;
			String PPID = "";
			String PDB = "";
			String time_created_exited = "";
			
			for(String line : output)
			{
		
				if(line == null)
					continue;
				
				line = line.trim();
				
				if(line.length() < 4)
					continue;
				
				if(!line.contains("0x"))
					continue;
				
				if(line.contains("---------------------"))
					continue;
				
				array = line.split(" ");
				offset = "";
				process_name = "";
				PID = -1;
				PPID = "";
				PDB = "";
				time_created_exited = "";
								
				if(array == null || array.length < 3)
					continue;
				
				//Offset(P)          Name                PID   PPID PDB        Time created                   Time exited                   
				//------------------ ---------------- ------ ------ ---------- ------------------------------ ------------------------------
				//0x0000000001c60418 taskmgr.exe         656   1800 0x049402c0 2016-12-09 10:18:33 UTC+0000                                 
				
				for(String token : array)
				{
					if(token == null || token.trim().equals(" "))
						continue;
					
					
					if(offset == null || offset.equals(""))
						offset = token;
					
					else if(process_name == null || process_name.equals(""))
						process_name = token;//SS0ny@
					
					//at this point, check if we're ready to store the PID. if not, add to the process name
					else if(offset != null && offset.length() > 0 && process_name != null && process_name.trim().length() > 0 && PID < 0)
					{
						try
						{
							PID = Integer.parseInt(token.trim());
							
							//store the PID and process name
							if(PID > -1 && process_name.trim().length() > 0)
								tree_PROCESS.put(PID, process_name);
						}
						catch(Exception e)
						{
							PID = -1;
							process_name = process_name + " " + token;
							continue;
						}
					}
					
					else if(PPID == null || PPID.equals(""))
						PPID = token;
					
					else if(PDB == null || PDB.equals(""))
						PDB = token;
															
					else
						time_created_exited = time_created_exited + " " + token;
										
				}
				
				//driver.directive(line);
				//driver.directive("\toffset: " + offset + "\t" + "process_name: " + process_name + " \tPID: " + PID + "\tPPID: " + PPID + "\tPDB: " + PDB + "\ttime_created_exited: " + time_created_exited);
				
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_plugin_psscan", e);
		}
		
		return false;
		
	}
	
	
	//////////////////////////
	////////////
	////////
	
	public boolean process_plugin_mftparser(LinkedList<String> output, PrintWriter pw, String delimiter, File fleOutput)
	{
		try
		{
			if(output == null || output.isEmpty())
				return false;
			
			if(pw == null)
				return false;
			
			if(fleOutput == null || !fleOutput.exists())
			{
				if(Advanced_Analysis_Director.DO_NOT_INCLUDE_TIME_STAMP_IN_FILE_NAME)
					fleOutput = new File("./_mft_parser.txt");
				else
					fleOutput = new File("./_mft_parser_"+ driver.get_time_stamp("_") + ".txt");
				
				try	{	fleOutput.mkdirs();}catch(Exception e){}
			}
			
			String path_output_directory = fleOutput.getCanonicalPath().trim();
			
			if(path_output_directory.contains("."))
				path_output_directory = path_output_directory.substring(0, path_output_directory.lastIndexOf("."));
							
			path_output_directory = path_output_directory.trim();
			
			if(!path_output_directory.endsWith(File.separator))
				path_output_directory = path_output_directory + File.separator;
			
			File fleOutput_directory = new File(path_output_directory);
			
			try	{	fleOutput_directory.mkdirs();	}	catch(Exception e){}
			
			this.path_to_output_directory = path_output_directory;
								
			TreeMap<String, FilePrintWriter> tree_unique_file_extensions = new TreeMap<String, FilePrintWriter>();
			String key = "";
			
			MFT_HEADER = "Creation Date" + delimiter + "Creation Time" + delimiter + "Creation UTC" + delimiter + "Modified Date" + delimiter + "Modified Time" + delimiter + "Modified UTC" + delimiter + "MFT Altered Date" + delimiter + "MFT Altered Time" + delimiter + "MFT Altered UTC" + delimiter + "Access Date" + delimiter + "Access Time" + delimiter + "Access UTC" + delimiter + "Type/Name/Path" + delimiter + "Entry Atrribute" + delimiter + "Extension";
			
			//although there's a lot of data presented from this plugin, we're mainly interested in lines that appear to be like the following:
			//2016-12-09 09:58:35 UTC+0000 2016-11-29 06:35:23 UTC+0000   2016-12-09 09:58:36 UTC+0000   2016-12-09 09:58:36 UTC+0000   Archive
			
			pw.println("\n#################################################################################################################");
			pw.println("# MFT SPECIFIC ENTRIES");
			pw.println("#################################################################################################################");
			//pw.println("Creation Date" + delimiter + "Creation Time" + delimiter + "Creation UTC" + delimiter + "Modified Date" + delimiter + "Modified Time" + delimiter + "Modified UTC" + delimiter + "MFT Altered Date" + delimiter + "MFT Altered Time" + delimiter + "MFT Altered UTC" + delimiter + "Access Date" + delimiter + "Access Time" + delimiter + "Access UTC" + delimiter + "Type/Name/Path" + delimiter + "Entry Atrribute" + delimiter + "Extension");
			pw.println(MFT_HEADER);
			

			if(parent != null && parent.jtaConsole != null)
			{
				parent.jtaConsole.append("\n#################################################################################################################");
				parent.jtaConsole.append("# MFT SPECIFIC ENTRIES");
				parent.jtaConsole.append("#################################################################################################################");
				//parent.jtaConsole.append("Creation Date" + delimiter + "Creation Time" + delimiter + "Creation UTC" + delimiter + "Modified Date" + delimiter + "Modified Time" + delimiter + "Modified UTC" + delimiter + "MFT Altered Date" + delimiter + "MFT Altered Time" + delimiter + "MFT Altered UTC" + delimiter + "Access Date" + delimiter + "Access Time" + delimiter + "Access UTC" + delimiter + "Type/Name/Path" + delimiter + "Entry Atrribute" + delimiter + "Extension");
				parent.jtaConsole.append(MFT_HEADER);
			}
			
			String ENTRY_ATTRIBUTE = "";
			String [] array  = null;
			String out = "";
			String UPPER = "";
			String lower = "";
			String extension = "";//useful for filtering specifically on prefetch activity
			
			list_prefetch = new LinkedList<String>();
			list_mft = new LinkedList<String>();
			
			for(String line : output)
			{
				if(line == null)
					continue;
				
				line = line.trim();
				
				if(line.equals(""))
					continue;
				
				UPPER = line.toUpperCase().trim();
				lower = line.toLowerCase().trim();
				
				if(UPPER.startsWith("$") && UPPER.contains("STANDARD_INFORMATION"))
					ENTRY_ATTRIBUTE = "$STANDARD_INFORMATION";				
				else if(UPPER.startsWith("$") && UPPER.contains("DATA ADS"))
					ENTRY_ATTRIBUTE = "$DATA ADS";
				else if(UPPER.startsWith("$") && UPPER.contains("DATA"))
					ENTRY_ATTRIBUTE = "$DATA";
				else if(UPPER.startsWith("$") && UPPER.contains("FILE_NAME (AL)"))
					ENTRY_ATTRIBUTE = "$FILE_NAME (AL)";
				else if(UPPER.startsWith("$") && UPPER.contains("FILE_NAME"))
					ENTRY_ATTRIBUTE = "$FILE_NAME";
				else if(UPPER.startsWith("$") && UPPER.contains("OBJECT_ID"))
					ENTRY_ATTRIBUTE = "$OBJECT_ID";								
				
				//parse for the entry we prefer
				if(line.length() < 6 || !line.substring(4,5).equals("-"))
					continue;
				
				try	{Integer.parseInt(line.substring(0,4).trim());}	catch(Exception e){	continue;	}
				
				//made it here, it is likely in the correct form, thus keep it!
				
				//determine the extension (useful for filtering specifically on prefetch files, etc)
				try
				{
					if(lower.contains("."))
					{
						extension = lower.substring(lower.lastIndexOf(".")+1).trim();						
					}
					else
						extension = "";
				}
				catch(Exception e)
				{
					extension = "";
				}
				
				
				
				array = line.split(" ");
												
				if(array == null || array.length < 7)
					continue;
				
				//get rid of extra spaces
				out = "";
				for(String token : array)
				{
					if(token == null || token.trim().equals(""))
						continue;
					
					token = token.trim();
					
					if(	token.startsWith("0") || token.startsWith("1") || token.startsWith("2") || token.startsWith("3") || token.startsWith("4") 	|| token.startsWith("5") || 
						token.startsWith("6") || token.startsWith("7") || token.startsWith("8") || token.startsWith("9") || token.startsWith("UTC") || token.startsWith("utc"))
							out = out + token.trim() + delimiter;
					else
						out = out + token.trim() + " ";
				}
				
				out = out.trim();
				out = out + delimiter + ENTRY_ATTRIBUTE + delimiter + extension;
				

				if(extension.endsWith("pf") || out.toLowerCase().contains("\\prefetch\\"))
				{
					list_prefetch.add(out);
					key = "prefetch";
				}
				else
					key = extension;
				
				if(key == null || key.trim().equals(""))
					key = "no_extension";
								
				//save to main file
				pw.println(out);	
				
				//store in list
				list_mft.add(out);
												
				if(parent != null && parent.jtaConsole != null)
					parent.jtaConsole.append(out);

				//save to extension file
				if(tree_unique_file_extensions.containsKey(key))
				{
					tree_unique_file_extensions.get(key).println(out);
				}
				else
				{
					FilePrintWriter fileExtension = new FilePrintWriter(path_output_directory + key +".txt");
					fileExtension.println(out);
					
					if(fileExtension.fle.exists())
						tree_unique_file_extensions.put(key, fileExtension);
				}
				
				
			}//end for on each line
			
			//
			//done, print prefetch data now...
			//
			if(list_prefetch != null && list_prefetch.size() > 0)
			{
				pw.println("\n#################################################################################################################");
				pw.println("# PREFETCH SPECIFIC ENTRIES");
				pw.println("#################################################################################################################");
				pw.println(MFT_HEADER);
				

				if(parent != null && parent.jtaConsole != null)
				{
					parent.jtaConsole.append("\n#################################################################################################################");
					parent.jtaConsole.append("# PREFETCH SPECIFIC ENTRIES");
					parent.jtaConsole.append("#################################################################################################################");
					parent.jtaConsole.append(MFT_HEADER);
				}
				
				for(String prefetch : list_prefetch)
				{
					if(prefetch == null || prefetch.trim().equals(""))
						continue;
					
					pw.println(prefetch);
					
					if(parent != null && parent.jtaConsole != null)
						parent.jtaConsole.append(prefetch);						
				}
			}
			
			//
			//close extension files
			//
			if(tree_unique_file_extensions != null && !tree_unique_file_extensions.isEmpty())
			{
				sop("");
				sop("Specific MFT entry files have been written to --> " + path_output_directory);
				
				for(FilePrintWriter f : tree_unique_file_extensions.values())
				{
					if(!f.fle.exists())
						continue;						
					
					f.flush();
					f.close();
				}
			}
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_plugin_mftparser", e);
		}
		
		return false;
	}
	
	public boolean sop(String out)
	{
		try
		{
			if(parent != null && parent.jtaConsole != null)
				parent.jtaConsole.append(out);
			else
				driver.sop(out);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "sop", e);
		}
		
		return false;
	}
	
	////////////////////////////////
	/////////////////////
	/////////////////
	//////////
	public boolean process_plugin_pstree(LinkedList<String> output)
	{
		try
		{
			if(output == null || output.size() < 1)
				return false;
			
			String [] array = null;
			String offset = "";
			String process_name = "";
			int PID = -1;
			String PPID = "";
			String threads = "";
			String handles = "";
			String time = "";
			
			for(String line : output)
			{
		
				if(line == null)
					continue;
				
				line = line.trim();
				
				if(line.length() < 4)
					continue;
				
				if(!line.contains("0x"))
					continue;
				
				if(line.contains("---------------------"))
					continue;
				
				array = line.split(" ");
				offset = "";
				process_name = "";
				PID = -1;
				PPID = "";
				threads = "";
				handles = "";
				time = "";
								
				if(array == null || array.length < 3)
					continue;
				
				
				
				//Name                                                  Pid   PPid   Thds   Hnds Time
				//-------------------------------------------------- ------ ------ ------ ------ ----
				// 0x81fd0820:explorer.exe                              888   1336     25    725 2016-12-09 09:58:37 UTC+0000
				
		                      				
				for(String token : array)
				{
					if(token == null || token.trim().equals(" "))
						continue;	
					
					if(token.trim().startsWith("\\."))
						continue;
					
					//0x81fd0820:explorer.exe 
					if(token.contains(":") && offset.trim().equals(""))
					{
						String [] arr = token.split(":");
						
						if(arr == null || arr.length < 2)
							continue;
						
						offset = arr[0].trim();
						process_name = arr[1].trim(); 
					}
					
										
					//at this point, check if we're ready to store the PID. if not, add to the process name
					else if(offset != null && offset.length() > 0 && process_name != null && process_name.trim().length() > 0 && PID < 0)
					{
						try
						{
							PID = Integer.parseInt(token.trim());
							
							//store the PID and process name
							if(PID > -1 && process_name.trim().length() > 0)
								tree_PROCESS.put(PID, process_name);
						}
						catch(Exception e)
						{
							PID = -1;
							process_name = process_name + " " + token;
							continue;
						}
					}
					
					else if(PPID == null || PPID.equals(""))
						PPID = token;
					
					else if(threads == null || threads.equals(""))
						threads = token;
					
					else if(handles == null || handles.equals(""))
						handles = token;
					
					else
						time = time + " " + token;
										
				}
				
				//driver.directive(line);
				//driver.directive("\toffset: " + offset + "\t" + "process_name: " + process_name + " \tPID: " + PID + "\tPPID: " + PPID + "\ttheads: " + threads + "\thandles: " + handles + "\ttime: " + time);
				
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_plugin_pstree", e);
		}
		
		return false;
		
	}
	
	
	
	
	public boolean rename_files_dumpfiles(String directory_path, PrintWriter pwOut)
	{
		try
		{
			if(tree_dumpfiles_offsets == null || tree_dumpfiles_offsets.size() < 1 || directory_path == null || directory_path.trim().equals(""))
				return false;
												
			File fle_directory_path = new File(directory_path);
			
			if(fle_directory_path == null || !fle_directory_path.exists() || !fle_directory_path.isDirectory())
				return false;
						
			String path = fle_directory_path.getCanonicalPath().trim();
			
			if(!path.endsWith(File.separator))
				path = path + File.separator;
			
						
			
			//finished, now read through the directory and create the file attributes to be standard for all files
			LinkedList<File> listing = new LinkedList<File>();
			listing = driver.getFileListing(new File(path), true, null, listing);
			
			String array [] = null;
			String PID = "";
			String resource_name = "";
			String offset= "";
			String extension = "";
			String process_name = "";
			int int_PID = -1;
			
			if(listing == null  || listing.isEmpty())
				return false;
			
			for(File fle : listing)
			{
				if(fle == null || !fle.exists() || !fle.isFile())
					continue;
				
				//skip output files
				if(fle.getCanonicalPath().toLowerCase().contains(parent.plugin_name) && fle.getCanonicalPath().toLowerCase().trim().endsWith(".txt"))
					continue;
				
				//in volatility version 2.6,  files are stored as file.4.0x81e95e48.vacb
				//in the tree, data is stored as PID.OFFSET --> resource_name
				
				array = fle.getName().split(".");
				PID = "";
				offset = "";
				resource_name = "";
				process_name = "";
				extension = "";
				int_PID = -1;
				
				if(array == null || array.length < 1)
					array = fle.getName().split("\\.");
				
				if(array == null || array.length < 4)
					continue;
				
				PID = array[1].trim();
				offset = array[2].trim();
				extension = array[3].trim();
				
				try
				{
					int_PID = Integer.parseInt(PID);
					process_name = tree_PROCESS.get(int_PID).trim() + ".";
				}
				catch(Exception e)
				{
					process_name = "";
				}
				
				try{ resource_name = tree_dumpfiles_offsets.get(PID + "." + offset).trim() + ".";	}
				catch(Exception e){				resource_name = "";			}
				
				if(resource_name == null || resource_name.trim().equals(""))
				{
					//try just offset
					try{ resource_name = tree_dumpfiles_offsets.get(offset).trim() + ".";	}
					catch(Exception e){				resource_name = "";			}
				}
				
				if(process_name == null)
					process_name = "";
				
				if(resource_name == null || resource_name.toLowerCase().trim().startsWith("null"))
					resource_name = "";
				

				
				//curr file name == file.4.0x81e95e48.vacb
				//new file name == process_name.pid.resource_name.offset.extension
				
				File fleNew = new File(fle.getCanonicalPath().replace(fle.getName().trim(), process_name + PID + "." + resource_name + offset + "." + extension));
				
				//driver.directive(fle.getCanonicalPath());
				//driver.directive("PID: " + PID + "\tprocess_name: " + process_name + "\tresource_name: " + resource_name);
				
				//rename
				try	{	fle.renameTo(fleNew);} catch(Exception e){}
				
			}//end for to rename files
				
			//
			//determine file attributes now
			//
			LinkedList<File> renamed_listing = new LinkedList<File>();
			renamed_listing = driver.getFileListing(new File(path), true, null, renamed_listing);
			
			for(File fle : renamed_listing)
			{
				if(fle == null || !fle.exists() || !fle.isFile())
					continue;
				
				//skip output files
				if(fle.getCanonicalPath().toLowerCase().contains(parent.plugin_name) && fle.getCanonicalPath().toLowerCase().trim().endsWith(".txt"))
					continue;
				
				//otw, process file					
				FileAttributeData attr = new FileAttributeData(fle, null, null);
				attr.set_hash(false);
				pwOut.println(attr.get_attributes("\t  "));
				
				if(parent != null && parent.jtaConsole != null)
	        		parent.jtaConsole.append(attr.get_name_size_hash("\t  "));
			}
			
			
			return true;
			
		}//end try
		catch(Exception e)
		{
			driver.eop(myClassName, "rename_files_dumpfiles", e);
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
	public boolean write_mftparser_manifest(PrintWriter pw, String header, String delimiter, PrintWriter pw_super_timeline)
	{
		try
		{
			if(pw == null)
				return false;	
			
			delimiter = delimiter + " ";
			
			File fle = this.fleOutput; 
			
//			if(fle == null)
//				fle = this.fle_import;
			
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
				driver.directive("Exception caught in write_mftparser_manifest mtd in " + this.myClassName + " --> I could not open the output file in order to write contents to manifest file!");
				return false;
			}
							 			
			driver.directivesp("\nwriting " + header + " contents to manifest file...");
				
			
			
			//write contents
			String line = "", lower = "";
			
			
			boolean begin_storing_entries = false;
			
			int line_number = -1;
			String [] arr = null;
			String output_line = "";
			
			
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
					
					lower = line.toLowerCase().trim();
					
					if(lower.equals(""))
						continue;
					
					//seek the start of our specific MFT entries
					if(lower.startsWith("# mft specific entries"))
					{
						begin_storing_entries = true;
						pw.println("#" + header + delimiter + Advanced_Analysis_Director.get_header(delimiter, false, header, null));
						
						pw_super_timeline.println(Advanced_Analysis_Director.get_header(delimiter, true, header, null));
					}
					
					if(!begin_storing_entries)
						continue;
					
					if(lower.startsWith("#"))
						continue;
					
					//omit header line
					if(lower.startsWith("creation"))
						continue;
					
					//analyze every line from this moment onward
					arr = line.split("\t");
					
					output_line = null;
					
					//we should have 14 entries here, if not, alert and skip!
					if(arr.length > 13)
						output_line = analyze_mft_parser_line_14(arr, delimiter);
					
					if(output_line == null)
					{
						driver.directive("Analysis parsing error on " + header + " line [" + line_number + "]! I had difficulty parsing line --> " + line);
						continue;
					}
					
					
					
					//write entries out!
					pw.println(header + delimiter + output_line);
					
					//write entry to manifest_timeline
					pw_super_timeline.println(this.super_timeline_entry);
					
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
			driver.eop(myClassName, "write_mftparser_manifest", e, false);
		}
		
		return false;
	}
	
	
	public String analyze_mft_parser_line_14(String arr[], String delimiter)
	{
		String output_line = null;
		super_timeline_entry = null;
		
		try
		{
			if(arr == null || arr.length < 12)
				return null;
			
			String entry_type = "mft";
			String path = "";
			String extension = null;
			
			output_line = 	arr[0] + " " +  //creation date
							arr[1] + " " +  //creation time
							arr[2] + "\t"+  //creation utc
							arr[3] + " " +  //modified date
							arr[4] + " " +  //modified time
							arr[5] + "\t"+  //modified utc
							arr[6] + " " +  //mft altered date
							arr[7] + " " +  //mft altered time
							arr[8] + "\t"+  //mft altered utc
							arr[9] + " " +  //access date
							arr[10] + " " + //access time
							arr[11] + "\t"+ //access utc
							arr[12] + "\t"; //type_name_path
			
			//entry_attr
			if(arr.length > 13)
			{
				output_line = output_line + arr[13] + "\t"; 
				entry_type = arr[13];
			}
			
			//extension
			if(arr.length > 14)
			{
				output_line = output_line + arr[14] + "\t";
				extension = arr[14];
			}
			
			String creation_time = arr[0] + " " + arr[1] + " " + arr[2];
			String modified_time = arr[3] + " " + arr[4] + " " + arr[5];
			String mft_altered_time = arr[6] + " " + arr[7] + " " + arr[8];
			String access_time = arr[9] + " " + arr[10] + " " + arr[11];
			path = arr[12];
			
			
			super_timeline_entry = 	driver.get_latest_time(creation_time, modified_time, mft_altered_time, access_time, 0) + delimiter + "mftparser" + delimiter + entry_type + delimiter + path + delimiter + creation_time + delimiter + modified_time + delimiter + mft_altered_time + delimiter + access_time;
			
			if(extension != null)
				this.super_timeline_entry = this.super_timeline_entry + delimiter + extension;
							
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_mft_parser_line_14", e);							
		}
		
		return output_line;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
