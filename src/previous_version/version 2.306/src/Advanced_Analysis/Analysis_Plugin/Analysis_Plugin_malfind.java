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

public class Analysis_Plugin_malfind extends _Analysis_Plugin_Super_Class implements Runnable, ActionListener
{
	public static final String myClassName = "Analysis_Plugin_malfind";
	public static volatile Driver driver = new Driver();
	

	
	public volatile Advanced_Analysis_Director parent = null;


	public volatile String lower = "";
	
	public volatile Node_Process process = null;
	public volatile Node_Malfind malfind = null;
	public volatile String process_name = null;
	public volatile String pid = null;
	public volatile String address = null;
	public volatile String vad_tag = null;
	public volatile String protection = null;
	public volatile String flags = null;
	public volatile boolean MZ_present = false;
	public volatile boolean JMP_present = false;
	public volatile boolean analyzed_first_0x_line = false;
	
	
	public volatile String malfind_dump_file_name = null;
	
	


	
	public Analysis_Plugin_malfind(File file, Advanced_Analysis_Director par, String PLUGIN_NAME, String PLUGIN_DESCRIPTION, boolean execute_via_thread, JTextArea_Solomon jta_OUTPUT)
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
			
			try	{ parent.tree_advanced_analysis_threads.put(this.plugin_name, this);	} catch(Exception e){}
			EXECUTION_STARTED = true;
			
			try	{	Advanced_Analysis_Director.list_plugins_in_execution.add(this.plugin_name);	} catch(Exception e){}

			
			boolean status = false;
			
			status = execute_plugin(plugin_name, plugin_description, null, "", true);			
					
			//dump files
			dump_files();
			
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
	
	public boolean dump_files()
	{
		try
		{
			if(fleOutput == null || !fleOutput.exists())
				return false;
			
			String path = fleOutput.getParentFile().getCanonicalPath().trim();
			
			if(!path.endsWith(File.separator))
				path = path + File.separator;
			
			File directory = new File(path + "malfind_dump");
			
			try	{	directory.mkdirs();	} catch(Exception e){}
			
			//execute cmd
			String cmd = "\"" + Interface.fle_volatility.getCanonicalPath().trim() + "\" -f \"" + Interface.fle_memory_image.getCanonicalPath().trim() + "\"" + " --profile=" + Interface.PROFILE + " " + this.plugin_name + " --dump-dir \"" + directory.getCanonicalPath();

			//
			//EXECUTE COMMAND!
			//
			ProcessBuilder process_builder = null;	
			
			
			if(driver.isWindows)
				process_builder = new ProcessBuilder("cmd.exe", "/C",  cmd);	
							
			//else if(driver.isLinux)
			else
				process_builder = new ProcessBuilder("/bin/bash", "-c",  cmd);
			
			//
			//redirect error stream
			//
			process_builder.redirectErrorStream(true); 
						
			//
			//instantiate new process
			//
			Process process = process_builder.start();
			
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
			
		    //rename
		    LinkedList<File> list = new LinkedList<File>();
		    
		    list = driver.getFileListing(directory, true, null, list);
		    
		    if(list == null || list.isEmpty())
		    	return false;
		    
		    String file_name = null;
		    
		    for(File fle : list)
		    {
		    	try
		    	{
		    		file_name = fle.getName().toLowerCase().trim();
		    		
		    		Node_Process node_process = null;
		    		Node_Malfind malfind = null;
		    		String eprocess_offset = null;
		    		String address = null;
		    		
		    		
		    		try
		    		{
		    			//process.0x843b9030.0x3a0000.dmp
		    			String array [] = file_name.split("\\.");
		    			
		    			eprocess_offset = array[1].toLowerCase().trim();
		    			address = array[2].toLowerCase().trim();
		    			
		    			node_process = parent.tree_PROCESS_linked_by_pslist_EPROCESS_base_address.get(eprocess_offset);
		    			malfind = node_process.tree_malfind.get(address);
		    		}
		    		catch(Exception e){}
		    		
		    		if(!parent.tree_malfind_dump_name_conversion_table.containsKey(file_name))
		    		{
		    			//link file to process malfind
		    			malfind.store_malfind_file_dump_attributes(fle);		    					    			
		    			continue;
		    		}
		    		
		    		File fle_new = new File(fle.getCanonicalPath().replace(file_name, ""+parent.tree_malfind_dump_name_conversion_table.get(file_name)));
		    		
		    		
		    		try		
		    		{	
		    			fle.renameTo(fle_new);
		    			malfind.store_malfind_file_dump_attributes(fle_new);
		    			
		    		} catch(Exception e)
		    		{
		    			malfind.store_malfind_file_dump_attributes(fle);
		    		}
		    		
		    		
		    		
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
			driver.eop(myClassName, "dump_files", e);
		}
		
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
			
			
			if(lower.startsWith("process"))
			{				
				
				//re-init
				malfind = null;
				process = null;				
				process_name = null;
				pid = null;
				address = null;
				vad_tag = null;
				protection = null;
				flags = null;
				MZ_present = false;
				JMP_present = false;
				analyzed_first_0x_line = false;
				malfind_dump_file_name = null;
				
				//process line - Process: explorer.exe Pid: 2236 Address: 0x3660000
				process_name = line.substring(8, lower.indexOf("pid:")).trim(); 
				pid = line.substring(lower.indexOf("pid:")+5, lower.indexOf("address:")).trim();
				address = line.substring(line.lastIndexOf(":")+1).trim();
				
				String original_dump_file_name = "";
				
				try	
				{					
					process = parent.tree_PROCESS.get(Integer.parseInt(pid.trim()));
					
					original_dump_file_name = "process." + process.offset_pslist.toLowerCase().trim() + "." + address.toLowerCase().trim() + ".dmp";
					
					if(process != null && address != null && !address.trim().equals("") && !parent.tree_PROCESS_linked_by_pslist_EPROCESS_base_address.containsKey(address))
						parent.tree_PROCESS_linked_by_pslist_EPROCESS_base_address.put(address,  process);
						
					//e.g. process.0x86926030.0x3660000.dmp from volatility_2.6_win64_standalone.exe -f Sample-14-3.mem --profile=Win7SP1x86 malfind --dump-dir ./
					
					try	{	parent.tree_malfind_dump_name_conversion_table.put(original_dump_file_name, process.process_name + "_" + pid + "_" + process.offset_pslist + "_" + address + ".dmp");} catch(Exception e){}
					try	{	parent.tree_malfind_original_dump_name_to_process.put(original_dump_file_name, process);} catch(Exception e){}
				} 
				
				catch(Exception e){	process = null;}
				
				//create nodes
				malfind = new Node_Malfind(process_name, pid, process, address);
				
				//link to process
				if(process != null)
				{
					if(process.tree_malfind == null)
						process.tree_malfind = new TreeMap<String, Node_Malfind>();
					
					//link to process	
					process.tree_malfind.put(address,  malfind);
					
					//link by dump file name as well - not the most elegant... but it'll work
					//process.tree_malfind.put(original_dump_file_name,  malfind);
					
					//link to director
					parent.tree_MALFIND.put(process.PID, process);
				}
			}

			else if(lower.startsWith("vad tag") && malfind != null)
			{
				malfind.vad_tag = line.substring(9, line.indexOf(" ", 10)).trim();
				malfind.protection = line.substring(line.lastIndexOf(":")+1).trim();
				
				parent.tree_MALFIND_PAGE_PROTECTION_TYPES.put(malfind.protection, null);
			}
			
			else if(lower.startsWith("flags:") && malfind != null)
			{
				malfind.flags = line.substring(7).trim();
			}
			
			//owt, search for MZ header
			//else if(lower.startsWith("0x") && malfind != null && lower.contains("4d 5a 00 00 00 00 00 00"))			
			else if(lower.startsWith("0x") && !analyzed_first_0x_line && malfind != null)
			{
				analyzed_first_0x_line = true;
				
				//parse first line
				String line_analysis = lower.replace("     ", " ").replace("    ", " ").replace("   ", " ").replace("  ", " ");
				//0x01f60000  4d 5a 41 52 55 48 89 e5 48 83 ec 20 48 83 e4 f0   MZARUH..H...H...
				String arr [] = line_analysis.split(" ");
				
				if(arr != null && arr.length > 0)
				{
					//search for m and z
					try
					{
						if( (arr[1].trim().equals("4d") || arr[1].trim().equals("5a")) && (arr[2].trim().equals("5a") || arr[2].trim().equals("4d")) )
						{
							malfind.MZ_present = true;
							parent.tree_malfind_MZ_Detcted.put(line, malfind);
							malfind.culprit_line = line;
						}												
					}
					catch(Exception e){/*do n/t*/}
					
				}
					
				
				
				
			}
			else if(lower.startsWith("0x") && malfind != null && !analyzed_first_0x_line && lower.contains("jmp"))			
			{
				analyzed_first_0x_line = true;
				malfind.Trampoline_initial_JMP_Detected = true;
			}			
			else if(lower.startsWith("0x"))			
			{
				analyzed_first_0x_line = true;				
			}
			
			//store details
			if(lower.startsWith("0x") && malfind != null)
			{
				if(malfind.list_details == null)
					malfind.list_details = new LinkedList<String>();
				
				malfind.list_details.add(line);
				
				if(malfind.list_details.size() == 4)
					malfind.list_details.add(".");
			}
			
			//check for first jmp after header
//			malfind	 list_details:	 0x00260000  e9 b5 00 00 00 4d 31 c9 31 c0 ac 41 c1 c9 0d 3c   .....M1.1..A...<
//			malfind	 list_details:	 0x00260010  61 7c 02 2c 20 41 01 c1 38 e0 75 ec c3 31 d2 65   a|.,.A..8.u..1.e
//			malfind	 list_details:	 0x00260020  48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 12 48   H.R`H.R.H.R.H..H
//			malfind	 list_details:	 0x00260030  8b 72 50 48 0f b7 4a 4a 45 31 c9 31 c0 ac 3c 61   .rPH..JJE1.1..<a
//			malfind	 list_details:	 .
//			malfind	 list_details:	 0x00260000 e9b5000000       JMP 0x2600ba
//			malfind	 list_details:	 0x00260005 4d               DEC EBP
//			malfind	 list_details:	 0x00260006 31c9             XOR ECX, ECX
//			malfind	 list_details:	 0x00260008 31c0             XOR EAX, EAX
//			malfind	 list_details:	 0x0026000a ac               LODSB
//			malfind	 list_details:	 0x0026000b 41               INC ECX
//			malfind	 list_details:	 0x0026000c c1c90d           ROR ECX, 0xd
//			malfind	 list_details:	 0x0026000f 3c61             CMP AL, 0x61
//			malfind	 list_details:	 0x00260011 7c02             JL 0x260015
//			malfind	 list_details:	 0x00260013 2c20             SUB AL, 0x20
//			malfind	 list_details:	 0x00260015 41               INC ECX
//			malfind	 list_details:	 0x00260016 01c1             ADD ECX, EAX
//			malfind	 list_details:	 0x00260018 38e0             CMP AL, AH
//			malfind	 list_details:	 0x0026001a 75ec             JNZ 0x260008
//			malfind	 list_details:	 0x0026001c c3               RET
//			malfind	 list_details:	 0x0026001d 31d2             XOR EDX, EDX
//			malfind	 list_details:	 0x0026001f 6548             DEC EAX
//			malfind	 list_details:	 0x00260021 8b5260           MOV EDX, [EDX+0x60]
//			malfind	 list_details:	 0x00260024 48               DEC EAX
//			malfind	 list_details:	 0x00260025 8b5218           MOV EDX, [EDX+0x18]
//			malfind	 list_details:	 0x00260028 48               DEC EAX
//			malfind	 list_details:	 0x00260029 8b5220           MOV EDX, [EDX+0x20]
//			malfind	 list_details:	 0x0026002c 48               DEC EAX
//			malfind	 list_details:	 0x0026002d 8b12             MOV EDX, [EDX]
//			malfind	 list_details:	 0x0026002f 48               DEC EAX
//			malfind	 list_details:	 0x00260030 8b7250           MOV ESI, [EDX+0x50]
//			malfind	 list_details:	 0x00260033 48               DEC EAX
//			malfind	 list_details:	 0x00260034 0fb74a4a         MOVZX ECX, WORD [EDX+0x4a]
//			malfind	 list_details:	 0x00260038 45               INC EBP
//			malfind	 list_details:	 0x00260039 31c9             XOR ECX, ECX
//			malfind	 list_details:	 0x0026003b 31c0             XOR EAX, EAX
//			malfind	 list_details:	 0x0026003d ac               LODSB
//			malfind	 list_details:	 0x0026003e 3c61             CMP AL, 0x61
				
			
			if(malfind != null && malfind.list_details != null && malfind.list_details.size() < 7 && malfind.list_details.size() >= 6)
			{
				try
				{
					if( malfind.list_details.get(5).toLowerCase().trim().contains("jmp"))
					{
						malfind.Trampoline_initial_JMP_Detected = true;
						parent.tree_malfind_JMP_Detcted.put(line, malfind);
						malfind.culprit_line = malfind.list_details.get(5);
					}
				}
				catch(Exception e){}
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
