/**
 * think of this as a netstat entry line e.g., 0x81acf008 192.168.30.129:1347       54.83.43.69:80            888
 * 
 * @author Solomon Sonya
 */

package Advanced_Analysis;

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


public class Node_Netstat_Entry 
{
	public static final String myClassName = "Node_Netstat_Entry";
	public static volatile Driver driver = new Driver();
	
	public static final String header = "netstat ";
	
	public static volatile boolean use_system_out_println_for_output = true;
	
	public volatile String lower = null;
	public volatile boolean XREF_SEARCH_HIT_FOUND = false; 
	
	public static volatile TreeMap<String, Node_Netstat_Entry> tree_whois_lookup = new TreeMap<String, Node_Netstat_Entry>();
	
	
	public volatile int PID = -1;
	public volatile Node_Process process = null;
	
	//
	//connections - Windows XP and 2003 only
	//
	public volatile String offset_connections = null;
	public volatile String local_address = null;
	public volatile String foreign_address = null;
	
	//
	//connscan
	//
	public volatile String offset_connscan = null;
	
	//
	//sockets
	//
	public volatile String offset_sockets = null;
	public volatile String local_port = null;
	public volatile String proto_value = null;
	public volatile String protocol = null;
	public volatile String creation_date = null;
	public volatile String creation_time = null;
	public volatile String creation_utc = null;
	
	//
	//sockscan
	//
	public volatile String offset_sockscan = null;
	
	//
	//netscan
	//
	public volatile String offset_netscan = null;
	public volatile String state = null;
	public volatile String owner_name = null;
	
	//
	//whois
	//
	public volatile File fle_whois_directory = null;
	public volatile String path_whois_directory = null;
	public volatile File fle_whois_output = null;
	public volatile LinkedList<String> list_whois_entry = null;
	public volatile String lookup = null;
	
	
	public Node_Netstat_Entry()
	{
		try
		{
			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Node_Netstat_Entry", e);
		}
	}
	
	
	
	
	public String get_html_entry()
	{
		try
		{
			String entry = "";
			
			if(protocol != null && !protocol.trim().equals(""))
				entry = entry + "Proto: " + protocol + " ";
			
			if(local_address != null && !local_address.trim().equals(""))
				entry = entry + "Local Address: " + local_address + " ";
			
			if(foreign_address != null && !foreign_address.trim().equals(""))
				entry = entry + "Foreign Address: " + foreign_address + " ";
			
			if(state != null && !state.trim().equals(""))
				entry = entry + "State: " + state + " ";
			
			if(this.creation_date != null && !creation_date.trim().equals(""))
				entry = entry + "Created: " + creation_date + " " + this.creation_time + " " + this.creation_utc + " ";
			
			if(PID > -1 )
				entry = entry + "PID: [" + PID + "] ";
			/*
			if(this.process != null && this.process.process_name != null && !this.process.process_name.trim().equals(""))
				entry = entry + "Process Name: " + this.process.process_name + " ";*/
			
			
			return entry;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_html_entry", e);
		}
		
		return "";
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	public String toString()
	{
		try
		{
			return "local address: " + local_address + "\tforeign address: " + foreign_address + "\tPID: " + PID + "\tprotocol: " + this.protocol + "\tstate: " + state + "\towner_name: " + owner_name + "\tcreated: " + this.creation_date + " " + this.creation_time + " " + this.creation_utc;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "toString", e);
		}
		
		return ".!.";
	}
	
	public boolean is_foreign_address_private_or_non_routable()
	{
		try
		{
			lookup = this.foreign_address;
			
			if(lookup == null)
				return true;
			
			lookup = lookup.trim();
			
			if(lookup.equals(""))
				return true;
			if(lookup.startsWith("10."))
				return true;
			if(lookup.startsWith("192.168"))
        		return true;
			if(driver.is_private_ipv4_address(lookup))
				return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "is_foreign_address_private_or_non_routable", e);
		}
		
		return false;
	}
	
	public boolean whois(String PATH_fle_analysis_directory)
	{
		try
		{
			File whois = Start.fle_whois;
			
			if(driver.isWindows && (whois == null || !whois.exists() || !whois.isFile()))
				return false;
			
			if(this.foreign_address == null || this.foreign_address.trim().equals(""))
				return false;
			
			lookup = this.foreign_address.trim();
			
			//validate
			if(lookup.equals(""))
				return false;
			if(lookup.startsWith("10."))
				return false;
			if(lookup.startsWith("192.168"))
        		return false;
			if(driver.is_private_ipv4_address(lookup))
				return true;
			
			//normalize
			if(lookup.contains("http://"))
				lookup = lookup.substring(7).trim();
			if(lookup.contains("https://"))
				lookup = lookup.substring(8).trim();
			if(lookup.contains("www."))
				lookup = lookup.substring(4).trim();
					
			if(lookup.contains(":"))
				lookup = lookup.substring(0, lookup.indexOf(":")).trim();
			
			if(lookup.length() < 2)
				return false;	
			
						
			try
			{
				if(!tree_whois_lookup.containsKey(lookup))
					tree_whois_lookup.put(lookup, this);
				else//we have already performed whois on an entry, don't repeat it again
					return true;
			}
			catch(Exception e){}
			
			
			fle_whois_directory = new File(PATH_fle_analysis_directory + File.separator + "whois");
			
			try	{	fle_whois_directory.mkdirs(); 	} catch(Exception e){}
			
			path_whois_directory = fle_whois_directory.getCanonicalPath().trim();
			
			if(!path_whois_directory.endsWith(File.separator))
				path_whois_directory = path_whois_directory + File.separator;			
			
			fle_whois_output = new File(path_whois_directory + "whois_" + lookup + ".txt");
									
			Thread thread_execution = new Thread() 
			{
			    public void run() 
			    {
			    	try 
			    	{
			    		//
						//EXECUTE COMMAND!
						//
						
						String command = "\"" + whois.getCanonicalPath() + "\"";
						String params = " -nobanner " + lookup;
						
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
							process_builder = new ProcessBuilder("/bin/bash", "-c",  "whois " + lookup);				
							execution_command = command +  params;
						}
						
						//
						//redirect error stream
						//
						process_builder.redirectErrorStream(true); 
									
						//
						//instantiate new process
						//
						Process process = null;
						BufferedReader brIn = null;
						boolean execute_new_whois_lookup = true;
						
						//check if this file already exists (i.e., we are reloading vice executing this for the first time
						if(fle_whois_output != null && fle_whois_output.exists())
						{
							sop("loading prexisting whois at " + fle_whois_output);
							brIn = new BufferedReader(new FileReader(fle_whois_output));
							execute_new_whois_lookup = false;
						}
						else
						{
							sop("executing whois " + lookup);							
							process_builder.start();																		
							brIn = new BufferedReader(new InputStreamReader(process.getInputStream()));
						}
						

//sop("Executing: " + execution_command);
						//
						//process command output
						//
						LineIterator line_iterator = new LineIterator(brIn);
						String line = "";
						String lower = "";
						
						
						PrintWriter pw = null;
						
						if(execute_new_whois_lookup)
							pw = new PrintWriter(new FileWriter(fle_whois_output));
						
					    try 
					    {
					        while (line_iterator.hasNext()) 
					        {	     		        	
					        	line = line_iterator.nextLine();
					        	
					        	if(line == null)
					        		continue;
					        	
					        	if(execute_new_whois_lookup)
									pw.println(line);					        	
					        	
					        	lower = line.toLowerCase().trim();
					        	
					        	if(lower.startsWith(">"))
					        		continue;
					        	if(lower.startsWith("notice:"))
					        		continue;
					        	if(lower.startsWith("url of the icann"))
					        		continue;
					        	if(lower.startsWith("terms of use"))
					        		continue;
					        	if(lower.startsWith("by the following"))
					        		continue;
					        	if(lower.startsWith("to: "))
					        		continue;
					        	if(lower.startsWith("#"))
					        		continue;
					        	if(lower.startsWith("%"))
					        		continue;
					        	
					        	line = line.trim();
					        	
					        	//determine if we keep the line
					        	if(line.contains(": ") || line.contains(":\t"))
					        	{
					        		if(list_whois_entry == null)
					        			list_whois_entry = new LinkedList<String>();
					        		
					        		if(!list_whois_entry.contains(line))
					        			list_whois_entry.add(line);
					        	}
					        	
					        	
					        }		       	       		       		        	                		        		      
					    }
					    catch(Exception e)
					    {
					    	driver.eop(myClassName, "whois - loop", e);
					    }
					    
					    if(execute_new_whois_lookup)
					    {	
					    	try	{	pw.flush();} catch(Exception e){}
					    	try	{	pw.close();} catch(Exception e){}
					    }
					    
			    	} 
			    	
			    	catch(Exception e) 
			    	{
			    		//System.out.println();
			    	}
			    }  
			};

			thread_execution.start();
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "whois");
		}
		
		return false;
	}
	
	public boolean sop(String out)
	{
		try
		{
			if(use_system_out_println_for_output)
				System.out.println(out);
			else
				Interface.jpnlAdvancedAnalysisConsole.append(out);						
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "sop", e);
		}
		
		return false;
	}
	
	public boolean sp(String out)
	{
		try
		{
			if(use_system_out_println_for_output)
				System.out.print(out);
			else
				Interface.jpnlAdvancedAnalysisConsole.append_sp(out);						
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "sp", e);
		}
		
		return false;
	}
	
	
	
	
	/**
	 * e.g. given an output like [1512] Winrar.exe Malfind [Detail] - 0x00df0020  fe 07 00 00 48 ff 20 90 41 ba 82 00 00 00 48 b8   ....H...A.....H.
	 * container_search_name == "Malfind", mneumonic == "Detail", search_string could == ff 20 90, output line would be 0x00df0020  fe 07 00 00 48 ff 20 90 41 ba 82 00 00 00 48 b8   ....H...A.....H.
	 * 
	 * @param search_chars_from_user
	 * @param search_chars_from_user_lower
	 * @param jta
	 * @param searching_proces
	 * @param container_search_name
	 * @return
	 */
	public boolean search_XREF(String search_chars_from_user, String search_chars_from_user_lower, JTextArea_Solomon jta, Node_Process searching_proces, String container_search_name)
	{
		try
		{ 
			XREF_SEARCH_HIT_FOUND = false;
			
			XREF_SEARCH_HIT_FOUND |= this.check_value(offset_connections, "offset_connections", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(local_address, "local_address", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(foreign_address, "foreign_address", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(offset_connscan, "offset_connscan", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(offset_sockets, "offset_sockets", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(local_port, "local_port", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(proto_value, "proto_value", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(protocol, "protocol", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(creation_date, "creation_date", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(creation_time, "creation_time", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(creation_utc, "creation_utc", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(offset_sockscan, "offset_sockscan", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(offset_netscan, "offset_netscan", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(state, "state", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(owner_name, "owner_name", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(path_whois_directory, "path_whois_directory", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(lookup, "lookup", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			
			if(list_whois_entry != null)
			{
				for(String detail : list_whois_entry)
				{
					XREF_SEARCH_HIT_FOUND |= this.check_value(detail, "Details", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
				}
			}
	
			
			//disable for now, I fear this may introduce a circular recursive reference... 
//			if(this.tree_whois_lookup != null)
//			{
//				for(Node_Netstat_Entry node: this.tree_whois_lookup.values())
//				{
//					if(node == null)
//						continue;
//					
//					node.search_XREF(search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
//				}
//			}
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "search_XREF", e);
		}
		
		lower = null;
		return XREF_SEARCH_HIT_FOUND;
		
	}

	/**
	 * e.g. given an output like [1512] Winrar.exe Malfind [Detail] - 0x00df0020  fe 07 00 00 48 ff 20 90 41 ba 82 00 00 00 48 b8   ....H...A.....H.
	 * container_search_name == "Malfind", mneumonic == "Detail", search_string could == ff 20 90, output line would be 0x00df0020  fe 07 00 00 48 ff 20 90 41 ba 82 00 00 00 48 b8   ....H...A.....H.
	 * 
	 * @param value_to_check
	 * @param mneumonic
	 * @param search_string
	 * @param search_string_lower
	 * @param jta
	 * @param searching_proces
	 * @return
	 */
	public boolean check_value(String value_to_check, String mneumonic, String search_string, String search_string_lower, JTextArea_Solomon jta, Node_Process searching_proces, String container_search_name)	
	{
		try
		{
			if(value_to_check == null)
				return false;
			
			lower = value_to_check.toLowerCase().trim();
			
			if(lower.equals(""))
				return false;
			
			if(searching_proces == null)
				return false;
			
			if(lower.contains(search_string_lower))
			{
				searching_proces.append_to_jta_XREF(container_search_name + " [" + mneumonic + "]: " + value_to_check, jta);
				return true;
			}
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "check_value", e);
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
	private boolean write_manifest_entry(PrintWriter pw, String key, String value)
	{
		try
		{
			if(pw == null)
				return false;
			
			if(key == null || key.trim().equals("") || value == null || value.trim().equals(""))
				return false;
			
			
			
			pw.println(header + key + ":\t" + value);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_manifest_entry", e);
		}
		
		return false;
	}
	
	public boolean write_manifest(PrintWriter pw, String header, String delimiter, String key_identifier_token)
	{
		try
		{
			if(pw == null)
				return false;
			
			//public static volatile TreeMap<String, Node_Netstat_Entry> tree_whois_lookup = new TreeMap<String, Node_Netstat_Entry>();
			//public volatile int PID = -1;
			//public volatile Node_Process process = null;
			
			//public volatile File fle_whois_directory
			//public volatile File fle_whois_output
			
			
			delimiter = delimiter + " ";
			
			String netstat = 	 					
								//
								//connections - Windows XP and 2003 only
								//
								driver.get_trimmed_entry("offset_connections", offset_connections, delimiter, true, false, key_identifier_token) 	+ 
								driver.get_trimmed_entry("local_address", local_address, delimiter, true, false, key_identifier_token) 				+ 
								driver.get_trimmed_entry("foreign_address", foreign_address, delimiter, true, false, key_identifier_token) 			+ 
								
								//
								//connscan
								//
								driver.get_trimmed_entry("offset_connscan", offset_connscan, delimiter, true, false, key_identifier_token)	+	
								
								//
								//sockets
								//
								driver.get_trimmed_entry("offset_sockets", offset_sockets, delimiter, true, false, key_identifier_token)	+
								driver.get_trimmed_entry("local_port", local_port, delimiter, true, false, key_identifier_token)	+	
								driver.get_trimmed_entry("proto_value", proto_value, delimiter, true, false, key_identifier_token)	+
								driver.get_trimmed_entry("protocol", protocol, delimiter, true, false, key_identifier_token)	+	
								driver.get_trimmed_entry("creation_date", creation_date, delimiter, true, false, key_identifier_token)	+
								driver.get_trimmed_entry("creation_time", creation_time, delimiter, true, false, key_identifier_token)	+	
								driver.get_trimmed_entry("creation_utc", creation_utc, delimiter, true, false, key_identifier_token)	+
								
								//
								//sockscan
								//
								driver.get_trimmed_entry("offset_sockscan", offset_sockscan, delimiter, true, false, key_identifier_token)	+	
								
								
								//
								//netscan
								//
								driver.get_trimmed_entry("offset_netscan", offset_netscan, delimiter, true, false, key_identifier_token)	+
								driver.get_trimmed_entry("state", state, delimiter, true, false, key_identifier_token)	+	
								driver.get_trimmed_entry("owner_name", owner_name, delimiter, true, false, key_identifier_token)	+	
								driver.get_trimmed_entry("lookup", lookup, delimiter, true, false, key_identifier_token)
								;			
			
			driver.write_manifest_entry(pw, header, netstat);
			
//			//
//			//connections - Windows XP and 2003 only
//			//			
//			write_manifest_entry(pw, "offset_connections", offset_connections);			
//			write_manifest_entry(pw, "local_address", local_address);
//			write_manifest_entry(pw, "foreign_address", foreign_address);
//
//			//
//			//connscan
//			//						
//			write_manifest_entry(pw, "offset_connscan", offset_connscan);
//						
//			//
//			//sockets
//			//
//			write_manifest_entry(pw, "offset_sockets", offset_sockets);
//			write_manifest_entry(pw, "local_port", local_port);
//			write_manifest_entry(pw, "proto_value", proto_value);
//			write_manifest_entry(pw, "protocol", protocol);
//			write_manifest_entry(pw, "creation_date", creation_date);
//			write_manifest_entry(pw, "creation_time", creation_time);
//			write_manifest_entry(pw, "creation_utc", creation_utc);
//			
//			//
//			//sockscan
//			//
//			write_manifest_entry(pw, "offset_sockscan", offset_sockscan);
//			
//			//
//			//netscan
//			//
//			write_manifest_entry(pw, "offset_netscan", offset_netscan);
//			write_manifest_entry(pw, "state", state);
//			write_manifest_entry(pw, "owner_name", owner_name);
			
			//
			//whois
			//
			//write_manifest_entry(pw, "path_whois_directory", path_whois_directory);
			//write_manifest_entry(pw, "lookup", lookup);
			
			if(list_whois_entry != null && !list_whois_entry.isEmpty())
			{
				for(String entry : list_whois_entry)
				{
					pw.println(header + "whois" + ":\t " + entry);
				}
				
			}
			
			
			
//			pw.println(Driver.END_OF_ENTRY_MINOR);
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_manifest", e);
		}
		
		pw.println(Driver.END_OF_ENTRY_MINOR);
		return false;
	}
	
	
	
	public static boolean import_manifest_line_entry(String mtd_designator, String line, Advanced_Analysis_Director director, Node_Process process)
	{
		try
		{
			if(line == null)
				return false;
			
			if(mtd_designator != null && line.toLowerCase().trim().startsWith(mtd_designator.toLowerCase().trim()))
				line = driver.trim_key(mtd_designator, line, true);					
			
			String arr [] = line.split("\t");
			
			//validate entries
			if(arr == null || arr.length < 2)
			{
				driver.directive("* * * invalid import_manifest_line_entry mtd_designator: [" + mtd_designator + "] recieved in " + myClassName + "\t line --> " + line);
				return false;
			}
			
			//validate key, value tuple(s)
			if(arr.length%2 != 0)
			{
				driver.directive("* * * incongruent import_manifest_line_entry mtd_designator: [" + mtd_designator + "] recieved in " + myClassName + "\t line --> " + line);
				return false;
			}
			
			//
			//instntiate node
			//
			Node_Netstat_Entry node = new Node_Netstat_Entry();
			
			//
			//set container structure to node
			//
			if(process != null)
			{
				node.process = process;
				node.PID = process.PID;
			}
			
			//init
			String key = "", value = "";
	
			//
			//process entry
			//
			for(int i = 0; i < arr.length; i+=2)
			{
				try
				{
					key = arr[i].toLowerCase().trim();
					value = arr[i+1].trim();
					
					if(key.endsWith(":"))
						key = key.substring(0, key.length()-1).trim();

					//mutator functions
					if(key.equals("offset_connections")) node.offset_connections = value;
					else if(key.equals("local_address")) node.local_address = value;
					else if(key.equals("foreign_address")) node.foreign_address = value;
					else if(key.equals("offset_connscan")) node.offset_connscan = value;
					else if(key.equals("offset_sockets")) node.offset_sockets = value;
					else if(key.equals("local_port")) node.local_port = value;
					else if(key.equals("proto_value")) node.proto_value = value;
					else if(key.equals("protocol")) node.protocol = value;
					else if(key.equals("creation_date")) node.creation_date = value;
					else if(key.equals("creation_time")) node.creation_time = value;
					else if(key.equals("creation_utc")) node.creation_utc = value;
					else if(key.equals("offset_sockscan")) node.offset_sockscan = value;
					else if(key.equals("offset_netscan")) node.offset_netscan = value;
					else if(key.equals("state")) node.state = value;
					else if(key.equals("owner_name")) node.owner_name = value;
					else if(key.equals("path_whois_directory")) node.path_whois_directory = value;
					else if(key.equals("lookup")) node.lookup = value;
					
					else
						driver.directive("Unknown import_manifest_line_entry mtd on designation [" + mtd_designator + "] in class: " + myClassName + " at index: [" + i + "] key:[" + key + "] value:[" + value + "] on line --> "  + line);
				}
				catch(Exception e)
				{
					driver.directive("Exception in import_manifest_line_entry mtd on designation [" + mtd_designator + "] in class: " + myClassName + " at index: [" + i + "] key:[" + key + "] value:[" + value + "] on line --> "  + line);
					continue;
				}
			}
			
			/////////////////////////////////////////////////////////////////////////
			// set link key
			/////////////////////////////////////////////////////////////////////////
			key = node.local_address;

			/////////////////////////////////////////////////////////////////////////
			// link node to containing structure
			/////////////////////////////////////////////////////////////////////////
			process.tree_netstat.put(key, node);
			
			/////////////////////////////////////////////////////////////////////////
			// link node to director tree
			/////////////////////////////////////////////////////////////////////////
			if(director != null)
				director.tree_NETSTAT.put(process.PID, process);
			
			return true;
		}
		catch(Exception e)
		{
			driver.directive("* * Unknown import_manifest_line_entry key: [" + mtd_designator + "] recieved in " + myClassName);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
			
	
	
}
