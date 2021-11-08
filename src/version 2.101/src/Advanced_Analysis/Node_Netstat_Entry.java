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
	
	public static volatile boolean use_system_out_println_for_output = true;
	
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
	
	
	
	
	
	
	
	
}
