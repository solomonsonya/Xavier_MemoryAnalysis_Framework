/**
 * @author Solomon Sonya
 */

package Driver;

import java.awt.BorderLayout;
import java.io.*;
import java.net.Socket;
import java.util.LinkedList;
import java.util.TreeMap;
import java.util.*;

import javax.swing.*;
import Encryption.Encryption;
import GEO_Location.GEO_Location;
import Plugin.Process_Plugin;
import ServerSocket_Client.ServerSocket_Client;
import ServerSocket_Client.ThdClientSocket;
import Worker.ThdWorker;

public class StandardInListener extends Thread implements Runnable
{
	public volatile static Driver driver = new Driver();
	public static final String myClassName = "StandardInListener";
	
	public static volatile String lower = "";
	
	public volatile PrintWriter pwOut = null;
	public volatile BufferedReader brIn = null;
	
	public static volatile boolean stop = false;
	
	public static volatile TreeMap<String, Integer> tmp_packet_count = new TreeMap<String, Integer>();	
	public static volatile TreeMap<String, Integer> tmp_packet_count_OVERFLOW = new TreeMap<String, Integer>();
	
	public static volatile boolean launch_configuration_BOTH_SENSOR_AND_PARSER = false;
	public static volatile boolean launch_configuration_PARSER = false;
	public static volatile boolean launch_configuration_SENSOR = false;
	
	public static volatile TreeMap<String, Integer> tmp_packet_count_total = new TreeMap<String, Integer>();	
	public static volatile TreeMap<String, Integer> tmp_packet_count_OVERFLOW_bar = new TreeMap<String, Integer>();
	public static volatile int max_overflow_count = 0;
	
	public static volatile int count = 0;
	
	
	
	
	public StandardInListener()
	{
		try
		{
			brIn = new BufferedReader(new InputStreamReader(System.in));
			pwOut = new PrintWriter(new BufferedOutputStream(System.out));
			
			
			
			this.start();
			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
		
	}
	
	public StandardInListener(BufferedReader br, PrintWriter pw)
	{
		try
		{
			brIn = br;
			pwOut = pw;			
			
			this.start();
			
			
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
			String line = "";
			
			while((line = brIn.readLine())!= null) 
			{
				line = line.trim();
				
				if(line.equals(""))
					continue;
				
				determineCommand(line);
			}
			
			driver.directive("\n\nBreaking from Infinite Loop in " + myClassName + ". Ready to terminate program!");
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "run", e);
		}
	}
	
	public boolean determineCommand(String line)
	{
		try
		{
			if(line == null || line.trim().equals(""))
				return false;
			
			line = line.trim();
			
			lower = line.toLowerCase().trim();
			
			if(lower.equals("s") || lower.equals("status") || lower.startsWith("display_status") || lower.startsWith("display status"))
				display_status();
			
			else if(lower.startsWith("import_geo") || lower.startsWith("import geo") || lower.startsWith("import_gps") || lower.startsWith("import gps"))
			{
				GEO_Location geo = new GEO_Location(true, null);
			}
															
			else if(line.equalsIgnoreCase("verbose") || line.equalsIgnoreCase("v") || line.equalsIgnoreCase("-verbose") || line.equalsIgnoreCase("-v"))
				toggle_verbose();	
			
			else if(lower.startsWith("export_geo") || lower.startsWith("export geo"))
				GEO_Location.export_geo(true,  "\t",  true,  "geo_table.txt");
									
			else if(line.toLowerCase().startsWith("parser_connect") || line.toLowerCase().startsWith("parser connect"))
				parser_connect(line.substring(14));
					
			
			else if(line.toLowerCase().startsWith("resolution_connect") || line.toLowerCase().startsWith("resolution connect"))
				resolution_connect(line.substring(18));
			
			else if(line.toLowerCase().startsWith("resolution_request") || line.toLowerCase().startsWith("resolution request"))
				resolution_connect(line.substring(18));
			
			else if(line.toLowerCase().startsWith("request_resolution") || line.toLowerCase().startsWith("request resolution"))
				resolution_connect(line.substring(18));
			
			else if(line.toLowerCase().startsWith("request_connect") || line.toLowerCase().startsWith("request connect"))
				resolution_connect(line.substring(15));
			
			else if(line.toLowerCase().startsWith("listen"))
				establish_server_socket(line.substring(6));
			
			else if(line.toLowerCase().startsWith("-listen"))
				establish_server_socket(line.substring(7));
			
			else if(line.toLowerCase().startsWith("-establish_server_socket"))
				establish_server_socket(line.substring(24));
			
			else if(line.toLowerCase().startsWith("establish_server_socket"))
				establish_server_socket(line.substring(23));
			
			else if(line.toLowerCase().startsWith("-establish server socket"))
				establish_server_socket(line.substring(24));
			
			else if(line.toLowerCase().startsWith("establish server socket"))
				establish_server_socket(line.substring(23));
									
			else if(line.toLowerCase().startsWith("-set_encryption") || line.toLowerCase().startsWith("-set encryption"))
				set_encryption(line.substring(15));
			
			else if(line.toLowerCase().startsWith("set_encryption") || line.toLowerCase().startsWith("set encryption"))
				set_encryption(line.substring(14));
			
			else if(line.toLowerCase().startsWith("encryption"))
				set_encryption(line.substring(10));
									
			else if(line.toLowerCase().equalsIgnoreCase("log"))
				toggle_logging();
			
			else if(line.equalsIgnoreCase("disconnect"))
				disconnect_all();
						
			else if(lower.startsWith("pid"))
				pid(lower.substring(3));
			
			else if(lower.startsWith("print_offset") || lower.startsWith("print offset"))
				print_offset();
			
			else if(lower.startsWith("print_pid") || lower.startsWith("print pid"))
				print_pid();
			
			else if(lower.startsWith("offset"))
				offset(lower.substring(6));
			
			else if(line.equalsIgnoreCase("stop"))
				stop = true;
			
			else if(line.toLowerCase().equals("exit"))
			{
				exit();
			}
			
			
			else
			{
				driver.directive("unrecognized command --> " + line);	
				
				
				
			}
				
		
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "determineCommand", e);
		}
		
		return false;
	}
	
	
	
	public boolean pid(String PID)
	{
		try
		{
			if(PID == null || PID.trim().equals(""))
			{
				driver.directive("PUNT! I am missing a PID to search for you...");
				return false;
			}
			
			PID = PID.trim();
			
			int int_PID = Integer.parseInt(PID);
			
			if(Process_Plugin.tree_PROCESS == null || Process_Plugin.tree_PROCESS.isEmpty() || !Process_Plugin.tree_PROCESS.containsKey(int_PID))
			{
				driver.directive("PUNT! No processes have been stored matching PID: [" + PID + "]");
				return false;
			}
			
			driver.directive(""+Process_Plugin.tree_PROCESS.get(int_PID));
			
			return true;
		}
		catch(Exception e)
		{
			driver.directive("Unable to process request.  Please check parameters and try again...");
		}
		
		return false;
	}
	
	public static boolean update_geo()
	{
		try
		{
			driver.directive("Updating applicable geo entries...");
			GEO_Location.update_geo_resolution();
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "update_geo", e);
		}
		
		return false;
	}
	
	public boolean offset(String offset)
	{
		try
		{
			if(offset == null || offset.trim().equals(""))
			{
				driver.directive("PUNT! I am missing a PID to search for you...");
				return false;
			}
			
			offset = offset.trim();
			
			
			if(Process_Plugin.tree_dumpfiles_offsets == null || Process_Plugin.tree_dumpfiles_offsets.isEmpty() || !Process_Plugin.tree_dumpfiles_offsets.containsKey(offset))
			{
				driver.directive("PUNT! No resources have been stored matching offset: [" + offset + "]");
				return false;
			}
			
			driver.directive(""+Process_Plugin.tree_dumpfiles_offsets.get(offset));
			
			return true;
		}
		catch(Exception e)
		{
			driver.directive("* * Unable to process offset retrieval request.  Please check parameters and try again...");
		}
		
		return false;
	}
	
	public static boolean import_file(File fle)
	{
		try
		{
			if(fle == null || !fle.exists() || !fle.isFile())
				fle = driver.querySelectFile(true, "Please select file to import", JFileChooser.FILES_ONLY, false, false);
			
			if(fle == null || !fle.exists() || !fle.isFile())
			{
				driver.directive("\nPUNT! No valid file selected!");
				return false;
			}
			
			driver.directive("Ready to continue with import file --> " + fle.getCanonicalPath());
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "import_file", e);
		}
		
		return false;
	}
	
	
	
	public boolean exit()
	{
		try
		{
			driver.directive("\nProgram Terminated.");
			
			//close sockets
			
			
			
			
			System.exit(0);
			
			return true;
		}
		 catch(Exception e)
		{
			 driver.eop(myClassName, "exit", e);
		}
		
		return false;
	}
	
	public boolean disconnect_all()
	{
		try
		{
			driver.directive("executing disconnection actions...");
			
			//call close mtd of all other Sockets 
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "disconnect_all", e);
		}
		
		return false;
	}
	
	public boolean toggle_logging()
	{
		try
		{
			Log.toggle_logging();
						
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "toggle_logging", e);
		}
		
		return false;
	}
	
	public static boolean set_encryption(String key)
	{
		boolean previous_output_state = driver.output_enabled;
		
		try
		{
			//disable output
			driver.output_enabled = false;
			
			if(key == null || key.trim().equals(""))
			{
				driver.directive("\nENCRYPTION HAS BEEN DISABLED!");	
				
				driver.encryption_key = null;
								
			}
			
			if(key != null && key.trim().equalsIgnoreCase("null"))
			{
				driver.directive("\n\nNOTE: your [null] parameter is a reserved word with this encryption command specifying to disable encryption");
				
				driver.directive("ENCRYPTION HAS BEEN DISABLED!");	
				
				driver.encryption_key = null;
								
			}
			
			if(key != null)
			{
				key = key.trim();
				
				driver.encryption_key = key;
				
				driver.directive("Encryption key has been set to [" + key + "]");
				
				//iterate through connection sockets
				
			}
			
			//set the encryption keys!
			
			
			
			driver.output_enabled = previous_output_state;
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "set_encryption", e);
		}
		
		
		driver.output_enabled = previous_output_state;
		
		return true;
	}
	
	public boolean toggle_verbose_sensor()
	{
		try
		{
			driver.sensor_output_enabled = !driver.sensor_output_enabled;
			
			if(driver.sensor_output_enabled)
				driver.directive("Sensor output is enabled.");
			else
				driver.directive("Sensor output is disabled.");
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "toggle_verbose_sensor", e);
		}
		
		return false;
	}
	
	public boolean toggle_verbose_parser()
	{
		try
		{
			driver.parser_output_enabled = !driver.parser_output_enabled;
			
			if(driver.parser_output_enabled)
				driver.directive("parser output is enabled.");
			else
				driver.directive("parser output is disabled.");
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "toggle_verbose_parser", e);
		}
		
		return false;
	}
	
	public boolean establish_server_socket(String port)
	{
		try
		{
			int PORT = Integer.parseInt(port.trim());
			
			if(PORT < 0)
			{
				throw new Exception("PORT number must be greater than 0!");
			}
			
			ServerSocket_Client svrskt = new ServerSocket_Client(PORT);
			
			return true;
		}
		catch(Exception e)
		{
			driver.directive("ERROR! Invalid port received. Please run command again and specify valid listen port!");
		}
		
		return false;
	}
	
	public boolean parser_connect(String location)
	{
		try
		{
			if(location == null || location.trim().equals(""))
			{
				driver.directive("ERROR! It appears you are missing location parameters for the connect command! Please try again!");
				return false;
			}
			
			location = location.trim();
			
			
			String array [] = null;
			
			if(location.contains(":"))
				array = location.split(":");
			else if(location.contains(","))
				array = location.split(",");
			else 
				array = location.split(" ");
			
			String address = array[0].trim();
			int port = Integer.parseInt(array[1].trim());
			
			if(address.equalsIgnoreCase("localhost") || address.equalsIgnoreCase("local host") || address.equalsIgnoreCase("-localhost") || address.equalsIgnoreCase("-local host"))
				address = "127.0.0.1";
			
			//Connect
			driver.directive("Attempting to connect sensor out to transport data to PARSER --> " + address + " : " + port);
			
			try
			{
				Socket skt = new Socket(address, port);
				
				ThdClientSocket thd = new ThdClientSocket(null, skt);
			}
			catch(Exception ee)
			{
				driver.directive("ERROR! I was unable to establish a connection to PARSER at --> " + address + " : " + port);
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.directive("ERROR! I was expecting command: parser_connect <ip address> <port>\nPlease try again...");
		}
		
		return false;
	}
	
	
	
	public boolean toggle_verbose()
	{
		try
		{
			driver.output_enabled = !Driver.output_enabled;
			
			if(driver.output_enabled)
				driver.directive("Output is enabled!");
			else
				driver.directive("Output is disabled!");
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "toggle_verbose", e);
		}
		
		return false;
	}
	
	
	
	public boolean resolution_connect(String location)
	{
		try
		{
			if(location == null || location.trim().equals(""))
			{
				driver.directive("ERROR *  It appears you are missing location parameters for the connect command! Please try again!");
				return false;
			}
			
			location = location.trim();
			
			
			String array [] = null;
			
			if(location.contains(":"))
				array = location.split(":");
			else if(location.contains(","))
				array = location.split(",");
			else 
				array = location.split(" ");
			
			String address = array[0].trim();
			int port = Integer.parseInt(array[1].trim());
			
			if(address.equalsIgnoreCase("localhost") || address.equalsIgnoreCase("local host") || address.equalsIgnoreCase("-localhost") || address.equalsIgnoreCase("-local host"))
				address = "127.0.0.1";
			
			//Connect
			driver.directive("Attempting to connect out to resolution request server --> " + address + " : " + port);
			
			try
			{
				Socket skt = new Socket(address, port);
				
				driver.directive("Ready to continue in " + myClassName + " with resolution connect");
				//ResolutionRequest_ThdSocket thd = new ResolutionRequest_ThdSocket(null, skt);
			}
			catch(Exception ee)
			{
				driver.directive("ERROR *  I was unable to establish a connection to resolution request server at --> " + address + " : " + port);
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.directive("ERROR! I was expecting command: resolution_connect <ip address> <port>\nPlease try again...");
		}
		
		return false;
	}
	
	
	
	
	
	public boolean display_status()
	{
		try
		{
			driver.directive("\n /////////// STATUS ////////////");
			driver.directive(driver.FULL_NAME);
			
			driver.directive("");
			driver.directive("Time of First Start: " + driver.TIME_OF_FIRST_START);
			
			if(driver.encryption_key == null)
				driver.directive("Encryption Key --> " + "//NOT SET//");
			else
				driver.directive("Encryption Key --> " + driver.encryption_key);
			
			
			driver.directive("Verbose is enabled: " + driver.output_enabled);
			driver.directive("Sensor Verbose is enabled: " + driver.sensor_output_enabled);
			driver.directive("Parser Verbose is enabled: " + driver.parser_output_enabled);
			
			if(driver.PID != null && !driver.PID.trim().equals(""))
			{
				driver.directive("PID: " + driver.PID);
				driver.directive("HOST NAME: " + driver.HOST_NAME);
			}
			
			if((ServerSocket_Client.list_server_sockets == null || ServerSocket_Client.list_server_sockets.isEmpty()))
			{
				driver.directive("No server sockets instantiated yet!");
			}
			else
			{
				for(ServerSocket_Client svrskt : ServerSocket_Client.list_server_sockets)
				{
					driver.directive("Sensor ServerSocket --> " + svrskt.get_status());
				}
				
			}
			
			if(ThdClientSocket.list_outbound_connections != null && !ThdClientSocket.list_outbound_connections.isEmpty())
			{
				driver.directive("Num Outbound Sensor Socket connections: " + ThdClientSocket.list_outbound_connections.size());
				
				for(ThdClientSocket thd : ThdClientSocket.list_outbound_connections)
				{
					driver.directive("\tOutbound Sensor Socket -->" + thd.CONNECTION_ADDRESS);
				}
			}
						
						
			
			driver.directive("");
						
			driver.directive("");			
			driver.directive("Heap Size: " + Runtime.getRuntime().totalMemory()/1e6 + "(MB) Max Heap Size: " + Runtime.getRuntime().maxMemory()/1e6 + "(MB) Free Heap Size: " + Runtime.getRuntime().freeMemory()/1e6 + "(MB) Consumed Heap Size: " + (Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory())/1e6 + "(MB)");
			driver.directive("");	
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "display_status", e);
		}
		
		return false;
	}
	
	
	
	public static String normalize_lookup(String lookup, boolean drop_subdomains)
	{
		try
		{
			String []array_ip = null;
			
			if(lookup == null || lookup.trim().equals(""))
				return "";
			
			lookup = lookup.trim();
			
			if(lookup.toLowerCase().startsWith("https://"))
				lookup = lookup.substring(8).trim();
			if(lookup.toLowerCase().startsWith("http://"))
				lookup = lookup.substring(7).trim();
			if(lookup.toLowerCase().startsWith("www1."))
				lookup = lookup.substring(5).trim();
			if(lookup.toLowerCase().startsWith("www3."))
				lookup = lookup.substring(5).trim();
			if(lookup.toLowerCase().startsWith("ww3."))
				lookup = lookup.substring(4).trim();
			if(lookup.toLowerCase().startsWith("www."))
				lookup = lookup.substring(4).trim();
			if(lookup.toLowerCase().startsWith("/"))
				lookup = lookup.substring(1).trim();
			if(lookup.toLowerCase().startsWith("/"))
				lookup = lookup.substring(1).trim();
			if(lookup.toLowerCase().startsWith("."))
				lookup = lookup.substring(1).trim();
			
			//bifurcate domain name from URL
			if(lookup.contains("/"))
			{
				array_ip = lookup.split("\\/");				
				
				if(array_ip[0] != null && !array_ip[0].trim().equals(""))
					lookup = array_ip[0].trim();
				else if(array_ip.length > 1 && array_ip[2] != null && !array_ip[2].trim().equals(""))
					lookup = array_ip[0].trim();				
			}
			
			lookup = lookup.replaceAll("\\*", "");
			
			
			//drop subdomains
			if(drop_subdomains)
			{
											
				array_ip = lookup.split("\\.");
				
				//separate look, also process full subdomain request just in case it reveals interesting information
				if(array_ip != null && array_ip.length > 2)
				{
					//Whois whois = new Whois(lookup, true);
				}
				
				//check if we have many subdomains
				if(array_ip != null && array_ip.length > 4)
				{
					lookup = array_ip[array_ip.length-2] + "." + array_ip[array_ip.length-1] ;
				}
				
				//check if we may have an ip address
				//NOTE: BELOW SHOULD START A NEW IF control flow, do not make it an else if!
				else if(array_ip != null && array_ip.length > 3)
				{
					try
					{
						Integer.parseInt(array_ip[0].trim());
						Integer.parseInt(array_ip[1].trim());
						Integer.parseInt(array_ip[2].trim());
						Integer.parseInt(array_ip[3].trim());
						
						//first 4 octets are ip addresses					
						lookup = array_ip[0].trim() + "." + array_ip[1].trim() + "." +array_ip[2].trim() + "." + array_ip[3].trim();
					}
					catch(Exception e)
					{
						//something went wrong, so consider it a subdomain...
						if(array_ip != null && array_ip.length > 1)
							lookup = array_ip[array_ip.length-2] + "." + array_ip[array_ip.length-1];
					}
				}
				
				//not ip address, thus remove subdomains
				else if(array_ip != null && array_ip.length > 1)
					lookup = array_ip[array_ip.length-2] + "." + array_ip[array_ip.length-1];
			}
			
			lookup = lookup.toLowerCase().trim();			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "normalize_lookup", e, true);
		}
		
		return lookup;
	}
	
	
	public boolean print_pid()
	{
		try
		{			
			if(Process_Plugin.tree_PROCESS == null || Process_Plugin.tree_PROCESS.isEmpty() )
			{
				driver.directive("PUNT! No processes have been populated yet! Consider running plugin: pslist, psscan, pstree, etc");
				return false;
			}
			
			for(int key : Process_Plugin.tree_PROCESS.keySet())
			{
				driver.directive("" + key + ", \t" + Process_Plugin.tree_PROCESS.get(key));
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.directive("Unable to process print_pid request.  Please check parameters and try again...");
		}
		
		return false;
	}
	
	
	public boolean print_offset()
	{
		try
		{			
			if(Process_Plugin.tree_dumpfiles_offsets == null || Process_Plugin.tree_dumpfiles_offsets.isEmpty() )
			{
				driver.directive("PUNT! No resources have been populated yet! Consider running dumpfiles plugin");
				return false;
			}
			
			for(String key : Process_Plugin.tree_dumpfiles_offsets.keySet())
			{
				driver.directive("" + key + ", \t" + Process_Plugin.tree_dumpfiles_offsets.get(key));
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.directive("Unable to process print_offset request.  Please check parameters and try again...");
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	

}

