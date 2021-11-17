/**
 * @author Solomon Sonya
 */


package Driver;

	
	

	import java.awt.Dimension;
import java.awt.Toolkit;
	
	import java.awt.datatransfer.Clipboard;
	import java.awt.datatransfer.StringSelection;
	import java.io.BufferedReader;
	import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
	import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
	import java.io.StringWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.text.DecimalFormat;
import java.text.SimpleDateFormat;
	import java.util.Date;
	import java.util.LinkedList;
	import javax.swing.JFileChooser;
	import javax.swing.JOptionPane;
	import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.UIManager;

import Encryption.Encryption;
import GEO_Location.*;


	public class Driver 
	{
		
		
		public static final String NAME = "Xavier Framework";
		public static final String NAME_LOWERCASE = "xavier_framework";
		public static final String VERSION = "1.002";
		public static final String FULL_NAME = NAME + " vrs " + VERSION;
						
		public static Log log_unrecognized = null; 
		
		public static final String delimiter1 = "#####";
		public static final String delimiter2 = "~~~~~";
		public static final String delimiter3 = "````````";
		
		public static volatile String encryption_key = null;
		
		public static volatile SimpleDateFormat dateFormat_yyyy_mm_dd_hh_mm_ss = new SimpleDateFormat("yyyy-MM-dd-HHmm_ss");
		public static volatile Date dateTime_yyyy_mm_dd_hh_mm_ss = new Date(System.currentTimeMillis());
		public static volatile String TIME_OF_FIRST_START = ""+System.currentTimeMillis();
		
		public static Time time = new Time();
		//public static ThreadSound sound = new ThreadSound();
		
				
		public static final String NOT_FOUND = "no results returned from selected query";
		
		public static volatile String myIPAddress = "";
		
		public static volatile boolean displayed_welcome = false;
		public static final String myClassName = "Driver";
		
		public static volatile boolean map_chrome_complete = false;
		
		public static volatile boolean output_enabled = true;
		
		public static volatile boolean sensor_output_enabled = true;
		public static volatile boolean parser_output_enabled = true;
		
		public volatile String [] arr_ip = null;
		public volatile long value = 0;
		public static final int pow_256_3 = (int)Math.pow(256,3);
		public static final int pow_256_2 = (int)Math.pow(256,2);
		public static final int pow_256_1 = (int)Math.pow(256,1);
		public static final int pow_256_0 = (int)Math.pow(256,0);
		
		public static volatile LinkedList<String> interface_names = null;
		
		public static volatile boolean isWindows = false;
		public static volatile boolean isLinux = false;
		public static volatile boolean isMac = false;
		public static volatile boolean isSolarix = false;
		public static volatile String OS  = mapOS();
		public static volatile String user_name = "";
		public static volatile String host_name = "";
		public static volatile String path_app_data = "";
		public static volatile String path_app_data_microsoft_cookies = "";		
		public static volatile File fle_path_app_data_microsoft_cookies = null;
		
		public static volatile String path_local_app_data = "";
		/**Expected at %localappdata%\Google\Chrome\User Data\Default\Cookies*/
		public static volatile String path_app_data_chrome_cookies = "";
		
		/**Expected at %localappdata%\Google\Chrome\User Data\Profile 1\History*/
		public static volatile String path_app_data_chrome_history = "";
		
		
		/**Expected at %localappdata%\Google\Chrome\User Data\Default\Cookies*/
		public static volatile File fle_path_app_data_chrome_cookies = null;
		
		/**Expected at %localappdata%\Google\Chrome\User Data\Profile 1\History*/
		public static volatile File fle_path_app_data_chrome_history = null;
		
		public static volatile boolean populated_device_specification_lists = false;
		
		

		
		public static volatile SimpleDateFormat dateFormat_yyyy_mm_dd_hh_mm_ss_colon = new SimpleDateFormat("yyyy-MM-dd-HHmm:ss");
		public static volatile Date dateTime_yyyy_mm_dd_hh_mm_ss_colon = new Date(System.currentTimeMillis());
		
		public static volatile LinkedList<String> tshark_interfaces = new LinkedList<String>();
		public static volatile String [] arr_tshark_interfaces = null;
		
		public static volatile boolean map_complete = false;
		
		public static String PID_and_system_name =  "";
		public static String PID = "";
		public static String HOST_NAME = "";
		
		public volatile int division_units = 0;
		public volatile String specification = "bytes";
		public volatile double len = 0;
		public volatile double size = 0;
		public volatile DecimalFormat decimal_format = new DecimalFormat(".##");
		
		
		public static volatile GEO_Location GEO_LOCATION_ME = null;
		
		public Driver()	
		{
			try
			{
				if(!map_complete)
				{
					TIME_OF_FIRST_START = getTime_Specified_Hyphenated_with_seconds(System.currentTimeMillis());
					
					setLookAndFeel(); 
					mapOS();		
					map_os_properties();
					map_chrome_cookie_location();
					map_PID_and_system_name();
					
					map_complete = true;
					
					//GEO_LOCATION_ME = new GEO_Location();
					
					//disable standard error
		        	try
		        	{
		        		System.setErr(new PrintStream(new OutputStream() {
		        		    public void write(int b) {
		        		    }
		        		}));
		        	}
		        	catch(Exception e){}
				}
				
				
			}
			
			catch(Exception e)
			{
				this.eop(myClassName, "Constructor - 1", e);
			}						
		}
		
		public boolean map_PID_and_system_name()
		{
			try
			{
				if(this.PID_and_system_name != null && !this.PID_and_system_name.trim().equals(""))
					return true;
				
				this.PID_and_system_name = java.lang.management.ManagementFactory.getRuntimeMXBean().getName();
				
				if(this.PID_and_system_name.contains("@"))
				{
					this.PID = PID_and_system_name.substring(0, PID_and_system_name.indexOf("@"));
					this.HOST_NAME = PID_and_system_name.substring(PID_and_system_name.indexOf("@")+1);
				}
				
				
				return true;
			}
			
			catch(Exception e)
			{
				this.eop(myClassName, "map_PID_and_system_name");						
			}
			
			return false;
		}
		
		public volatile String string_list_search = "";
		
		public boolean log_unrecognized(String line)
		{
			try
			{
				if(log_unrecognized == null)
					log_unrecognized = new Log("parser/unrecognized_data/",  "unrecognized_line_from_sensor", 250, 999999999);
				
				log_unrecognized.log_directly(line);
				
				return true;
			}
			catch(Exception e)
			{
				this.eop(myClassName, "log_unrecognized", e);
			}
			
			return false;
		}
		
		public boolean map_os_properties()
		{
			try
			{
				user_name = System.getProperty("user.name");
				host_name = InetAddress.getLocalHost().getHostName();
				
				if(isWindows)
				{
					Process proc = Runtime.getRuntime().exec("cmd.exe /C echo %appdata%");

					BufferedReader br = new BufferedReader(new InputStreamReader(proc.getInputStream()));
					String line = "", response = "";
					
					while((line = br.readLine()) != null)
					{
						if(line.trim().equals(""))
							continue;
						
						response = response + line.trim();
					}
					
					try	{	br.close();	} catch(Exception e){}
					
					path_app_data = response;
					
					if(path_app_data != null && !path_app_data.trim().equals(""))
					{
						path_app_data = path_app_data.trim();
						
						if(!path_app_data.endsWith(File.separator))
							path_app_data = path_app_data + File.separator;
						
						
						path_app_data_microsoft_cookies = path_app_data + "Microsoft" + File.separator + "Windows" + File.separator + "Cookies";
						
						fle_path_app_data_microsoft_cookies = new File(path_app_data_microsoft_cookies);
						
						if(!fle_path_app_data_microsoft_cookies.exists() || !fle_path_app_data_microsoft_cookies.isDirectory())
						{
							//try windows 8 feature
							path_app_data_microsoft_cookies = path_app_data + "Microsoft" + File.separator + "Windows" + File.separator + "INetCookies";
							
							fle_path_app_data_microsoft_cookies = new File(path_app_data_microsoft_cookies);
						}
						
						if(!fle_path_app_data_microsoft_cookies.exists() || !fle_path_app_data_microsoft_cookies.isDirectory())
							fle_path_app_data_microsoft_cookies = null;			
						
					}
					
					
					
				}
				
				
				
				return true;
			}
			catch(Exception e)
			{
				System.out.println("Check map_os_properties...");
			}
			
			return false;
		}
			
		public static String mapOS()
		{
			try
			{
				String os = System.getProperty("os.name").toLowerCase();
				
				if(os.contains("win"))
					isWindows = true;
				else if(os.contains("nix") || os.contains("nux") || os.contains("aix"))
					isLinux = true;
				else if(os.contains("mac"))
					isMac = true;
				else if(os.contains("sun"))
					isSolarix = true;
				
				
				
				return os;
			}
			
			catch(Exception e)
			{
				System.out.println("Exception determining OS version");
			}
			
			return "unknown";
			
		}
		
		public String normalize_domain_name(String lookup)	
		{	
			try	{	return get_domain_name(lookup);	}
			catch(Exception e){}
			return lookup;
		}
		
		public String get_domain_name(String lookup)
		{
			try
			{
				String [] arr = null;
				
				lookup = lookup.trim();
				
				if(lookup.toLowerCase().startsWith("https://"))
					lookup = lookup.substring(8).trim();
				if(lookup.toLowerCase().startsWith("http://"))
					lookup = lookup.substring(7).trim();
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
					arr = lookup.split("\\/");				
					
					if(arr[0] != null && !arr[0].trim().equals(""))
						lookup = arr[0].trim();
					else if(arr.length > 1 && arr[2] != null && !arr[2].trim().equals(""))
						lookup = arr[0].trim();				
				}
				
				
				//drop subdomains
				arr = lookup.split("\\.");
				
				//check if we may have an ip address
				if(arr != null && arr.length > 3)
				{
					try
					{
						Integer.parseInt(arr[0].trim());
						Integer.parseInt(arr[1].trim());
						Integer.parseInt(arr[2].trim());
						Integer.parseInt(arr[3].trim());
						
						//first 4 octets are ip addresses					
						lookup = arr[0].trim() + "." + arr[1].trim() + "." +arr[2].trim() + "." +arr[3].trim();
					}
					catch(Exception e)
					{
						//something went wrong, so consider it a subdomain...
						if(arr != null && arr.length > 1)
							lookup = arr[arr.length-2] + "." + arr[arr.length-1];
					}
				}
				
				//not ip address, thus remove subdomains
				else if(arr != null && arr.length > 1)
					lookup = arr[arr.length-2] + "." + arr[arr.length-1];
				
				lookup = lookup.trim();			
				
			}
			catch(Exception e)
			{
				eop(myClassName, "normalize_lookup", e);
			}
			
			return lookup;
		}
		
		/**
		 * This method queries the user via JChooser to select a file
		 * 
		 * Examples: INPUT  FILE TO LOAD --> querySelectFile(false, "Please specify data set to import", JFileChooser.FILES_ONLY, false, false);
		 * Examples: OUTPUT FILE TO SAVE --> querySelectFile(true, "Please specify outfile location for " + x, JFileChooser.DIRECTORIES_ONLY, false, false)
		 */
		public  File querySelectFile(boolean openDialog, String dialogueTitle, int fileChooserSelectionMode, boolean thisLoadsCSV, boolean useFileFilter)
		{
			
			/**
			 * Drivers_Thread.fleCarrier_NetworkCommand = Drivers.querySelectFile(true, "Please Select the Carrier Image to hold the Steganographic command(s) and content", JFileChooser.FILES_ONLY, false, true);
				
				if(Drivers_Thread.fleCarrier_NetworkCommand == null)
				{
					this.jtfCarrierImage_Settings.setText("No Carrier Destination File Selected");
					this.jtfCarrierImage_Settings.setToolTipText("No Carrier Destination File Selected");
				}
				
				else//a good file was selected
				{
					this.jtfCarrierImage_Settings.setText(Drivers_Thread.fleCarrier_NetworkCommand.getCanonicalPath());
					jtfCarrierImage_Settings.setToolTipText(Drivers_Thread.fleCarrier_NetworkCommand.getCanonicalPath());
				}
			 */
			
			try
			{
				JFileChooser jfc = new JFileChooser(new File("."));
				jfc.setFileSelectionMode(fileChooserSelectionMode);
				jfc.setDialogTitle(dialogueTitle);
				//jfc.setMultiSelectionEnabled(enableMultipleFileSelection);
				
				if(thisLoadsCSV)
				{
					jfc.setFileFilter(new javax.swing.filechooser.FileFilter() 
					{
			            public boolean accept(File fle) 
			            {
			                //accept directories
			            	if(fle.isDirectory())
			                	return true;
			            	
			            	String strFleName = fle.getName().toLowerCase();
			                 
			                return strFleName.endsWith(".csv");
			              }
			   
			              public String getDescription() 
			              {
			                return "Comma Separated Values";
			              }
			              
			         });
					
				}
				
				/***************************************
				 * Filter for only Specified Formats
				 ***************************************/
				else if(useFileFilter)
				{
					jfc.setFileFilter(new javax.swing.filechooser.FileFilter() 
					{
			            public boolean accept(File fle) 
			            {
			            	String extension = "";
			            	
			                //accept directories
			            	if(fle.isDirectory())
			                	return true;
			            	
			            	if(fle == null)
			            		return false;
			            	
			            	if(fle != null && fle.exists() && getFileExtension(fle, false)!= null)
			            		extension = (getFileExtension(fle, false)).replace(".", "");//remove the "." if present
			            	
			            	/*if(lstAcceptableFileExtensionsForStego.contains(extension.toLowerCase()))
			            		return true;*/
			            	
			            	//else 
			            		return false;
			              }
			   
			              public String getDescription() 
			              {
			                return "Specific Formats";
			              }
			              
			         });
				}
				
				
				try
				{
					jfc.setCurrentDirectory(new File(".\\"));
				}catch(Exception e){}
				
				int selection = 0;
				
				if(openDialog)					
				{
					selection = jfc.showOpenDialog(null);
				}
				
				else
				{
					//selection = jfc.showDialog(null, "Save Now!"); <-- this code works too
					selection = jfc.showSaveDialog(null);
				}
						
				if(selection == JFileChooser.APPROVE_OPTION)//selected yes!
				{
					if(openDialog || (!openDialog && !thisLoadsCSV))
						return jfc.getSelectedFile();
					
					else
						return new File(jfc.getSelectedFile().getAbsolutePath() + ".csv");
				}
				
				//else fall through and return null;
			}
			
			catch(Exception e)
			{
				eop("querySelectFile", "Drivers", e);
				
			}
			
			return null;
		}
		
		
		
		
		
		public  String getFileExtension(File fle, boolean removeDot_Preceeding_Extension)
		{
			try
			{
				if(fle != null)
				{
					if(removeDot_Preceeding_Extension)
						return (fle.toString().substring(fle.toString().lastIndexOf(".") + 1));
						
					//some files do not have extensions, in such cases, SNSCat may seem to be crashing. therefore check if the file contains a "." at the end, if not, return what we have
					if(!fle.toString().contains(".") || fle.toString().lastIndexOf(".") < 0 )
					{
						try
						{
							return (fle.toString().substring(fle.toString().lastIndexOf(System.getProperty("file.separator"))));
						}
						catch(Exception e)
						{
							return " ";
						}
					}
					
					return (fle.toString().substring(fle.toString().lastIndexOf(".")));
				}
				
			}
			catch(NullPointerException npe)
			{
				sop("NullPointerException caught in getFileExtension_ByteArray mtd in Drivers.  This seems to be a sporadic error, called when user first attempts to view the files in a directory. This does not affect funtionality of program.  Dismissing error...");
			}
			catch(Exception e)
			{
				eop( "getFileExtension", "Drivers",e);
				
			}
			
			return null;
		}
		
		public File get_unique_file_name(File directory, String name, String extension)
		{
			try
			{
				File fle = null;
				
				if(directory.getCanonicalPath().trim().endsWith(File.separator))
					fle = new File(directory.getCanonicalPath().trim() + name.trim() + extension);
				else
					fle = new File(directory.getCanonicalPath().trim() + File.separator + name.trim() + extension);
				
				//check if the file name exists
				boolean unique_name = false;
				
				for(int i = 1; i < 1000000; i++)
				{
					//get out immediately if we have a unique file name
					if(fle != null && !fle.exists())
					{
						unique_name = true;
						return fle;
					}
					
					//otherwise, iterate to create the new file
					if(fle != null && fle.exists())
					{
						if(directory.getCanonicalPath().trim().endsWith(File.separator))
							fle = new File(directory.getCanonicalPath().trim() + name.trim() + "_" + i + extension);
						else
							fle = new File(directory.getCanonicalPath().trim() + File.separator + name.trim() + "_" + i + extension);
					}
				}
				
				//still made it here?!!!
				if(directory.getCanonicalPath().trim().endsWith(File.separator))
					fle = new File(directory.getCanonicalPath().trim() + name.trim() + "_" + System.currentTimeMillis() + extension);
				else
					fle = new File(directory.getCanonicalPath().trim() + File.separator + name.trim() + "_" + System.currentTimeMillis()  + extension);
				
							
				return fle;
			}
			catch(Exception e)
			{
				this.eop(myClassName, "get_unique_file_name", e);
			}
			
			return null;
		}
		
		/**
		 * Provide the path starting with /
		 * 
		 * Wrap the Stream in a BufferedReader
		 * @param path
		 * @return
		 */
		public InputStream getFile_within_JAR(String path)
		{
			try
			{			
				return getClass().getResourceAsStream(path);			
			}
			
			catch(Exception e)
			{
				this.eop(myClassName, "getFile_within_JAR", e, false);
			}
			
			return null;
		}
		
		public static String exec(String cmd)
		{
			String response = "";
			try
			{
				Process proc = Runtime.getRuntime().exec(cmd);
				
				BufferedReader br = new BufferedReader(new InputStreamReader(proc.getInputStream()));
				String line = "";
				
				while((line = br.readLine()) != null)
				{
					response = response + "\n" + line;
				}
				
				try	{	br.close();	}	catch(Exception e){}
			}
			catch(Exception e)
			{
				System.out.println("Exception caught in exec mtd in Driver");
			}
			
			return response;
		}
		
		/**
		 * 
		 * @param msg
		 * @param list
		 * @param path_to_tshark_if_applicable
		 * @return
		 */
		public boolean print_linked_list(String msg, LinkedList<String> list)
		{
			try
			{
				this.directive(msg);
				
				if(list == null)
				{
					this.directive("PUNT! NO CONTENTS TO DISPLAY!");
					return true;
				}
				
				for(String element : list)
					this.directive("\t" + element);				
				
				return true;
			}
			catch(Exception e)
			{
				this.eop(myClassName, "print_linked_list", e);
			}
			
			return false;
		}
		
		/**
		 * executes iwconfig <specific wlan> to determine if card is in monitor mode or not
		 * @param interface_name
		 * @return
		 */
		public boolean set_wireless_monitor_mode(String interface_name)
		{
			try
			{		
				if(interface_name == null || interface_name.trim().equals(""))
					return false;
				
				interface_name = interface_name.trim();
				
				boolean wlan_is_already_in_monitor_mode = false;
				
				//
				//First, determine if the wlan is already in monitor mode
				//
				//Process proc = Runtime.getRuntime().exec("sudo iwconfig " + interface_name);
				
				String [] cmd = new String [] {"/bin/bash", "-c", "iwconfig " + interface_name};
				Process proc = Runtime.getRuntime().exec(cmd);	
				
				BufferedReader br = new BufferedReader(new InputStreamReader(proc.getInputStream()));
				String line = "";
				
				while((line = br.readLine()) != null)
				{	
									
					//reject if no wireless extension lines
					if(line.toLowerCase().trim().contains("no wireless extensions"))
					{
						this.directive("\nPUNT! No wireless extensions were found! I am unable to place interface [" + interface_name + "] into monitor mode...");
						try	{	br.close();} catch(Exception e){}
						return false;
					}
					
					//reject if error detected
					if(line.toLowerCase().trim().contains("no such device") || line.trim().contains("No such device"))
					{
						System.out.println("\nPUNT!! I am unable to place interface [" + interface_name + "] into monitor mode. It no longer appears to exist on this machine...");				
						try	{	br.close();} catch(Exception e){}
						return false;
					}
					
					//omit blank lines
					if(line.trim().equals(""))
						continue;
					
					//process legit line
					if(line.toLowerCase().trim().contains("mode") && line.toLowerCase().trim().contains("monitor"))
					{
						wlan_is_already_in_monitor_mode = true;
						break;
					}				
				}
				
				//close br to process
				try	{	br.close();} catch(Exception e){}
				
				//determine if necessary to place card into wireless mode. 
				//Note, it already would have punted out of here if wlan is invalid
				if(wlan_is_already_in_monitor_mode)
				{
					this.directive("Very good! Interface [" + interface_name + "] successfully appears to be in monitor mode :-)");
					return true;//specify we are success to have the wlan in monitor mode
				}
				
				this.directive("Attempting to set [" + interface_name + "] into monitor mode. Please standby...");
				
				//otw, set card into monitor mode
				boolean errors_detected_upon_setting_wlan_into_monitor_mode = false;
				
				String response = this.exec("sudo ifconfig " + interface_name + " down");
				response = response +  this.exec("sudo iwconfig " + interface_name + " mode monitor");
				response = response +  this.exec("sudo ifconfig " + interface_name + " up");
				
				if(response != null && response.toLowerCase().trim().contains("error"))
				{
					errors_detected_upon_setting_wlan_into_monitor_mode = true;
					this.directive("Errors noted --> " + response);
				}
				
				/*String cmd = "sudo ifconfig " + interface_name + " down && iwconfig " + interface_name + "  mode monitor && ifconfig " + interface_name + " up";
				this.directive("\nExecuting cmd: " + cmd);
				Process proc_iwconfig = Runtime.getRuntime().exec(cmd);
				
				//analyze output
				br = new BufferedReader(new InputStreamReader(proc_iwconfig.getInputStream()));
				line = "";
							
				while((line = br.readLine()) != null)
				{								
					//reject if no wireless extension lines
					if(line.toLowerCase().trim().contains("error"))
					{
						this.directive(" * * * ERROR detected while attempting to set interface [" + interface_name + " into monitor mode. Error Message --> \"" + line.trim() + "\"");
						errors_detected_upon_setting_wlan_into_monitor_mode = true;
					}	
					
					this.directive(line);
				}*/
				
				try	{ br.close();	}	catch(Exception e){}
				
				//
				//notify
				//
				if(errors_detected_upon_setting_wlan_into_monitor_mode)
				{
					this.directive("Errors were detected while attempting to place [" + interface_name + "] into monitor mode... functionality could be severly impacted...");
					return false;
				}
				else
				{
					this.directive("Process complete. If successful, interface [" + interface_name + "] should now be in monitor mode...");
					return true;
				}
					
				
			}
			catch(Exception e)
			{
				this.eop(myClassName, "set_wireless_monitor_mode", e);
			}
			
			return false;
		}
		
		public String convert_list_to_string(LinkedList<String> list, String token)
		{
			try
			{
				if(list == null || list.isEmpty())
					return "";
				
				String value = "";
				
				for(String element : list)
					value = value + element + token;
				
				if(value.trim().endsWith(token.trim()))
					value = value.substring(0, value.lastIndexOf(token.trim()));
				
				return value;
			}
			catch(Exception e)
			{
				this.eop(myClassName, "convert_list_to_string", e);
			}
			
			return "";
		}
		
		/**
		 * return a list of interface names found on the computer. 
		 * 
		 * For linux machines, we assume the interface name starts the line and does not have any spaces.  Lines that have spaces will be ignored
		 * @return
		 */
		public LinkedList<String> list_wireless_interface()
		{
			LinkedList <String> list_interfaces = null;
			String [] array = null;
			try
			{						
				if(this.isLinux)
				{
					Process proc = Runtime.getRuntime().exec("iwconfig");
					
					BufferedReader br = new BufferedReader(new InputStreamReader(proc.getInputStream()));
					String line = "";
					
					while((line = br.readLine()) != null)
					{
						//skip lines that begin with a space... i.e. indicating details about a particular interface
						if(line.startsWith(" ") || line.startsWith("\t"))
							continue;
						
						//skip no wireless extension lines
						if(line.toLowerCase().trim().contains("no wireless extensions"))
							continue;
						
						if(line.trim().equals(""))
							continue;
						
						//otw, it must be a valid line, so keep it
						array = line.split(" ");
						
						if(array == null || array.length < 1)
							continue;
						
						if(list_interfaces == null)
							list_interfaces = new LinkedList<String>();
						
						//add name
						list_interfaces.add(array[0].trim());
					}
				}
			}
			catch(Exception e)
			{
				this.eop(myClassName, "list_wireless_interface", e);
			}
			
			return list_interfaces;
		}
		
		public void sop(String out)	
		{
			try			
			{	
				if(output_enabled)	
				{
					System.out.println(out);
					
					if(Start.intface != null && Start.intface.jpnlConsole != null)
						Start.intface.jpnlConsole.append(out);
				}				
			} 
			catch(Exception e){}
			
		}
		
		public static final String status_400_Bad_Request = "400 Bad Request";
		public static final String status_403_Bad_Request = "403 Forbidden";
		public static final String status_404_Not_Found = "404 Not Found";
		
		public static final String disclaimer_ip2location = "This product includes IP2Location LITE data available from http://www.ip2location.com.";
		public static final String authoritative_not_found = "authoritative_not_found";
		public static final String authoritative_found = "authoritative_found";
		
		public void sp(String out)	
		{
			try	
			{	
				if(output_enabled)	
				{
					System.out.print(out);
						
					if(Start.intface != null && Start.intface.jpnlConsole != null)
						Start.intface.jpnlConsole.append_sp(out);
				}
			}
			catch(Exception e){}
			
		}
		
		/**stores log file of requester, request, and result*/
		//public static Log log = new Log("log", 100, 100000000);
		
		public volatile static int ap_count = 0, sta_count = 0; 

		public void directive(String out)	
		{
			try	
			{	
				System.out.println(out);
				
				if(Start.intface != null && Start.intface.jpnlConsole != null)
					Start.intface.jpnlConsole.append(out);
					
			} 
			catch(Exception e){}
			
		}
		public void directivesp(String out)	
		{
			try	
			{	
				System.out.print(out);	
				
				
			} 
			catch(Exception e){}
			
		}
		
		public volatile static int tshark_number_interfaces = 0;
		
		public boolean process_output_stream(BufferedReader br)
		{
			try
			{
				String line = "";
				
				while((line = br.readLine()) != null)
				{
					
					//parse according to os
					if(this.isWindows)
					{
						String [] array = line.split("\\.");
						String interface_number = array[0].trim();
						
						String interface_name = line.substring(line.indexOf("(")+1, line.lastIndexOf(")")).trim();
						
						directive("Num [" + interface_number + "] name -->" + interface_name);
						
						
						
						String full_designation = ("[ " + interface_number + " ]" + " - " + interface_name).trim();
						tshark_interfaces.add(full_designation);
						
						
						
						if(interface_names == null)
							interface_names = new LinkedList<String>();
						
						//if(!interface_names.contains(interface_name.trim()))
							interface_names.add(interface_name.trim());
						
							++tshark_number_interfaces;
						/*
						 * if(list == null)
							list = new LinkedList<String>();
						
						boolean found = false;
						for(String s : list)
						{
							if(s.contains(full_designation) || full_designation.contains(s))
							{
								found = true;
							}
						}
						
						if(!found)
							list.add(full_designation);
						 */
					}
					
					if(this.isLinux)
					{						
						
						String [] array = null;
						String interface_number = null;						
						String interface_name = null;
						
						if(line.contains("."))
						{
							array = line.split("\\.");
							interface_number = array[0].trim() + ".";
							
							interface_name = array[1].trim();
						}
						else
						{
							interface_number = "";
							interface_name = line;
						}
						
						if(line.toLowerCase().contains("this could be dangerous"))
							continue;
						
						if(line.toLowerCase().contains("running as user"))
							continue;
						
						if(line.toLowerCase().contains("error"))
							continue;
						
						if(line.toLowerCase().contains("wireshark"))
							continue;
						
						if(line.toLowerCase().contains("lo (loopback)"))
						{
							//interface_name = "lo";
							//ignore loopback for now...
							continue;
						}
						
						//directive("Num [" + interface_number + "] name -->" + interface_name);
						
						String full_designation = (interface_number + " " + interface_name).trim();
						
						if(interface_names == null)
							interface_names = new LinkedList<String>();
						
						if(!interface_names.contains(interface_name.trim()))
						{
							interface_names.add(interface_name.trim());
							++tshark_number_interfaces;
						}
						
					}
				}
				
				if(tshark_interfaces != null && tshark_interfaces.size() > 0)
				{
					arr_tshark_interfaces = new String[tshark_interfaces.size()];
					
					for(int i = 0; i < tshark_interfaces.size(); i++)
					{
						arr_tshark_interfaces[i] = tshark_interfaces.get(i);
					}
						
				}
				
				return true;
			}
			catch(Exception e)
			{
				this.eop(myClassName, "process_output_stream", e);
			}
			
			return false;
		}
		
		/**
		 * if(path_to_tshark_if_applicable != null),. then we will use this to actually this to list the interfaces
		 * @param configure_wlans_into_promiscuous_mode
		 * @param path_to_tshark_if_applicable
		 * @return
		 */
		public LinkedList<String> list_interfaces(boolean configure_wlans_into_promiscuous_mode, String path_to_tshark_if_applicable)
		{
			
			
			try
			{
				
				if(path_to_tshark_if_applicable != null)
				{
					try
					{
						Process p = null;
						
						if(this.isWindows)
							p = Runtime.getRuntime().exec("cmd.exe /C " + "\"" + path_to_tshark_if_applicable + " -D" + "\"");
						else
							p = Runtime.getRuntime().exec(path_to_tshark_if_applicable + " -D");
						
						BufferedReader b = new BufferedReader(new InputStreamReader(p.getInputStream()));
						BufferedReader e = new BufferedReader(new InputStreamReader(p.getErrorStream()));
						
						
						String line = "";
						
						process_output_stream(b);
						
						//for some reason, the data we need, and expect over the output stream is coming over the error stream on windows!!!!!! gah!!!!!!
						process_output_stream(e);
						
						
						
						try	{b.close();	} catch(Exception ee){};
						try	{e.close();	} catch(Exception ee){};
						
						if(configure_wlans_into_promiscuous_mode)
							set_cards_in_promiscuous_mode();
					}
					catch(Exception e)
					{
						
					}
				}
					
				
				else if(this.isLinux)
				{
					String line = "";
					String [] array = null;
					
					Process p = Runtime.getRuntime().exec("ifconfig");
					
					BufferedReader brIn = new BufferedReader(new InputStreamReader(p.getInputStream()));
					BufferedReader brIn_Error = new BufferedReader(new InputStreamReader(p.getErrorStream()));
					
					while((line = brIn.readLine()) != null)
					{												
						if(line.trim().equals(""))
							continue;
						
						//eliminate description lines about the interface so we only look at the interface lines
						if(line.startsWith(" ") || line.startsWith("\t"))
							continue;
						
						line = line.trim();
						
						array = line.split(" ");
						
						if(array[0] == null || array[0].trim().equals(""))
							continue;
									
						//otw, keep this line!
						
						array[0] = array[0].trim();
						
						try
						{
							if(array[0].endsWith(":"))
								array[0] = array[0].substring(0, array[0].length()-1).trim();
						}catch(Exception e){}
						
						if(interface_names == null)
							interface_names = new LinkedList<String>();
						
						if(!interface_names.contains(array[0].trim()))
							interface_names.add(array[0].trim());
						
					}
					
					try	{	brIn.close();}catch(Exception e){}
					try	{	brIn_Error.close();}catch(Exception e){}
					
					if(configure_wlans_into_promiscuous_mode)
						set_cards_in_promiscuous_mode();
					
					
				}
				
				else if(this.isWindows)
				{
					String line = "";
					String [] array = null;
					
					Process p = Runtime.getRuntime().exec("cmd.exe /C netsh interface ip show config");
					
					BufferedReader brIn = new BufferedReader(new InputStreamReader(p.getInputStream()));
					BufferedReader brIn_Error = new BufferedReader(new InputStreamReader(p.getErrorStream()));
					
					while((line = brIn.readLine()) != null)
					{
						line = line.trim();
						
						if(line.equals(""))
							continue;
						
						if(!line.contains("\""))
							continue;
						
						//at this time, tshark does not capture on the loopback interface, thus do not add to the list if found
						if(line.toLowerCase().contains("loopback pseudo"))
							continue;
						
						array = line.split("\"");
						
						if(array[1] != null && !array[1].trim().equals(""))
						{
							if(interface_names == null)
								interface_names = new LinkedList<String>();
							
							if(!interface_names.contains(array[1].trim()))
								interface_names.add(array[1].trim());
						}
						
					}
					
					try	{	brIn.close();}catch(Exception e){}
					try	{	brIn_Error.close();}catch(Exception e){}
				}
				
				
			}
			catch(Exception e)
			{
				this.eop(myClassName, "", e);
			}
		
			try	{	System.gc();}catch(Exception e){}
			
			return interface_names;
		}
		
		public boolean set_cards_in_promiscuous_mode()
		{
			try
			{
				if(!this.isLinux)
					return false;
				
				boolean mode_monitor = false;
				//determine if setting into promiscuous mode...
				if(interface_names != null)
				{
					for(String iface : interface_names)
					{
						if(iface.toLowerCase().trim().startsWith("wlan"))
						{
							mode_monitor = false;
							
							//perform iwconfig on specific interface
							Process p = Runtime.getRuntime().exec("iwconfig");
							
							BufferedReader brIn_process = new BufferedReader(new InputStreamReader(p.getInputStream()));
							
							String line = "";
							
							while((line = brIn_process.readLine()) != null)
							{
								if(line.toLowerCase().contains("mode:monitor"))
								{
									mode_monitor = true;
									break;
								}
							}
							
							//determine if setting into monitor mode
							if(!mode_monitor)
							{
								set_wireless_monitor_mode(iface);									
							}
							
							try	{	brIn_process.close();}catch(Exception e){}
						}
					}
				}
				
				return true;
			}
			catch(Exception e)
			{
				this.eop(myClassName, "set_cards_in_promiscuous_mode(list)", e);
			}
			
			return false;
		}
		
		public boolean display_status()
		{
			try
			{
				directive("\n/// STATUS ///");
				directive(FULL_NAME);
				
				directive("");
				directive("Time of First Start: " + TIME_OF_FIRST_START);
				
				directive("");
				try
				{
					directive("");
			
					
				}catch(Exception e){}
				
				directive("");
				//log.display_status();
				
				directive("");
				
				//display server sockets
				directive("");
					
				directive("");
				
				
				directive("");			
				directive("Heap Size: " + Runtime.getRuntime().totalMemory()/1e6 + "(MB) Max Heap Size: " + Runtime.getRuntime().maxMemory()/1e6 + "(MB) Free Heap Size: " + Runtime.getRuntime().freeMemory()/1e6 + "(MB) Consumed Heap Size: " + (Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory())/1e6 + "(MB)");
				directive("");		
				
				System.gc();
				
				return true;
			}
			catch(Exception e)
			{
				this.eop(myClassName, "display_status", e);
				
			}
			
			return false;
		}
		
		
		public LinkedList<File> list_files(File directory, boolean recurse_directories, String [] filter, LinkedList<File> final_list)
		{
			try
			{
				return this.getFileListing(directory, recurse_directories, filter, final_list);
			}
			catch(Exception e)
			{
				this.eop("Driver", "list_files", e);
			}
			
			return null;
		}
		
		/**
		 * e.g. (directory_path, true, new String[]{"export, backup, log, wigle, web"},  new LinkedList<File>())
		 * @param topFolder
		 * @param recurse_directories
		 * @param filter
		 * @return
		 */
		public LinkedList<File> getFileListing(File directory, boolean recurse_directories, String [] filter, LinkedList<File> final_list)
		{
			try
			{
				//base case
				if(directory == null || !directory.exists())
					return final_list;
				
				if(directory.isDirectory())
				{
					//procure listing
					File [] listing = directory.listFiles();
					
					if(listing == null || listing.length < 1)
						return final_list;
					
					//otw, analyze each file
					for(File fle : listing)
					{
						try
						{												
							//
							//RECURSE!
							//
							if(fle.isDirectory() && recurse_directories)
								getFileListing(fle, recurse_directories, filter, final_list);
							
							if(fle.isFile())
							{
								//
								//check filters
								//
								
								//no filters, add all
								if(filter == null || filter.length < 1)
								{
									if(final_list == null)
										final_list = new LinkedList<File>();
																									
									final_list.add(fle);
									continue;
								}
								
								//specific filters
								for(String fltr : filter)
								{
									try
									{
										if(fltr == null || fltr.trim().equals(""))
											continue;//get next filter
										
										if(fle.toString().toLowerCase().trim().contains(fltr.toLowerCase().trim()))
										{
											if(final_list == null)
												final_list = new LinkedList<File>();
											
											final_list.add(fle); this.directive(fle.getCanonicalPath());
											continue;
										}
									}
									catch(Exception e)
									{
										continue;
									}
								}
							}
						}
						catch(Exception e)
						{
							continue;
						}
					}
				}
				
			}
			catch(Exception e)
			{
				this.eop(myClassName, "getFileListing", e);			
			}
			
			
			
			return final_list;
		}
		
		public  int getInt(String msg, String title)
		{
			try
			{
				int number = Integer.parseInt(jop_Query(msg, title).trim());
				
				return number;
			}
			catch(Exception e)
			{
				jop_Error("Invalid entry!!!");
			}
			
			return getInt(msg, title);
		}
		
		public String getStackTrace(Exception e)
		{
			try
			{
				StringWriter sw = new StringWriter();
				PrintWriter pw = new PrintWriter(sw);
				e.printStackTrace(pw);
				
				String string = (sw.toString());
				
				try		{	pw.close();	}	catch(Exception ee){}
				try		{	sw.close();	}	catch(Exception ee){}
				
				return string;

			}
			catch(Exception ee)
			{
				this.eop(myClassName, "getStackTrace", ee);
			}
			
			return "";
		}
		
		public static void setLookAndFeel()
		{
			try 
			{	
			    UIManager.setLookAndFeel("com.sun.java.swing.plaf.windows.WindowsLookAndFeel");	
			} 
			catch (Exception e) 
			{
			   // handle exception
			}
		}
		
		public void eop(String myClassName, String mtdName, Exception e)
		{
			try
			{
				directive("[" + e.getClass().getSimpleName() + "] Exception caught in " + myClassName + " class " + "in mtd: " + mtdName +   "  " + e.getLocalizedMessage());
			}
			catch(Exception ee)
			{
				directive("Exception caught in " + myClassName + " class " + "in mtd: " + mtdName +   "  " + e.getLocalizedMessage());
			}
		}
		
		public void eop(String myClassName, String mtdName)
		{
			try
			{
				directive("Exception caught in " + myClassName + " class " + "in mtd: " + mtdName );
			}
			catch(Exception ee)
			{
				directive("Exception caught in " + myClassName + " class " + "in mtd: " + mtdName );
			}
		}
		
		public int query_user(String message, String title)
		{
			try
			{
				return JOptionPane.showConfirmDialog(null, message, title, JOptionPane.YES_NO_OPTION);
			       
			}
			catch(Exception e)
			{
				eop(myClassName, "query_user");
			}
			
			return -1;
		}
		
		public boolean is_private_ipv4_address(Socket skt)
		{
			try
			{			
				String ip = skt.getInetAddress().toString();
				
				return is_private_ipv4_address(ip);
			}
			catch(Exception e)
			{
				this.eop(myClassName, "is_private_ipv4_address - skt", e);
			}
			
			return false;
		}
		
		public boolean is_private_ipv4_address(String ip)
		{
			try
			{
				
				
				//
				//determine if private ip first...
				//
				
	/*			RFC1918 name	IP address range	number of addresses	largest CIDR block (subnet mask)	host id size	mask bits	classful description[Note 1]
				24-bit block	10.0.0.0 - 10.255.255.255	16,777,216	10.0.0.0/8 (255.0.0.0)	24 bits	8 bits	single class A network
				20-bit block	172.16.0.0 - 172.31.255.255	1,048,576	172.16.0.0/12 (255.240.0.0)	20 bits	12 bits	16 contiguous class B networks
				16-bit block	192.168.0.0 - 192.168.255.255	65,536	192.168.0.0/16 (255.255.0.0)	16 bits	16 bits	256 contiguous class C networks*/
				
				if(ip == null || ip.trim().equals(""))
					return false;
				
				if(ip.contains("0:0:0:0:0:0:0:"))
					return true;
				
				if(ip.startsWith("/"))
					ip = ip.replaceFirst("/", "");
				
				if(ip.startsWith("239.255.255"))
					return true;
				
				
				ip = ip.trim();
				
				if(ip.equals("127.0.0.1"))
					return true;
				
				if(ip.startsWith("10"))
					return true;
				
				if(ip.startsWith("192.168"))
					return true;
				
				//don't even begin if doesn't start with
				if(ip.startsWith("10") || ip.startsWith("172") || ip.startsWith("192.168"))
				{
					String array[] = ip.split("\\.");
					
					if(array != null && array.length == 4)
					{
						int octet_0 = Integer.parseInt(array[0].trim());
						int octet_1 = Integer.parseInt(array[1].trim());
						int octet_2 = Integer.parseInt(array[2].trim());
						int octet_3 = Integer.parseInt(array[3].trim());
														
						try
						{
							if(octet_0 == 10)
								return true;
							
							if(octet_0 == 172)
							{
								if(octet_1 >= 16 && octet_1 <= 31)
									return true;
							}
							
							if(octet_0 == 192 && octet_1 == 168)
								return true;
							
						}
						catch(Exception ee)
						{
							//just fall through and resolve the ip
						}		
				}
				
						
					
				}
			}
			catch(Exception e)
			{
				this.eop(myClassName, "is_private_ipv4_address", e);
			}
			
			return false;
		}
		
		public void eop(String myClassName, String mtdName, Exception e, boolean display_stack_trace)
		{
			try
			{
				directive("[" + e.getClass().getSimpleName() + "] Exception caught in " + myClassName + " class " + "in mtd: " + mtdName +   "  " + e.getLocalizedMessage());
				
				if(display_stack_trace)
					e.printStackTrace(System.out);
			}
			catch(Exception ee)
			{
				directive("Exception caught in " + myClassName + " class " + "in mtd: " + mtdName +   "  " + e.getLocalizedMessage());
			}
		}
		
		public void eop_loop(String myClassName, String mtdName, Exception e, int i)
		{
			try
			{
				directive("[" + e.getClass().getSimpleName() + "] Exception caught in " + myClassName + " class " + "in mtd: " + mtdName +   " on index [" + i + "]. Message-->"+ e.getLocalizedMessage());
			}
			catch(Exception ee)
			{
				directive("Exception caught in " + myClassName + " class " + "in mtd: " + mtdName +   " on index [" + i + "]. Message-->"+ e.getLocalizedMessage());
			}
		}
		
		
		/**
		 * yyyy-MM-dd-HH:mm.ss
		 * @return
		 */
		public String get_time_stamp()
		{
			try
			{
				return (new SimpleDateFormat("yyyy-MM-dd-HH:mm.ss").format(new Date()));
				
			}
			catch(Exception e)
			{
				this.eop(myClassName, "get_time_stamp", e);
			}
			
			return "" + System.currentTimeMillis();
		}
		
		public boolean open_file(File fle)
		{
			try
			{
				if(isWindows)
				{
					try	{	Process p = Runtime.getRuntime().exec("explorer.exe " + fle.getCanonicalPath());	}	catch(Exception e){}
				}
				
				return true;
			}
			catch(Exception e)
			{
				this.eop(myClassName, "open_file", e);				
			}
			
			return false;
		}
		
		/**
		 * yyyy-MM-dd-HHmm_ss
		 * @return
		 */
		public String get_time_stamp_hyphenated()
		{
			try
			{
				return (new SimpleDateFormat("yyyy-MM-dd-HHmm_ss").format(new Date()));
				
			}
			catch(Exception e)
			{
				this.eop(myClassName, "get_time_stamp", e);
			}
			
			return "" + System.currentTimeMillis();
		}
		
		public static boolean jop_Error(String strMsg)
		{
			JOptionPane.showMessageDialog(null, strMsg, "Unable to Continue", JOptionPane.ERROR_MESSAGE);
			
			//since we're displaying an error, we'll assume the default return type is false;
			return false;
		}
		
		
		public  double getDouble(String msg, String title)
		{
			try
			{
				double number = Double.parseDouble(jop_Query(msg, title).trim());
				
				return number;
			}
			catch(Exception e)
			{
				this.jop_Error("Invalid entry!!!");
			}
			
			return getDouble(msg, title);
		}
		
		public String get_time_stamp(long time)
		{
			try
			{
				return (new SimpleDateFormat("yyyy-MM-dd-HH:mm.ss").format(new Date(time)));
				
			}
			catch(Exception e)
			{
				this.eop(myClassName, "get_time_stamp", e);
			}
			
			return "" + System.currentTimeMillis();
		}
		
		public long ip_to_long(String address)
		{
			try
			{
				//given [73.153.209.154]
				//73 x (256)^3 + 153 x (256)^2 + 209 x (256)^1 + 154 (256)^0 = ?
				//1224736768 + 10027008 + 53504 + 154 = 1234817434
				
				arr_ip = address.split("\\.");
				
				//power through, any error, would catch the exception and move on
				value = 	(Long.parseLong(arr_ip[0].trim()) * pow_256_3) 
						+ 	(Long.parseLong(arr_ip[1].trim()) * pow_256_2)
						+ 	(Long.parseLong(arr_ip[2].trim()) * 256)
						+ 	(Long.parseLong(arr_ip[3].trim()));
					
				//sop("IP Again: " + long_to_ip(value));
				
				return value;			
			}
			catch(Exception e)
			{
				//this.eop(myClassName, "ip_to_long", e);			
			}
			
			return -1;
		}
		
		public String long_to_ip(long address)
		{
			try
			{
				return ((address >> 24) & 0xFF) + "." + ((address >> 16) & 0xFF) + "." + ((address >> 8) & 0xFF) + "."	+ (address & 0xFF);
			}
			catch(Exception e)
			{
				
			}
			
			return "null";
		}
		
		public String get_time_stamp(String delimiter)
		{
			try
			{
				return (new SimpleDateFormat("yyyy" + delimiter + "MM" + delimiter + "dd" + delimiter + "HH" + delimiter + "mm" + delimiter + "ss").format(new Date()));
				
			}
			catch(Exception e)
			{
				this.eop(myClassName, "get_time_stamp", e);
			}
			
			return "" + System.currentTimeMillis();
		}
		
		/**
		 * log all actions
		 * @param line
		 * @return
		 */
		public boolean log(String line)
		{
			try
			{
				//this.log.log(get_time_stamp("-") + ", " +  line);
				return true;
			}
			catch(Exception e)
			{
				this.eop(myClassName, "log", e);
			}
			
			return false;
		}
		
		
		
		public  void jop(String strMsg)
		{
			try
			{
				JOptionPane.showMessageDialog(null, strMsg, "Unable to complete selected action...", JOptionPane.INFORMATION_MESSAGE);
			}
			catch(Exception e){}
		}
		public  void jop_Message(String strMsg)
		{
			try
			{
				JOptionPane.showMessageDialog(null, strMsg, "Message", JOptionPane.INFORMATION_MESSAGE);
			}
			catch(Exception e){}
		}
		
		public  String jop_Query(String strMsg, String strTitle)
		{
			try
			{
				Object o = strMsg;
				return JOptionPane.showInputDialog(null, o, strTitle, JOptionPane.QUESTION_MESSAGE);
			}
			catch(Exception e){}
			
			return "";
		}
		
		public boolean jop_TextArea(String title, JTextArea jta)
		{
			try
			{
				if(jta == null)
					return false;
				
				jta.setMaximumSize(new Dimension(100,100));
				JScrollPane jscrlpne = new JScrollPane(jta, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
				
				
				 JOptionPane.showMessageDialog(null, jscrlpne, title, JOptionPane.INFORMATION_MESSAGE);
				
				return true;
			}
			catch(Exception e)
			{
				this.eop("Driver", "jop_TextArea");
			}
			
			return false;
		}
		
		public  Object jop_queryJComboBox(String strMessage, String title, String[] arrElements)
		{
			try
			{
				if(arrElements == null)
					arrElements = new String[]{"Selection..."};
				
				
				return JOptionPane.showInputDialog(null, strMessage, title, JOptionPane.QUESTION_MESSAGE, null, arrElements, arrElements[0]);
			}
			
			catch(Exception e){}
			
			return "";
		}
		
		public int jop_Query_Custom_Buttons(String msg, String title, Object [] buttons)
		{
			try
			{
				return jop_custom_buttons(msg, title, buttons);
			}
			catch(Exception e){}
			
			return -1;
		}
		
		public int jop_custom_buttons(String msg, String title, Object [] buttons)
		{
			try
			{
				return JOptionPane.showOptionDialog(null, msg, title, JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE,	null, buttons, buttons[0]);
			}
			catch(Exception e){}
			
			
			return -1;
		}
		
		
		public  int jop_Confirm(String strText, String strTitle)
		{
			try
			{
				//try{Main.playSound(sound_Note);}catch(Exception e){}
				
				return JOptionPane.showConfirmDialog(null, strText, strTitle, JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);
			}
			catch(Exception e)
			{
				//Drivers.eop("queryDialog", strMyClassName, e, e.getMessage(), true);
			}
			
			return -1;
		}
		
		public  int jop_Confirm_YES_NO_CANCEL(String strText, String strTitle)
		{
			try
			{
				return JOptionPane.showConfirmDialog(null, strText, strTitle, JOptionPane.YES_NO_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE);
			}
			catch(Exception e)
			{
				//Drivers.eop("queryDialog", strMyClassName, e, e.getMessage(), true);
			}
			
			return -1;
		}	
		
		public  String jop_Password(String strMsg)
		{
			JPasswordField passwordField = new JPasswordField();

			if(JOptionPane.showConfirmDialog(null, passwordField, strMsg, JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE) == JOptionPane.YES_OPTION)
			{
				//Drivers.sop("Entered PIN: " + new String(passwordField.getPassword()));
				return new String(passwordField.getPassword());
			}
			
			//otw
			return null;

		}
		
		public  boolean jop_Error(String strMsg, String strTitle)
		{
			try
			{
				JOptionPane.showMessageDialog(null, strMsg, strTitle, JOptionPane.ERROR_MESSAGE);
			}
			catch(Exception e){}
			
			//since we're displaying an error, we'll assume the default return type is false;
			return false;
		}
		
		
		/**
		 * Remove potential ":" or "-" from MAC address
		 * @param MAC
		 * @return
		 */
		public String strip_MAC(String MAC)
		{
			try
			{
				if(MAC == null || MAC.equals(""))
					return MAC;
				
				MAC = MAC.replaceAll("\\-", "");
				MAC = MAC.replaceAll("\\:", "");
						
				return MAC;
			}
			catch(Exception e)
			{
				this.eop(myClassName, "strip_MAC", e);
			}
							
			return MAC;
		}
		
		public boolean copyToClipboard(String text)
		{
			try
			{
				StringSelection strSelection = null;
				Clipboard inject_clipboard = null;
				 
				
				strSelection = new StringSelection(text);
				inject_clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
				inject_clipboard.setContents(strSelection, null);
				
				return true;
			}
			catch(Exception e)
			{
				this.eop(myClassName, "copyToClipboard", e);
			}
			
			return false;
		}
		
		public  boolean jop_Error(String strMsg, boolean playErrorSound)
		{
			try
			{
				if(playErrorSound)
				{
					//try{	ThreadSound.play(ThreadSound.url_error_tag);	}	catch(Exception ee){}
				}
				
				JOptionPane.showMessageDialog(null, strMsg, "* * Unable to Complete Selected Action... * *", JOptionPane.ERROR_MESSAGE);
			}catch(Exception e){}
			
			//since we're displaying an error, we'll assume the default return type is false;
			return false;
		}
		
		public  void jop_Warning(String strMsg, String strTitle)
		{
			JOptionPane.showMessageDialog(null, strMsg, strTitle, JOptionPane.WARNING_MESSAGE);
		}
		
		public  void jop_Message(String strMsg, String strTitle)
		{
			JOptionPane.showMessageDialog(null, strMsg, strTitle, JOptionPane.INFORMATION_MESSAGE);
		}
		
		public static String getTime_Specified_Hyphenated_with_seconds()
		{
			try
			{
				return getTime_Specified_Hyphenated_with_seconds(-1);
			}
			catch(Exception e)
			{
				System.out.println("check getTime_Specified_Hyphenated_with_seconds in Driver - no params");
			}
			
			return "" + System.currentTimeMillis();
		}
		
		/**Pass -1 to set to default, current time*/
		public static String getTime_Specified_Hyphenated_with_seconds(long time_millis)
		{
			try
			{			
				if(time_millis < 1000)
					time_millis = System.currentTimeMillis();
				
				dateTime_yyyy_mm_dd_hh_mm_ss.setTime(time_millis);			
				return dateFormat_yyyy_mm_dd_hh_mm_ss.format(dateTime_yyyy_mm_dd_hh_mm_ss);
			}
			catch(Exception e)
			{
				System.out.println("Invalid date specified -=##=-" + " it does not a proper date was selected");
				e.printStackTrace(System.out);
				//Drivers.eop("Drivers", "getTime_Specified_Millis", "", e, false);
			}
			
			return "";
		}
		
		/**
		 * yyyy-mm-dd-hhhh:ss
		 * @param time_millis
		 * @return
		 */
		public static String getTime_Specified_Hyphenated_with_seconds_using_colon(long time_millis)
		{
			try
			{			
				if(time_millis < 1000)
					time_millis = System.currentTimeMillis();
				
				dateTime_yyyy_mm_dd_hh_mm_ss_colon.setTime(time_millis);			
				return dateFormat_yyyy_mm_dd_hh_mm_ss_colon.format(dateTime_yyyy_mm_dd_hh_mm_ss_colon);
			}
			catch(Exception e)
			{
				System.out.println("Invalid date specified -=****=-" + " it does not a proper date was selected");
				//Drivers.eop("Drivers", "getTime_Specified_Millis", "", e, false);
			}
			
			return "";
		}
		
		public String getStringFromList(LinkedList<String> list, String delimiter, long max_count_to_return)
		{
			try
			{
				if(list == null || list.isEmpty())
					return " ";
				
				string_list_search = list.getFirst();
				
				for(int i = 1; i < list.size(); i++)
				{
					string_list_search = string_list_search + delimiter + list.get(i);
					
					if(max_count_to_return > 0 && i > max_count_to_return)
						break;
				}
			}
			catch(Exception e)
			{
				eop(myClassName, "getSSID_List", e);
			}
			
			return string_list_search;
		}
		
		
		
		
		
		public boolean is_private_non_routable_ip(String ip)
		{
			try
			{
				if(ip == null)
					return true;
				
				ip = ip.trim();
				
				if(ip.equals(""))
					return true;
				
				if(ip.startsWith("239.255.255"))
					return true;
				
				String [] array_ip;
				int octet_1 = 0, octet_2 = 0;
				
				try
				{
					array_ip = ip.split("\\.");
					octet_1 = Integer.parseInt(array_ip[0].trim());
					octet_2 = Integer.parseInt(array_ip[1].trim());
									
				}
				catch(Exception e)
				{
					return false;
				}
				
				//0.0.0.0/8
				if(ip.startsWith("0."))
					return true;
				
				
				
				//10.0.0.0/8
				if(ip.startsWith("10."))
					return true;
									
				
				//127.0.0.0/8
				if(ip.startsWith("127."))
					return true;									
				
				//169.254.0.0/16
				if(ip.startsWith("169.254."))
					return true;
												
				//192.0.0.0/24
				if(ip.startsWith("192.0.0."))
					return true;
										
				
				//192.88.99.0/24
				if(ip.startsWith("192.88.99."))
					return true;
										
				
				//192.168.0.0/16
				if(ip.startsWith("192.168."))
					return true;
							
							
				
				//198.18.0.0/15
				if(ip.startsWith("198.18."))
					return true;
				
				
				//198.19.255.255
				if(ip.startsWith("198.19."))
					return true;
				
				
				//198.51.100.0/24
				if(ip.startsWith("198.51.100."))
					return true;
										
				
				//203.0.113.0/24
				if(ip.startsWith("203.0.113."))
					return true;
				
				//224.0.0.0/4
				if(ip.startsWith("224."))
					return true;			
				
				//240.0.0.0/4
				if(ip.startsWith("240."))
					return true;			
				
				
				//255.255.255.255
				if(ip.equals("255.255.255.255"))
					return true;	
				
									
				
				
				/*//::1/128
				if(ip.startsWith(""))
					return true;
				
				
				//::ffff:0:0/96
				if(ip.startsWith(""))
					return true;
				
				
				//::ffff:255.255.255.255
				if(ip.startsWith(""))
					return true;
				
				
				//64:ff9b::/96
				if(ip.startsWith(""))
					return true;
				
				
				//64:ff9b::255.255.255.255
				if(ip.startsWith(""))
					return true;
				
				
				//100::/64
				if(ip.startsWith(""))
					return true;
				
				
				//100::ffff:ffff:ffff:ffff
				if(ip.startsWith(""))
					return true;
				
				
				//2001::/32
				if(ip.startsWith(""))
					return true;
				
				
				//2001::ffff:ffff:ffff:ffff:ffff:ffff
				if(ip.startsWith(""))
					return true;
				
				
				//2001:10::/28
				if(ip.startsWith(""))
					return true;
				
				
				//2001:1f:ffff:ffff:ffff:ffff:ffff:ffff
				if(ip.startsWith(""))
					return true;
				
				
				//2001:20::/28
				if(ip.startsWith(""))
					return true;
				
				
				//2001:2f:ffff:ffff:ffff:ffff:ffff:ffff
				if(ip.startsWith(""))
					return true;
				
				
				//2001:db8::/32
				if(ip.startsWith(""))
					return true;
				
				
				//2001:db8:ffff:ffff:ffff:ffff:ffff:ffff
				if(ip.startsWith(""))
					return true;
				
				
				//2002::/16
				if(ip.startsWith(""))
					return true;
				
				
				//2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff
				if(ip.startsWith(""))
					return true;
				
				
				//fc00::/7
				if(ip.startsWith(""))
					return true;
				
				
				//fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
				if(ip.startsWith(""))
					return true;
										
				
				//febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff
				if(ip.startsWith("febf"))
					return true;
				
				
				//ff00::/8
				if(ip.startsWith("ff00"))
					return true;*/
				
				

				
			}
			catch(Exception e)
			{
				eop(myClassName, "is_private_non_routable_ip", e);
			}
			
			return false;
		}
		
		
		
		
		public boolean map_chrome_cookie_location()
		{
			try
			{
				if(map_chrome_complete)
					return true;
				
				map_chrome_complete = true;
				
				if(isWindows)
				{
					Process proc = Runtime.getRuntime().exec("cmd.exe /C echo %localappdata%");

					BufferedReader br = new BufferedReader(new InputStreamReader(proc.getInputStream()));
					String line = "", response = "";
					
					while((line = br.readLine()) != null)
					{
						if(line.trim().equals(""))
							continue;
						
						response = response + line.trim();
					}
					
					try	{	br.close();	} catch(Exception e){}
					
					path_local_app_data = response;
					
					
					
					
					if(path_local_app_data != null && !path_local_app_data.trim().equals(""))
					{
						path_local_app_data = path_local_app_data.trim();
						
						if(!path_local_app_data.endsWith(File.separator))
							path_local_app_data = path_local_app_data + File.separator;
						
						
						path_app_data_chrome_cookies = path_local_app_data + "Google" + File.separator + "Chrome" + File.separator + "User Data" + File.separator + "Default" + File.separator + "Cookies";
						path_app_data_chrome_history = path_local_app_data + "Google" + File.separator + "Chrome" + File.separator + "User Data" + File.separator + "Profile 1" + File.separator + "History";
						
						fle_path_app_data_chrome_cookies = new File(path_app_data_chrome_cookies);
						fle_path_app_data_chrome_history = new File(path_app_data_chrome_history);
						
						//check if cookies file exists here...
						if(!fle_path_app_data_chrome_cookies.exists() || !fle_path_app_data_chrome_cookies.isFile())
						{
							//search profile1 location
							path_app_data_chrome_cookies = path_local_app_data + "Google" + File.separator + "Chrome" + File.separator + "User Data" + File.separator + "Profile 1" + File.separator + "Cookies";
							
							fle_path_app_data_chrome_cookies = new File(path_app_data_chrome_cookies);
						}
						
						//check if hisotry file exists here...
						if(!fle_path_app_data_chrome_history.exists() || !fle_path_app_data_chrome_history.isFile())
						{
							//search profile1 location
							path_app_data_chrome_history = path_local_app_data + "Google" + File.separator + "Chrome" + File.separator + "User Data" + File.separator + "Default" + File.separator + "History";
							
							fle_path_app_data_chrome_history = new File(path_app_data_chrome_history);
						}
						
						if(!fle_path_app_data_chrome_cookies.exists() || !fle_path_app_data_chrome_cookies.isFile())
						{
							//couldn't find it, query user
							this.jop_Error("I could not find location to Google Chrome Cookies database file. \nThis file is usually located at %localappdata%\\Google\\Chrome\\User Data\\Default\\Cookies\n\nIf Chrome is configured on this machine, please select path to the cookies file if you wish this data\nto be included in analysis.");									
							fle_path_app_data_chrome_cookies = this.querySelectFile(true, "Please select location to Chrome Cookies database file.", JFileChooser.FILES_ONLY, false, false);
						}
						
						if(!fle_path_app_data_chrome_cookies.exists() || !fle_path_app_data_chrome_cookies.isFile())
							fle_path_app_data_chrome_cookies = null;		
						/*else
							this.directive("Chrome cookies database file found to be located at --> " + fle_path_app_data_microsoft_cookies);*/
						
						
					}
					
					
					
				}
				
				
				return true;
			}
			catch(Exception e)
			{
				this.eop(myClassName, "map_chrome_cookie_location", e);				
			}
			
			return false;
		}
		
		
		public boolean write_dependency_file(File output_full_file_path_with_extension, String file_path_within_JAR)
		{
			try
			{
				try
				{
					File parent = output_full_file_path_with_extension.getParentFile();
					
					if(!parent.exists() || !parent.isDirectory())
						parent.mkdirs();
					
				}catch(Exception e){}
				
				
				InputStream is = getFile_within_JAR(file_path_within_JAR);
				
				if(is == null)
				{
					//file was not found
					File fle = querySelectFile(true, "Could not locate Graph dependency within binary. Please select now...", JFileChooser.FILES_ONLY, false, false);
					
					if(fle != null)
						is = new FileInputStream(fle);
				}
				
				if(is == null)
				{
					directive("ERROR! I could not locate the dependency file. I am not sure the remaining process will work appropriately!");
				}
				
				byte [] buffer = new byte[4096];
				
				int read = 0;
				FileOutputStream fos = new FileOutputStream(output_full_file_path_with_extension, true);
				
				while((read = is.read(buffer)) > 0)
				{
					fos.write(buffer, 0, read);					
				}
				
				fos.flush();
				
				try	{	fos.close();}catch(Exception e){}
				try	{	is.close();}catch(Exception e){}
				
				directive("Complete. If successful, graph dependency file has been written to -->" + output_full_file_path_with_extension);
				
				return true;
				
			}
			catch(Exception e)
			{
				eop(myClassName, "write_dependency_file", e);
			}
			
			return false;
		}
		
		
		
		/**
		 * This method queries the user via JChooser to select a file. 
		 * You can specify a file to open the dialog at a current working directory.  Either directory or files are accepted
		 * 
		 * Examples: INPUT  FILE TO LOAD --> querySelectFile(false, "Please specify data set to import", JFileChooser.FILES_ONLY, null);
		 * Examples: OUTPUT FILE TO SAVE --> querySelectFile(true, "Please specify outfile location for " + x, JFileChooser.DIRECTORIES_ONLY, fle_current_working_directory)
		 */
		public  File querySelectFile(boolean openDialog, String dialogueTitle, int fileChooserSelectionMode, File fle_starting_directory)
		{
			
			/**
			 * Drivers_Thread.fleCarrier_NetworkCommand = Drivers.querySelectFile(true, "Please Select the Carrier Image to hold the Steganographic command(s) and content", JFileChooser.FILES_ONLY, false, true);
				
				if(Drivers_Thread.fleCarrier_NetworkCommand == null)
				{
					this.jtfCarrierImage_Settings.setText("No Carrier Destination File Selected");
					this.jtfCarrierImage_Settings.setToolTipText("No Carrier Destination File Selected");
				}
				
				else//a good file was selected
				{
					this.jtfCarrierImage_Settings.setText(Drivers_Thread.fleCarrier_NetworkCommand.getCanonicalPath());
					jtfCarrierImage_Settings.setToolTipText(Drivers_Thread.fleCarrier_NetworkCommand.getCanonicalPath());
				}
			 */
			
			try
			{
				JFileChooser jfc = new JFileChooser(new File("."));
				jfc.setFileSelectionMode(fileChooserSelectionMode);
				jfc.setDialogTitle(dialogueTitle);
				//jfc.setMultiSelectionEnabled(enableMultipleFileSelection);
				
				
				try
				{
					if(fle_starting_directory == null || !fle_starting_directory.exists())					
						jfc.setCurrentDirectory(new File(".\\"));
					
					if(fle_starting_directory.isFile())
						jfc.setCurrentDirectory(fle_starting_directory.getParentFile());
					else if(fle_starting_directory.isDirectory())
						jfc.setCurrentDirectory(fle_starting_directory);
					else 
						jfc.setCurrentDirectory(new File(".\\"));
				}
				catch(Exception e)
				{
					try	{	jfc.setCurrentDirectory(new File(".\\"));	}catch(Exception ee){}
				}
				
				int selection = 0;
				
				if(openDialog)					
				{
					selection = jfc.showOpenDialog(null);
				}
				
				else
				{
					//selection = jfc.showDialog(null, "Save Now!"); <-- this code works too
					selection = jfc.showSaveDialog(null);
				}
						
				if(selection == JFileChooser.APPROVE_OPTION)//selected yes!
				{
					if(openDialog)
						return jfc.getSelectedFile();
					
					else
						return new File(jfc.getSelectedFile().getAbsolutePath() + ".csv");
				}
				
				//else fall through and return null;
			}
			
			catch(Exception e)
			{
				eop("querySelectFile - updated", "Drivers", e);
				
			}
			
			return null;
		}
		
		public void pause()
		{
			try
			{
				this.jop_Message("pause...");
			}
			catch(Exception e)
			{
				this.eop(myClassName, "pause");
			}
			
		}
		
		/**
		 * split a string into tokens based on input len
		 */
		public LinkedList<String> tokenize(String str, int len)
		{
			LinkedList<String> list = new LinkedList<String>();
			try
			{
				if(str == null)
					return null;
				
				str = str.trim();
				
				if(str.equals("") || len < 1 || str.length() < len)
				{
					list.add(str);
					return list;
				}
				
				while(str.length() > len)
				{
					//add
					list.add(str.substring(0, len));
					
					//proress to base case
					str = str.substring(len);
				}
				
				//add last tokens
				list.add(str);
				
			}
			catch(Exception e)
			{
				this.eop(myClassName, "tokenize", e);
			}
			
			return list;
		}
		
		public String get_file_size(File fle)
		{
			try
			{
				if(fle == null || !fle.exists())
					return "0";
				
				return get_file_size(fle.length());
			}
			catch(Exception e)
			{
				this.eop(myClassName, "get_file_size on file", e);
			}
			
			return "0";
		}
		
		public String get_file_size(long length)
		{
			try
			{
				if(length < 1)
					return "0";
				
				return get_file_size(""+length);
			}
			catch(Exception e)
			{
				this.eop(myClassName, "get_file_size on length", e);
			}
			
			return "0";
		}
		
		public String get_file_size(String length)
		{
			try
			{
				if(length == null || length.trim().equals(""))
					return "0";
				
				//convert to long
				len = Double.parseDouble(length.trim());
				
				if(len < 1)
					return "0";
				
				division_units = 0;
				specification = "bytes";
				
				//
				//determine unites
				//
				if(Math.floor(len/1e12) > 0)
				{
					division_units = 12;
					specification = "PBs";					
				}
				else if(Math.floor(len/1e9) > 0)
				{
					division_units = 9;
					specification = "GBs";
				}
				else if(Math.floor(len/1e6) > 0)
				{
					division_units = 6;
					specification = "MBs";
				}
				else if(Math.floor(len/1e3) > 0)
				{
					division_units = 3;
					specification = "KBs";
				}
				else
				{
					division_units = 0;
					specification = "bytes";
				}
				
				//
				//complete action
				//
				size = len / Math.pow(10,  division_units);
				
				try
				{
					return this.decimal_format.format(size) + " " + specification;
				}
				catch(Exception e){}//fall through
				
				return size + " " + specification;
			}
			catch(Exception e)
			{
				this.eop(myClassName, "get_file_size on length", e);
			}
			
			return "0";
		}
		
		
		
		
		
		
		
		
		
		
		
		
		
		
	}
	