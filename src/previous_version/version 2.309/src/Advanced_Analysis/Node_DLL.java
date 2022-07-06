/**
 * Known Issues: printing file_attr entry may have a file name referencing a process, but could be imported by serveral processes - each with a different MD5 dump. However, most (if not all) are the same file size.
 * I may come back and print out each file name to the same dump if needed...
 * 
 * @author Solomon Sonya
 */


package Advanced_Analysis;

import java.io.*;
import java.util.LinkedList;
import java.util.TreeMap;

import Driver.Driver;
import Driver.FileAttributeData;
import Interface.JTextArea_Solomon;

public class Node_DLL 
{
	public static final String myClassName = "Node_DLL";
	public static volatile Driver driver = new Driver();
	
	public volatile String lower = null;
	public volatile boolean XREF_SEARCH_HIT_FOUND = false;
	
	public volatile Advanced_Analysis_Director director = null;
	
	public static final int MAX_TREE_NODE_COUNT = Advanced_Analysis_Director.MAX_TREE_NODE_COUNT;
	
	//unique processes linked to this DLL
	public volatile TreeMap<Integer, Node_Process> tree_process = new TreeMap<Integer, Node_Process>();
	
	//list of processes that store this DLL at base address
	public volatile TreeMap<String, LinkedList<Node_Process>> tree_base_address = new TreeMap<String, LinkedList<Node_Process>>();
		
	public volatile TreeMap<String, Node_ApiHook> tree_api_hook = new TreeMap<String, Node_ApiHook>();	
	
	//Import function names
	/**populated by dependencies*/
	public volatile TreeMap<String, Node_Import_DLL_Function> tree_import_function_table_dependencies = new TreeMap<String, Node_Import_DLL_Function>();
	
	/**populated by impscan - 0x00b290c4 0x7599c204 GDI32.dll            CreateFontW; IAT varies by importing process, however call address and function name are the same
	 * store based on call address*/
	public volatile TreeMap<String, Node_Import_DLL_Function> tree_import_function_table_impscan = new TreeMap<String, Node_Import_DLL_Function>();
	
	//tree of attributes - each DLL dump may be slightly different based on the process and how volatility dumps the module
	public volatile TreeMap<Integer, FileAttributeData> tree_file_dump_attributes = new TreeMap<Integer, FileAttributeData>();
	
	public volatile String base_addresses = null;

	//Set in analyze_dlldump plugin class
	/**use data from fle_attributes vice this fle object*/
	public volatile File fle = null;
	public volatile FileAttributeData fle_attributes = null;
	
	//
	//DLLLIST
	//
	public volatile String base = null;
	public volatile String size = null;
	public volatile String load_count = null;
	public volatile String path = null;

	public String found_in_dlllist = null;
	public String found_in_ldrmodule = null;
	
	//
	//LDRMODULES
	//
	public volatile String in_load = null;
	public volatile String in_init = null;
	public volatile String in_mem = null;
	
	//
	//VERINFO
	//
	public volatile boolean found_in_verinfo_plugin = false;
	public volatile String file_version = null;
	public volatile String product_name = null;
	public volatile String comments = null;
	public volatile String company_name = null;
	public volatile String flags = null;
	public volatile String internal_name = null;
	public volatile String legal_trademarks = null;
	public volatile String ole_self_register = null;
	public volatile String os = null;
	public volatile String original_file_name = null;
	public volatile String copyright_legal_copyright = null;	
	public volatile String file_description = null;
	public volatile String file_type = null;
	public volatile String product_version = null;
	
	public volatile String file_size = null;
	public volatile String date_modified = null;
	public volatile String language = null;
	
	
	public volatile boolean I_HAVE_WRITTEN_PROCESS_HEADER_ALREADY = false;
	
	public volatile boolean printed_node_under_process = false;
	
	/**set during import manifest function reading in import file details*/
	public volatile String importing_processes_import_manifest = null;
	public volatile Node_ApiHook api_hook_import_manifest = null;
	
	public Node_DLL(Advanced_Analysis_Director DIRECTOR)
	{
		try
		{
			director = DIRECTOR;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
	}
	
	
	
	
	
	public String toString()
	{
		try
		{
			return path + "\t" + "base: " + this.base + "\tsize: " + this.size + "\tload_count: " + load_count + "\tfile version: " + file_version + "\tproduct version: " + product_version + "\tcompany name: " + company_name + "\tfile type: " + file_type + "\tfile description: " + file_description + "\tcopyright: " + copyright_legal_copyright;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "toString", e);
		}
		
		return "* - *";
	}
	
	
	
	
	
	
	public boolean write_module_information(String tab, PrintWriter pw, Node_Process PROCESS)
	{
		try
		{
			try
			{
				pw.println(tab +  "{ \"name\": \"" +  normalize_html(path.substring(path.lastIndexOf("\\")+1).trim()).replace("\\", "\\\\") + "\" , \"children\": [");
			}
			catch(Exception e)
			{
				pw.println(tab +  "{ \"name\": \"" +  normalize_html(path).replace("\\", "\\\\") + "\" , \"children\": [");	
			}						
			
			
				pw.println(tab +  "{ \"name\": \"" +  normalize_html("Module Information").replace("\\", "\\\\") + "\" , \"children\": [");
				
					driver.write_node_ENTRY("Path: ", path, pw);
				
					if(file_version != null && !file_version.trim().equals(""))
						pw.println(tab + "	" +  "{ \"name\": \"File Version: " + normalize_html(file_version).replace("\\", "\\\\") + "\" },");
	
					if(product_name != null && !product_name.trim().equals(""))
						pw.println(tab + "	" +  "{ \"name\": \"Product Name: " + normalize_html(product_name).replace("\\", "\\\\") + "\" },");
	
					if(comments != null && !comments.trim().equals(""))
						pw.println(tab + "	" +  "{ \"name\": \"Comments: " + normalize_html(comments).replace("\\", "\\\\") + "\" },");
	
					if(company_name != null && !company_name.trim().equals(""))
						pw.println(tab + "	" +  "{ \"name\": \"Company Name: " + normalize_html(company_name).replace("\\", "\\\\") + "\" },");
	
					if(flags != null && !flags.trim().equals(""))
						pw.println(tab + "	" +  "{ \"name\": \"Flags: " + normalize_html(flags).replace("\\", "\\\\") + "\" },");
	
					if(internal_name != null && !internal_name.trim().equals(""))
						pw.println(tab + "	" +  "{ \"name\": \"Internal Name: " + normalize_html(internal_name).replace("\\", "\\\\") + "\" },");
	
					if(legal_trademarks != null && !legal_trademarks.trim().equals(""))
						pw.println(tab + "	" +  "{ \"name\": \"Legal Trademarks: " + normalize_html(legal_trademarks).replace("\\", "\\\\") + "\" },");
	
					if(ole_self_register != null && !ole_self_register.trim().equals(""))
						pw.println(tab + "	" +  "{ \"name\": \"OLE Self Register: " + normalize_html(ole_self_register).replace("\\", "\\\\") + "\" },");
	
					if(os != null && !os.trim().equals(""))
						pw.println(tab + "	" +  "{ \"name\": \"OS: " + normalize_html(os).replace("\\", "\\\\") + "\" },");
	
					if(original_file_name != null && !original_file_name.trim().equals(""))
						pw.println(tab + "	" +  "{ \"name\": \"Original File Name: " + normalize_html(original_file_name).replace("\\", "\\\\") + "\" },");
	
					if(copyright_legal_copyright != null && !copyright_legal_copyright.trim().equals(""))
						pw.println(tab + "	" +  "{ \"name\": \"Copyright: " + normalize_html(copyright_legal_copyright).replace("\\", "\\\\") + "\" },");
	
					if(file_description != null && !file_description.trim().equals(""))
						pw.println(tab + "	" +  "{ \"name\": \"File Description: " + normalize_html(file_description).replace("\\", "\\\\") + "\" },");
	
					if(file_type != null && !file_type.trim().equals(""))
						pw.println(tab + "	" +  "{ \"name\": \"File Type: " + normalize_html(file_type).replace("\\", "\\\\") + "\" },");
	
					if(product_version != null && !product_version.trim().equals(""))
						pw.println(tab + "	" +  "{ \"name\": \"Product Version: " + normalize_html(product_version).replace("\\", "\\\\") + "\" },");	
	
					if(file_size != null && !file_size.trim().equals(""))
						pw.println(tab + "	" +  "{ \"name\": \"File Size: " + normalize_html(file_size).replace("\\", "\\\\") + "\" },");
	
					if(date_modified != null && !date_modified.trim().equals(""))
						pw.println(tab + "	" +  "{ \"name\": \"Date Modified: " + normalize_html(date_modified).replace("\\", "\\\\") + "\" },");
	
					if(language != null && !language.trim().equals(""))
						pw.println(tab + "	" +  "{ \"name\": \"Language: " + normalize_html(language).replace("\\", "\\\\") + "\" },");
					
				pw.println(tab + "\t" +  "]},");
				
				//
				//NODE - File Attributes
				//
				if(this.fle_attributes != null)
					this.fle_attributes.write_node_file_attributes(pw, PROCESS, this);
				
				//
				//importing processes
				//
				if(this.tree_process != null && tree_process.size() > 1)
				{
					pw.println(tab + "\t" +  "{ \"name\": \"" +  normalize_html("Importing Processes").replace("\\", "\\\\") + "\" , \"children\": [");
					
					for(Node_Process process : this.tree_process.values())
					{
						if(process == null)
							continue;
						
						//pw.println(tab + "\t\t"+ "	" +  "{ \"name\": \"" + normalize_html(process.get_process_html_header()).replace("\\", "\\\\") + "\" },");
						
						pw.println(tab + "\t" +  "{ \"name\": \"" +  normalize_html(process.get_process_html_header()).replace("\\", "\\\\") + "\" , \"children\": [");
						
						//
						//import Functions
						//
						if(tree_import_function_table_dependencies != null)
						{
							pw.println(tab + "\t\t" +  "{ \"name\": \"" +  normalize_html("Import Functions").replace("\\", "\\\\") + "\" , \"children\": [");
							
							for(Node_Import_DLL_Function node : this.tree_import_function_table_dependencies.values())
							{
								if(node.tree_process.containsValue(process))
									driver.write_node_ENTRY("", node.function_name, pw);
							}
							
							pw.println(tab + "\t\t" +  "]},");
						}
						
						pw.println(tab + "\t" +  "]},");
					}
					
					pw.println(tab + "\t" +  "]},");
				}
				
				//
				//base addresses
				//
				if(this.tree_base_address != null && tree_base_address.size() > 0)
				{
					pw.println(tab + "\t" +  "{ \"name\": \"" +  normalize_html("Base Addresses").replace("\\", "\\\\") + "\" , \"children\": [");
					
					for(String key : this.tree_base_address.keySet())
					{
						try
						{
							LinkedList<Node_Process> list = this.tree_base_address.get(key);
							
							if(list.size() < 1)
								continue;
							
							pw.println(tab + "\t\t" +  "{ \"name\": \"" +  normalize_html(key).replace("\\", "\\\\") + "\" , \"children\": [");
							
							for(Node_Process process : list)
							{
								if(process == null)
									continue;
								
								pw.println(tab + "\t\t\t"+ "	" +  "{ \"name\": \"" + normalize_html(process.get_process_html_header()).replace("\\", "\\\\") + "\" },");
							}
							
							pw.println(tab + "\t\t" +  "]},");
						}
						catch(Exception e){}
					}					
					
										
					pw.println(tab + "\t" +  "]},");
				}
				
				//
				//Api Hooks
				//
				if(this.tree_api_hook != null && tree_api_hook.size() > 0)
				{
					pw.println(tab + "\t" +  "{ \"name\": \"" +  normalize_html("API Hooks").replace("\\", "\\\\") + "\" , \"children\": [");
					
						if(this.tree_api_hook.size() > MAX_TREE_NODE_COUNT)
						{
							int count = 0;				
							pw.println("\t\t\t" +  "{ \"name\": \"" + driver.normalize_html("[" + count + "]").replace("\\", "\\\\") + "\" , \"children\": [");
							
							for(Node_ApiHook hook : this.tree_api_hook.values())
							{															
								if(count % MAX_TREE_NODE_COUNT == 0 && count > 0)
								{
									pw.println("\t\t\t" +  "]},");
									
									pw.println("\t\t\t" +  "{ \"name\": \"" + driver.normalize_html("[" + count + "]").replace("\\", "\\\\") + "\" , \"children\": [");
								}
								
								++count;
								
								if(hook == null)
									continue;
								
								
								
								hook.write_hook_html(tab + "\t\t", pw);
								
								
							}
							
							pw.println("\t\t\t" +  "]},");								
						}
					
						else
						{
							for(Node_ApiHook hook : this.tree_api_hook.values())
							{
								if(hook == null)
									continue;
								
								hook.write_hook_html(tab + "\t\t", pw);
							}
						}
					
					pw.println(tab + "\t" +  "]},");
				}
				
			//"T:/LAPTOP_SSD/Ise/Ise/CODE/Xavier_Framework/Xavier_Framework_Workspace/Xavier_Project/xavier_framework/import/memory_analysis/volatility_2.6_win64_standalone.exe" -f "T:/LAPTOP_SSD/Ise/Ise/CODE/Xavier_Framework/Xavier_Framework_Workspace/Xavier_Project/xavier_framework/import/memory_image/mem_WinXPSP3x86" yarascan -Y "http" --profile=WinXPSP3x86	
				//
				//
				//
				
				
				
				//
				//
				//
				
				
				
				
				//
				//
				//
				
				
				
				//
				//
				//
			
			
			pw.println(tab +  "]},");
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_module_information", e);
		}
		
		return false;
	}
	
	
	
	
	public String normalize_html(String value)
	{
		try
		{
			if(value == null)
				return "";
			
			return value.replace("\"", "&#34;").replace("'", "&#39;").replace(";", "&#59;");//.replace("&", "&amp");
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "normalize_html", e);
		}
		
		return value;
	}
	
	
	public boolean store_dll_base(String base_address, Node_Process process, Advanced_Analysis_Director director)
	{
		try
		{
			if(base_address == null)
				return false;
			
			if(process == null)
				return false;
			
			base_address = base_address.toLowerCase().trim();
			
			if(base_address.equals(""))
				return false;
			
			//
			//link process to tree
			//
			tree_process.put(process.PID, process);
			
			//
			//link process to this base
			//
			LinkedList<Node_Process> list = this.tree_base_address.get(base_address);
			
			if(list == null)
			{
				this.tree_base_address.put(base_address, new LinkedList<Node_Process>());
				
				//get the list again
				list = this.tree_base_address.get(base_address);
				
				if(this.base_addresses == null || base_addresses.trim().equals(""))
					base_addresses = base_address;
				else
					base_addresses = base_addresses + ", " + base_address;
			}
			

			
			if(!list.contains(process))
				list.add(process);
			
			
			//
			//store self in parent DLL base
			//
			if(director != null)
			{
				LinkedList<Node_DLL> list_parent = director.tree_DLL_MODULES_linked_by_VAD_base_start_address.get(base_address);
				
				if(list_parent == null)
				{
					director.tree_DLL_MODULES_linked_by_VAD_base_start_address.put(base_address, new LinkedList<Node_DLL>());
					
					//get the list again
					list_parent = director.tree_DLL_MODULES_linked_by_VAD_base_start_address.get(base_address);
				}
				
				if(!list_parent.contains(this))
					list_parent.add(this);
			}
			
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "store_dll_base", e);
		}
		
		return false;
	}
	
	
	public boolean store_import_function(String function_name, Node_Process process)
	{
		try
		{
			if(function_name == null)
				return false;
			
			String function_name_lower = function_name.trim();
			
			if(function_name_lower.equals(""))
				return false;
			
			function_name = function_name.trim();
			
			Node_Import_DLL_Function function = this.tree_import_function_table_dependencies.get(function_name_lower);
			
			if(function == null)
				function = new Node_Import_DLL_Function(function_name, this, process);//handle linking
			else
				function.link_process(process);
			
			try
			{
				if(process != null && !process.tree_import_functions_DEPRECATED.containsValue(this))
					process.tree_import_functions_DEPRECATED.put(this.path.toLowerCase().trim(), this);	
			}
			catch(Exception e){}
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "store_import_function", e);
		}
		
		return false;
	}
	
	
	public static Node_DLL get_dll(String name, Node_Process process, TreeMap<String, Node_DLL> tree_dll)
	{
		
		
		try
		{
			if(name == null)
				return null;
			
			String name_lower = name.toLowerCase().trim();
			
			if(name_lower.equals(""))
				return null;
			
			name = name.trim();
			
			//
			//search through process list first
			//
			if(process != null && process.tree_dll != null)
			{
				for(Node_DLL dll : process.tree_dll.values())
				{
					try
					{
						if(dll.path.toLowerCase().trim().endsWith(name_lower))
							return dll;								
					}
					catch(Exception e)
					{
						continue;
					}
				}
			}
			
			//
			//made it here, not found in process or process is null, search the tree
			//
			if(tree_dll == null || tree_dll.size() < 1)
				return null;
			
			for(Node_DLL dll : tree_dll.values())
			{
				try
				{
					if(dll.path.toLowerCase().trim().endsWith(name_lower))
						return dll;							
				}
				catch(Exception e)
				{
					continue;
				}
			}						
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_gll", e);
		}
		
		return null;
	}
	
	
	public String get_name()
	{
		try
		{
			if(this.path.contains("/"))
				return this.path.substring(this.path.lastIndexOf("/")+1).trim();
			else
				return this.path.substring(this.path.lastIndexOf("\\")+1).trim();
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_name", e);
		}
		
		return "-";
	}
	
	
	/**
	 * Full Details 
	 * @param pw
	 * @return
	 */
	public boolean write_table_DLL_information(PrintWriter pw)
	{
		try
		{
			pw.print("<tr>");
			
			
			String name = "";
			
			try	{ name = 	this.path.substring(this.path.lastIndexOf("\\")+1).trim();} catch(Exception e){name = path;}
			
			pw.print(" <td> " + driver.normalize_html(name).replace("\\", "&#92") + "</td>");
			pw.print(" <td> " + driver.normalize_html(path).replace("\\", "&#92") + "</td>");
			
			if(this.fle_attributes != null)
				this.fle_attributes.write_html_table_entries(pw);
			else
			{
				pw.print(" <td> " + driver.normalize_html("").replace("\\", "&#92") + "</td>");
				pw.print(" <td> " + driver.normalize_html("-").replace("\\", "&#92") + "</td>");
				pw.print(" <td> " + driver.normalize_html("").replace("\\", "&#92") + "</td>");
				pw.print(" <td> " + driver.normalize_html("").replace("\\", "&#92") + "</td>");
			}
			
			this.write_table_module_information(pw);
			
			//Importing Processes
			if(this.tree_process != null && this.tree_process.size() > 0)
			{
				String import_process_list = "";
				
				for(Node_Process process : this.tree_process.values())
				{
					if(process == null)
						continue;
					
					import_process_list = import_process_list + ", " + process.get_process_html_header();
				}
				
				import_process_list = import_process_list.trim();
				
				if(import_process_list.startsWith(","))
					import_process_list = import_process_list.substring(1).trim();
					
					pw.print(" <td> " + driver.normalize_html(import_process_list).replace("\\", "&#92") + "</td>");					
			}
			
			//importing processes from import list
			else if(this.tree_import_function_table_dependencies != null)
			{
				String import_list = "-";
				LinkedList<Node_Process> list_process = new LinkedList<Node_Process>();
				
				try
				{
					LinkedList<Node_Import_DLL_Function> list = new LinkedList<Node_Import_DLL_Function>(tree_import_function_table_dependencies.values());
					
					Node_Import_DLL_Function function_name = null;
					
					//outter: iterate through each function_name
					for(int i = 0; i < list.size(); i++)
					{
						//procure each import function
						function_name = list.get(i);
						
						if(function_name == null || function_name.tree_process == null || function_name.tree_process.isEmpty())
							continue;
						
						//innter: iterate through each process importing each function_name
						for(Node_Process process : function_name.tree_process.values())
						{
							if(process == null || list_process.contains(process))
								continue;
							
							list_process.add(process);
						}
						
					}
					
					Node_Process first_process = list_process.getFirst();
					import_list = first_process.get_process_html_header();
					
					for(int i = 1; i < list_process.size(); i++)
						import_list = import_list + ", " + list_process.get(i).get_process_html_header();
					
					
				}
				catch(Exception e)
				{
					
				}
				
				pw.print(" <td> " + driver.normalize_html(import_list).replace("\\", "&#92") + "</td>");
			}
			
			//
			//Base Address
			//
			pw.print(" <td> " + driver.normalize_html(base_addresses).replace("\\", "&#92") + "</td>");
					
			pw.print("</tr>");
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_table_DLL_information", e);
		}
		
		pw.print("</tr>");
		return false;
	}
	
	public boolean print_import_funciton_names(Node_Process process, PrintWriter pw, String delimiter)
	{
		try
		{
			if(this.tree_import_function_table_dependencies == null || this.tree_import_function_table_dependencies.size() < 1)
				return false;
			
			for(Node_Import_DLL_Function function : this.tree_import_function_table_dependencies.values())
			{
				if(process == null)
					pw.print(delimiter + function.function_name);
				else if(function.tree_process.containsKey(process.PID))
					pw.print(delimiter + function.function_name);
					
			}
			
			return true;					
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "print_import_funciton_names", e);
		}
		
		return false;
	}
	
	
	/**
	 * Partial Information
	 * @param pw
	 * @return
	 */
	public boolean write_table_module_information(PrintWriter pw)
	{
		try
		{
			pw.print(" <td> " + driver.normalize_html(this.file_version).replace("\\", "&#92") + "</td>");
			pw.print(" <td> " + driver.normalize_html(this.product_name).replace("\\", "&#92") + "</td>");
			pw.print(" <td> " + driver.normalize_html(this.original_file_name).replace("\\", "&#92") + "</td>");
			pw.print(" <td> " + driver.normalize_html(this.internal_name).replace("\\", "&#92") + "</td>");
			pw.print(" <td> " + driver.normalize_html(this.os).replace("\\", "&#92") + "</td>");
			//pw.print(" <td> " + driver.normalize_html(this.comments).replace("\\", "&#92") + "</td>");
			pw.print(" <td> " + driver.normalize_html(this.company_name).replace("\\", "&#92") + "</td>");
			pw.print(" <td> " + driver.normalize_html(this.flags).replace("\\", "&#92") + "</td>");
			//pw.print(" <td> " + driver.normalize_html(this.legal_trademarks).replace("\\", "&#92") + "</td>");
			pw.print(" <td> " + driver.normalize_html(this.copyright_legal_copyright).replace("\\", "&#92") + "</td>");
			//pw.print(" <td> " + driver.normalize_html(File Type).replace("\\", "&#92") + "</td>");
			//pw.print(" <td> " + driver.normalize_html(File Size).replace("\\", "&#92") + "</td>");
			pw.print(" <td> " + driver.normalize_html(this.product_version).replace("\\", "&#92") + "</td>");
			//pw.print(" <td> " + driver.normalize_html(this.date_modified).replace("\\", "&#92") + "</td>");
			//pw.print(" <td> " + driver.normalize_html(Language).replace("\\", "&#92") + "</td>");
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_table_module_information", e);
		}
		
		return false;
	}
	
	
	/**Write PROCESS header and underline about this process when a hit is found, however only do this once per XREF search.  This function is to 
	 * simplify the code such that I don't have to check this value each time*/
	public boolean write_process_header_for_XREF_hit(JTextArea_Solomon jta, boolean append_own_header_and_underline, Node_Process searching_process, Node_Driver searching_driver, Node_DLL searching_dll)
	{
		try
		{
			if(I_HAVE_WRITTEN_PROCESS_HEADER_ALREADY)
				return true;					
			
			if(searching_driver != null && !searching_driver.I_HAVE_WRITTEN_PROCESS_HEADER_ALREADY)
				searching_driver.write_process_header_for_XREF_hit(jta);
			
			else if(searching_process != null && !searching_process.I_HAVE_WRITTEN_PROCESS_HEADER_ALREADY)
				searching_process.write_process_header_for_XREF_hit(jta);
			
			//hit found!
			if(jta != null && append_own_header_and_underline)
				jta.append("\n\nDLL: " + this.get_name() + "\n" + driver.UNDERLINE);
			
			I_HAVE_WRITTEN_PROCESS_HEADER_ALREADY = true;
			
									
		}
		catch(Exception e)
		{
			driver.eop(this.myClassName, "write_header_for_XREF_hit",  e);
		}
		
		return false;
	}
	
	public boolean append_to_jta_XREF(String out, JTextArea_Solomon jta, boolean append_own_header_and_underline, Node_Process searching_process, Node_Driver searching_driver, Node_DLL searching_dll, String structure_name)
	{
		try
		{
			XREF_SEARCH_HIT_FOUND = true;
			
			if(jta == null)
				return false;
			
			write_process_header_for_XREF_hit(jta, append_own_header_and_underline, searching_process, searching_driver, searching_dll);
			
			if(append_own_header_and_underline)
				jta.append(out);
			else//doing this search on behalf of another entity e.g. process
				jta.append(structure_name + " [" + this.get_name() + "] - " + out);
			
			return XREF_SEARCH_HIT_FOUND;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "append_to_jta_XREF", e);
		}
		
		return XREF_SEARCH_HIT_FOUND;
	}
	
	public boolean search_XREF(String search_chars_from_user, String search_chars_from_user_lower, JTextArea_Solomon jta, boolean append_own_header_and_underline, Node_Process searching_proces, Node_Driver searching_driver, Node_DLL searching_dll, String structure_name)
	{
		try
		{
			XREF_SEARCH_HIT_FOUND = false;
			I_HAVE_WRITTEN_PROCESS_HEADER_ALREADY = false;
			
			if(in_load != null && this.in_load.toLowerCase().trim().contains(search_chars_from_user_lower))
				this.append_to_jta_XREF("In_load: " + this.in_load, jta, append_own_header_and_underline, searching_proces, searching_driver, searching_dll, structure_name);
						
			if(in_init != null && this.in_init.toLowerCase().trim().contains(search_chars_from_user_lower))
				this.append_to_jta_XREF("in_init: " + this.in_init, jta, append_own_header_and_underline, searching_proces, searching_driver, searching_dll, structure_name);
			
			if(in_mem != null && this.in_mem.toLowerCase().trim().contains(search_chars_from_user_lower))
				this.append_to_jta_XREF("in_mem: " + this.in_mem, jta, append_own_header_and_underline, searching_proces, searching_driver, searching_dll, structure_name);
			
			if(base_addresses != null && this.base_addresses.toLowerCase().trim().contains(search_chars_from_user_lower))
				this.append_to_jta_XREF("Base_Address: " + this.base_addresses, jta, append_own_header_and_underline, searching_proces, searching_driver, searching_dll, structure_name);
			
			if(base != null && this.base.toLowerCase().trim().contains(search_chars_from_user_lower))
				this.append_to_jta_XREF("Base: " + this.base, jta, append_own_header_and_underline, searching_proces, searching_driver, searching_dll, structure_name);
			
			if(size != null && this.size.toLowerCase().trim().contains(search_chars_from_user_lower))
				this.append_to_jta_XREF("Size: " + this.size, jta, append_own_header_and_underline, searching_proces, searching_driver, searching_dll, structure_name);
			
			if(load_count != null && this.load_count.toLowerCase().trim().contains(search_chars_from_user_lower))
				this.append_to_jta_XREF("Load Count: " + this.load_count, jta, append_own_header_and_underline, searching_proces, searching_driver, searching_dll, structure_name);
			
			if(path != null && this.path.toLowerCase().trim().contains(search_chars_from_user_lower))
				this.append_to_jta_XREF("Path: " + this.path, jta, append_own_header_and_underline, searching_proces, searching_driver, searching_dll, structure_name);
					
			if(file_version != null && file_version.toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("File Version: " + this.file_version, jta, append_own_header_and_underline, searching_proces, searching_driver, searching_dll, structure_name);
			if(product_name != null && product_name.toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("Product Name: " + this.product_name, jta, append_own_header_and_underline, searching_proces, searching_driver, searching_dll, structure_name);
			if(comments != null && comments.toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("Comments: " + this.comments, jta, append_own_header_and_underline, searching_proces, searching_driver, searching_dll, structure_name);
			if(company_name != null && company_name.toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("Company Name: " + this.company_name, jta, append_own_header_and_underline, searching_proces, searching_driver, searching_dll, structure_name);
			if(flags != null && flags.toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("Flags: " + this.flags, jta, append_own_header_and_underline, searching_proces, searching_driver, searching_dll, structure_name);
			if(internal_name != null && internal_name.toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("Internal Name: " + this.internal_name, jta, append_own_header_and_underline, searching_proces, searching_driver, searching_dll, structure_name);
			if(legal_trademarks != null && legal_trademarks.toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("Legal Trademarks: " + this.legal_trademarks, jta, append_own_header_and_underline, searching_proces, searching_driver, searching_dll, structure_name);
			if(ole_self_register != null && ole_self_register.toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("OLE Self Register: " + this.ole_self_register, jta, append_own_header_and_underline, searching_proces, searching_driver, searching_dll, structure_name);
			if(os != null && os.toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("OS: " + this.os, jta, append_own_header_and_underline, searching_proces, searching_driver, searching_dll, structure_name);
			if(original_file_name != null && original_file_name.toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("Original File Name: " + this.original_file_name, jta, append_own_header_and_underline, searching_proces, searching_driver, searching_dll, structure_name);
			if(copyright_legal_copyright != null && copyright_legal_copyright.toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("Legal Copyright: " + this.copyright_legal_copyright, jta, append_own_header_and_underline, searching_proces, searching_driver, searching_dll, structure_name);
			if(file_description != null && file_description.toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("File Description: " + this.file_description, jta, append_own_header_and_underline, searching_proces, searching_driver, searching_dll, structure_name);
			if(file_type != null && file_type.toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("File Type: " + this.file_type, jta, append_own_header_and_underline, searching_proces, searching_driver, searching_dll, structure_name);
			if(product_version != null && product_version.toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("Product Version: " + this.product_version, jta, append_own_header_and_underline, searching_proces, searching_driver, searching_dll, structure_name);
			if(file_size != null && file_size.toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("File Size: " + this.file_size, jta, append_own_header_and_underline, searching_proces, searching_driver, searching_dll, structure_name);
			if(date_modified != null && date_modified.toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("Date Modified: " + this.date_modified, jta, append_own_header_and_underline, searching_proces, searching_driver, searching_dll, structure_name);
			if(language != null && language.toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("Language: " + this.language, jta, append_own_header_and_underline, searching_proces, searching_driver, searching_dll, structure_name);

			//search base addresses
			if(tree_base_address != null && tree_base_address.size() > 0)
			{
				for(String base_addr : this.tree_base_address.keySet())
				{
					if(base_addr != null && base_addr.toLowerCase().trim().contains(search_chars_from_user_lower)) this.append_to_jta_XREF("Base Address: " + base_addr, jta, append_own_header_and_underline, searching_proces, searching_driver, searching_dll, structure_name);									
				}
			}
				
			//
			//tree_api_hook
			//
			if(tree_api_hook != null)
			{
				for(Node_ApiHook node : this.tree_api_hook.values())
				{
					if(node == null)
						continue;
					
					XREF_SEARCH_HIT_FOUND |= node.search_XREF(search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, "API Hook");
				}
			}
			
			
			//
			//tree_import_function_table_dependencies
			//
			if(tree_import_function_table_dependencies != null)
			{
				for(Node_Import_DLL_Function node : this.tree_import_function_table_dependencies.values())
				{
					if(node == null)
						continue;
					
					XREF_SEARCH_HIT_FOUND |= node.search_XREF(search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, "Dependencies");
				}
			}
			
			
			//
			//tree_import_function_table_dependencies
			//
			if(tree_import_function_table_impscan != null)
			{
				for(Node_Import_DLL_Function node : this.tree_import_function_table_impscan.values())
				{
					if(node == null)
						continue;
					
					XREF_SEARCH_HIT_FOUND |= node.search_XREF(search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, "Imp Scan");
				}
			}
			
			//
			//File Attribute
			//
			if(fle != null)
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle.getCanonicalPath(), "File", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, searching_driver, searching_dll, "DLL");
			
			///////////////////////////////////////////////////////////////////////
			//
			//File Attributes
			//
			//////////////////////////////////////////////////////////////////////
			if(this.fle_attributes != null)
			{
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.creation_date, "File Creation Date", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, searching_driver, searching_dll, "File Attributes");
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.extension, "File Extension", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, searching_driver, searching_dll, "File Attributes");
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.file_name, "File Name", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, searching_driver, searching_dll, "File Attributes");
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.hash_md5, "File Hash - MD5", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, searching_driver, searching_dll, "File Attributes");
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.hash_sha256, "File Hash - Sha256", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, searching_driver, searching_dll, "File Attributes");
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.last_accessed, "FileLast Accessed", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, searching_driver, searching_dll, "File Attributes");
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.last_modified, "File Last Modified", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, searching_driver, searching_dll, "File Attributes");
				XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.size, "File Size", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, searching_driver, searching_dll, "File Attributes");
			}
			
			
			//
			//tree_file_dump_attributes
			//
			if(tree_file_dump_attributes != null)
			{
				File fle = null;
				for(FileAttributeData fle_attributes : this.tree_file_dump_attributes.values())
				{
					if(fle_attributes == null)
						continue;
					
					fle = fle_attributes.fle;
					
					if(fle != null)
						XREF_SEARCH_HIT_FOUND |= this.check_value(fle.getCanonicalPath(), "File", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, searching_driver, searching_dll, "DLL");
					
					///////////////////////////////////////////////////////////////////////
					//
					//File Attributes
					//
					//////////////////////////////////////////////////////////////////////
					if(this.fle_attributes != null)
					{
						XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.creation_date, "File Creation Date", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, searching_driver, searching_dll, "File Attributes");
						XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.extension, "File Extension", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, searching_driver, searching_dll, "File Attributes");
						XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.file_name, "File Name", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, searching_driver, searching_dll, "File Attributes");
						XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.hash_md5, "File Hash - MD5", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, searching_driver, searching_dll, "File Attributes");
						XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.hash_sha256, "File Hash - Sha256", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, searching_driver, searching_dll, "File Attributes");
						XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.last_accessed, "FileLast Accessed", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, searching_driver, searching_dll, "File Attributes");
						XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.last_modified, "File Last Modified", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, searching_driver, searching_dll, "File Attributes");
						XREF_SEARCH_HIT_FOUND |= this.check_value(fle_attributes.size, "File Size", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, searching_driver, searching_dll, "File Attributes");
					}
					
					
				}
			}
			
			//
			//do not search process list att bcs was searched before getting here...
			//
			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "search_XREF", e);
		}
		
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
	public boolean check_value(String value_to_check, String mneumonic, String search_string, String search_string_lower, JTextArea_Solomon jta, Node_Process searching_proces, Node_Driver searching_driver, Node_DLL searching_dll, String structure_name)	
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
				searching_proces.append_to_jta_XREF(structure_name + " [" + mneumonic + "]: " + value_to_check, jta);
				
				
				
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
	 * basic attributes, does not include info from trees or discuss node_process linkages
	 * @param pw
	 * @return
	 */
	public boolean write_manifest_basic(String header, PrintWriter pw)
	{
		try
		{
			//leave off fle, fle_attributes, file_dump_name - include this in the full details manifest export
									
			//
			//DLLLIST
			//
			driver.write_manifest_entry(pw, header + "\t " + "path", path);
			driver.write_manifest_entry(pw, header + "\t " + "base", base);
			driver.write_manifest_entry(pw, header + "\t " + "base_addresses", base_addresses);			
			driver.write_manifest_entry(pw, header + "\t " + "size", size);
			driver.write_manifest_entry(pw, header + "\t " + "load_count", load_count);			
			driver.write_manifest_entry(pw, header + "\t " + "found_in_dlllist", found_in_dlllist);
			driver.write_manifest_entry(pw, header + "\t " + "found_in_ldrmodule", found_in_ldrmodule);
			

			//
			//LDRMODULES
			//
			driver.write_manifest_entry(pw, header + "\t " + "in_load", in_load);
			driver.write_manifest_entry(pw, header + "\t " + "in_init", in_init);
			driver.write_manifest_entry(pw, header + "\t " + "in_mem", in_mem);
			
			//
			//VERINFO
			//
			driver.write_manifest_entry(pw, header + "\t " + "found_in_verinfo_plugin", ""+found_in_verinfo_plugin);
			driver.write_manifest_entry(pw, header + "\t " + "file_version", file_version);
			driver.write_manifest_entry(pw, header + "\t " + "product_name", product_name);
			driver.write_manifest_entry(pw, header + "\t " + "comments", comments);
			driver.write_manifest_entry(pw, header + "\t " + "company_name", company_name);
			driver.write_manifest_entry(pw, header + "\t " + "flags", flags);
			driver.write_manifest_entry(pw, header + "\t " + "internal_name", internal_name);
			driver.write_manifest_entry(pw, header + "\t " + "legal_trademarks", legal_trademarks);
			driver.write_manifest_entry(pw, header + "\t " + "ole_self_register", ole_self_register);
			driver.write_manifest_entry(pw, header + "\t " + "os", os);
			driver.write_manifest_entry(pw, header + "\t " + "original_file_name", original_file_name);
			driver.write_manifest_entry(pw, header + "\t " + "copyright_legal_copyright", copyright_legal_copyright);
			driver.write_manifest_entry(pw, header + "\t " + "file_description", file_description);
			driver.write_manifest_entry(pw, header + "\t " + "file_type", file_type);
			driver.write_manifest_entry(pw, header + "\t " + "product_version", product_version);
			driver.write_manifest_entry(pw, header + "\t " + "file_size", file_size);
			driver.write_manifest_entry(pw, header + "\t " + "date_modified", date_modified);
			driver.write_manifest_entry(pw, header + "\t " + "language", language);

			//
			//File attribute
			//
			write_manifest_file_attributes(pw, header, "\t");
			
			









			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_manifest_basic", e);
		}
		
		return false;
	}
	/**
	 * Search tree of attrs for my specific dll attribute
	 * */	
	public boolean write_manifest_file_attributes(PrintWriter pw, String header, String delimiter)	
	{
		try
		{
			if(FileAttributeData.tree_file_attributes == null || FileAttributeData.tree_file_attributes.isEmpty())
				return false;
			
			boolean found = false;
			
			//
			//search tree first, if found, then write attr object from tree
			//
			for(FileAttributeData attr : FileAttributeData.tree_file_attributes.values())
			{
				try
				{
					//file name is in format: WinRAR.exe_1512_gdiplus.dll_3fa10b30_7fefbc20000
					String [] arr = attr.file_name.split("_");
														
					if(arr[2].toLowerCase().trim().equals(this.get_name()))
					{						
						fle_attributes.write_manifest_entry(pw, header + "\t file_attr\t ", this.get_name());						
						found = true;
						break;
					}
					
					
				}
				catch(Exception e)
				{
					continue;
				}
			}
			
			//
			//otw, not found intree above, determine if we have it in our fle_attr object
			//
			if(!found & fle_attributes != null)
			{
				pw.println(Driver.END_OF_ENTRY_MINOR);
				fle_attributes.write_manifest_entry(pw, header + "\t file_attr\t ", this.get_name());				
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_manifest_file_attributes", e);
		}
		
		return false;
	}
	
	public String get_importing_processes(String delimiter)
	{
		String process_list = "";
		
		try
		{
			if(tree_process != null && !tree_process.isEmpty())
			{									
				LinkedList<Node_Process> list = new LinkedList<Node_Process>(tree_process.values());
				
				process_list = "" + list.removeFirst().PID;
				if(list != null && !list.isEmpty())
				{
					for(Node_Process process : list)
					{
						if(process == null || process.PID < 0 || process_list.contains(""+process.PID))
							continue;
						
						process_list = process_list + delimiter + process.PID;
					}											
				}
				
				if(process_list == null || process_list.replace(",", "").trim().equals(""))
					return importing_processes_import_manifest;
			}
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_importing_processes", e);
		}
		
		return process_list;
	}
	
	public boolean write_manifest(PrintWriter pw, String delimiter, boolean include_underline)
	{
		
		String process_list = "";
		
		try
		{
			if(pw == null)
				return false;
			
			String header = "dll";
			
			//////////////////////////////////////////////////////
			//
			// write_manifest_basic
			//
			/////////////////////////////////////////////////////
			write_manifest_basic(header, pw);
			
			
			
			try
			{
				//////////////////////////////////////////////////////
				//
				// importing processes
				//
				/////////////////////////////////////////////////////
				if(tree_process != null && !tree_process.isEmpty())
				{		
					
					
					LinkedList<Node_Process> list = new LinkedList<Node_Process>(tree_process.values());
					
					process_list = "" + list.removeFirst().PID;
					if(list != null && !list.isEmpty())
					{
						for(Node_Process process : list)
						{
							if(process == null || process.PID < 0 || process_list.contains(""+process.PID))
								continue;
							
							process_list = process_list + ", " + process.PID;
						}
												
					}					 					
				}
				
				
				////////////////////////////////////////////////////////
				//
				// tree_base_address processes
				//
				/////////////////////////////////////////////////////
				if(tree_base_address != null && !tree_base_address.isEmpty())
				{
					for(LinkedList<Node_Process> list_base : tree_base_address.values())
					{
						if(list_base == null || list_base.isEmpty())
							continue;														
						
						for(Node_Process process : list_base)
						{
							if(process == null || process.PID < 0 || process_list.contains(""+process.PID))
								continue;
							
							//check if this is the first PID
							if(process_list == null || process_list.trim().startsWith(","))
								process_list = ""+process.PID;
							else
								process_list = process_list + ", " + process.PID;
						}
					}
				}
				
				////////////////////////////////////////////////////////
				//
				// write output
				//
				/////////////////////////////////////////////////////
//				if(process_list != null && !process_list.trim().equals(""))
//					pw.println(Driver.END_OF_ENTRY_MINOR);
				driver.write_manifest_entry(pw, header + "\t " + "importing_processes", process_list);
				
				
				////////////////////////////////////////////////////////
				//
				// APIHOOKS
				//
				/////////////////////////////////////////////////////
				write_manifest_apihooks(header + "\t api_hooks", pw, delimiter, include_underline);
				
			}
			catch(Exception ee)
			{
				driver.directive("NOTE: manifest caught exception printing process import list in " + this.myClassName);
			}
			
			pw.println(Driver.END_OF_ENTRY_MAJOR);
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "write_manifest", e);
		}
		
		return false;
	}
	
	
	public boolean write_manifest_apihooks(String header, PrintWriter pw, String delimiter, boolean include_underline)
	{
		try
		{
			if(this.tree_api_hook == null || this.tree_api_hook.isEmpty())
				return false;
			
			pw.println(Driver.END_OF_ENTRY_MINOR);
			
			for(Node_ApiHook node : tree_api_hook.values())
			{
				if(node == null)
					continue;
				
				node.write_manifest(pw,  header, delimiter, include_underline);
				pw.println(Driver.END_OF_ENTRY_MINOR);
			}
			
			return true;
		}
		catch(Exception e) 
		{
			driver.eop(myClassName, "write_manifest_apihooks", e);
		}
		
		return false;
		
	}
	
	
	public boolean process_import_manifest_token(int beginning_offset, String key, String value, String []arr, String line, String lower, String mtd_designator, Long line_num, BufferedReader br, int designator_len, boolean multi_lines_used_to_describe_single_node, Node_Process process)
	{
		try
		{
			

			//Set in analyze_dlldump plugin class
			if(key.equals("fle_attributes") || key.equals("file_attr")) 
			{
//				if(this.fle_attributes == null)
//					this.fle_attributes = new FileAttributeData(arr, 1);
//				else
//					this.fle_attributes.import_data(arr, beginning_offset);
				
				if(fle_attributes == null)
					fle_attributes = new FileAttributeData(this);
									
					fle_attributes.import_manifest_entry(arr[2], arr[3], line);
			}

			//
			//DLLLIST
			//
			else if(key.equals("base_addresses") || key.equals("base")) 
			{
				if(key.equals("base_addresses"))
					base_addresses = value;
				else if(key.equals("base"))
					base = value; 
				
				if(value.trim().length() > 0 && process != null)
				{
					if(this.tree_base_address == null)
						this.tree_base_address = new TreeMap<String, LinkedList<Node_Process>>();
					
					LinkedList<Node_Process> list = null;
					
					if(this.tree_base_address.containsKey(value))
						list = this.tree_base_address.get(value);
					
					if(list == null)
					{
						list = new LinkedList<Node_Process>();
						list.add(process);
						this.tree_base_address.put(value,  list);
					}
					
					if(!list.contains(process))
						list.add(process);
				}
					
			}
			
			else if(key.equals("size")) size = value;
			else if(key.equals("load_count")) load_count = value;
			else if(key.equals("path")) path = value;

			else if(key.equals("found_in_dlllist")) found_in_dlllist = value;
			else if(key.equals("found_in_ldrmodule")) found_in_ldrmodule = value;

			//
			//LDRMODULES
			//
			else if(key.equals("in_load")) in_load = value;
			else if(key.equals("in_init")) in_init = value;
			else if(key.equals("in_mem")) in_mem = value;

			//
			//VERINFO
			//
			else if(key.equals("found_in_verinfo_plugin")) try	{	found_in_verinfo_plugin = Boolean.parseBoolean(value.trim());} catch(Exception e){}
			else if(key.equals("file_version")) file_version = value;
			else if(key.equals("product_name")) product_name = value;
			else if(key.equals("comments")) comments = value;
			else if(key.equals("company_name")) company_name = value;
			else if(key.equals("flags")) flags = value;
			else if(key.equals("internal_name")) internal_name = value;
			else if(key.equals("legal_trademarks")) legal_trademarks = value;
			else if(key.equals("ole_self_register")) ole_self_register = value;
			else if(key.equals("os")) os = value;
			else if(key.equals("original_file_name")) original_file_name = value;
			else if(key.equals("copyright_legal_copyright")) copyright_legal_copyright = value;
			else if(key.equals("file_description")) file_description = value;
			else if(key.equals("file_type")) file_type = value;
			else if(key.equals("product_version")) product_version = value;

			else if(key.equals("file_size")) file_size = value;
			else if(key.equals("date_modified")) date_modified = value;
			else if(key.equals("language")) language = value;


			else if(key.equals("I_HAVE_WRITTEN_PROCESS_HEADER_ALREADY")) try	{ I_HAVE_WRITTEN_PROCESS_HEADER_ALREADY = Boolean.parseBoolean(value.trim()); } catch(Exception e){}
			else if(key.equals("printed_node_under_process")) try	{ printed_node_under_process = Boolean.parseBoolean(value.trim()); } catch(Exception e){}

			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_import_manifest_token", e);
		}
		
		return false;
		
	}
	
	
	
	
	public boolean import_manifest_line_entry(String line_entry, String []arr, String key, String value, Advanced_Analysis_Director director)
	{
		try
		{
			if(key == null || value == null)
				return false;
			
			key = key.trim();
			value = value.trim();
			
			if(key.endsWith(":"))
				key = key.substring(0, key.length()-1);
			
			if(value.endsWith(":"))
				value = value.substring(0, value.length()-1);
			
			if(key.equals("path"))  
			{
				path = value;
				
				//
				//link DLL to tree
				//
				String path_lower = path.toLowerCase().trim();
				
				if(director.tree_DLL_by_path.containsKey(path_lower))
					driver.directive("\n\nNOTE: In " + this.myClassName + " import_manifest_line_entry mtd, I found a duplicate DLL path stored Director's tree_DLL_by_path");
				
				director.tree_DLL_by_path.put(path_lower, this);
			}
			
			else if(key.equals("base_addresses"))			base_addresses = value;
			
			else if(key.equals("base"))  {	base = value;	link_self_to_respective_trees();	}
			else if(key.equals("size"))  size = value;
			else if(key.equals("load_count"))  load_count = value;
			 
			else if(key.equals("found_in_dlllist"))  found_in_dlllist = value;
			else if(key.equals("found_in_ldrmodule"))  found_in_ldrmodule = value;
			else if(key.equals("in_load"))  in_load = value;
			else if(key.equals("in_init"))  in_init = value;
			else if(key.equals("in_mem"))  in_mem = value;
			else if(key.equals("found_in_verinfo_plugin"))
			{
				if(value.toLowerCase().trim().equals("true"))  found_in_verinfo_plugin = true;
			}
			else if(key.equals("file_version"))  file_version = value;
			else if(key.equals("product_name"))  product_name = value;
			else if(key.equals("comments"))  comments = value;
			else if(key.equals("company_name"))  company_name = value;
			else if(key.equals("flags"))  flags = value;
			else if(key.equals("internal_name"))  internal_name = value;
			else if(key.equals("legal_trademarks"))  legal_trademarks = value;
			else if(key.equals("ole_self_register"))  ole_self_register = value;
			else if(key.equals("os"))  os = value;
			else if(key.equals("original_file_name"))  original_file_name = value;
			else if(key.equals("copyright_legal_copyright"))  copyright_legal_copyright = value;
			else if(key.equals("file_description"))  file_description = value;
			else if(key.equals("file_type"))  file_type = value;
			else if(key.equals("product_version"))  product_version = value;
			else if(key.equals("file_size"))  file_size = value;
			else if(key.equals("date_modified"))  date_modified = value;
			else if(key.equals("language"))  language = value;
			
			else if(key.startsWith("file_attr"))  
			{
				if(this.fle_attributes == null)
					this.fle_attributes = new FileAttributeData(this);
												
				fle_attributes.import_manifest_entry(key, value, line_entry);
			}
			
			else if(key.equals("importing_processes"))  {	importing_processes_import_manifest = value;	populate_importing_processes_lists(value, ",");		}
			
			else if(key.startsWith("api_hooks"))
			{
				line_entry = line_entry.substring(line_entry.indexOf("api_hooks") + "api_hooks".length()).trim();
				
				try
				{
					String []array = line_entry.split("\t");
					
					key = array[0].toLowerCase().trim();
					value = array[1].trim();
					
					this.import_manifest_line_api_hooks(line_entry, array, key, value, director);
				}
				
				catch(Exception e)
				{
					driver.directive("\n\n* * * * * ERROR!!! I could not bifurcate \"api_hooks\" and establish new key and value from line --> " + line_entry);
				}
			}
			
			else if(key.startsWith("api_hook"))
			{
				line_entry = line_entry.substring(line_entry.indexOf("api_hook") + "api_hook".length()).trim();
				
				//copy from above
				try
				{
					String []array = line_entry.split("\t");
					
					key = array[0].toLowerCase().trim();
					value = array[1].trim();
					
					this.import_manifest_line_api_hooks(line_entry, array, key, value, director);														
				}
				
				catch(Exception e)
				{
					driver.directive("\n\n* * * * * ERROR!!! I could not bifurcate \"api_hook\" and establish new key and value from line --> " + line_entry);
				}
			}

					
			else
				driver.directive("Unknown import_manifest_line_entry key: [" + key + "] recieved in " + this.myClassName);
			
			
			
			
			return true;
		}
		catch(Exception e)
		{
			//driver.eop(myClassName, "import_manifest_line_entry", e);
			driver.directive("* * Unknown import_manifest_line_entry key: [" + key + "] recieved in " + this.myClassName);
		}
		
		return false;
	}
	
	public boolean import_manifest_line_api_hooks(String line_entry, String []arr, String key, String value, Advanced_Analysis_Director director)
	{
		try
		{
			if(key == null || value == null | key.trim().equals(""))
				return false;
			
			if(key.equals("hook_address"))  
			{
				api_hook_import_manifest = new Node_ApiHook();
				api_hook_import_manifest.hook_address = value;
				
				//link
				if(director.tree_API_HOOK == null)
					director.tree_API_HOOK = new TreeMap<String, Node_ApiHook>();
				
				director.tree_API_HOOK.put(value, api_hook_import_manifest);
				
				if(this.tree_api_hook == null)
					tree_api_hook = new TreeMap<String, Node_ApiHook>();
				
				this.tree_api_hook.put(value, api_hook_import_manifest);
				
			}
			
			else if(key.equals("pid") && api_hook_import_manifest.process == null)
			{
				api_hook_import_manifest.pid = value;
				
				try	{	api_hook_import_manifest.PID = Integer.parseInt(value);	} catch(Exception e){}
				
				api_hook_import_manifest.process = director.tree_PROCESS.get(api_hook_import_manifest.PID);
				
				if(api_hook_import_manifest.process != null)
				{
					if(api_hook_import_manifest.process.tree_api_hook == null)
						api_hook_import_manifest.process.tree_api_hook = new TreeMap<String, Node_ApiHook>();
						
					//link
					api_hook_import_manifest.process.tree_api_hook.put(api_hook_import_manifest.hook_address, api_hook_import_manifest);															
				}
				else
				{
					driver.directive("\n\nNOTE: I could not find APIHOOK Process for PID: " + api_hook_import_manifest.PID);
				}
			}
			
			else if(key.equals("hook_mode"))  api_hook_import_manifest.hook_mode = value;
			else if(key.equals("hook_type"))  api_hook_import_manifest.hook_type = value;
			else if(key.equals("process_line"))  api_hook_import_manifest.process_line = value;
			else if(key.equals("process_name"))  api_hook_import_manifest.process_name = value;
			else if(key.equals("victim_module_line"))  api_hook_import_manifest.victim_module_line = value;
			else if(key.equals("victim_module_name"))  api_hook_import_manifest.victim_module_name = value;
			else if(key.equals("victim_module_base_address"))  api_hook_import_manifest.victim_module_base_address = value;
			else if(key.equals("function"))  api_hook_import_manifest.function = value;
			else if(key.equals("hooking_module"))  api_hook_import_manifest.hooking_module = value;
			
			else if(key.equals("MZ_Detected") || key.toLowerCase().trim().equals("mz_detected"))
			{
				if(value.trim().equalsIgnoreCase("true"))
				{
					api_hook_import_manifest.MZ_Detected = true;
					
					if(director.list_API_HOOKS_WITH_MZ_PRESENT == null)
						director.list_API_HOOKS_WITH_MZ_PRESENT = new LinkedList<Node_DLL>();
						
					if(!director.list_API_HOOKS_WITH_MZ_PRESENT.contains(this))
						director.list_API_HOOKS_WITH_MZ_PRESENT.add(this);
				}
			}
			else if(key.equals("Trampoline_Initial_JMP_Detected") || key.toLowerCase().trim().equals("trampoline_initial_jmp_detected"))
			{
				if(value.trim().equalsIgnoreCase("true"))
				{
					api_hook_import_manifest.Trampoline_Initial_JMP_Detected = true;
					
					if(director.list_API_HOOKS_WITH_HEAD_TRAMPOLINE_PRESENT == null)
						director.list_API_HOOKS_WITH_HEAD_TRAMPOLINE_PRESENT = new LinkedList<Node_DLL>();
						
					if(!director.list_API_HOOKS_WITH_HEAD_TRAMPOLINE_PRESENT.contains(this))
						director.list_API_HOOKS_WITH_HEAD_TRAMPOLINE_PRESENT.add(this);
				}
			}
			
			else if(key.startsWith("list_dissassembly_0"))
			{
				if(api_hook_import_manifest.list_dissassembly_0 == null)
					api_hook_import_manifest.list_dissassembly_0 = new LinkedList<String>();
				
				try
				{
					line_entry = line_entry.substring(line_entry.indexOf("list_dissassembly_0:") + "list_dissassembly_0:".length()).trim();   
				}
				catch(Exception e)
				{
					line_entry = value;
				}
				
				api_hook_import_manifest.list_dissassembly_0.add(line_entry);
			}
			
			else if(key.startsWith("list_dissassembly_1"))
			{
				if(api_hook_import_manifest.list_dissassembly_1 == null)
					api_hook_import_manifest.list_dissassembly_1 = new LinkedList<String>();
				
				try
				{
					line_entry = line_entry.substring(line_entry.indexOf("list_dissassembly_1:") + "list_dissassembly_1:".length()).trim();   
				}
				catch(Exception e)
				{
					line_entry = value;
				}
				
				api_hook_import_manifest.list_dissassembly_1.add(line_entry);
			}
			
			else if(key.startsWith("list_dissassembly_2"))
			{
				if(api_hook_import_manifest.list_dissassembly_2 == null)
					api_hook_import_manifest.list_dissassembly_2 = new LinkedList<String>();
				
				try
				{
					line_entry = line_entry.substring(line_entry.indexOf("list_dissassembly_2:") + "list_dissassembly_2:".length()).trim();   
				}
				catch(Exception e)
				{
					line_entry = value;
				}
				
				api_hook_import_manifest.list_dissassembly_2.add(line_entry);
			}
			
			else if(key.startsWith("list_dissassembly_3"))
			{
				if(api_hook_import_manifest.list_dissassembly_3 == null)
					api_hook_import_manifest.list_dissassembly_3 = new LinkedList<String>();
				
				try
				{
					line_entry = line_entry.substring(line_entry.indexOf("list_dissassembly_3:") + "list_dissassembly_3:".length()).trim();   
				}
				catch(Exception e)
				{
					line_entry = value;
				}
				
				api_hook_import_manifest.list_dissassembly_3.add(line_entry);
			}
			
			

			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "import_manifest_line_api_hooks", e);
		}
		
		return false;
	}
	
	public boolean populate_importing_processes_lists(String importing_process_list, String delimiter)
	{
		try
		{
			if(importing_process_list == null || importing_process_list.trim().equals(""))
				return false;
									
			//bifurcate process list
			String [] arr = null;
			
			try
			{
				arr = importing_process_list.split(delimiter);
			}
			catch(Exception e)
			{
				arr = new String[]{importing_process_list};
			}
			
			if(arr == null || arr.length < 1)
			{
				driver.directive("\n\nNOTE: I could not process importing_processes value [" + importing_process_list + "] for DLL at path --> " + this.path);
				return false;
			}
			
			//
			//process entries
			//
			for(String pid : arr)
			{
				try
				{
					if(pid == null || pid.trim().equals(""))
						continue;									
					
					//
					//procure process, throw exception otw
					//
					Node_Process process = director.tree_PROCESS.get(Integer.parseInt(pid.trim()));
					
					//
					//link DLL to process
					//
					if(process.tree_dll == null)
						process.tree_dll = new TreeMap<String, Node_DLL>();
						
					if(!process.tree_dll.containsKey(path))
						process.tree_dll.put(path, this);
					
					//
					//link process to my tree
					//
					if(this.tree_process == null)
						this.tree_process = new TreeMap<Integer, Node_Process>();
						
					if(process.PID < -1)
						continue;
						
					if(this.tree_process.containsValue(process))
						continue;
					
					//
					//link process to tree
					//
					this.tree_process.put(process.PID, process);
					
					//
					//link process by base address as well
					//
					if(this.base != null)
					{
						LinkedList<Node_Process> list_process = tree_base_address.get(base);
						
						if(list_process == null)
						{
							list_process = new LinkedList<Node_Process>();
							this.tree_base_address.put(base,  list_process);
						}
						
						if(!list_process.contains(process))
							list_process.add(process);
					}
																		
				}
				catch(Exception e)
				{
					driver.directive("I could not complete importing process for PID [" + pid + "]");
					continue;
				}
			}
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "populate_importing_processes_lists", e);
		}
		
		return false;
	}
	
	public boolean link_self_to_respective_trees()
	{
		try
		{
			//
			//get base address
			//
			if(base == null || base.trim().equals(""))
			{				
				driver.directive("\n\n* * * ERROR: I could not find base address for DLL at path: " + path);
				return false;
			}
			
			//
			//store self in parent DLL base
			//
			if(director != null)
			{											
				//
				//VAD BASE START ADDRESS
				//
				LinkedList<Node_DLL> list_parent = director.tree_DLL_MODULES_linked_by_VAD_base_start_address.get(base);
				
				if(list_parent == null)
				{
					list_parent = new LinkedList<Node_DLL>();
					
					director.tree_DLL_MODULES_linked_by_VAD_base_start_address.put(base, list_parent);					
				}
				
				if(!list_parent.contains(this))
					list_parent.add(this);
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "link_self_to_respective_trees", e);
		}
		
		return false;
	}
	
	
	
	
	public LinkedList<String> get_importing_processes()
	{
		try
		{
			String importing_process = this.get_importing_processes(",");
			
			if(importing_process == null)
				return null;
			
			LinkedList<String> list = new LinkedList<String>();
			
			String [] arr = importing_process.split(",");
			
			for(String entry : arr)
			{
				if(entry == null || entry.trim().equals(""))
					continue;
				
				list.add(entry.trim());
			}
			
			return list;
				
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_importing_processes - array", e);
		}
		
		return null;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
