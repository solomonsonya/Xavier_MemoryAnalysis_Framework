/**
 * 
 * 
 * @author Solomon Sonya
 */

// table header right above other table --> <table><caption><u></u></caption> <tbody><tr> <td style="text-align:center"> <b>Memory Analysis Tool Name</b></td> </tbody></table>

package Advanced_Analysis.Analysis_Report;

import java.util.*;
import java.io.*;
import org.apache.commons.io.LineIterator;
import Advanced_Analysis.Analysis_Plugin.Analysis_Plugin_dlllist;
import Advanced_Analysis.Analysis_Plugin.*;
import Advanced_Analysis.*;
import Driver.*;
import Driver.FileAttributeData;
import Driver.FilePrintWriter;
import Interface.Interface;
import Interface.JTextArea_Solomon;
import Plugin.Plugin;

public class Dependency_File_Writer_Tables extends Thread implements Runnable 
{
	public static final String myClassName = "Dependency_File_Writer_Tables";
	public static volatile Driver driver = new Driver();
	
	public volatile Analysis_Report_Container_Writer parent = null;
	public volatile Advanced_Analysis_Director director = null;
	
	
	public Dependency_File_Writer_Tables(Analysis_Report_Container_Writer par)
	{
		try
		{
			parent = par;
			director = parent.parent;
			
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
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "commence_action", e);
		}
		
		return false;
	}
	
	public boolean write_table_file_header(String FILE_NAME, String title, PrintWriter pw)
	{
		try
		{
			pw.println("<!DOCTYPE html>	");
			pw.println("<!-- Solomon Sonya @Carpenter1010 - Happy Hunting! -->	");
			pw.println("<html> <head> <style> table {   font-family: arial, sans-serif;   border-collapse: collapse;   width: 100%; }");
			pw.println("td, th {   border: 1px solid #11111111;   text-align: left;   padding: 8px; }");
			pw.println("tr:nth-child(odd) {  background-color: #dddddd; } </style> </head> <body style=\"background-color:white; " + Analysis_Report_Container_Writer.word_wrap_directive + "\">");
			
			pw.println("<p> <b>" + title + "</b><hr></p>"); 
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_table_file_header", e);
		}
		
		return false;
	}
	
	public File write_dependency_file_PROCESS_information_table(String FILE_NAME, String title)
	{
		File fle = null;
		
		try
		{
			if(director.tree_PROCESS == null || director.tree_PROCESS.isEmpty())
			{
				driver.sop_CONSOLE_ONLY("\nPUNT! Process Tree appears to be empty! No dependency file to write...");
				return null;
			}
			
			///////////////////////////////////////////////////////////////////////
			//CREATE FILE
			///////////////////////////////////////////////////////////////////////
			fle = new File(parent.path_dependency_directory + FILE_NAME);
			PrintWriter pw = new PrintWriter(new FileWriter(fle));
			
			///////////////////////////////////////////////////////////////////////
			//HEADER
			///////////////////////////////////////////////////////////////////////			
			write_table_file_header(FILE_NAME, title, pw);					
			
			///////////////////////////////////////////////////////////////////////
			//DEFINTE TABLE COLUMN HEADERS 
			///////////////////////////////////////////////////////////////////////
			String [] arr_column_headers = new String[]
			{
					"PID", 
					"Process Name", 
					"File Size", 
					"VirusTotal", 
					"Hash - MD5", 
					"Hash - SHA-256", 
					"PPID", 
					"Parent Process Name", 
					"Start", 
					"Exit", 
					//write_table_header("Sibling Process(es)", 
					//write_table_header("Offspring Procces(es)", 

					"Path", 
					"Command Line", 
					"File Version", 
					"Product Name", 
					"Original File Name", 
					"Internal Name", 
					"OS", 
					//write_table_header("Comments", 
					"Company Name", 
					"Flags", 
					//write_table_header("Legal Trademark", 
					"Copyright", 
					//write_table_header("File Type", 
					//write_table_header("File Size", 
					"Product Version", 
					//write_table_header("Date Modified", 
					//write_table_header("Language", 

					//write_table_header("Import DLL(s)", 
					//write_table_header("Privileges", 			

					"Thread", 
					"Handles", 
					"Session", 
					"Wow64", 
					"PDB", 

					"plist", 
					"pscan", 
					"thrdproc", 
					"pspcid", 
					"csrss", 
					"session", 
					"dskthrd", 

					"Offset (V) - pslist", 
					"Offset (P) - psscan", 
					"Offset (P) - psxview", 
					"Offset (P) - pstree", 
					"vadtree", 	
			};													
			
									
			///////////////////////////////////////////////////////////////////////
			//WRITE TABLE COLUMN HEADERS 
			///////////////////////////////////////////////////////////////////////
			pw.println("<table id=\"output_table_solomon_sonya\">");
			pw.println("<tr>");	
			write_onclick_sort_function_and_col_header(arr_column_headers, pw);
				/*write_table_column_header("PID", pw);
				write_table_column_header("Process Name", pw);
				write_table_column_header("File Size", pw);
				write_table_column_header("VirusTotal", pw);
				write_table_column_header("Hash - MD5", pw);
				write_table_column_header("Hash - SHA-256", pw);
				write_table_column_header("PPID", pw);
				write_table_column_header("Parent Process Name", pw);
				write_table_column_header("Start", pw);
				write_table_column_header("Exit", pw);
				//write_table_header("Sibling Process(es)", pw);
				//write_table_header("Offspring Procces(es)", pw);
				
				write_table_column_header("Path", pw);
				write_table_column_header("Command Line", pw);
				write_table_column_header("File Version", pw);
				write_table_column_header("Product Name", pw);
				write_table_column_header("Original File Name", pw);
				write_table_column_header("Internal Name", pw);
				write_table_column_header("OS", pw);
				//write_table_header("Comments", pw);
				write_table_column_header("Company Name", pw);
				write_table_column_header("Flags", pw);
				//write_table_header("Legal Trademark", pw);
				write_table_column_header("Copyright", pw);
				//write_table_header("File Type", pw);
				//write_table_header("File Size", pw);
				write_table_column_header("Product Version", pw);
				//write_table_header("Date Modified", pw);
				//write_table_header("Language", pw);
				
				//write_table_header("Import DLL(s)", pw);
				//write_table_header("Privileges", pw);							
				
				write_table_column_header("Thread", pw);
				write_table_column_header("Handles", pw);
				write_table_column_header("Session", pw);
				write_table_column_header("Wow64", pw);
				write_table_column_header("PDB", pw);
				
				write_table_column_header("plist", pw);
				write_table_column_header("pscan", pw);
				write_table_column_header("thrdproc", pw);
				write_table_column_header("pspcid", pw);
				write_table_column_header("csrss", pw);
				write_table_column_header("session", pw);
				write_table_column_header("dskthrd", pw);
				
				write_table_column_header("Offset (V) - pslist", pw);
				write_table_column_header("Offset (P) - psscan", pw);
				write_table_column_header("Offset (P) - psxview", pw);
				write_table_column_header("Offset (P) - pstree", pw);
				write_table_column_header("vadtree", pw);*/
				
			pw.println("</tr>");	
			
			///////////////////////////////////////////////////////////////////////
			//TABLE DATA FROM NODES
			///////////////////////////////////////////////////////////////////////
			for(Node_Process process : director.tree_PROCESS.values())
			{
				try
				{
					if(process == null)
						continue;
					
					process.write_table_process_information(pw);
					pw.println("");
				}
				
				catch(Exception e)
				{
					continue;
				}
				
			}
			
			
			
				
			///////////////////////////////////////////////////////////////////////
			//FOOTER
			///////////////////////////////////////////////////////////////////////
			write_table_footer(pw);
			
			
			///////////////////////////////////////////////////////////////////////
			//Close File
			///////////////////////////////////////////////////////////////////////
			try	{	pw.flush();} catch(Exception e){}
			try	{	pw.close();} catch(Exception e){}
			
			return fle;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_dependency_file_PROCESS_information_table", e, true);
		}
		
		return fle;
	}
	
	public boolean write_table_footer(PrintWriter pw)
	{
		try
		{
			//
			//close table
			//
			pw.println("	</table> <a id=\"Home\"> </a>  </body>");									
			pw.println("		");
			
			
			//////////////////////////////////////////////////////////////////////
			//script for sorting by column upon mouse click
			/////////////////////////////////////////////////////////////////////
			pw.println("	<script>");
			pw.println("/* special thanks to https://www.w3schools.com/howto/howto_js_sort_table.asp for the below function*/	");
			pw.println("	function sortTable(n) {");
			pw.println("	  var table, rows, switching, i, x, y, shouldSwitch, dir, switchcount = 0;");
			pw.println("	  table = document.getElementById(\"output_table_solomon_sonya\");");
			pw.println("	  switching = true;");
			pw.println("	  // Set the sorting direction to ascending:");
			pw.println("	  dir = \"asc\";");
			pw.println("	  /* Make a loop that will continue until");
			pw.println("	  no switching has been done: */");
			pw.println("	  while (switching) {");
			pw.println("	    // Start by saying: no switching is done:");
			pw.println("	    switching = false;");
			pw.println("	    rows = table.rows;");
			pw.println("	    /* Loop through all table rows (except the");
			pw.println("	    first, which contains table headers): */");
			pw.println("	    for (i = 1; i < (rows.length - 1); i++) {");
			pw.println("	      // Start by saying there should be no switching:");
			pw.println("	      shouldSwitch = false;");
			pw.println("	      /* Get the two elements you want to compare,");
			pw.println("	      one from current row and one from the next: */");
			pw.println("	      x = rows[i].getElementsByTagName(\"TD\")[n];");
			pw.println("	      y = rows[i + 1].getElementsByTagName(\"TD\")[n];");
			pw.println("	      /* Check if the two rows should switch place,");
			pw.println("	      based on the direction, asc or desc: */");
			pw.println("	      if (dir == \"asc\") {");
			pw.println("	        if (x.innerHTML.toLowerCase() > y.innerHTML.toLowerCase()) {");
			pw.println("	          // If so, mark as a switch and break the loop:");
			pw.println("	          shouldSwitch = true;");
			pw.println("	          break;");
			pw.println("	        }");
			pw.println("	      } else if (dir == \"desc\") {");
			pw.println("	        if (x.innerHTML.toLowerCase() < y.innerHTML.toLowerCase()) {");
			pw.println("	          // If so, mark as a switch and break the loop:");
			pw.println("	          shouldSwitch = true;");
			pw.println("	          break;");
			pw.println("	        }");
			pw.println("	      }");
			pw.println("	    }");
			pw.println("	    if (shouldSwitch) {");
			pw.println("	      /* If a switch has been marked, make the switch");
			pw.println("	      and mark that a switch has been done: */");
			pw.println("	      rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);");
			pw.println("	      switching = true;");
			pw.println("	      // Each time a switch is done, increase this count by 1:");
			pw.println("	      switchcount ++;");
			pw.println("	    } else {");
			pw.println("	      /* If no switching has been done AND the direction is \"asc\",");
			pw.println("	      set the direction to \"desc\" and run the while loop again. */");
			pw.println("	      if (switchcount == 0 && dir == \"asc\") {");
			pw.println("	        dir = \"desc\";");
			pw.println("	        switching = true;");
			pw.println("	      }");
			pw.println("	    }");
			pw.println("	  }");
			pw.println("	}");
			pw.println("	</script>");

			
			///////////////////////////////////////////////////////////////////////
			//FOOTER
			///////////////////////////////////////////////////////////////////////
			pw.println("<hr><p>Xavier Memory Analysis Framework vrs" + driver.VERSION + " </a></u> by Solomon Sonya @Carpenter1010 - " + driver.get_time_stamp() + "</p></html>");
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_table_footer", e);
		}
		
		return false;
	}
	
	
	public boolean write_table_column_header(String header, PrintWriter pw)
	{
		try
		{
			pw.print("<th>" + header + "</th> " );
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_table_column_header", e);
		}
		
		return false;
	}
	

	public File write_dependency_files_DLL_table(String FILE_NAME, String title)
	{
		File fle = null;
		
		try
		{
			if(director.tree_DLL_by_path == null || director.tree_DLL_by_path.isEmpty())
			{
				driver.sop_CONSOLE_ONLY("\nPUNT! DLL Tree appears to be empty! No dependency file to write...");
				return null;
			}
			
			///////////////////////////////////////////////////////////////////////
			//CREATE FILE
			///////////////////////////////////////////////////////////////////////
			fle = new File(parent.path_dependency_directory + FILE_NAME);
			PrintWriter pw = new PrintWriter(new FileWriter(fle));
			
			///////////////////////////////////////////////////////////////////////
			//HEADER
			///////////////////////////////////////////////////////////////////////			
			write_table_file_header(FILE_NAME, title, pw);				
			
			///////////////////////////////////////////////////////////////////////
			//DEFINTE TABLE COLUMN HEADERS 
			///////////////////////////////////////////////////////////////////////
			String [] arr_column_headers = new String[]
			{
					"Name",
					"Path",

					"File Size",
					"VirusTotal",
					"Hash - MD5",
					"Hash - SHA-256",

					"File Version",
					"Product Name",
					"Original File Name",
					"Internal Name",
					"OS",
					//write_table_header("Comments",
					"Company Name",
					"Flags",
					//write_table_header("Legal Trademark",
					"Copyright",
					//write_table_header("File Type",
					//write_table_header("File Size",
					"Product Version",
					//write_table_header("Date Modified",
					//write_table_header("Language",

					"Importing Processes",
					"Base Addresses",

			};
									
					
			
									
			///////////////////////////////////////////////////////////////////////
			//WRITE TABLE COLUMN HEADERS 
			///////////////////////////////////////////////////////////////////////
			pw.println("<table id=\"output_table_solomon_sonya\">");
			pw.println("<tr>");		

			write_onclick_sort_function_and_col_header(arr_column_headers, pw);
				
				/*write_table_column_header("Name", pw);
				write_table_column_header("Path", pw);
				
				write_table_column_header("File Size", pw);
				write_table_column_header("VirusTotal", pw);
				write_table_column_header("Hash - MD5", pw);
				write_table_column_header("Hash - SHA-256", pw);
				
				write_table_column_header("File Version", pw);
				write_table_column_header("Product Name", pw);
				write_table_column_header("Original File Name", pw);
				write_table_column_header("Internal Name", pw);
				write_table_column_header("OS", pw);
				//write_table_header("Comments", pw);
				write_table_column_header("Company Name", pw);
				write_table_column_header("Flags", pw);
				//write_table_header("Legal Trademark", pw);
				write_table_column_header("Copyright", pw);
				//write_table_header("File Type", pw);
				//write_table_header("File Size", pw);
				write_table_column_header("Product Version", pw);
				//write_table_header("Date Modified", pw);
				//write_table_header("Language", pw);
				
				write_table_column_header("Importing Processes", pw);
				write_table_column_header("Base Addresses", pw);*/
				
				
				
				
			pw.println("</tr>");	
			
			///////////////////////////////////////////////////////////////////////
			//TABLE DATA FROM NODES
			///////////////////////////////////////////////////////////////////////
			for(Node_DLL node : director.tree_DLL_by_path.values())
			{
				try
				{
					if(node == null)
						continue;
					
					if(node.path.toLowerCase().trim().endsWith("exe"))
						continue;
					
					node.write_table_DLL_information(pw);
					pw.println("");
				}
				catch(Exception e)
				{
					continue;
				}
				
			}
			
			
			
				
			///////////////////////////////////////////////////////////////////////
			//FOOTER
			///////////////////////////////////////////////////////////////////////
			write_table_footer(pw);
			
			
			///////////////////////////////////////////////////////////////////////
			//Close File
			///////////////////////////////////////////////////////////////////////
			try	{	pw.flush();} catch(Exception e){}
			try	{	pw.close();} catch(Exception e){}
			
			return fle;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_dependency_files_DLL_table", e);
		}
		
		return fle;
	}
	
	
	
	public File write_dependency_files_NETSTAT_table(String FILE_NAME, String title)
	{
		File fle = null;
		
		try
		{
			if(director.tree_PROCESS == null || director.tree_PROCESS.isEmpty())
			{
				driver.sop_CONSOLE_ONLY("\nPUNT! PROCESS Tree appears to be empty! No dependency file to write...");
				return null;
			}
			
			///////////////////////////////////////////////////////////////////////
			//CREATE FILE
			///////////////////////////////////////////////////////////////////////
			fle = new File(parent.path_dependency_directory + FILE_NAME);
			PrintWriter pw = new PrintWriter(new FileWriter(fle));
			
			///////////////////////////////////////////////////////////////////////
			//HEADER
			///////////////////////////////////////////////////////////////////////			
			write_table_file_header(FILE_NAME, title, pw);					
			
			///////////////////////////////////////////////////////////////////////
			//DEFINTE TABLE COLUMN HEADERS 
			///////////////////////////////////////////////////////////////////////
			String [] arr_column_headers = new String[]
			{
					"Protocol",
					"Local Addresses",
					"Foreign Address",
					"Created",
					"PID",
					"Process Name",
					"State",
					"PPID",
					"Parent Process Name",
					"VirusTotal",
			};
									
															
			///////////////////////////////////////////////////////////////////////
			//WRITE TABLE COLUMN HEADERS 
			///////////////////////////////////////////////////////////////////////
			pw.println("<table id=\"output_table_solomon_sonya\">");
			pw.println("<tr>");	
			write_onclick_sort_function_and_col_header(arr_column_headers, pw);
						
				/*write_table_column_header("Protocol", pw);
				write_table_column_header("Local Addresses", pw);
				write_table_column_header("Foreign Address", pw);
				write_table_column_header("Created", pw);
				write_table_column_header("PID", pw);
				write_table_column_header("Process Name", pw);
				write_table_column_header("State", pw);
				write_table_column_header("PPID", pw);
				write_table_column_header("Parent Process Name", pw);
				write_table_column_header("VirutTotal", pw);	*/															
			pw.println("</tr>");	
			
			///////////////////////////////////////////////////////////////////////
			//TABLE DATA FROM NODES
			///////////////////////////////////////////////////////////////////////
			for(Node_Process node : director.tree_PROCESS.values())
			{
				try
				{
					if(node == null)
						continue;										
					
					node.write_table_NETSTAT_information(pw);
					pw.println("");
				}
				catch(Exception e)
				{
					continue;
				}
				
			}
			
			
			
				
			///////////////////////////////////////////////////////////////////////
			//FOOTER
			///////////////////////////////////////////////////////////////////////
			write_table_footer(pw);
			
			
			///////////////////////////////////////////////////////////////////////
			//Close File
			///////////////////////////////////////////////////////////////////////
			try	{	pw.flush();} catch(Exception e){}
			try	{	pw.close();} catch(Exception e){}
			
			return fle;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_dependency_files_NETSTAT_table", e);
		}
		
		return fle;
	}
	
	

	
	public File write_dependency_files_DRIVER_table(String FILE_NAME, String title, boolean include_counts_of_other_trees, TreeMap<String, Node_Driver> tree)
	{
		File fle = null;
		
		try
		{
			if(tree == null || tree.isEmpty())
			{
				driver.sop_CONSOLE_ONLY("\nPUNT! DRIVER Tree appears to be empty! No dependency file to write...");
				return null;
			}
			
			///////////////////////////////////////////////////////////////////////
			//CREATE FILE
			///////////////////////////////////////////////////////////////////////
			fle = new File(parent.path_dependency_directory + FILE_NAME);
			PrintWriter pw = new PrintWriter(new FileWriter(fle));
			
			///////////////////////////////////////////////////////////////////////
			//HEADER
			///////////////////////////////////////////////////////////////////////			
			write_table_file_header(FILE_NAME, title, pw);				
			
			///////////////////////////////////////////////////////////////////////
			//DEFINTE TABLE COLUMN HEADERS 
			///////////////////////////////////////////////////////////////////////
			String [] arr_column_headers = null; 
			
			if(include_counts_of_other_trees)
			{
				arr_column_headers = new String[]
				{
					
						"Module Name",
						"File Size",
						"VirusTotal",
						"Hash - MD5",
						"Hash - SHA-256",
						"File Path",
						"Driver Name",
						"Alternate Name",
						"Service Key",
						"Base",
						"Start",
						"# Ptr",
						"# Handle",
						"Size (V)",
						"Size (P)",
						"Offset (P) - ModScan",
						"Offset (P) - DriverScan",
						"Offset (V) - Modules",
						
						//extra counts
						"# Callbacks Detected",
						"# Driver IRP Detected",
						"# Timers Detected",
						"# Unloaded Modules Detected",
						
				};						
			}
			else
			{
				arr_column_headers = new String[]
				{
					
						"Module Name",
						"File Size",
						"VirusTotal",
						"Hash - MD5",
						"Hash - SHA-256",
						"File Path",
						"Driver Name",
						"Alternate Name",
						"Service Key",
						"Base",
						"Start",
						"# Ptr",
						"# Handle",
						"Size (V)",
						"Size (P)",
						"Offset (P) - ModScan",
						"Offset (P) - DriverScan",
						"Offset (V) - Modules"																	
				};
			}
			
			
			
									
					
			
									
			///////////////////////////////////////////////////////////////////////
			//WRITE TABLE COLUMN HEADERS 
			///////////////////////////////////////////////////////////////////////
			pw.println("<table id=\"output_table_solomon_sonya\">");
			pw.println("<tr>");		
			write_onclick_sort_function_and_col_header(arr_column_headers, pw);
					
				/*write_table_column_header("Module Name", pw);
				write_table_column_header("File Size", pw);
				write_table_column_header("VirusTotal", pw);
				write_table_column_header("Hash - MD5", pw);
				write_table_column_header("Hash - SHA-256", pw);
				write_table_column_header("File Path", pw);
				write_table_column_header("Driver Name", pw);
				write_table_column_header("Alternate Name", pw);
				write_table_column_header("Service Key", pw);
				write_table_column_header("Base", pw);
				write_table_column_header("Start", pw);
				write_table_column_header("# Ptr", pw);
				write_table_column_header("# Handle", pw);
				write_table_column_header("Size (V)", pw);
				write_table_column_header("Size (P)", pw);
				write_table_column_header("Offset (P) - ModScan", pw);
				write_table_column_header("Offset (P) - DriverScan", pw);
				write_table_column_header("Offset (V) - Modules", pw);
				
				if(include_counts_of_other_trees)
				{
					write_table_column_header("# Callbacks Detected", pw);
					write_table_column_header("# Driver IRP Detected", pw);
					write_table_column_header("# Timers Detected", pw);
					write_table_column_header("# Unloaded Modules Detected", pw);
				}
				*/
																				
			pw.println("</tr>");	
			
			///////////////////////////////////////////////////////////////////////
			//TABLE DATA FROM NODES
			///////////////////////////////////////////////////////////////////////
			for(Node_Driver node : tree.values())
			{
				try
				{
					if(node == null)
						continue;										
					
					node.write_table_DRIVER_information(pw, include_counts_of_other_trees);
					pw.println("");
				}
				catch(Exception e)
				{
					continue;
				}
				
			}
			
			
			
				
			///////////////////////////////////////////////////////////////////////
			//FOOTER
			///////////////////////////////////////////////////////////////////////
			write_table_footer(pw);
			
			
			///////////////////////////////////////////////////////////////////////
			//Close File
			///////////////////////////////////////////////////////////////////////
			try	{	pw.flush();} catch(Exception e){}
			try	{	pw.close();} catch(Exception e){}
			
			return fle;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_dependency_files_DRIVER_table", e);
		}
		
		return fle;
	}
	
	
	
	
	public File write_dependency_files_MALFIND_table(String FILE_NAME, String title)
	{
		File fle = null;
		
		try
		{			
			///////////////////////////////////////////////////////////////////////
			//CREATE FILE
			///////////////////////////////////////////////////////////////////////
			fle = new File(parent.path_dependency_directory + FILE_NAME);
			PrintWriter pw = new PrintWriter(new FileWriter(fle));
			
			///////////////////////////////////////////////////////////////////////
			//HEADER
			///////////////////////////////////////////////////////////////////////			
			write_table_file_header(FILE_NAME, title, pw);				
			
			///////////////////////////////////////////////////////////////////////
			//DEFINTE TABLE COLUMN HEADERS 
			///////////////////////////////////////////////////////////////////////
			String [] arr_column_headers = new String[]
			{
					"PID",
					"Process Name",
					"File Size",
					"VirusTotal",
					"Hash - MD5",
					"Hash - SHA-256",
					"PPID",
					"Parent Process Name",
					
					"Address",
					"VAD Tag",
					"Protection",
					"Flags",
					"MZ Present",
					
					"Malfind Dump Image Name",
					"Malfind Dump File Size",
					"VirusTotal",
					"Malfind Dump Hash - MD5",
					"Malfind Dump Hash - SHA-256",
			};
									
																
			///////////////////////////////////////////////////////////////////////
			//WRITE TABLE COLUMN HEADERS 
			///////////////////////////////////////////////////////////////////////
			pw.println("<table id=\"output_table_solomon_sonya\">");
			pw.println("<tr>");	
			write_onclick_sort_function_and_col_header(arr_column_headers, pw);
						
				/*write_table_column_header("PID", pw);
				write_table_column_header("Process Name", pw);
				write_table_column_header("File Size", pw);
				write_table_column_header("VirusTotal", pw);
				write_table_column_header("Hash - MD5", pw);
				write_table_column_header("Hash - SHA-256", pw);
				write_table_column_header("PPID", pw);
				write_table_column_header("Parent Process Name", pw);
				
				write_table_column_header("Address", pw);
				write_table_column_header("VAD Tag", pw);
				write_table_column_header("Protection", pw);
				write_table_column_header("Flags", pw);
				write_table_column_header("MZ Present", pw);
				
				write_table_column_header("Malfind Dump Image Name", pw);
				write_table_column_header("Malfind Dump File Size", pw);
				write_table_column_header("VirusTotal", pw);
				write_table_column_header("Malfind Dump Hash - MD5", pw);
				write_table_column_header("Malfind Dump Hash - SHA-256", pw);*/
					
																				
			pw.println("</tr>");	
			
			///////////////////////////////////////////////////////////////////////
			//TABLE DATA FROM NODES
			///////////////////////////////////////////////////////////////////////
			for(Node_Process node : director.tree_PROCESS.values())
			{
				try
				{
					if(node == null || node.tree_malfind == null || node.tree_malfind.size() < 1)
						continue;										
					
					node.write_dependency_files_MALFIND_table(pw);
					pw.println("");
				}
				catch(Exception e)
				{
					continue;
				}
				
			}
			
			
			
				
			///////////////////////////////////////////////////////////////////////
			//FOOTER
			///////////////////////////////////////////////////////////////////////
			write_table_footer(pw);
			
			
			///////////////////////////////////////////////////////////////////////
			//Close File
			///////////////////////////////////////////////////////////////////////
			try	{	pw.flush();} catch(Exception e){}
			try	{	pw.close();} catch(Exception e){}
			
			return fle;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_dependency_files_MALFIND_table", e);
		}
		
		return fle;
	}
	
	
	public File write_dependency_files_VADTREE_table(String FILE_NAME, String title)
	{
		File fle = null;
		
		try
		{			
			///////////////////////////////////////////////////////////////////////
			//CREATE FILE
			///////////////////////////////////////////////////////////////////////
			fle = new File(parent.path_dependency_directory + FILE_NAME);
			PrintWriter pw = new PrintWriter(new FileWriter(fle));
			
			///////////////////////////////////////////////////////////////////////
			//HEADER
			///////////////////////////////////////////////////////////////////////			
			write_table_file_header(FILE_NAME, title, pw);				
			
			///////////////////////////////////////////////////////////////////////
			//DEFINTE TABLE COLUMN HEADERS 
			///////////////////////////////////////////////////////////////////////
			String [] arr_column_headers = new String[]
			{
					"PID",
					"Process Name",
					"vadtree",
					"Binary Size",
					"VirusTotal",
					"Hash - MD5",
					"Hash - SHA-256",
					"PPID",
					"Parent Process Name",
					"Start",
					"Exit",		
					"Path",
					"Command Line",	
			};
												
									
			///////////////////////////////////////////////////////////////////////
			//WRITE TABLE COLUMN HEADERS 
			///////////////////////////////////////////////////////////////////////
			pw.println("<table id=\"output_table_solomon_sonya\">");
			pw.println("<tr>");		
			write_onclick_sort_function_and_col_header(arr_column_headers, pw);
					
				/*write_table_column_header("PID", pw);
				write_table_column_header("Process Name", pw);
				write_table_column_header("vadtree", pw);
				write_table_column_header("Binary Size", pw);
				write_table_column_header("VirusTotal", pw);
				write_table_column_header("Hash - MD5", pw);
				write_table_column_header("Hash - SHA-256", pw);
				write_table_column_header("PPID", pw);
				write_table_column_header("Parent Process Name", pw);
				write_table_column_header("Start", pw);
				write_table_column_header("Exit", pw);		
				write_table_column_header("Path", pw);
				write_table_column_header("Command Line", pw);	*/																															
			pw.println("</tr>");	
			
			///////////////////////////////////////////////////////////////////////
			//TABLE DATA FROM NODES
			///////////////////////////////////////////////////////////////////////
			for(Node_Process node : director.tree_PROCESS.values())
			{
				try
				{
					node.write_dependency_files_VADTREE_table(pw);
					pw.println("");
				}
				catch(Exception e)
				{
					continue;
				}
				
			}
			
			
			
				
			///////////////////////////////////////////////////////////////////////
			//FOOTER
			///////////////////////////////////////////////////////////////////////
			write_table_footer(pw);
			
			
			///////////////////////////////////////////////////////////////////////
			//Close File
			///////////////////////////////////////////////////////////////////////
			try	{	pw.flush();} catch(Exception e){}
			try	{	pw.close();} catch(Exception e){}
			
			return fle;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_dependency_files_VADTREE_table", e);
		}
		
		return fle;
	}
	
	public File write_dependency_files_THREADS_table(String FILE_NAME, String title)
	{
		File fle = null;
		
		try
		{			
			///////////////////////////////////////////////////////////////////////
			//CREATE FILE
			///////////////////////////////////////////////////////////////////////
			fle = new File(parent.path_dependency_directory + FILE_NAME);
			PrintWriter pw = new PrintWriter(new FileWriter(fle));
			
			///////////////////////////////////////////////////////////////////////
			//HEADER
			///////////////////////////////////////////////////////////////////////			
			write_table_file_header(FILE_NAME, title, pw);						
			
			///////////////////////////////////////////////////////////////////////
			//DEFINTE TABLE COLUMN HEADERS 
			///////////////////////////////////////////////////////////////////////
			String [] arr_column_headers = new String[]
			{
					"PID",
					"Process Name",
					"File Size",
					"VirusTotal",
					"Hash - MD5",
					"Hash - SHA-256",
					"PPID",
					"Parent Process Name",
					
					"ethread_address",
					"TID",
					"tags",
					"Created",
					"Exited",
					"Owning Process Name",
					"Attached Process Name",
					"State",
					"Base Priority",
					"Priority",
					"TEB",
					"Start Address",
					"Service Table Address",
					"Service Table 0",
					"Service Table 1",
					"Service Table 2",
					"Service Table 3",
					"Win32 hread",
					"Cross Thread Flags",
					"eax",
					"ebx",
					"ecx",
					"edx",
					"esi",
					"edi",
					"eip",
					"esp",
					"ebp",
					"err",
					"cs",
					"ss",
					"ds",
					"es",
					"gs",
					"fs",
					"efl",
					"dr0",
					"dr1",
					"dr2",
					"dr3",
					"dr4",
					"dr5",
					"dr6",
					"dr7",
			};
									
															
			///////////////////////////////////////////////////////////////////////
			//WRITE TABLE COLUMN HEADERS 
			///////////////////////////////////////////////////////////////////////
			pw.println("<table id=\"output_table_solomon_sonya\">");
			pw.println("<tr>");		
			write_onclick_sort_function_and_col_header(arr_column_headers, pw);
					
				/*write_table_column_header("PID", pw);
				write_table_column_header("Process Name", pw);
				write_table_column_header("File Size", pw);
				write_table_column_header("VirusTotal", pw);
				write_table_column_header("Hash - MD5", pw);
				write_table_column_header("Hash - SHA-256", pw);
				write_table_column_header("PPID", pw);
				write_table_column_header("Parent Process Name", pw);
				
				write_table_column_header("ethread_address", pw);
				write_table_column_header("TID", pw);
				write_table_column_header("tags", pw);
				write_table_column_header("Created", pw);
				write_table_column_header("Exited", pw);
				write_table_column_header("Owning Process Name", pw);
				write_table_column_header("Attached Process Name", pw);
				write_table_column_header("State", pw);
				write_table_column_header("Base Priority", pw);
				write_table_column_header("Priority", pw);
				write_table_column_header("TEB", pw);
				write_table_column_header("Start Address", pw);
				write_table_column_header("Service Table Address", pw);
				write_table_column_header("Service Table 0", pw);
				write_table_column_header("Service Table 1", pw);
				write_table_column_header("Service Table 2", pw);
				write_table_column_header("Service Table 3", pw);
				write_table_column_header("Win32 hread", pw);
				write_table_column_header("Cross Thread Flags", pw);
				write_table_column_header("eax", pw);
				write_table_column_header("ebx", pw);
				write_table_column_header("ecx", pw);
				write_table_column_header("edx", pw);
				write_table_column_header("esi", pw);
				write_table_column_header("edi", pw);
				write_table_column_header("eip", pw);
				write_table_column_header("esp", pw);
				write_table_column_header("ebp", pw);
				write_table_column_header("err", pw);
				write_table_column_header("cs", pw);
				write_table_column_header("ss", pw);
				write_table_column_header("ds", pw);
				write_table_column_header("es", pw);
				write_table_column_header("gs", pw);
				write_table_column_header("fs", pw);
				write_table_column_header("efl", pw);
				write_table_column_header("dr0", pw);
				write_table_column_header("dr1", pw);
				write_table_column_header("dr2", pw);
				write_table_column_header("dr3", pw);
				write_table_column_header("dr4", pw);
				write_table_column_header("dr5", pw);
				write_table_column_header("dr6", pw);
				write_table_column_header("dr7", pw);*/
				
					
																				
			pw.println("</tr>");	
			
			///////////////////////////////////////////////////////////////////////
			//TABLE DATA FROM NODES
			///////////////////////////////////////////////////////////////////////
			for(Node_Process node : director.tree_PROCESS.values())
			{
				try
				{
					if(node == null || node.tree_threads == null || node.tree_threads.size() < 1)
						continue;										
					
					node.write_table_THREADS_information(pw);
					pw.println("");
				}
				catch(Exception e)
				{
					continue;
				}
				
			}
			
			
			
				
			///////////////////////////////////////////////////////////////////////
			//FOOTER
			///////////////////////////////////////////////////////////////////////
			write_table_footer(pw);
			
			
			///////////////////////////////////////////////////////////////////////
			//Close File
			///////////////////////////////////////////////////////////////////////
			try	{	pw.flush();} catch(Exception e){}
			try	{	pw.close();} catch(Exception e){}
			
			return fle;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_dependency_files_THREADS_table", e);
		}
		
		return fle;
	}
	
	
	
	
	
	
	
	public File write_dependency_files_HASHDUMP_table(String FILE_NAME, String title)
	{			
		File fle = null;
		
		try
		{			
			///////////////////////////////////////////////////////////////////////
			//CREATE FILE
			///////////////////////////////////////////////////////////////////////
			fle = new File(parent.path_dependency_directory + FILE_NAME);
			PrintWriter pw = new PrintWriter(new FileWriter(fle));
			
			///////////////////////////////////////////////////////////////////////
			//HEADER
			///////////////////////////////////////////////////////////////////////			
			write_table_file_header(FILE_NAME, title, pw);						
			
			///////////////////////////////////////////////////////////////////////
			//DEFINTE TABLE COLUMN HEADERS 
			///////////////////////////////////////////////////////////////////////
			String [] arr_column_headers = new String[]
			{
				"HashDump Details"
			};
									
			
			
									
			///////////////////////////////////////////////////////////////////////
			//WRITE TABLE COLUMN HEADERS 
			///////////////////////////////////////////////////////////////////////
			pw.println("<table id=\"output_table_solomon_sonya\">");
			pw.println("<tr>");		
			write_onclick_sort_function_and_col_header(arr_column_headers, pw);
					
				/*write_table_column_header("HashDump Details", pw);*/
			pw.println("</tr>");	
			
			///////////////////////////////////////////////////////////////////////
			//TABLE DATA FROM NODES
			///////////////////////////////////////////////////////////////////////
			for(String entry : director.tree_hashdump.keySet())
			{
				pw.print("<tr>");
					this.write_table_cell_entry(pw, entry);
				pw.print("</tr>\n");
			}
												
			///////////////////////////////////////////////////////////////////////
			//FOOTER
			///////////////////////////////////////////////////////////////////////
			write_table_footer(pw);
			
			
			///////////////////////////////////////////////////////////////////////
			//Close File
			///////////////////////////////////////////////////////////////////////
			try	{	pw.flush();} catch(Exception e){}
			try	{	pw.close();} catch(Exception e){}
			
			return fle;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_dependency_files_HASHDUMP_table", e);
		}
		
		return fle;
	}
	
	
	/**
	 * self-contained
	 * @param FILE_NAME
	 * @param title
	 * @return
	 */
	public File write_dependency_files_HIVELIST_table(String FILE_NAME, String title)
	{			
		File fle = null;
		
		try
		{			
			///////////////////////////////////////////////////////////////////////
			//CREATE FILE
			///////////////////////////////////////////////////////////////////////
			fle = new File(parent.path_dependency_directory + FILE_NAME);
			PrintWriter pw = new PrintWriter(new FileWriter(fle));
			
			///////////////////////////////////////////////////////////////////////
			//HEADER
			///////////////////////////////////////////////////////////////////////			
			write_table_file_header(FILE_NAME, title, pw);						
			
			///////////////////////////////////////////////////////////////////////
			//DEFINTE TABLE COLUMN HEADERS 
			///////////////////////////////////////////////////////////////////////
			String [] arr_column_headers = new String[]
			{
					"Registry Name",
					"Path",
					"Virtual Address",
					"Physical Address"	
			};
									
						
									
			///////////////////////////////////////////////////////////////////////
			//WRITE TABLE COLUMN HEADERS 
			///////////////////////////////////////////////////////////////////////
			pw.println("<table id=\"output_table_solomon_sonya\">");
			pw.println("<tr>");	
			write_onclick_sort_function_and_col_header(arr_column_headers, pw);
						
				/*write_table_column_header("Registry Name", pw);
				write_table_column_header("Path", pw);
				write_table_column_header("Virtual Address", pw);
				write_table_column_header("Physical Address", pw);*/
			pw.println("</tr>");	
			
			///////////////////////////////////////////////////////////////////////
			//TABLE DATA FROM NODES
			///////////////////////////////////////////////////////////////////////
			for(Node_hivelist node : director.tree_hivelist.values())
			{
				try
				{
					if(node == null || node.name_registry == null)
						continue;
					
					String name = node.name_registry;
					
					try
					{
						if(name.contains("\\"))
						{
							name = node.name_registry.substring(node.name_registry.lastIndexOf("\\")+1).trim();
							
							String updated_name = driver.get_value_from_second_to_last_token("\\", node.name_registry).trim();
							
							if(updated_name.trim().equals(""))
								name = node.name_registry.substring(node.name_registry.lastIndexOf("\\")+1).trim();
							else
								name = updated_name;							
						}
					}
					catch(Exception e)
					{
						name = node.name_registry;
					}
					
					
					pw.print("<tr>");
						this.write_table_cell_entry(pw, name);
						this.write_table_cell_entry(pw, node.name_registry);
						this.write_table_cell_entry(pw, node.virtual_address);
						this.write_table_cell_entry(pw, node.physical_address);
					pw.print("</tr>\n");
				}
				
				catch(Exception e)
				{
					continue;
				}
				
			}
												
			///////////////////////////////////////////////////////////////////////
			//FOOTER
			///////////////////////////////////////////////////////////////////////
			write_table_footer(pw);
			
			
			///////////////////////////////////////////////////////////////////////
			//Close File
			///////////////////////////////////////////////////////////////////////
			try	{	pw.flush();} catch(Exception e){}
			try	{	pw.close();} catch(Exception e){}
			
			return fle;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_dependency_files_HIVELIST_table", e);
		}
		
		return fle;
	}
	
	
	/**
	 * self-contained
	 * @param FILE_NAME
	 * @param title
	 * @return
	 */
	public File write_dependency_files_SIDS_table(String FILE_NAME, String title)
	{			
		File fle = null;
		
		try
		{			
			///////////////////////////////////////////////////////////////////////
			//CREATE FILE
			///////////////////////////////////////////////////////////////////////
			fle = new File(parent.path_dependency_directory + FILE_NAME);
			PrintWriter pw = new PrintWriter(new FileWriter(fle));
			
			///////////////////////////////////////////////////////////////////////
			//HEADER
			///////////////////////////////////////////////////////////////////////			
			write_table_file_header(FILE_NAME, title, pw);					
			
			///////////////////////////////////////////////////////////////////////
			//DEFINTE TABLE COLUMN HEADERS 
			///////////////////////////////////////////////////////////////////////
			String [] arr_column_headers = new String[]
			{
					"SID",
					"OWNER"
			};
									
															
			///////////////////////////////////////////////////////////////////////
			//WRITE TABLE COLUMN HEADERS 
			///////////////////////////////////////////////////////////////////////
			pw.println("<table id=\"output_table_solomon_sonya\">");
			pw.println("<tr>");	
			write_onclick_sort_function_and_col_header(arr_column_headers, pw);
						
				/*write_table_column_header("SID", pw);
				write_table_column_header("OWNER", pw);*/
			pw.println("</tr>");	
			
			///////////////////////////////////////////////////////////////////////
			//TABLE DATA FROM NODES
			///////////////////////////////////////////////////////////////////////
			for(String key : director.tree_SIDS.keySet())
			{
				try
				{
					if(key == null || !director.tree_SIDS.containsKey(key))
						continue;
					
					String value = director.tree_SIDS.get(key);
					
					if(value == null)
						continue;
					
					pw.print("<tr>");
						this.write_table_cell_entry(pw, key);
						this.write_table_cell_entry(pw, value);
					pw.print("</tr>\n");
				}
				
				catch(Exception e)
				{
					continue;
				}
				
			}
												
			///////////////////////////////////////////////////////////////////////
			//FOOTER
			///////////////////////////////////////////////////////////////////////
			write_table_footer(pw);
			
			
			///////////////////////////////////////////////////////////////////////
			//Close File
			///////////////////////////////////////////////////////////////////////
			try	{	pw.flush();} catch(Exception e){}
			try	{	pw.close();} catch(Exception e){}
			
			return fle;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_dependency_files_SIDS_table", e);
		}
		
		return fle;
	}
	
	
	public File write_dependency_files_MFT_table(String FILE_NAME, String title, File fle_import)
	{			
		
		if(fle_import == null || !fle_import.isFile() || !fle_import.exists())
		{
			driver.directive("* * * ERROR! I could not find MFT file --> " + fle_import);
			return null;
		}
		
		
		
		File fle = null;	
		
		
		try
		{			
			///////////////////////////////////////////////////////////////////////
			//CREATE FILE
			///////////////////////////////////////////////////////////////////////
			fle = new File(parent.path_dependency_directory + FILE_NAME);
			PrintWriter pw = new PrintWriter(new FileWriter(fle));
			
			///////////////////////////////////////////////////////////////////////
			//HEADER
			///////////////////////////////////////////////////////////////////////			
			write_table_file_header(FILE_NAME, title, pw);				
			
			///////////////////////////////////////////////////////////////////////
			//DEFINTE TABLE COLUMN HEADERS 
			///////////////////////////////////////////////////////////////////////
			String [] arr_column_headers = new String[]
			{
					"Creation Date",
					"Creation Time",
					"Creation TimeZone",
					"Modified Date",
					"Modified Time",
					"Modified TimeZone",
					"Altered Date",
					"Altered Time",
					"Altered TimeZone",
					"Access Date",
					"Access Time",
					"Access TimeZone",
					"Type/Name/Path",
					"Entry Atrribute",
					"Extension",
			};									
							
			
									
			///////////////////////////////////////////////////////////////////////
			//WRITE TABLE COLUMN HEADERS 
			///////////////////////////////////////////////////////////////////////
			pw.println("<table id=\"output_table_solomon_sonya\">");
			pw.println("<tr>");		
			write_onclick_sort_function_and_col_header(arr_column_headers, pw);
					
				/*write_table_column_header("Creation Date", pw);
				write_table_column_header("Creation Time", pw);
				write_table_column_header("Creation TimeZone", pw);
				write_table_column_header("Modified Date", pw);
				write_table_column_header("Modified Time", pw);
				write_table_column_header("Modified TimeZone", pw);
				write_table_column_header("Altered Date", pw);
				write_table_column_header("Altered Time", pw);
				write_table_column_header("Altered TimeZone", pw);
				write_table_column_header("Access Date", pw);
				write_table_column_header("Access Time", pw);
				write_table_column_header("Access TimeZone", pw);
				write_table_column_header("Type/Name/Path", pw);
				write_table_column_header("Entry Atrribute", pw);
				write_table_column_header("Extension", pw);*/
			pw.println("</tr>");	
			
			///////////////////////////////////////////////////////////////////////
			//TABLE DATA FROM NODES
			///////////////////////////////////////////////////////////////////////
			String line = "";
			BufferedReader brIn = new BufferedReader(new FileReader(fle_import));
			String []array = null;
			while((line = brIn.readLine()) != null)
			{
				line = line.trim();
				
				if(line.equals(""))
					continue;
				
				array = line.split("\t");
				
				if(array == null || array.length < 1)
					continue;
				
				pw.print("<tr>");
				
					if(array.length > 15)
					{
						this.write_table_cell_entry(pw, array[0].trim());
						this.write_table_cell_entry(pw, array[1].trim());
						this.write_table_cell_entry(pw, array[2].trim());
						this.write_table_cell_entry(pw, array[3].trim());
						this.write_table_cell_entry(pw, array[4].trim());
						this.write_table_cell_entry(pw, array[5].trim());
						this.write_table_cell_entry(pw, array[6].trim());
						this.write_table_cell_entry(pw, array[7].trim());
						this.write_table_cell_entry(pw, array[8].trim());
						this.write_table_cell_entry(pw, array[9].trim());
						this.write_table_cell_entry(pw, array[10].trim());
						this.write_table_cell_entry(pw, array[11].trim());
						this.write_table_cell_entry(pw, array[12].trim());
						this.write_table_cell_entry(pw, array[13].trim() + " " + array[14].trim());						
						this.write_table_cell_entry(pw, array[15].trim());
						
					}
					else
					{
						for(String entry : array)
						{
							this.write_table_cell_entry(pw, entry.trim());
						}
					}
					
				
				pw.print("</tr>\n");
				
			}
				
			try	{ brIn.close();} catch(Exception e){}
												
			///////////////////////////////////////////////////////////////////////
			//FOOTER
			///////////////////////////////////////////////////////////////////////
			write_table_footer(pw);
			
			
			///////////////////////////////////////////////////////////////////////
			//Close File
			///////////////////////////////////////////////////////////////////////
			try	{	pw.flush();} catch(Exception e){}
			try	{	pw.close();} catch(Exception e){}
			
			return fle;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_dependency_files_MFT_table", e);
		}
		
		return fle;
	}
	
	
	
	
	
	
	public File write_dependency_files_AUDIT_POLICIES_table(String FILE_NAME, String title)
	{			
		File fle = null;
		
		try
		{			
			///////////////////////////////////////////////////////////////////////
			//CREATE FILE
			///////////////////////////////////////////////////////////////////////
			fle = new File(parent.path_dependency_directory + FILE_NAME);
			PrintWriter pw = new PrintWriter(new FileWriter(fle));
			
			///////////////////////////////////////////////////////////////////////
			//HEADER
			///////////////////////////////////////////////////////////////////////			
			write_table_file_header(FILE_NAME, title, pw);					
			
			///////////////////////////////////////////////////////////////////////
			//DEFINTE TABLE COLUMN HEADERS 
			///////////////////////////////////////////////////////////////////////
			String [] arr_column_headers = new String[]
			{
					"Audit Details"
			};
									
				
			
									
			///////////////////////////////////////////////////////////////////////
			//WRITE TABLE COLUMN HEADERS 
			///////////////////////////////////////////////////////////////////////
			pw.println("<table id=\"output_table_solomon_sonya\">");
			pw.println("<tr>");	
			write_onclick_sort_function_and_col_header(arr_column_headers, pw);
						
				/*write_table_column_header("Audit Details", pw);*/
			pw.println("</tr>");	
			
			///////////////////////////////////////////////////////////////////////
			//TABLE DATA FROM NODES
			///////////////////////////////////////////////////////////////////////
			for(String entry : director.node_audit_policy.list_details)
			{
				pw.print("<tr>");
					this.write_table_cell_entry(pw, entry);
				pw.print("</tr>\n");
			}
												
			///////////////////////////////////////////////////////////////////////
			//FOOTER
			///////////////////////////////////////////////////////////////////////
			write_table_footer(pw);
			
			
			///////////////////////////////////////////////////////////////////////
			//Close File
			///////////////////////////////////////////////////////////////////////
			try	{	pw.flush();} catch(Exception e){}
			try	{	pw.close();} catch(Exception e){}
			
			return fle;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_dependency_files_AUDIT_POLICIES_table", e);
		}
		
		return fle;
	}
	
	
	
	public boolean write_table_cell_entry(PrintWriter pw, String value)
	{
		try
		{
			pw.print(" <td> " + driver.normalize_html(value).replace("\\", "&#92") + "</td>");
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_table_cell_entry", e);
		}
		
		return false;
	}
	
	
	public boolean write_onclick_sort_function_and_col_header(String [] arr, PrintWriter pw)
	{
		try
		{
			if(arr == null || arr.length < 1)
				return false;
			
			for(int i = 0; i < arr.length; i++)
			{				
				pw.println("<th onclick=\"sortTable(" + i + ")\">" + arr[i] + "</th>");
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_onclick_sort_function_and_col_header", e);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	

}
