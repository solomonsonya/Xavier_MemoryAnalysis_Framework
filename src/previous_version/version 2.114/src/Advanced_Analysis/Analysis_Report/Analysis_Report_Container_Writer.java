/**
 * HTML output file - Container - or wrapper file
 * 
 * This is the analysis report - and wrapper of other html pages for the analysis
 * 
 * @author Solomon Sonya
 * 
 * Special thanks to https://bl.ocks.org/d3noob/43a860bc0024792f8803bba8ca0d5ecd#index.html for example of the condensable tree
 */

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



public class Analysis_Report_Container_Writer extends Thread implements Runnable
{
	public static final String myClassName = "Analysis_Report_Container_Writer";
	public static volatile Driver driver = new Driver();
	
	public volatile Dependency_File_Writer_Tree dependency_file_writer_process_informaiton_tree = null;
	public volatile Dependency_File_Writer_Tree dependency_file_writer_system_informaiton_tree = null;
	public volatile Dependency_File_Writer_Tables dependency_file_writer_tables = null;
	public static String html_title = "Xavier Memory Analysis Report";
	
	public static boolean WRITE_SHORTCUT_TABLES = false;
	public static boolean WORD_WRAP = false;
	public static String word_wrap_directive = "";
	
	public static volatile boolean open_file_when_complete = true;
	
	public volatile File fle_volatility = null;
	public volatile File fle_memory_image = null;
	public volatile String PROFILE = Interface.PROFILE;
	public volatile String profile_lower = ""; 
	public volatile String path_fle_analysis_directory = "";
	public volatile FileAttributeData file_attr_volatility = null;  
	public volatile FileAttributeData file_attr_memory_image = null;
	public volatile String investigator_name = "";
	public volatile String investigation_description = "";
	
	public static final int WRITE_PROCESS_INDEX_PROCESS_TREE_ONLY = 0;
	
	public volatile Advanced_Analysis_Director parent = null;

	public volatile File fle_dependency_directory = null;
	public volatile String path_dependency_directory = "";
	
	
	public volatile File fle_analysis_report_html = null;
	public volatile String path_analysis_report_html = "";
	
	public volatile PrintWriter pw = null;
	
	public volatile String computer_name = "SYSTEM";
	public volatile String system_root = null;
	public volatile String system_drive = null;
	
	public static volatile int tree_div_width_SYSTEM_INFORMATION_TREE = 3000;
	public static volatile int tree_div_height_SYSTEM_INFORMATION_TREE = 1000;
	public static volatile int tree_length_to_each_node_SYSTEM_INFORMATION_TREE = 300;
	
	public static volatile int tree_div_width_PROCESS_TREE = 3000;
	public static volatile int tree_div_height_PROCESS_TREE = 600;
	public static volatile int tree_length_to_each_node_PROCESS_TREE = 300;
	
	public static volatile int tree_div_width_PROCESS_INFORMATION_TREE = 4000;
	public static volatile int tree_div_height_PROCESS_INFORMATION_TREE = 1000;
	public static volatile int tree_length_to_each_node_PROCESS_INFORMATION_TREE = 400;
		
	
	
	
	public volatile int max_process_offspring_count = 1; 
	
	public volatile String process_tree_file_name = "process_tree.html";
	public volatile String process_information_tree_file_name = "process_information_tree.html";
	public volatile String system_information_tree_file_name = "system_information_tree.html";
			
	public volatile String netstat_information_tree_file_name = "netstat_information_tree.html";
	
	public static final int determine_node_separation_INDEX_PROCESS_NAME = 0;
	
	public volatile boolean i_have_written_impscan_plugins = false;
	
	public static final int DEFAULT_TABLE_DIV_HEIGHT = 700;
	public static final int TABLE_DIV_HEIGHT_PER_ROW = 36;
	
	public Analysis_Report_Container_Writer(Advanced_Analysis_Director par)
	{
		try
		{
			if(WORD_WRAP)
				this.word_wrap_directive = "";
			else
				word_wrap_directive = "white-space: nowrap;";
			
			parent = par;
			
			fle_volatility = parent.fle_volatility;
			fle_memory_image = parent.fle_memory_image;
			PROFILE = parent.PROFILE;
			profile_lower = parent.profile_lower;
			path_fle_analysis_directory = parent.path_fle_analysis_directory;
			file_attr_volatility = parent.file_attr_volatility;
			file_attr_memory_image = parent.file_attr_memory_image;
			investigator_name = parent.investigator_name;
			investigation_description = parent.investigation_description;
			
			this.computer_name = parent.computer_name;
			this.system_drive = parent.system_drive;
			this.system_root = parent.system_root;
			
			//configure output names
			system_information_tree_file_name = system_information_tree_file_name + "_" + parent.fle_memory_image.getName() + ".html";
			
			this.start();
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1");
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
			//Escape characters
			//&#39; for '
			//&#34; for "
			
			String time_stamp = driver.get_time_stamp("_");
			
			//this.fle_analysis_report_html = new File(this.path_fle_analysis_directory + "html" + File.separator + "analysis_report_" + this.fle_memory_image.getName() + "_" + time_stamp + ".html");
			
			this.fle_analysis_report_html = new File(this.path_fle_analysis_directory + "_html" + File.separator + "analysis_report_" + this.fle_memory_image.getName() + ".html");
			
			try	{	fle_analysis_report_html.getParentFile().mkdirs();} catch(Exception e){}
			path_analysis_report_html = fle_analysis_report_html.getCanonicalPath().trim();
			
			if(!path_analysis_report_html.endsWith(File.separator))
				path_analysis_report_html = path_analysis_report_html + File.separator;
									
			//
			//procure background data
			//
			initialize_component();
			
			//
			//dependency directory and d3.js file
			//
			write_dependency_files();			
			
			//
			//Write Container Analysis Report File
			//
			pw = new PrintWriter(new FileWriter(fle_analysis_report_html));
			
			//
			//notify
			//
			sop("\n\nWriting analysis report to location: " + fle_analysis_report_html);			
			
			//
			//write header
			//
			write_analysis_report_header(pw);
			
			//
			//process
			//
			write_button_graphs(pw);
			
			//
			//System Information
			//
			write_button_tables(pw);
			
			//
			//Raw Output
			//
			write_button_raw_plugins(pw);
			
			//
			//footer
			//
			write_analysis_report_footer(pw);
			
			//
			//close
			//
			try	{	pw.flush();	}	catch(Exception e){}
			try	{	pw.close();	}	catch(Exception e){}
			
			if(this.open_file_when_complete)
			{
				driver.open_file(this.fle_analysis_report_html);
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "run", e);
		}
		
		return false;
	}
	
	public boolean write_dependency_files()
	{
		try
		{
			
			//configure output names
			//system_information_tree_file_name = system_information_tree_file_name + "_" + parent.fle_memory_image.getName() + ".html";
			
			dependency_file_writer_process_informaiton_tree = new Dependency_File_Writer_Tree(this, false, Dependency_File_Writer_Tree.OUTPUT_INDEX_PROCESS_INFORMATION);
			dependency_file_writer_system_informaiton_tree = new Dependency_File_Writer_Tree(this, false, Dependency_File_Writer_Tree.OUTPUT_INDEX_SYSTEM_INFORMATION_TREE);   
									
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_dependency_files", e);
		}
		
		return false;
	}
	
	
	public boolean initialize_file_paths()
	{
		try
		{
			//
			//create dependency directory
			//
			path_dependency_directory = fle_analysis_report_html.getParentFile().getCanonicalPath().trim();
			
			if(!path_dependency_directory.endsWith(File.separator))
				path_dependency_directory = path_dependency_directory + File.separator + "dependency" + File.separator;
			else
				path_dependency_directory = path_dependency_directory + "dependency" + File.separator;
			
			this.fle_dependency_directory = new File(path_dependency_directory);
			
			try	{	fle_dependency_directory.mkdirs();} catch(Exception e){}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "initialize_file_paths", e);
		}
		
		return false;
	}
	
	public boolean initialize_component()
	{
		try
		{
						
			initialize_file_paths();
			
			
			
			//determine_max_sub_process_offspring_count();
			//determine_max_node_separation_line_lenth(determine_node_separation_INDEX_PROCESS_NAME);
			
			process_tree_file_name = "process_tree_" + fle_memory_image.getName() + ".html";
			process_information_tree_file_name = "process_information_tree_" + fle_memory_image.getName() + ".html";
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "initialize_component", e);
		}
		
		return false;
	}
	
	/*public boolean determine_max_node_separation_line_lenth(int determine_node_separation_index)
	{
		try
		{
			int max_name_length = 5;
			String value = "";
			int length = 0;
			
			for(Node_Process process : parent.tree_PROCESS.values())
			{
				if(process == null)
					continue;
				
				//procure value to test
				switch(determine_node_separation_index)
				{
					case determine_node_separation_INDEX_PROCESS_NAME:
					{
						value = process.get_process_html_header();
						break;
					}
					
					default: //assume process name only
					{
						value = process.get_process_html_header();
						break;
					}
				}//end switch
				
				
				//test value
				if(value == null)
					continue;
				
				length = value.length();
				
				if(length > max_name_length)
					max_name_length = length;
				
				
			}//end for
			
			sop("LENGTH: " + max_name_length);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "determine_max_node_separation_line_lenth_based_on_process_name", e);
		}
		
		return false;
	}*/
	
	/**
	 * set max offspring by any parent process
	 * @return
	 */
	/*public boolean determine_max_sub_process_offspring_count()
	{
		try
		{
			for(Node_Process process : parent.tree_PROCESS.values())
			{
				if(process == null)
					continue;
				
				if(process.tree_child_process == null)
					continue;
				
				if(process.tree_child_process.size() > max_process_offspring_count)
					max_process_offspring_count = process.tree_child_process.size();
			}
			
			int tree_height_temp = max_process_offspring_count * tree_height_multiplication_factor_PROCESS_TREE;
			
			if(tree_height_temp > tree_div_height)
				tree_div_height = tree_height_temp;
			
			//check if there is an override from the config file and reset if necessary
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "determine_max_sub_process_offspring_count", e);
		}
		
		return false;
	}*/
	
	
	
	
	public LinkedList<Node_Process> get_list_processes_create_duplicates(TreeMap<Integer, Node_Process> tree, LinkedList<Node_Process> list)
	{
		try
		{
			if(tree == null)
				return null;
			
			if(list == null)
				list = new LinkedList<Node_Process>();
				
			boolean add_last = false;
			
			if(list.isEmpty()) //there are prev entries in the list, add the new nodes to the top
				add_last = true;
			
			//iterate and populate
			for(Node_Process process : tree.values())
			{
				if(process == null)
					continue;
				
				if(add_last)
					list.addLast(process);
				else
					list.addFirst(process);
			}
			
			return list;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_list_process_create_duplicates", e);
		}
		
		return null;
	}
	
	
	
	
	
	
	
	public boolean write_button_graphs(PrintWriter pwOut)
	{
		try
		{
			//<p> <h1> <a id="Discovery">Discovery </a> </h1> <hr> </p>
			//<a id="Process">Process</a>
			
			//outer btn		
			
			//pw.println("<button type=\"button\" class=\"collapsible active\"><a id=\"Graphs\">Graphs</a></button> <div class=\"content\" style=\"display: block; overflow: auto; width=auto; height=auto\">  <p> Data 1 </p>");
			pw.println("<button type=\"button\" class=\"collapsible active\"><a id=\"Graphs\">Graphs</a></button> <div class=\"content\" style=\"display: block; overflow: auto; width=auto; height=auto\">  <p>  </p>");
			pw.println("");
			
			//
			//Process Tree - inner btn
			//
			if(Dependency_File_Writer_Tree.use_recursion_to_produce_process_call_tree)
			{
				//only proceed here if we're writing the information recursively... disable incase the recursion causes issues...
				pw.println("	<button type=\"button\" class=\"collapsible\">Process Tree</button>	<div class=\"content\" style=\"overflow: auto; width=auto; height=auto\">		  ");
				
				pw.println("		<p></p>");
				pw.println("		<iframe src=\"dependency/" + process_tree_file_name + "\" width=\"100%\" height=\"" + (tree_div_height_PROCESS_TREE+30) + "\"></iframe>");						
				pw.println("		<a href=\"#Home\"> Home </a>" + "&nbsp&nbsp&nbsp&nbsp" + "<a href=\"dependency/" + process_tree_file_name + "\"> " + process_tree_file_name + " </a>");
				pw.println("	</div>");
				pw.println("");
				pw.println("	");
			}
			
						
			//
			//GraphViz - Inner btn
			//
			pw.println("	<!--/////////////////////////////////////////////////////--> ");
			pw.println("		  	");
			pw.println("	<p></p><button type=\"button\" class=\"collapsible\"><a id=\"Process_GraphViz\">Process GraphViz</a></button>");
			pw.println("	<div class=\"content\" style=\"overflow: auto; width=auto; height=auto\">");
			pw.println("		<p>  <img src=\"./../" + parent.relative_path_to_converted_dot_process_image + "\" alt=\"Mapping\" width=\"auto\"  height=\"auto\"> </p>  ");
			pw.println("			 "); 
			//pw.println("		<a href=\"#Home\"> Home </a>");
			pw.println("		<a href=\"#Home\"> Home </a>" + "&nbsp&nbsp&nbsp&nbsp" + "<a href=\"./../" + parent.relative_path_to_converted_dot_process_image + "\"> " + "Dot Image" + " </a>");
			pw.println("	</div>");	
			
			
			//
			//Process Information Tree - inner btn
			//
			pw.println("		  	");
			pw.println("	<p></p><button type=\"button\" class=\"collapsible\">Process Information Tree</button>	<div class=\"content\" style=\"overflow: auto; width=auto; height=auto\">		  ");			
			pw.println("		<p></p>");
			pw.println("		<iframe src=\"dependency/" + process_information_tree_file_name + "\" width=\"100%\" height=\"" + (tree_div_height_PROCESS_INFORMATION_TREE+30) + "\"></iframe>");						
			//pw.println("		<a href=\"#Home\"> Home </a>");
			pw.println("		<a href=\"#Home\"> Home </a>" + "&nbsp&nbsp&nbsp&nbsp" + "<a href=\"dependency/" + process_information_tree_file_name + "\"> " + process_information_tree_file_name + " </a>");
			pw.println("	</div>");
			pw.println("");
			pw.println("	");
			
			//
			//System Information Tree - inner btn
			//
			pw.println("		  	");
			pw.println("	<p></p><button type=\"button\" class=\"collapsible\">System Information Tree</button>	<div class=\"content\" style=\"overflow: auto; width=auto; height=auto\">		  ");			
			pw.println("		<p></p>");
			pw.println("		<iframe src=\"dependency/" + system_information_tree_file_name + "\" width=\"100%\" height=\"" + (tree_div_height_PROCESS_INFORMATION_TREE+100) + "\"></iframe>");						
			pw.println("		<a href=\"#Home\"> Home </a>" + "&nbsp&nbsp&nbsp&nbsp" + "<a href=\"dependency/" + system_information_tree_file_name + "\"> " + system_information_tree_file_name + " </a>");
			pw.println("	</div>");
			pw.println("");
			pw.println("	");
			
			
			
			
			
			
			
			
			//////////////////////////////////////////////////////////////////////////////////////////////////
			//close outter btn
			pw.println("</div>");
			pw.println("<!--/////////////////////////////////////////////////////-->"); 
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_button_graphs", e);
		}
		
		return false;
	}
	
	public String normalize_html(String value)
	{
		try
		{
			return value.replace("\"", "&#34;").replace("'", "&#39;");
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "normalize_html", e);
		}
		
		return value;
	}
	
	public boolean write_button_tables(PrintWriter pwOut)
	{
		try
		{
			if(parent.fle_memory_image == null)
			{
				driver.directive("PUNT! Memory Import Image appears to be null. - Terminating writing file info for now...");
				return false;
			}
			
			dependency_file_writer_tables = new Dependency_File_Writer_Tables(this);
			
			String button_title = "";
			String import_file_name = "";
			String page_title = "";
			int initial_frame_height = 700;		
			File fle = null;
			
			
			//pw.println("<p> Data 1 </p>");
			pw.println("<p>  </p>");
			//outer btn
			//pw.println("<button type=\"button\" class=\"collapsible\"><a id=\"Tables\">Tables</a></button> <div class=\"content\">  <p> Data 1 </p>");
			pw.println("<button type=\"button\" class=\"collapsible active\"><a id=\"Tables\">Tables</a></button> <div class=\"content\" style=\"display: block; overflow: auto; width=auto; height=auto\">  <p>  </p>");
			pw.println("");
			
						
			
			///////////////////////////////////////////////////////////////////////////////
			//Process Information Table - inner btn
			///////////////////////////////////////////////////////////////////////////////	
			/**change this --> */				if(parent.tree_PROCESS != null && parent.tree_PROCESS.size() > 0){
			/**change this --> */ button_title = "Process Information";
			
			page_title = button_title + " Table - " + parent.fle_memory_image.getName();						
			import_file_name = button_title.trim().toLowerCase().replace(" ", "_") + "_table_" + parent.fle_memory_image.getName() + ".html";
			
			/**change this --> */fle = dependency_file_writer_tables.write_dependency_file_PROCESS_information_table(import_file_name, page_title);						
			
			/**leave the rest below alone */
			initial_frame_height = 170 + TABLE_DIV_HEIGHT_PER_ROW * parent.tree_PROCESS.size();
			if(initial_frame_height > this.DEFAULT_TABLE_DIV_HEIGHT) initial_frame_height = DEFAULT_TABLE_DIV_HEIGHT;
			
			
			pw.println("		  	");
			pw.println("	<p></p><button type=\"button\" class=\"collapsible\">" + button_title + " </button>	<div class=\"content\" style=\"overflow: auto; width=auto; height=auto\">		  ");			
			pw.println("		<p></p>");
			pw.println("		<iframe src=\"dependency/" + import_file_name + "\" width=\"100%\" height=\"" + initial_frame_height + "\"></iframe>");						
			pw.println("		<a href=\"#Home\"> Home </a>" + "&nbsp&nbsp&nbsp&nbsp" + "<a href=\"dependency/" + import_file_name + "\"> " + import_file_name + " </a>");
			pw.println("	</div>");
			pw.println("");
			pw.println("	");
			}
			
			
			
			///////////////////////////////////////////////////////////////////////////////
			//DLL Information Table - inner btn
			///////////////////////////////////////////////////////////////////////////////		
			/**change this --> */				if(parent.tree_DLL_by_path != null || parent.plugin_dlllist != null){
			/**change this --> */button_title = "DLL Information";
			
			page_title = button_title + " Table - " + parent.fle_memory_image.getName();						
			import_file_name = button_title.trim().toLowerCase().replace(" ", "_") + "_table_" + parent.fle_memory_image.getName() + ".html";
			
			/**change this --> */fle = dependency_file_writer_tables.write_dependency_files_DLL_table(import_file_name, page_title);						
			
			/**leave the rest below alone */
			initial_frame_height = 170 + TABLE_DIV_HEIGHT_PER_ROW * parent.tree_DLL_by_path.size();
			if(initial_frame_height > this.DEFAULT_TABLE_DIV_HEIGHT) initial_frame_height = DEFAULT_TABLE_DIV_HEIGHT;
						
			pw.println("		  	");
			pw.println("	<p></p><button type=\"button\" class=\"collapsible\">" + button_title + " </button>	<div class=\"content\" style=\"overflow: auto; width=auto; height=auto\">		  ");			
			pw.println("		<p></p>");
			pw.println("		<iframe src=\"dependency/" + import_file_name + "\" width=\"100%\" height=\"" + initial_frame_height + "\"></iframe>");						
			pw.println("		<a href=\"#Home\"> Home </a>" + "&nbsp&nbsp&nbsp&nbsp" + "<a href=\"dependency/" + import_file_name + "\"> " + import_file_name + " </a>");
			pw.println("	</div>");
			pw.println("");
			pw.println("	");
			}
			
			///////////////////////////////////////////////////////////////////////////////
			//Netstat Information Table - inner btn
			///////////////////////////////////////////////////////////////////////////////	
			/**change this --> */				if(parent.tree_NETSTAT != null && parent.tree_NETSTAT.size() > 0){
			/**change this --> */button_title = "Netstat Information";
			
			page_title = button_title + " Table - " + parent.fle_memory_image.getName();						
			import_file_name = button_title.trim().toLowerCase().replace(" ", "_") + "_table_" + parent.fle_memory_image.getName() + ".html";
			
			/**change this --> */fle = dependency_file_writer_tables.write_dependency_files_NETSTAT_table(import_file_name, page_title);						
			
			/**leave the rest below alone */
			initial_frame_height = 170 + TABLE_DIV_HEIGHT_PER_ROW * parent.tree_NETSTAT.size();
			if(initial_frame_height > this.DEFAULT_TABLE_DIV_HEIGHT) initial_frame_height = DEFAULT_TABLE_DIV_HEIGHT;
						
			pw.println("		  	");
			pw.println("	<p></p><button type=\"button\" class=\"collapsible\">" + button_title + " </button>	<div class=\"content\" style=\"overflow: auto; width=auto; height=auto\">		  ");			
			pw.println("		<p></p>");
			pw.println("		<iframe src=\"dependency/" + import_file_name + "\" width=\"100%\" height=\"" + initial_frame_height + "\"></iframe>");						
			pw.println("		<a href=\"#Home\"> Home </a>" + "&nbsp&nbsp&nbsp&nbsp" + "<a href=\"dependency/" + import_file_name + "\"> " + import_file_name + " </a>");
			pw.println("	</div>");
			pw.println("");
			pw.println("	");
			}
			
			///////////////////////////////////////////////////////////////////////////////
			//MFT File Tables
			///////////////////////////////////////////////////////////////////////////////
			if(parent.plugin_mftparser != null && parent.plugin_mftparser.path_to_output_directory != null && !parent.plugin_mftparser.path_to_output_directory.trim().equals(""))
			{
				//write header
				pw.println("	<p></p><button type=\"button\" class=\"collapsible\">" + "MFT - Master File Table" + " </button>	<div class=\"content\" style=\"overflow: auto; width=auto; height=auto\">		  ");			
				pw.println("		<p></p>");								
											
				write_mft_table("MFT - DLL Information", "dll.txt");
				write_mft_table("MFT - Drivers Information", "sys.txt");
				write_mft_table("MFT - Event Logs Information", "evt.txt");
				write_mft_table("MFT - EXE Information", "exe.txt");
				write_mft_table("MFT - Prefetch Information", "prefetch.txt");
				write_mft_table("MFT - Temp File Information", "tmp.txt");
				write_mft_table("MFT - TXT Information", "txt.txt");
				write_mft_table("MFT - ZIP Information", "zip.txt");
				
				//close header
				pw.println("	</div>");
			}
			
			
			
			///////////////////////////////////////////////////////////////////////////////
			//Get HASHDUMP Information Table - inner btn
			///////////////////////////////////////////////////////////////////////////////			
/**change this --> */ if(parent.tree_hashdump != null && parent.tree_hashdump.size() > 0)
			{			
				/**change this --> */button_title = "HASHDUMP Information";

				page_title = button_title + " Table - " + parent.fle_memory_image.getName();						
				import_file_name = button_title.trim().toLowerCase().replace(" ", "_") + "_table_" + parent.fle_memory_image.getName() + ".html";

				/**change this --> */fle = dependency_file_writer_tables.write_dependency_files_HASHDUMP_table(import_file_name, page_title);						

				/**leave the rest below alone */
				initial_frame_height = 170 + TABLE_DIV_HEIGHT_PER_ROW * parent.tree_hashdump.size();
				if(initial_frame_height > this.DEFAULT_TABLE_DIV_HEIGHT) initial_frame_height = DEFAULT_TABLE_DIV_HEIGHT;
							
				pw.println("		  	");
				pw.println("	<p></p><button type=\"button\" class=\"collapsible\">" + button_title + " </button>	<div class=\"content\" style=\"overflow: auto; width=auto; height=auto\">		  ");			
				pw.println("		<p></p>");
				pw.println("		<iframe src=\"dependency/" + import_file_name + "\" width=\"100%\" height=\"" + initial_frame_height + "\"></iframe>");						
				pw.println("		<a href=\"#Home\"> Home </a>" + "&nbsp&nbsp&nbsp&nbsp" + "<a href=\"dependency/" + import_file_name + "\"> " + import_file_name + " </a>");
				pw.println("	</div>");
				pw.println("");
				pw.println("	");
			}
			
			///////////////////////////////////////////////////////////////////////////////
			//Get SIDS Information Table - inner btn
			///////////////////////////////////////////////////////////////////////////////			
/**change this --> */ if(parent.tree_SIDS != null && parent.tree_SIDS.size() > 0)			{			
				/**change this --> */button_title = "SIDS Information";

				page_title = button_title + " Table - " + parent.fle_memory_image.getName();						
				import_file_name = button_title.trim().toLowerCase().replace(" ", "_") + "_table_" + parent.fle_memory_image.getName() + ".html";

				/**change this --> */fle = dependency_file_writer_tables.write_dependency_files_SIDS_table(import_file_name, page_title);						

				/**leave the rest below alone */
				initial_frame_height = 170 + TABLE_DIV_HEIGHT_PER_ROW * parent.tree_SIDS.size();
				if(initial_frame_height > this.DEFAULT_TABLE_DIV_HEIGHT) initial_frame_height = DEFAULT_TABLE_DIV_HEIGHT;
						
				pw.println("		  	");
				pw.println("	<p></p><button type=\"button\" class=\"collapsible\">" + button_title + " </button>	<div class=\"content\" style=\"overflow: auto; width=auto; height=auto\">		  ");			
				pw.println("		<p></p>");
				pw.println("		<iframe src=\"dependency/" + import_file_name + "\" width=\"100%\" height=\"" + initial_frame_height + "\"></iframe>");						
				pw.println("		<a href=\"#Home\"> Home </a>" + "&nbsp&nbsp&nbsp&nbsp" + "<a href=\"dependency/" + import_file_name + "\"> " + import_file_name + " </a>");
				pw.println("	</div>");
				pw.println("");
				pw.println("	");
			}

			
			///////////////////////////////////////////////////////////////////////////////
			//Get HIVELIST Information Table - inner btn
			///////////////////////////////////////////////////////////////////////////////			
/**change this --> */ if(parent.tree_hivelist != null && parent.tree_hivelist.size() > 0)
			{			
				/**change this --> */button_title = "HiveList Information";
			
				page_title = button_title + " Table - " + parent.fle_memory_image.getName();						
				import_file_name = button_title.trim().toLowerCase().replace(" ", "_") + "_table_" + parent.fle_memory_image.getName() + ".html";
			
				/**change this --> */fle = dependency_file_writer_tables.write_dependency_files_HIVELIST_table(import_file_name, page_title);						
			
				/**leave the rest below alone */
				initial_frame_height = 170 + TABLE_DIV_HEIGHT_PER_ROW * parent.tree_hivelist.size();
				if(initial_frame_height > this.DEFAULT_TABLE_DIV_HEIGHT) initial_frame_height = DEFAULT_TABLE_DIV_HEIGHT;
							
				pw.println("		  	");
				pw.println("	<p></p><button type=\"button\" class=\"collapsible\">" + button_title + " </button>	<div class=\"content\" style=\"overflow: auto; width=auto; height=auto\">		  ");			
				pw.println("		<p></p>");
				pw.println("		<iframe src=\"dependency/" + import_file_name + "\" width=\"100%\" height=\"" + initial_frame_height + "\"></iframe>");						
				pw.println("		<a href=\"#Home\"> Home </a>" + "&nbsp&nbsp&nbsp&nbsp" + "<a href=\"dependency/" + import_file_name + "\"> " + import_file_name + " </a>");
				pw.println("	</div>");
				pw.println("");
				pw.println("	");
			}

			///////////////////////////////////////////////////////////////////////////////
			//Audit Policies Information Table - inner btn
			///////////////////////////////////////////////////////////////////////////////			
/**change this --> */if(parent.node_audit_policy != null && parent.node_audit_policy.list_details != null && parent.node_audit_policy.list_details.size() > 0)
			{			
				/**change this --> */button_title = "Audit Policies Information";
			
				page_title = button_title + " Table - " + parent.fle_memory_image.getName();						
				import_file_name = button_title.trim().toLowerCase().replace(" ", "_") + "_table_" + parent.fle_memory_image.getName() + ".html";
			
				/**change this --> */fle = dependency_file_writer_tables.write_dependency_files_AUDIT_POLICIES_table(import_file_name, page_title);						
			
				/**leave the rest below alone */
				initial_frame_height = 170 + TABLE_DIV_HEIGHT_PER_ROW * parent.node_audit_policy.list_details.size();
				if(initial_frame_height > this.DEFAULT_TABLE_DIV_HEIGHT) initial_frame_height = DEFAULT_TABLE_DIV_HEIGHT;
							
				pw.println("		  	");
				pw.println("	<p></p><button type=\"button\" class=\"collapsible\">" + button_title + " </button>	<div class=\"content\" style=\"overflow: auto; width=auto; height=auto\">		  ");			
				pw.println("		<p></p>");
				pw.println("		<iframe src=\"dependency/" + import_file_name + "\" width=\"100%\" height=\"" + initial_frame_height + "\"></iframe>");						
				pw.println("		<a href=\"#Home\"> Home </a>" + "&nbsp&nbsp&nbsp&nbsp" + "<a href=\"dependency/" + import_file_name + "\"> " + import_file_name + " </a>");
				pw.println("	</div>");
				pw.println("");
				pw.println("	");
			}


			
			///////////////////////////////////////////////////////////////////////////////
			//MALFIND Information Table - inner btn
			///////////////////////////////////////////////////////////////////////////////	
/**change this --> */				if(parent.tree_MALFIND != null && parent.tree_MALFIND.size() > 0){
/**change this --> */button_title = "Malfind Information";

			page_title = button_title + " Table - " + parent.fle_memory_image.getName();						
			import_file_name = button_title.trim().toLowerCase().replace(" ", "_") + "_table_" + parent.fle_memory_image.getName() + ".html";

/**change this --> */fle = dependency_file_writer_tables.write_dependency_files_MALFIND_table(import_file_name, page_title);						

/**leave the rest below alone */
			initial_frame_height = 170 + TABLE_DIV_HEIGHT_PER_ROW * parent.tree_MALFIND.size();
			if(initial_frame_height > this.DEFAULT_TABLE_DIV_HEIGHT) initial_frame_height = DEFAULT_TABLE_DIV_HEIGHT;
						
			pw.println("		  	");
			pw.println("	<p></p><button type=\"button\" class=\"collapsible\">" + button_title + " </button>	<div class=\"content\" style=\"overflow: auto; width=auto; height=auto\">		  ");			
			pw.println("		<p></p>");
			pw.println("		<iframe src=\"dependency/" + import_file_name + "\" width=\"100%\" height=\"" + initial_frame_height + "\"></iframe>");						
			pw.println("		<a href=\"#Home\"> Home </a>" + "&nbsp&nbsp&nbsp&nbsp" + "<a href=\"dependency/" + import_file_name + "\"> " + import_file_name + " </a>");
			pw.println("	</div>");
			pw.println("");
			pw.println("	");
			
}
			
			
			
			

			
			///////////////////////////////////////////////////////////////////////////////
			//DRIVERS Information Table - inner btn
			///////////////////////////////////////////////////////////////////////////////	
			/**change this --> */				if(parent.tree_DRIVERS != null && parent.tree_DRIVERS.size() > 0){
			/**change this --> */button_title = "Drivers Information";
			
			page_title = button_title + " Table - " + parent.fle_memory_image.getName();						
			import_file_name = button_title.trim().toLowerCase().replace(" ", "_") + "_table_" + parent.fle_memory_image.getName() + ".html";
			
			/**change this --> */fle = dependency_file_writer_tables.write_dependency_files_DRIVER_table(import_file_name, page_title, true, parent.tree_DRIVERS);						
			
			/**leave the rest below alone */
			initial_frame_height = 170 + TABLE_DIV_HEIGHT_PER_ROW * parent.tree_DRIVERS.size();
			if(initial_frame_height > this.DEFAULT_TABLE_DIV_HEIGHT) initial_frame_height = DEFAULT_TABLE_DIV_HEIGHT;
						
			pw.println("		  	");
			pw.println("	<p></p><button type=\"button\" class=\"collapsible\">" + button_title + " </button>	<div class=\"content\" style=\"overflow: auto; width=auto; height=auto\">		  ");			
			pw.println("		<p></p>");
			pw.println("		<iframe src=\"dependency/" + import_file_name + "\" width=\"100%\" height=\"" + initial_frame_height + "\"></iframe>");						
			pw.println("		<a href=\"#Home\"> Home </a>" + "&nbsp&nbsp&nbsp&nbsp" + "<a href=\"dependency/" + import_file_name + "\"> " + import_file_name + " </a>");
			pw.println("	</div>");
			pw.println("");
			pw.println("	");
			}
			
			
			
			///////////////////////////////////////////////////////////////////////////////
			//THREADS Information Table - inner btn
			///////////////////////////////////////////////////////////////////////////////	
			/**change this --> */				if(parent.plugin_threads != null){
			/**change this --> */button_title = "Threads Information";

			page_title = button_title + " Table - " + parent.fle_memory_image.getName();						
			import_file_name = button_title.trim().toLowerCase().replace(" ", "_") + "_table_" + parent.fle_memory_image.getName() + ".html";

			/**change this --> */fle = dependency_file_writer_tables.write_dependency_files_THREADS_table(import_file_name, page_title);						

			/**leave the rest below alone */
			initial_frame_height = DEFAULT_TABLE_DIV_HEIGHT;
						
			pw.println("		  	");
			pw.println("	<p></p><button type=\"button\" class=\"collapsible\">" + button_title + " </button>	<div class=\"content\" style=\"overflow: auto; width=auto; height=auto\">		  ");			
			pw.println("		<p></p>");
			pw.println("		<iframe src=\"dependency/" + import_file_name + "\" width=\"100%\" height=\"" + initial_frame_height + "\"></iframe>");						
			pw.println("		<a href=\"#Home\"> Home </a>" + "&nbsp&nbsp&nbsp&nbsp" + "<a href=\"dependency/" + import_file_name + "\"> " + import_file_name + " </a>");
			pw.println("	</div>");
			pw.println("");
			pw.println("	");
			}
			
			
			
			
			
			

			///////////////////////////////////////////////////////////////////////////////
			//UNLOADED MODULES Information Table - inner btn
			///////////////////////////////////////////////////////////////////////////////	
/**change this --> */				if(parent.tree_UNLOADED_MODULES != null && parent.tree_UNLOADED_MODULES.size() > 0){
/**change this --> */button_title = "Unloaded Modules Information";

			page_title = button_title + " Table - " + parent.fle_memory_image.getName();						
			import_file_name = button_title.trim().toLowerCase().replace(" ", "_") + "_table_" + parent.fle_memory_image.getName() + ".html";

/**change this --> */fle = dependency_file_writer_tables.write_dependency_files_DRIVER_table(import_file_name, page_title, false, parent.tree_UNLOADED_MODULES);						

/**leave the rest below alone */
			initial_frame_height = 170 + TABLE_DIV_HEIGHT_PER_ROW * parent.tree_UNLOADED_MODULES.size();
			if(initial_frame_height > this.DEFAULT_TABLE_DIV_HEIGHT) initial_frame_height = DEFAULT_TABLE_DIV_HEIGHT;
						
			pw.println("		  	");
			pw.println("	<p></p><button type=\"button\" class=\"collapsible\">" + button_title + " </button>	<div class=\"content\" style=\"overflow: auto; width=auto; height=auto\">		  ");			
			pw.println("		<p></p>");
			pw.println("		<iframe src=\"dependency/" + import_file_name + "\" width=\"100%\" height=\"" + initial_frame_height + "\"></iframe>");						
			pw.println("		<a href=\"#Home\"> Home </a>" + "&nbsp&nbsp&nbsp&nbsp" + "<a href=\"dependency/" + import_file_name + "\"> " + import_file_name + " </a>");
			pw.println("	</div>");
			pw.println("");
			pw.println("	");
			}
			
			
			///////////////////////////////////////////////////////////////////////////////
			//CALLBACKS Information Table - inner btn
			///////////////////////////////////////////////////////////////////////////////			
/**change this --> */				if(parent.tree_CALLBACKS != null && parent.tree_CALLBACKS.size() > 0){
/**change this --> */button_title = "Callbacks Information";	

			page_title = button_title + " Table - " + parent.fle_memory_image.getName();						
			import_file_name = button_title.trim().toLowerCase().replace(" ", "_") + "_table_" + parent.fle_memory_image.getName() + ".html";
			
/**change this --> */fle = dependency_file_writer_tables.write_dependency_files_DRIVER_table(import_file_name, page_title, false, parent.tree_CALLBACKS);						
			
/**leave the rest below alone */
			initial_frame_height = 170 + TABLE_DIV_HEIGHT_PER_ROW * parent.tree_CALLBACKS.size();
			if(initial_frame_height > this.DEFAULT_TABLE_DIV_HEIGHT) initial_frame_height = DEFAULT_TABLE_DIV_HEIGHT;
						
			pw.println("		  	");
			pw.println("	<p></p><button type=\"button\" class=\"collapsible\">" + button_title + " </button>	<div class=\"content\" style=\"overflow: auto; width=auto; height=auto\">		  ");			
			pw.println("		<p></p>");
			pw.println("		<iframe src=\"dependency/" + import_file_name + "\" width=\"100%\" height=\"" + initial_frame_height + "\"></iframe>");						
			pw.println("		<a href=\"#Home\"> Home </a>" + "&nbsp&nbsp&nbsp&nbsp" + "<a href=\"dependency/" + import_file_name + "\"> " + import_file_name + " </a>");
			pw.println("	</div>");
			pw.println("");
			pw.println("	");
			}
			
			///////////////////////////////////////////////////////////////////////////////
			//DRIVER IRP HOOKS Information Table - inner btn
			///////////////////////////////////////////////////////////////////////////////	
/**change this --> */				if(parent.tree_DRIVER_IRP_HOOK != null && parent.tree_DRIVER_IRP_HOOK.size() > 0){
/**change this --> */button_title = "Driver IRP Hooks Information";

			page_title = button_title + " Table - " + parent.fle_memory_image.getName();						
			import_file_name = button_title.trim().toLowerCase().replace(" ", "_") + "_table_" + parent.fle_memory_image.getName() + ".html";

/**change this --> */fle = dependency_file_writer_tables.write_dependency_files_DRIVER_table(import_file_name, page_title, false, parent.tree_DRIVER_IRP_HOOK);						

			/**leave the rest below alone */
			initial_frame_height = 170 + TABLE_DIV_HEIGHT_PER_ROW * parent.tree_DRIVER_IRP_HOOK.size();
			if(initial_frame_height > this.DEFAULT_TABLE_DIV_HEIGHT) initial_frame_height = DEFAULT_TABLE_DIV_HEIGHT;
						
			pw.println("		  	");
			pw.println("	<p></p><button type=\"button\" class=\"collapsible\">" + button_title + " </button>	<div class=\"content\" style=\"overflow: auto; width=auto; height=auto\">		  ");			
			pw.println("		<p></p>");
			pw.println("		<iframe src=\"dependency/" + import_file_name + "\" width=\"100%\" height=\"" + initial_frame_height + "\"></iframe>");						
			pw.println("		<a href=\"#Home\"> Home </a>" + "&nbsp&nbsp&nbsp&nbsp" + "<a href=\"dependency/" + import_file_name + "\"> " + import_file_name + " </a>");
			pw.println("	</div>");
			pw.println("");
			pw.println("	");
}

			///////////////////////////////////////////////////////////////////////////////
			//TIMERS Information Table - inner btn
			///////////////////////////////////////////////////////////////////////////////		
/**change this --> */				if(parent.tree_TIMERS != null && parent.tree_TIMERS.size() > 0){
/**change this --> */button_title = "Timers Information";

			page_title = button_title + " Table - " + parent.fle_memory_image.getName();						
			import_file_name = button_title.trim().toLowerCase().replace(" ", "_") + "_table_" + parent.fle_memory_image.getName() + ".html";

/**change this --> */fle = dependency_file_writer_tables.write_dependency_files_DRIVER_table(import_file_name, page_title, false, parent.tree_TIMERS);						

			/**leave the rest below alone */
			initial_frame_height = 170 + TABLE_DIV_HEIGHT_PER_ROW * parent.tree_TIMERS.size();
			if(initial_frame_height > this.DEFAULT_TABLE_DIV_HEIGHT) initial_frame_height = DEFAULT_TABLE_DIV_HEIGHT;
						
			pw.println("		  	");
			pw.println("	<p></p><button type=\"button\" class=\"collapsible\">" + button_title + " </button>	<div class=\"content\" style=\"overflow: auto; width=auto; height=auto\">		  ");			
			pw.println("		<p></p>");
			pw.println("		<iframe src=\"dependency/" + import_file_name + "\" width=\"100%\" height=\"" + initial_frame_height + "\"></iframe>");						
			pw.println("		<a href=\"#Home\"> Home </a>" + "&nbsp&nbsp&nbsp&nbsp" + "<a href=\"dependency/" + import_file_name + "\"> " + import_file_name + " </a>");
			pw.println("	</div>");
			pw.println("");
			pw.println("	");
			}
			
			
			///////////////////////////////////////////////////////////////////////////////
			//Get VADTree Information Table - inner btn
			///////////////////////////////////////////////////////////////////////////////			
/**change this --> */ if(parent.tree_PROCESS != null && parent.tree_PROCESS.size() > 0 && parent.tree_VAD_INFO != null && parent.plugin_vadtree != null){			
/**change this --> */button_title = "VADTREE Information";

				page_title = button_title + " Table - " + parent.fle_memory_image.getName();						
				import_file_name = button_title.trim().toLowerCase().replace(" ", "_") + "_table_" + parent.fle_memory_image.getName() + ".html";

/**change this --> */fle = dependency_file_writer_tables.write_dependency_files_VADTREE_table(import_file_name, page_title);						

				/**leave the rest below alone */
				initial_frame_height = 170 + TABLE_DIV_HEIGHT_PER_ROW * parent.tree_VAD_INFO.size();
				if(initial_frame_height > this.DEFAULT_TABLE_DIV_HEIGHT) initial_frame_height = DEFAULT_TABLE_DIV_HEIGHT;
							
				pw.println("		  	");
				pw.println("	<p></p><button type=\"button\" class=\"collapsible\">" + button_title + " </button>	<div class=\"content\" style=\"overflow: auto; width=auto; height=auto\">		  ");			
				pw.println("		<p></p>");
				pw.println("		<iframe src=\"dependency/" + import_file_name + "\" width=\"100%\" height=\"" + initial_frame_height + "\"></iframe>");						
				pw.println("		<a href=\"#Home\"> Home </a>" + "&nbsp&nbsp&nbsp&nbsp" + "<a href=\"dependency/" + import_file_name + "\"> " + import_file_name + " </a>");
				pw.println("	</div>");
				pw.println("");
				pw.println("	");
			}
			
			
			
			
			
			
			
			
			
			
			
			
			/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			//close outter btn
			pw.println("</div>");
			pw.println("<!--/////////////////////////////////////////////////////-->"); 
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_button_tables", e);
		}
		
		return false;
	}
	
	public boolean write_mft_table(String title, String file_name)
	{
		try
		{
			if(parent.plugin_mftparser == null || parent.plugin_mftparser.path_to_output_directory == null || parent.plugin_mftparser.path_to_output_directory.trim().equals(""))
			{
				driver.directive("Unable to continue with MFT file table creation, import directory appears to be invalid...");
				return false;
			}
			
			File fle = new File(parent.plugin_mftparser.path_to_output_directory + file_name);
			
			if(fle == null || !fle.isFile() || !fle.exists())
			{
				//driver.directive("NOTE! I could not find MFT file --> " + file_name + " at path: " + parent.plugin_mftparser.path_to_output_directory);
				return false;
			}
			
			///////////////////////////////////////////////////////////////////////////////
			//Get MFT Information Table - inner btn
			///////////////////////////////////////////////////////////////////////////////			
			
				/**change this --> */String button_title = title;

				String page_title = button_title + " Table - " + parent.fle_memory_image.getName();						
				String import_file_name = button_title.trim().toLowerCase().replace(" ", "_") + "_table_" + parent.fle_memory_image.getName() + ".html";

				/**change this --> */fle = dependency_file_writer_tables.write_dependency_files_MFT_table(import_file_name, page_title, fle);						

				/**leave the rest below alone */
				int initial_frame_height = DEFAULT_TABLE_DIV_HEIGHT;
							
				pw.println("		  	");
				pw.println("	<p></p><button type=\"button\" class=\"collapsible\">" + button_title + " </button>	<div class=\"content\" style=\"overflow: auto; width=auto; height=auto\">		  ");			
				pw.println("		<p></p>");
				pw.println("		<iframe src=\"dependency/" + import_file_name + "\" width=\"100%\" height=\"" + initial_frame_height + "\"></iframe>");						
				pw.println("		<a href=\"#Home\"> Home </a>" + "&nbsp&nbsp&nbsp&nbsp" + "<a href=\"dependency/" + import_file_name + "\"> " + import_file_name + " </a>");
				pw.println("	</div>");
				pw.println("");
				pw.println("	");
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_mft_table", e);
		}
		
		return false;
	}
	
	public boolean write_analysis_report_header(PrintWriter pwOut)
	{
		try
		{
			if(pwOut == null)
				return false;
			
			pw.println("	<!DOCTYPE html>	");
			pw.println("	<!-- Solomon Sonya @Carpenter1010 - Happy Hunting! -->	");
			pw.println("	<html lang=\"en\"><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=windows-1252\">	");
			pw.println("	<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">	");
			pw.println("	<style> .collapsible { background-color: #000; color: white; cursor: pointer; padding: 18px; width: 100%; border: none; text-align: left; outline: none; font-size: 15px; } .active, .collapsible:hover { background-color: #004C99; } .content { padding: 0 18px; display: none; overflow: hidden; background-color: #f5f1f1; } </style> </head><body style=\"\">	");
			pw.println("		");
			pw.println("		");
			pw.println("	<title>Xavier Memory Analysis Report - " + fle_memory_image.getName() + " </title>	");
			pw.println("		");
			pw.println("	<button type=\"button\" class=\"collapsible active\"><b>" + html_title + " - " + fle_memory_image.getName() + " </b></button> <div class=\"content\" style=\"display: block; " + word_wrap_directive + " overflow: auto; width=auto; height=auto\">	");
			pw.println("	<p>	");
			
			if(parent.PROFILE != null && parent.PROFILE.toLowerCase().trim().startsWith("win"))
			{
				pw.println("	</p><table><caption><u></u></caption> <tbody><tr> "
								+ "<th>Investigator Name</th> "
								+ "<th>Profile</th> "
								+ "<th>Investigation Date</th> "
								+ "<th>Computer Name</th> "
								+ "<th>Processor Details</th> "
								+ "<th>Investigation Description</th> "
								+ "<th>Memory Image Path</th>   "
						//+ "</tr>	");
						+ "	");
				
				pw.println("	<tr> "
								+ "<td> " + normalize_html(this.investigator_name) + " </td> "
								+ "<td> " + this.normalize_html(parent.PROFILE) + " </td>" 
								+ "<td> " + this.normalize_html(parent.EXECUTION_TIME_STAMP) + "</td> "
								+ "<td> " + this.normalize_html(this.computer_name) + " </td> "
								+ "<td> " + this.normalize_html(parent.PROCESSOR_ARCHITECTURE) + " </td> "
								+ "<td> " + this.normalize_html(this.investigation_description) + " </td> "
								+ "<td> " + this.normalize_html(this.fle_memory_image.toString()) + " </td>  "
						+ " </tr>	");
				
			}
			else
			{
				pw.println("	</p><table><caption><u></u></caption> <tbody><tr> <th>Investigator Name</th> <th>Investigation Date</th> <th>Investigation Description</th> <th>Memory Image Path</th> <th>Profile</th> </tr>	");
				pw.println("	<tr> <td> " + normalize_html(this.investigator_name) + " </td> <td> " + this.normalize_html(parent.EXECUTION_TIME_STAMP) + " </td> <td> " + this.normalize_html(this.investigation_description) + " </td> <td> " + this.normalize_html(this.fle_memory_image.toString()) + " </td> <td> " + this.normalize_html(parent.PROFILE) + " </td> </tr>	");
			}
			
			//pw.println("	</tbody></table> <hr>	");
			pw.println("		");
			pw.println("	<tr> <th>Memory Analysis Tool Name</th> <th>Tool File Size</th> <th>Creation Date</th> <th>Last Accessed Date</th> <th>Last Modified Date</th> <th>Analysis Tool MD5</th> <th>Analysis Tool SHA-256 </th> </tr>	");
			pw.println(this.normalize_html(parent.file_attr_volatility.get_html_table_information()));
			pw.println("	<tr> <th>Memory Image File Name</th> <th>Image File Size</th> <th>Creation Date</th> <th>Last Accessed Date</th> <th>Last Modified Date</th> <th>Memory Image MD5</th> <th>Memory Image SHA-256 </th> </tr>	");
			pw.println(this.normalize_html(parent.file_attr_memory_image.get_html_table_information()));
			pw.println("	</tbody></table> <a id=\"Home\"> </a>  <hr>	");
			
			
			pw.println("	<p></p> </div> <br>	");
			pw.println("		");
			pw.println("	<style> .node circle { fill: #fff; stroke: darkblue; stroke-width: 1.5px; } .node text { font: 12px sans-serif; } .link { fill: none; stroke: #bbb; stroke-width: 2px; } table { font-family: arial, sans-serif; border-collapse: collapse; width: 100%;} td, th { border: 1px solid #dddddd; text-align: left; padding: 8px;} tr:nth-child(even) { background-color: #dddddd;} .col-container { display: table; width: 100%;} </style>	");
			pw.println("		");
			pw.println("		");
			pw.println("	<style type=\"text/css\"> .node { cursor: pointer; } .overlay{ background-color:#EEE; } .node circle { fill: #fff; stroke: steelblue; stroke-width: 1.5px; } .node text { font-size:10px; font-family:sans-serif; } .link { fill: none; stroke: #ccc;	");
			pw.println("	stroke-width: 1.5px; } .templink { fill: none; stroke: red; stroke-width: 3px; } .ghostCircle.show{ display:block; } .ghostCircle, .activeDrag .ghostCircle{ display: none; }</style>	");
			pw.println("		");
			pw.println("	<br>	");
			
			if(WRITE_SHORTCUT_TABLES)
				write_shortcut_tables(pw);
			
			
			
			pw.println("		");
			pw.println("		");
			pw.println("	<!--/////////////////////////////////////////////////////-->	");

			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_header", e);
		}
		
		return false;
	}
	
	
	public boolean write_shortcut_tables(PrintWriter pw)
	{
		try
		{
			
			
			pw.println("	<table>	");
			
				pw.print("	<tbody><tr> 	");
					pw.print("<td style=\"text-align:center\"><a href=\"#Process\"> Process </a></td>");
					pw.print("<td style=\"text-align:center\"><a href=\"#Process_Tree\"> Process Tree </a></td>");
					pw.print("<td style=\"text-align:center\"><a href=\"#Process_GraphViz\"> Process GraphViz </a></td>");
					pw.print("<td style=\"text-align:center\"><a href=\"#Process_List\"> Process List </a></td>");
					pw.print("<td style=\"text-align:center\"><a href=\"#Network\"> Network </a></td>");
					pw.print("<td style=\"text-align:center\"><a href=\"#Timeline\"> Timeline </a></td>");
					pw.print("<td style=\"text-align:center\"><a href=\"#Modules\"> Modules </a></td>");
					pw.print("<td style=\"text-align:center\"><a href=\"#Handles\"> Handles </a></td>");
				pw.print("	</tr>	");			
			pw.println("\n	</tbody></table><br>	");
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_shortcut_tables", e);
		}
		
		return false;
	}
	
	public boolean write_analysis_report_footer(PrintWriter pwOut)
	{
		try
		{
			if(pwOut == null)
				return false;
			
			pwOut.println("<script> var coll = document.getElementsByClassName(\"collapsible\"); var i;  for (i = 0; i < coll.length; i++) {   coll[i].addEventListener(\"click\", function() {     this.classList.toggle(\"active\");     var content = this.nextElementSibling;     if (content.style.display === \"block\") {       content.style.display = \"none\";     } else {       content.style.display = \"block\";     }   }); } </script>");
			pwOut.println("<p><br><br><br><hr><a href =\"https://github.com/solomonsonya/Xavier_MemoryAnalysis_Framework\"> Xavier Memory Analysis Framework vrs" + driver.VERSION + " </a></u> by Solomon Sonya <a href=\"https://twitter.com/carpenter1010\">@Carpenter1010</a> - " + driver.get_time_stamp() + "</p>");
			pwOut.println("</body></html>");

			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_footer", e);
		}
		
		return false;
	}
	
	
	
	public static boolean sop(String out)
	{
		try
		{
			Interface.jpnlAdvancedAnalysisConsole.append(out);						
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "sop", e);
		}
		
		return false;
	}
	
	public static boolean sp(String out)
	{
		try
		{
			Interface.jpnlAdvancedAnalysisConsole.append_sp(out);						
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "sop", e);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	public static boolean set_node_length_PROCESS_TREE(int len)
	{
		try
		{
			if(len < 1)
			{
				String entry = driver.jop_Query("Length between each node is currently set to [" + tree_length_to_each_node_PROCESS_TREE + "].\nPlease enter new length between nodes:\n", "Set Length between Nodes");
				
				try	
				{	
					len = Integer.parseInt(entry.trim());										
				}
				catch(Exception e)
				{
					driver.jop_Error("Invalid entry!");
					return false;
				}
			}
			
			if(len > 0)
			{
				tree_length_to_each_node_PROCESS_TREE = len;
				sop("Tree length has successfully been set to [" + tree_length_to_each_node_PROCESS_TREE + "].");
				
				try	{	Interface.jmnuitm_Set_Node_Length_PROCESS_TREE.setToolTipText("<html>Set the initial length between each node in analysis report html file. <br>Right now, length is set to <b>" + tree_length_to_each_node_PROCESS_TREE  + "</b></html>");	} catch(Exception e){}
				
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "set_node_length", e);
		}
		
		return false;
	}
	
	public static boolean set_initial_div_height_PROCESS_TREE(int len)
	{
		try
		{
			if(len < 1)
			{
				String entry = driver.jop_Query("Initial height of the html file that is added as a frame into the main Analysis Report container html file is currently set to [" + tree_div_height_PROCESS_TREE + "].\nPlease enter new height value:\n", "Set HTML Height Value");
				
				try	{	len = Integer.parseInt(entry.trim());	}
				catch(Exception e)
				{
					driver.jop_Error("Invalid entry!!");
					return false;
				}
			}
			
			if(len > 0)
			{
				tree_div_height_PROCESS_TREE = len;
				sop("Initial tree height has successfully been set to [" + tree_div_height_PROCESS_TREE + "].");
				
				
				try	{Interface.jmnuitm_Set_Div_Height_PROCESS_TREE.setToolTipText("<html>Set the initial height of the html file that is added as a frame into the main Analysis Report container html file. <br>Right now, initial height is set to <b>" + tree_div_height_PROCESS_TREE  + "</b></html>");} catch(Exception e){}
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "set_initial_div_height", e);
		}
		
		return false;
	}
	
	
	
	public static boolean set_initial_div_width_PROCESS_TREE(int len)
	{
		try
		{
			if(len < 1)
			{
				String entry = driver.jop_Query("Initial width of the html file that is added as a frame into the main Analysis Report container html file is currently set to [" + tree_div_width_PROCESS_TREE + "].\nPlease enter new width value:\n", "Set HTML Width Value");
				
				try	{	len = Integer.parseInt(entry.trim());	}
				catch(Exception e)
				{
					driver.jop_Error("Invalid entry!!!");
					return false;
				}
			}
			
			if(len > 0)
			{
				tree_div_width_PROCESS_TREE = len;
				sop("Initial tree width has successfully been set to [" + tree_div_width_PROCESS_TREE + "].");
				
				try	{Interface.jmnuitm_Set_Div_Width_PROCESS_TREE.setToolTipText("<html>Set the initial width of the html file that is added as a frame into the main Analysis Report container html file. <br>Right now, initial width is set to <b>" + Analysis_Report_Container_Writer.tree_div_width_PROCESS_TREE  + "</b></html>");} catch(Exception e){}
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "set_initial_div_width", e);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
		
	
		
	
	public static boolean set_node_length_PROCESS_INFORMATION_TREE(int len)
	{
		try
		{
			if(len < 1)
			{
				String entry = driver.jop_Query("Length between each node is currently set to [" + tree_length_to_each_node_PROCESS_INFORMATION_TREE + "].\nPlease enter new length between nodes:\n", "Set Length between Nodes");
				
				try	
				{	
					len = Integer.parseInt(entry.trim());										
				}
				catch(Exception e)
				{
					driver.jop_Error("Invalid entry!");
					return false;
				}
			}
			
			if(len > 0)
			{
				tree_length_to_each_node_PROCESS_INFORMATION_TREE = len;
				sop("Tree length has successfully been set to [" + tree_length_to_each_node_PROCESS_INFORMATION_TREE + "].");
				
				try	{	Interface.jmnuitm_Set_Node_Length_PROCESS_INFORMATION_TREE.setToolTipText("<html>Set the initial length between each node in analysis report html file. <br>Right now, length is set to <b>" + tree_length_to_each_node_PROCESS_INFORMATION_TREE  + "</b></html>");	} catch(Exception e){}
				
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "set_node_length_PROCESS_INFORMATION_TREE", e);
		}
		
		return false;
	}
	
	public static boolean set_initial_div_height_PROCESS_INFORMATION_TREE(int len)
	{
		try
		{
			if(len < 1)
			{
				String entry = driver.jop_Query("Initial height of the html file that is added as a frame into the main Analysis Report container html file is currently set to [" + tree_div_height_PROCESS_INFORMATION_TREE + "].\nPlease enter new height value:\n", "Set HTML Height Value");
				
				try	{	len = Integer.parseInt(entry.trim());	}
				catch(Exception e)
				{
					driver.jop_Error("Invalid entry!!");
					return false;
				}
			}
			
			if(len > 0)
			{
				tree_div_height_PROCESS_INFORMATION_TREE = len;
				sop("Initial tree height has successfully been set to [" + tree_div_height_PROCESS_INFORMATION_TREE + "].");
				
				
				try	{Interface.jmnuitm_Set_Div_Height_PROCESS_INFORMATION_TREE.setToolTipText("<html>Set the initial height of the html file that is added as a frame into the main Analysis Report container html file. <br>Right now, initial height is set to <b>" + tree_div_height_PROCESS_INFORMATION_TREE  + "</b></html>");} catch(Exception e){}
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "set_initial_div_height_PROCESS_INFORMATION_TREE", e);
		}
		
		return false;
	}
	
	
	
	public static boolean set_initial_div_width_PROCESS_INFORMATION_TREE(int len)
	{
		try
		{
			if(len < 1)
			{
				String entry = driver.jop_Query("Initial width of the html file that is added as a frame into the main Analysis Report container html file is currently set to [" + tree_div_width_PROCESS_INFORMATION_TREE + "].\nPlease enter new width value:\n", "Set HTML Width Value");
				
				try	{	len = Integer.parseInt(entry.trim());	}
				catch(Exception e)
				{
					driver.jop_Error("Invalid entry!!!");
					return false;
				}
			}
			
			if(len > 0)
			{
				tree_div_width_PROCESS_INFORMATION_TREE = len;
				sop("Initial tree width has successfully been set to [" + tree_div_width_PROCESS_INFORMATION_TREE + "].");
				
				try	{Interface.jmnuitm_Set_Div_Width_PROCESS_INFORMATION_TREE.setToolTipText("<html>Set the initial width of the html file that is added as a frame into the main Analysis Report container html file. <br>Right now, initial width is set to <b>" + Analysis_Report_Container_Writer.tree_div_width_PROCESS_INFORMATION_TREE  + "</b></html>");} catch(Exception e){}
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "set_initial_div_width_PROCESS_INFORMATION_TREE", e);
		}
		
		return false;
	}
	
	
	public boolean write_button_raw_plugins(PrintWriter pwOut)
	{
		try
		{
			if(parent.fle_memory_image == null)
			{
				driver.directive("PUNT!!!! Memory Import Image appears to be null. - Terminating writing file info for now...");
				return false;
			}
									
			String button_title = "";
			String import_file_path = "";
			String page_title = "";
			int initial_frame_height = 700;		
			File fle = null;
			String plugin_name = "";
			
			
			//pw.println("<p> Data 1 </p>");
			pw.println("<p>  </p>");
			//outer btn
			//pw.println("<button type=\"button\" class=\"collapsible active\"><a id=\"Tables\">Tables</a></button> <div class=\"content\" style=\"display: block; overflow: auto; width=auto; height=auto\">  <p>  </p>");
			pw.println("	<p></p><button type=\"button\" class=\"collapsible\">" + "Execution Plugins" + " </button>	<div class=\"content\" style=\"overflow: auto; width=auto; height=auto\">		  ");
			pw.println("");
			
			
			///////////////////////////////////////////////////////////////////////////////
			//PSLIST Button
			///////////////////////////////////////////////////////////////////////////////
/**change this --> */			fle = parent.fle_pslist;
/**change this --> */			plugin_name = "pslist";
			
			/**leave the rest below alone */
			if(fle != null && fle.isFile() && fle.length() > 1)
			{				
				button_title = plugin_name;
				page_title = button_title + " Plugin - " + parent.fle_memory_image.getName();						
				import_file_path = "./../" + plugin_name + "/" + fle.getName();					
				
				initial_frame_height = 500;			
				pw.println("		  	");
				pw.println("	<p></p><button type=\"button\" class=\"collapsible\">" + button_title + " </button>	<div class=\"content\" style=\"overflow: auto; width=auto; height=auto\">		  ");			
				pw.println("		<p></p>");
				pw.println("		<iframe src=\"" + import_file_path + "\" width=\"100%\" height=\"" + initial_frame_height + "\"></iframe>");						
				pw.println("		<a href=\"#Home\"> Home </a>" + "&nbsp&nbsp&nbsp&nbsp" + "<a href=\"" + import_file_path + "\"> " + plugin_name + " </a>");
				pw.println("	</div>");
				pw.println("");
				pw.println("	");
			
			}
			
			///////////////////////////////////////////////////////////////////////////////
			//PSSCAN Button
			///////////////////////////////////////////////////////////////////////////////
/**change this --> */			fle = parent.fle_psscan;
/**change this --> */			plugin_name = "psscan";
			
			/**leave the rest below alone */
			if(fle != null && fle.isFile() && fle.length() > 1)
			{				
				button_title = plugin_name;
				page_title = button_title + " Plugin - " + parent.fle_memory_image.getName();						
				import_file_path = "./../" + plugin_name + "/" + fle.getName();					
				
				initial_frame_height = 500;			
				pw.println("		  	");
				pw.println("	<p></p><button type=\"button\" class=\"collapsible\">" + button_title + " </button>	<div class=\"content\" style=\"overflow: auto; width=auto; height=auto\">		  ");			
				pw.println("		<p></p>");
				pw.println("		<iframe src=\"" + import_file_path + "\" width=\"100%\" height=\"" + initial_frame_height + "\"></iframe>");						
				pw.println("		<a href=\"#Home\"> Home </a>" + "&nbsp&nbsp&nbsp&nbsp" + "<a href=\"" + import_file_path + "\"> " + plugin_name + " </a>");
				pw.println("	</div>");
				pw.println("");
				pw.println("	");
			
			}
			
			///////////////////////////////////////////////////////////////////////////////
			//pstree Button
			///////////////////////////////////////////////////////////////////////////////
/**change this --> */			fle = parent.fle_pstree;
/**change this --> */			plugin_name = "pstree";
			
			/**leave the rest below alone */
			if(fle != null && fle.isFile() && fle.length() > 1)
			{				
				button_title = plugin_name;
				page_title = button_title + " Plugin - " + parent.fle_memory_image.getName();						
				import_file_path = "./../" + plugin_name + "/" + fle.getName();					
				
				initial_frame_height = 500;			
				pw.println("		  	");
				pw.println("	<p></p><button type=\"button\" class=\"collapsible\">" + button_title + " </button>	<div class=\"content\" style=\"overflow: auto; width=auto; height=auto\">		  ");			
				pw.println("		<p></p>");
				pw.println("		<iframe src=\"" + import_file_path + "\" width=\"100%\" height=\"" + initial_frame_height + "\"></iframe>");						
				pw.println("		<a href=\"#Home\"> Home </a>" + "&nbsp&nbsp&nbsp&nbsp" + "<a href=\"" + import_file_path + "\"> " + plugin_name + " </a>");
				pw.println("	</div>");
				pw.println("");
				pw.println("	");
			
			}
			
			///////////////////////////////////////////////////////////////////////////////
			//psxview Button
			///////////////////////////////////////////////////////////////////////////////
/**change this --> */			fle = parent.fle_psxview;
/**change this --> */			plugin_name = "psxview";
			
			/**leave the rest below alone */
			if(fle != null && fle.isFile() && fle.length() > 1)
			{				
				button_title = plugin_name;
				page_title = button_title + " Plugin - " + parent.fle_memory_image.getName();						
				import_file_path = "./../" + plugin_name + "/" + fle.getName();					
				
				initial_frame_height = 500;			
				pw.println("		  	");
				pw.println("	<p></p><button type=\"button\" class=\"collapsible\">" + button_title + " </button>	<div class=\"content\" style=\"overflow: auto; width=auto; height=auto\">		  ");			
				pw.println("		<p></p>");
				pw.println("		<iframe src=\"" + import_file_path + "\" width=\"100%\" height=\"" + initial_frame_height + "\"></iframe>");						
				pw.println("		<a href=\"#Home\"> Home </a>" + "&nbsp&nbsp&nbsp&nbsp" + "<a href=\"" + import_file_path + "\"> " + plugin_name + " </a>");
				pw.println("	</div>");
				pw.println("");
				pw.println("	");
			
			}
			
			///////////////////////////////////////////////////////////////////////////////
			//REMAINING PLUGINS
			///////////////////////////////////////////////////////////////////////////////
			
			
			
			for(_Analysis_Plugin_Super_Class plugin : parent.tree_advanced_analysis_threads.values())
			{
				
				
				///////////////////////////////////////////////////////////////////////////////
				//Plugin Button
				///////////////////////////////////////////////////////////////////////////////
								
				//if(plugin == null || plugin.fleOutput == null || !plugin.fleOutput.isFile() || plugin.fleOutput.length() < 1)
					//continue;
				
				if(plugin == null || plugin.plugin_name == null || plugin.plugin_name.trim().equals(""))
					continue;
				
				//select which file to use
				if(plugin.fleOutput != null && plugin.fleOutput.isFile() && plugin.fleOutput.length() > 0)
					fle = plugin.fleOutput;
				else if(plugin.fle_import != null && plugin.fle_import.isFile() && plugin.fle_import.length() > 0)
					fle = plugin.fle_import;
				else
				{
					driver.directive("NOTE: I could not find output file to write for plugin [" + plugin.plugin_name + "]");
					continue;
				}
///////////////////////////////////////////////////////////////////////////////
//These plugins are giving me difficulty in webpage at the moment...
///////////////////////////////////////////////////////////////////////////////	
//dumpfile sevent logs is giving trouble restoring the file, return here later and address
if(fle.getName().toLowerCase().trim().startsWith("_dumpfiles --regex .evtx$ --ignore-case_"))
	continue;
//if(fle.getName().toLowerCase().trim().startsWith("_cmdscan"))
//	continue;
//if(fle.getName().toLowerCase().trim().startsWith("_verinfo"))
//	continue;

			
	/**change this --> */button_title = plugin.plugin_name;
	
					//change for impscan to provide more detail
					try
					{
						if(plugin.plugin_name.equalsIgnoreCase("impscan"))
						{
							button_title = plugin.plugin_name + " " + plugin.plugin_special_identifer;
							
							write_button_impscan(pw);
							continue;
						}
					}
					catch(Exception e)
					{
						button_title = plugin.plugin_name;
					}

					page_title = button_title + " Plugin - " + parent.fle_memory_image.getName();						
					import_file_path = "./../" + plugin.plugin_name + "/" + fle.getName();				

					/**leave the rest below alone */
					initial_frame_height = 500;			
					pw.println("		  	");
					pw.println("	<p></p><button type=\"button\" class=\"collapsible\">" + button_title + " </button>	<div class=\"content\" style=\"overflow: auto; width=auto; height=auto\">		  ");			
					pw.println("		<p></p>");
					pw.println("		<iframe src=\"" + import_file_path + "\" width=\"100%\" height=\"" + initial_frame_height + "\"></iframe>");						
					pw.println("		<a href=\"#Home\"> Home </a>" + "&nbsp&nbsp&nbsp&nbsp" + "<a href=\"" + import_file_path + "\"> " + plugin.plugin_name + " </a>");
					pw.println("	</div>");
					pw.println("");
					pw.println("	");
				
			}
												
			
			/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			//close outter btn
			pw.println("</div>");
			pw.println("<!--/////////////////////////////////////////////////////-->"); 
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_button_raw_plugins", e);
		}
		
		return false;
	}
	
	
	public boolean write_button_impscan(PrintWriter pw)
	{
		
		try
		{
			if(this.i_have_written_impscan_plugins)
				return true;
			
			if(pw == null)
				return false;
						
			String button_title = "", page_title = "", import_file_path = "";
			int initial_frame_height = 500;
			File fle = null;
			
			//write outter button
			pw.println("	<p></p><button type=\"button\" class=\"collapsible\">" + "impscan" + " </button>	<div class=\"content\" style=\"overflow: auto; width=auto; height=auto\">		  ");			
			pw.println("		<p></p>");								
				
			for(_Analysis_Plugin_Super_Class plugin : parent.tree_advanced_analysis_threads.values())
			{								
				if(plugin == null || plugin.plugin_name == null || !plugin.plugin_name.toLowerCase().trim().startsWith("impscan"))
					continue;
				
				if(plugin.fleOutput != null && plugin.fleOutput.isFile() && plugin.fleOutput.length() > 0)
					fle = plugin.fleOutput;
				else if(plugin.fle_import != null && plugin.fle_import.isFile() && plugin.fle_import.length() > 0)
					fle = plugin.fle_import;
				else
				{
					driver.directive("NOTE: I could not find output file to write for plugin [" + plugin.plugin_name + "]");
					continue;
				}
				
				button_title = plugin.plugin_name + " " + plugin.plugin_special_identifer;
				
				page_title = button_title + " Plugin - " + parent.fle_memory_image.getName();						
				import_file_path = "./../" + plugin.plugin_name + "/" + fle.getName();				
	
				/**leave the rest below alone */
				initial_frame_height = 500;			
				pw.println("		  	");
				pw.println("	<p></p><button type=\"button\" class=\"collapsible\">" + button_title + " </button>	<div class=\"content\" style=\"overflow: auto; width=auto; height=auto\">		  ");			
				pw.println("		<p></p>");
				pw.println("		<iframe src=\"" + import_file_path + "\" width=\"100%\" height=\"" + initial_frame_height + "\"></iframe>");						
				pw.println("		<a href=\"#Home\"> Home </a>" + "&nbsp&nbsp&nbsp&nbsp" + "<a href=\"" + import_file_path + "\"> " + plugin.plugin_name + " </a>");
				pw.println("	</div>");
				pw.println("");
				pw.println("	");

			}
												
			//close outter button
			pw.println("	</div>");
			
			
			i_have_written_impscan_plugins = true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_button_impscan", e);
		}
		
		this.i_have_written_impscan_plugins = true;
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
