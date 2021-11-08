/**
 * @author Solomon Sonya
 */

package Advanced_Analysis;

import Driver.*;
import Interface.*;

import java.io.*;
import java.util.*;
import Advanced_Analysis.Analysis_Plugin.*;
import Advanced_Analysis.Analysis_Report.Dependency_File_Writer_Tree;

public class Node_svcscan 
{
	public static volatile Driver driver = new Driver();
	public static final String myClassName = "Node_svcscan";
	
	public volatile String offset = null;
	public volatile String order = null;
	public volatile String start = null;
	public volatile String pid = null;
	public volatile int PID = -1;
	public volatile String service_name = null;
	public volatile String display_name = null;
	public volatile String service_type = null;
	public volatile String service_state = null;
	public volatile String binary_path = null;
	
	public volatile Node_Process process = null;
	
	public Node_svcscan(String SERVICE_NAME)
	{
		try
		{
			service_name = SERVICE_NAME;
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1");
		}
	}
	
	
	
	
	public boolean write_tree_information(PrintWriter pw, Dependency_File_Writer_Tree dependency_writer)
	{
		try
		{
			//name node
			pw.println("\t" +  "{ \"name\": \"" + driver.normalize_html(this.service_name).replace("\\", "\\\\") + "\" , \"children\": [");
			
			driver.write_node_ENTRY("Offset: ", offset, pw);
			driver.write_node_ENTRY("Start: ", start, pw);
			driver.write_node_ENTRY("PID: ", pid, pw);
			driver.write_node_ENTRY("Service Name: ", service_name, pw);
			driver.write_node_ENTRY("Display Name: ", display_name, pw);
			driver.write_node_ENTRY("Service Type: ", service_type, pw);
			driver.write_node_ENTRY("Service State: ", service_state, pw);
			driver.write_node_ENTRY("Binary Path: ", binary_path, pw);
			
			
			pw.println("\t" +  "]},");
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_tree_information", e);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
