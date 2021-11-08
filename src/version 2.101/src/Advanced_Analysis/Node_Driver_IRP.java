/**
 * @author Solomon Sonya
 */

package Advanced_Analysis;

import Driver.*;
import Interface.*;

import java.io.*;
import java.util.*;
import Advanced_Analysis.Analysis_Plugin.*;

public class Node_Driver_IRP 
{
	public static volatile Driver driver = new Driver();
	public static final String myClassName = "Node_Driver_IRP";
	
	public volatile Node_Driver nde_driver = null;
	public volatile String driver_start = null;
	public volatile String driver_size = null;
	public volatile String driver_start_io = null;
	public volatile LinkedList<String> list_irp_entries = new LinkedList<String>();
	
	public volatile int index = 0;
	
	public Node_Driver_IRP(Node_Driver DRIVER)
	{
		try
		{
			nde_driver = DRIVER;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1");
		}
	}
	
	
	
	public boolean write_node_information(PrintWriter pw)
	{
		try
		{						
			pw.println("\t\t\t" +  "{ \"name\": \"" + driver.normalize_html("Hook [" + index + "]").replace("\\", "\\\\") + "\" , \"children\": [");
			
			if(this.nde_driver == null)
				driver.write_node_ENTRY("Driver Name: ", "Driver IRP Hook [" + index + "]", pw);
			else
				driver.write_node_ENTRY("Driver Name: ", this.nde_driver.module_name, pw);
			
			driver.write_node_ENTRY("Driver Start: ", this.driver_start, pw);
			driver.write_node_ENTRY("Driver Size: ", this.driver_size, pw);
			driver.write_node_ENTRY("Driver Start IO: ", this.driver_start_io, pw);
			
			if(this.list_irp_entries != null && this.list_irp_entries.size() > 0)
			{
				pw.println("\t\t\t\t" +  "{ \"name\": \"" + driver.normalize_html("Details").replace("\\", "\\\\") + "\" , \"children\": [");
				
					for(String entry : this.list_irp_entries)
					{
						driver.write_node_ENTRY("", entry, pw);
					}
				
				pw.println("\t\t\t\t" +  "]},");
			}
			
			

			
			
			
			pw.println("\t\t\t" +  "]},");			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_node_information", e);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
