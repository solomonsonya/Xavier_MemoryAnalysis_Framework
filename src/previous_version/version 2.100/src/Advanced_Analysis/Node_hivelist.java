/**
 * @author Solomon Sonya
 */

package Advanced_Analysis;

import Driver.*;
import Interface.*;

import java.io.*;
import java.util.*;
import Advanced_Analysis.Analysis_Plugin.*;

public class Node_hivelist 
{
	public static volatile Driver driver = new Driver();
	public static final String myClassName = "Node_hivelist";
	
	public volatile String virtual_address = null;
	public volatile String physical_address = null;
	public volatile String name_registry = "";
	
	public Node_hivelist()
	{
		try
		{
			
			
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
			
			String header = "";
			
			try	{	header = this.name_registry.substring(name_registry.lastIndexOf("\\")+1).trim();}
			catch(Exception e){	header = this.name_registry;}
			
			pw.println("\t\t\t" +  "{ \"name\": \"" + driver.normalize_html(header).replace("\\", "\\\\") + "\" , \"children\": [");

			driver.write_node_ENTRY("Name: ", this.name_registry, pw);
			driver.write_node_ENTRY("Virtual Address: ", this.virtual_address, pw);
			driver.write_node_ENTRY("Physical Address: ", this.physical_address, pw);
			
			pw.println("\t\t\t" +  "]},");//end process information
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_node_information", e);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
