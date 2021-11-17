/**
 * @author Solomon Sonya
 */

package Advanced_Analysis;

import java.io.*;
import java.util.*;
import Driver.*;

public class Node_Privs 
{
	public static final String myClassName = "Node_Privs";
	public static volatile Driver driver = new Driver();
	
	Node_Process process = null;
	public volatile int PID = -1;
	public volatile String process_name = "";
	public volatile String value = null;
	public volatile String privilege = null;
	public volatile String privilege_lower = null;
	public volatile String attributes = null;
	public volatile String description = "";
	
	
	
	
	
	
	
	public Node_Privs(Node_Process PROCESS, int pid, String PROCESS_NAME, String VALUE, String PRIVELEGE, String ATTRIBUTES, String DESCRIPTION)
	{
		try
		{
			process = PROCESS;
			PID = pid;
			privilege = PRIVELEGE;
			process_name = PROCESS_NAME;
			attributes = ATTRIBUTES;
			description = DESCRIPTION;
			
			privilege = privilege.trim();
			privilege_lower = privilege.toLowerCase().trim();
			
			//link
			if(process != null && privilege != null && !privilege.equals(""))
			{
				if(process.tree_privs == null)
					process.tree_privs = new TreeMap<String, Node_Privs>();
					
				process.tree_privs.put(privilege_lower,  this);								
			}
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
	}
	
	
	public boolean write_tree_entry(PrintWriter pw)
	{
		try
		{
			this.write_node_ENTRY("PID: ", ""+this.PID, pw);
			this.write_node_ENTRY("Process Name: ", this.process_name, pw);
			this.write_node_ENTRY("Value: ", this.value, pw);
			this.write_node_ENTRY("Privilege: ", this.privilege, pw);
			this.write_node_ENTRY("Attributes: ", this.attributes, pw);
			this.write_node_ENTRY("Description: ", this.description, pw);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_tree_entry", e);
		}
		
		return false;
	}
	
	public boolean write_node_ENTRY(String title, String value, PrintWriter pw)
	{
		try
		{
			if(value == null || value.trim().equals(""))
				return false;
					
			pw.println("\t\t\t" +  "{ \"name\": \"" + driver.normalize_html(title + " " + value).replace("\\", "\\\\") + "\" },");
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_node_ENTRY", e);
		}
		
		return false;
	}
	
	
	
	
}
