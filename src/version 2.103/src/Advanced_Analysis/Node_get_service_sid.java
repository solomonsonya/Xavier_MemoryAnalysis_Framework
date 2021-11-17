/**
 * @author Solomon Sonya
 */

package Advanced_Analysis;

import Driver.*;
import Interface.*;

import java.io.*;
import java.util.*;
import Advanced_Analysis.Analysis_Plugin.*;

public class Node_get_service_sid 
{
	public static volatile Driver driver = new Driver();
	public static final String myClassName = "Node_get_service_sid";
	
	/**e.g., S-1-5-80-2675092186-3691566608-1139246469-1504068187-1286574349*/
	public volatile String sid = null;
	
	/**e.g., Abiosdsk*/
	public volatile String name = null;
	
	public Node_get_service_sid()
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
			pw.println("\t\t" +  "{ \"name\": \"" + driver.normalize_html(this.name).replace("\\", "\\\\") + "\" , \"children\": [");

			driver.write_node_ENTRY("SID: ", this.sid, pw);
			driver.write_node_ENTRY("Value: ", this.name, pw);
			
			pw.println("\t\t" +  "]},");//end process information
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_service_sids", e);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
