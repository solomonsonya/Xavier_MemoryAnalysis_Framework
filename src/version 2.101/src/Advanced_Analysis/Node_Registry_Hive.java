/**
 * @author Solomon Sonya
 * 
 * e.g. 
 * PrintKey and Userassist plugins - \??\C:\Documents and Settings\Adham\Local Settings\Application Data\Microsoft\Windows\UsrClass.dat
 */

package Advanced_Analysis;

import Driver.*;
import Interface.*;

import java.io.*;
import java.util.*;
import Advanced_Analysis.Analysis_Plugin.*;

public class Node_Registry_Hive 
{
	public static volatile Driver driver = new Driver();
	public static final String myClassName = "Node_Registry_Hive";
	
	public volatile String registry = null;
	
	public volatile TreeMap<String, Node_Registry_Key> tree_registry_key = new TreeMap<String, Node_Registry_Key>();
	
	public volatile String last_updated = null;
	
	/**Registry: \Device\HarddiskVolume1\Documents and Settings\Administrator\NTUSER.DAT*/
	public Node_Registry_Hive(String REGISTRY)
	{
		try
		{
			registry = REGISTRY;
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1");
		}
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
