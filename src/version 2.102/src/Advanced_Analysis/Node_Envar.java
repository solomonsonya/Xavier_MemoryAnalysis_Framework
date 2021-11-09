/**
 * Environment Variables Node
 * @author Solomon Sonya
 */

package Advanced_Analysis;

import Advanced_Analysis.*;
import Driver.*;
import Interface.*;
import Plugin.*;
import Worker.*;
import java.awt.event.*;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.LinkedList;
import java.util.TreeMap;
import org.apache.commons.io.LineIterator;



public class Node_Envar 
{
	public static final String myClassName = "Node_Envars";
	public static volatile Driver driver = new Driver();
	
	public volatile Node_Process process = null;
	
	public volatile String block = null;
	/**e.g. COMPUTERNAME*/
	public volatile String variable = null;
	/**e.g. Solomon_Sonya_PC-3743686C6*/
	public volatile String value = null;
	
	
	
	public Node_Envar(Node_Process proc)
	{
		try
		{
			process = proc;
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
