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
	
	public volatile String lower = null;
	public volatile boolean XREF_SEARCH_HIT_FOUND = false;
	
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
	
	
	
	/**
	 * e.g. given an output like [1512] Winrar.exe Malfind [Detail] - 0x00df0020  fe 07 00 00 48 ff 20 90 41 ba 82 00 00 00 48 b8   ....H...A.....H.
	 * container_search_name == "Malfind", mneumonic == "Detail", search_string could == ff 20 90, output line would be 0x00df0020  fe 07 00 00 48 ff 20 90 41 ba 82 00 00 00 48 b8   ....H...A.....H.
	 * 
	 * @param search_chars_from_user
	 * @param search_chars_from_user_lower
	 * @param jta
	 * @param searching_proces
	 * @param container_search_name
	 * @return
	 */
	public boolean search_XREF(String search_chars_from_user, String search_chars_from_user_lower, JTextArea_Solomon jta, Node_Process searching_proces, String container_search_name)
	{
		try
		{  
			XREF_SEARCH_HIT_FOUND = false;
			
			XREF_SEARCH_HIT_FOUND |= this.check_value(block, "block", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(variable, "variable", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(value, "value", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
	
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "search_XREF", e);
		}
		
		lower = null;
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
	public boolean check_value(String value_to_check, String mneumonic, String search_string, String search_string_lower, JTextArea_Solomon jta, Node_Process searching_proces, String container_search_name)	
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
				searching_proces.append_to_jta_XREF(container_search_name + " [" + mneumonic + "]: " + value_to_check, jta);
				return true;
			}
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "check_value", e);
		}
		
		return false;
	}
	
	
	public boolean write_manifest_as_single_line(PrintWriter pw, String header, String delimiter)
	{
		try
		{
			if(pw == null)
				return false;	
			
			String output = "";
			
			output = output + driver.get_trimmed_entry("block", block, delimiter, false, true, ":");
			output = output + driver.get_trimmed_entry("variable", variable, delimiter, true, false, ":");	
			output = output + driver.get_trimmed_entry("value", value, delimiter, true, false, ":");

			//
			//write string!
			//
			driver.write_manifest_entry(pw, header, output);
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_manifest_as_single_line", e);
		}
		
		return false;
	}
	
	/**
	 * continuation mtd
	 * @param pw
	 * @param key
	 * @param value
	 * @return
	 */
	public boolean write_manifest(PrintWriter pw, String header, String delimiter, boolean include_underline, boolean print_output_as_single_line)
	{
		try
		{
			if(pw == null)
				return false;	
			
			delimiter = delimiter + " ";
			
			if(print_output_as_single_line)
				return write_manifest_as_single_line(pw, header, delimiter);
							 			
			driver.write_manifest_entry(pw, header, "block", block);
			driver.write_manifest_entry(pw, header, "variable", variable);
			driver.write_manifest_entry(pw, header, "value", value);
			

			if(include_underline)
				pw.println(Driver.END_OF_ENTRY_MINOR);

			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_manifest", e);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
}
