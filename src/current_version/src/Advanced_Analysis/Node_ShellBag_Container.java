/**
 * Shellbags contains may different type of information, however, so far, I found there are only 4 main categories of information placed in the output files:
 * 	TYPE_1 --> Value                     File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Unicode Name
	TYPE_2 --> Value   Mru   Entry Type     GUID                                     GUID Description     Folder IDs
	TYPE_3 --> Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path
	TYPE_4 --> Value   Mru   Entry Type     Path
 * 
 * The purpose of this class is to be a container for one of the above categories of data - and to be able to ruther parse data within each type to provide the output in a collapsed uniform manner
 * 
 * @author Solomon Sonya
 */

package Advanced_Analysis;

import java.awt.event.ActionListener;
import java.io.*;
import java.util.LinkedList;
import java.util.TreeMap;

import Advanced_Analysis.Analysis_Plugin.Analysis_Plugin_EXECUTION;
import Advanced_Analysis.Analysis_Plugin._Analysis_Plugin_Super_Class;
import Driver.Driver;
import Driver.FileAttributeData;
import Interface.JTextArea_Solomon;

public class Node_ShellBag_Container 
{
	public static final String myClassName = "Node_ShellBag_Container";
	public static volatile Driver driver = new Driver(); 
	
	/**Value                     File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Unicode Name*/
	public static final int TYPE_1 = 1;
	
	/**Value   Mru   Entry Type     GUID                                     GUID Description     Folder IDs*/
	public static final int TYPE_2 = 2;
	
	/**Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path*/
	public static final int TYPE_3 = 3;
	
	/**Value   Mru   Entry Type     Path*/
	public static final int TYPE_4 = 4;
	
	
	public volatile int my_type = 0;
	public volatile Advanced_Analysis_Director director = null;
	public volatile Analysis_Plugin_EXECUTION parent = null;
	
	public volatile TreeMap<String, Node_Generic> tree_shellbag_entries = new TreeMap<String, Node_Generic>();
	
	public Node_ShellBag_Container(int TYPE, Analysis_Plugin_EXECUTION par, Advanced_Analysis_Director DIRECTOR)
	{
		try
		{
			my_type = TYPE;
			director = DIRECTOR;
			parent = par;
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
		
	}
	
	
	
	public String get_manifest_header(String delimiter)
	{
		try
		{
			switch(this.my_type)
			{
				case TYPE_1: return "modified_date" + delimiter + "create_date" + delimiter + "access_date" + delimiter + "last_updated" + delimiter + "file_name" + delimiter + "unicode_name" + delimiter + "file_attr" + delimiter + "value" + delimiter + "registry_name" + delimiter + "key_name" + delimiter + "shellbag_type" + delimiter + "additional_details";
				case TYPE_2: return "last_updated" + delimiter + "guid_description" + delimiter + "guid" + delimiter + "folder_ids" + delimiter + "entry_type" + delimiter + "value" + delimiter + "mru" + delimiter +  "registry_name" + delimiter + "key_name" + delimiter  + "shellbag_type" + delimiter + "additional_details";
				case TYPE_3: return "modified_date" + delimiter + "create_date" + delimiter + "access_date" + delimiter + "last_updated" + delimiter + "path" + delimiter + "file_name" + delimiter + "file_attr" + delimiter + "value" + delimiter + "mru" + delimiter + "registry_name" + delimiter + "key_name" + delimiter  + "shellbag_type" + delimiter +  "additional_details";
				case TYPE_4: return "last_updated" + delimiter + "path" + delimiter + "entry_type" + delimiter + "value" + delimiter + "mru" + delimiter + "registry_name" + delimiter + "key_name" + delimiter  + "shellbag_type" + delimiter +  "additional_details";									
			}
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_manifest_header", e);
		}
		
		return "####";
	}
	
	
	
	public String get_timeliner_header(String delimiter)
	{
		try
		{
			switch(this.my_type)
			{
				case TYPE_1: return "time" + delimiter + "shellbags" + delimiter + "key" + delimiter + "value" + delimiter + "shellbag_type" + delimiter + "file_name" + delimiter + "file_attr" + delimiter + "create date" + delimiter + "modified_date" + delimiter + "access_date" + delimiter + "last_updated" + delimiter + "shellbag_value" + delimiter + "registry" + delimiter + "registry_key" + delimiter + "additional_details";
				case TYPE_2: return "time" + delimiter + "shellbags" + delimiter + "key" + delimiter + "value" + delimiter + "shellbag_type" + delimiter + "folder_ids" + delimiter + "entry_type" + delimiter + "guid" + delimiter + "shellbag_value" + delimiter + "mru" + delimiter + "registry" + delimiter + "registry_key" + delimiter + "additional_details";
				case TYPE_3: return "time" + delimiter + "shellbags" + delimiter + "key" + delimiter + "value" + delimiter + "shellbag_type" + delimiter + "file_name" + delimiter + "file_attr" + delimiter + "create date" + delimiter + "modified_date" + delimiter + "access_date" + delimiter + "last_updated" + delimiter + "shellbag_value" + delimiter + "mru" + delimiter + "registry" + delimiter + "registry_key" + delimiter + "additional_details";
				case TYPE_4: return "time" + delimiter + "shellbags" + delimiter + "key" + delimiter + "value" + delimiter + "shellbag_type" + delimiter + "entry_type" + delimiter + "shellbag_value"+ delimiter + "mru" + delimiter + "registry" + delimiter + "registry_key" + delimiter + "additional_details";
			}
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_manifest_header", e);
		}
		
		return "####";
	}
	
	
	
	
	
	
	
	
	
	
}

