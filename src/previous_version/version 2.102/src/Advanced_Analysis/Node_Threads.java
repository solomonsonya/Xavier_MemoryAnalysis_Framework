/**
 * @author Solomon Sonya
 */

package Advanced_Analysis;

import Driver.*;
import Interface.*;

import java.io.*;
import java.util.*;
import Advanced_Analysis.Analysis_Plugin.*;

public class Node_Threads 
{
	public static volatile Driver driver = new Driver();
	public static final String myClassName = "Node_Threads";
	
public volatile Node_Process process = null;
	
	public volatile String ethread_address = null;
	public volatile String pid = null;
	public volatile String TID = null;
	public volatile String tags = null;
	public volatile String created = null;
	public volatile String exited = null;
	public volatile String owning_process_name = null;
	public volatile String attached_process_name = null;
	public volatile String state = null;
	public volatile String base_priority = null;
	public volatile String priority = null;
	public volatile String TEB = null;
	public volatile String start_address = null;
	public volatile String service_table_address = null;
	public volatile String service_table_0 = null;
	public volatile String service_table_1 = null;
	public volatile String service_table_2 = null;
	public volatile String service_table_3 = null;
	public volatile String win32thread = null;
	public volatile String crossThreadFlags = null;
	public volatile String eax = null;
	public volatile String ebx = null;
	public volatile String ecx = null;
	public volatile String edx = null;
	public volatile String esi = null;
	public volatile String edi = null;
	public volatile String eip = null;
	public volatile String esp = null;
	public volatile String ebp = null;
	public volatile String err = null;
	public volatile String cs = null;
	public volatile String ss = null;
	public volatile String ds = null;
	public volatile String es = null;
	public volatile String gs = null;
	public volatile String fs = null;
	public volatile String efl = null;
	public volatile String dr0 = null;
	public volatile String dr1 = null;
	public volatile String dr2 = null;
	public volatile String dr3 = null;
	public volatile String dr4 = null;
	public volatile String dr5 = null;
	public volatile String dr6 = null;
	public volatile String dr7 = null;
	
	
	public Node_Threads(String ETHREAD, String Pid, String Tid, Node_Process PROCESS, String line)
	{
		try
		{
			if(ETHREAD != null)
				ethread_address = ETHREAD.trim();
			
			if(Pid != null)
				pid = Pid.trim();
			
			if(Tid != null)
				TID = Tid.trim();
			
			process = PROCESS;
			
			if(ethread_address != null && !ethread_address.equals("") && process != null && process.tree_threads == null)
				process.tree_threads = new TreeMap<String, Node_Threads>();
				
			if(ethread_address != null && !ethread_address.equals("") && process != null)
				process.tree_threads.put(ethread_address, this);
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1 on line[" + line + "]", e);			
		}
	}
	
	
	
	public boolean write_node_information(PrintWriter pw)
	{
		try
		{
			pw.println("\t\t" +  "{ \"name\": \"" + driver.normalize_html("TID: " + this.TID).replace("\\", "\\\\") + "\" , \"children\": [");

			if(this.process != null)
				driver.write_node_ENTRY("PID: ", ""+this.process.PID, pw);
			else
				driver.write_node_ENTRY("PID: ", this.pid, pw);
			
			
			driver.write_node_ENTRY("TID: ", this.TID, pw);
			driver.write_node_ENTRY("Created: ", this.created, pw);
			driver.write_node_ENTRY("Exited: ", this.exited, pw);
			driver.write_node_ENTRY("Owning Process: ", this.owning_process_name, pw);
			driver.write_node_ENTRY("Attached Process: ", this.attached_process_name, pw);
			driver.write_node_ENTRY("State: ", this.state, pw);
			driver.write_node_ENTRY("Base Priority: ", this.base_priority, pw);
			driver.write_node_ENTRY("Priority: ", this.priority, pw);
			driver.write_node_ENTRY("TEB: ", this.TEB, pw);
			driver.write_node_ENTRY("Ethread Address: ", this.ethread_address, pw);
			driver.write_node_ENTRY("Start Address: ", this.start_address, pw);
			driver.write_node_ENTRY("Win32Thread: ", this.win32thread, pw);
			
			if(this.service_table_address != null)
			{
				pw.println("\t\t\t" +  "{ \"name\": \"" + driver.normalize_html("Service Table: " + this.service_table_address).replace("\\", "\\\\") + "\" , \"children\": [");
				
				if(this.service_table_0 != null)
					driver.write_node_ENTRY("", this.service_table_0, pw);
				if(this.service_table_1 != null)
					driver.write_node_ENTRY("", this.service_table_1, pw);
				if(this.service_table_2 != null)
					driver.write_node_ENTRY("", this.service_table_2, pw);
				if(this.service_table_3 != null)
					driver.write_node_ENTRY("", this.service_table_3, pw);
				
				pw.println("\t\t\t" +  "]},");//end process information
			}
			
			
			
			if(eax != null || eip != null || cs != null || fs != null || dr0 != null)
			{
				pw.println("\t\t\t" +  "{ \"name\": \"" + driver.normalize_html("Cross Thread Flags / Registers").replace("\\", "\\\\") + "\" , \"children\": [");
				
				driver.write_node_ENTRY("eax: ", this.eax, pw);
				driver.write_node_ENTRY("ebx: ", this.ebx, pw);
				driver.write_node_ENTRY("ecx: ", this.ecx, pw);
				driver.write_node_ENTRY("edx: ", this.edx, pw);
				driver.write_node_ENTRY("esi: ", this.esi, pw);
				driver.write_node_ENTRY("edi: ", this.edi, pw);
				driver.write_node_ENTRY("eip: ", this.eip, pw);
				driver.write_node_ENTRY("esp: ", this.esp, pw);
				driver.write_node_ENTRY("ebp: ", this.ebp, pw);
				driver.write_node_ENTRY("err: ", this.err, pw);				
				driver.write_node_ENTRY("efl: ", this.efl, pw);
				driver.write_node_ENTRY("dr0: ", this.dr0, pw);
				driver.write_node_ENTRY("dr1: ", this.dr1, pw);
				driver.write_node_ENTRY("dr2: ", this.dr2, pw);
				driver.write_node_ENTRY("dr3: ", this.dr3, pw);
				driver.write_node_ENTRY("dr4: ", this.dr4, pw);
				driver.write_node_ENTRY("dr5: ", this.dr5, pw);
				driver.write_node_ENTRY("dr6: ", this.dr6, pw);
				driver.write_node_ENTRY("dr7: ", this.dr7, pw);
				driver.write_node_ENTRY("cs: ", this.cs, pw);
				driver.write_node_ENTRY("ss: ", this.ss, pw);
				driver.write_node_ENTRY("ds: ", this.ds, pw);
				driver.write_node_ENTRY("es: ", this.es, pw);
				driver.write_node_ENTRY("gs: ", this.gs, pw);
				driver.write_node_ENTRY("fs: ", this.fs, pw);				
				
				
				pw.println("\t\t\t" +  "]},");//end process information
			}
			
			
			
			pw.println("\t\t" +  "]},");//end process information			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_node_information", e);
		}
		
		return false;
	}
	
	public boolean write_table_THREADS_information(PrintWriter pw)
	{
		try
		{
			this.write_table_cell_entry(pw, ethread_address);
			this.write_table_cell_entry(pw, TID);
			this.write_table_cell_entry(pw, tags);
			this.write_table_cell_entry(pw, created);
			this.write_table_cell_entry(pw, exited);
			this.write_table_cell_entry(pw, owning_process_name);
			this.write_table_cell_entry(pw, attached_process_name);
			this.write_table_cell_entry(pw, state);
			this.write_table_cell_entry(pw, base_priority);
			this.write_table_cell_entry(pw, priority);
			this.write_table_cell_entry(pw, TEB);
			this.write_table_cell_entry(pw, start_address);
			this.write_table_cell_entry(pw, service_table_address);
			this.write_table_cell_entry(pw, service_table_0);
			this.write_table_cell_entry(pw, service_table_1);
			this.write_table_cell_entry(pw, service_table_2);
			this.write_table_cell_entry(pw, service_table_3);
			this.write_table_cell_entry(pw, win32thread);
			this.write_table_cell_entry(pw, crossThreadFlags);
			this.write_table_cell_entry(pw, eax);
			this.write_table_cell_entry(pw, ebx);
			this.write_table_cell_entry(pw, ecx);
			this.write_table_cell_entry(pw, edx);
			this.write_table_cell_entry(pw, esi);
			this.write_table_cell_entry(pw, edi);
			this.write_table_cell_entry(pw, eip);
			this.write_table_cell_entry(pw, esp);
			this.write_table_cell_entry(pw, ebp);
			this.write_table_cell_entry(pw, err);
			this.write_table_cell_entry(pw, cs);
			this.write_table_cell_entry(pw, ss);
			this.write_table_cell_entry(pw, ds);
			this.write_table_cell_entry(pw, es);
			this.write_table_cell_entry(pw, gs);
			this.write_table_cell_entry(pw, fs);
			this.write_table_cell_entry(pw, efl);
			this.write_table_cell_entry(pw, dr0);
			this.write_table_cell_entry(pw, dr1);
			this.write_table_cell_entry(pw, dr2);
			this.write_table_cell_entry(pw, dr3);
			this.write_table_cell_entry(pw, dr4);
			this.write_table_cell_entry(pw, dr5);
			this.write_table_cell_entry(pw, dr6);
			this.write_table_cell_entry(pw, dr7);
															
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_table_THREADS_information", e);
		}
				
		return false;
	}
	
	
	
	public boolean write_table_cell_entry(PrintWriter pw, String value)
	{
		try
		{
			pw.print(" <td> " + driver.normalize_html(value).replace("\\", "&#92") + "</td>");
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_table_cell_entry", e);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
