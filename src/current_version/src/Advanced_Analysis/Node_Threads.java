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
	
	public volatile String lower = null;
	public volatile boolean XREF_SEARCH_HIT_FOUND = false;
	
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
			
			XREF_SEARCH_HIT_FOUND |= this.check_value(ethread_address, "ethread_address", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(pid, "pid", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(TID, "TID", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(tags, "tags", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(created, "created", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(exited, "exited", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(owning_process_name, "owning_process_name", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(attached_process_name, "attached_process_name", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(state, "state", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(base_priority, "base_priority", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(priority, "priority", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(TEB, "TEB", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(start_address, "start_address", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(service_table_address, "service_table_address", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(service_table_0, "service_table_0", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(service_table_1, "service_table_1", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(service_table_2, "service_table_2", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(service_table_3, "service_table_3", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(win32thread, "win32thread", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(crossThreadFlags, "crossThreadFlags", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(eax, "eax", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(ebx, "ebx", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(ecx, "ecx", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(edx, "edx", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(esi, "esi", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(edi, "edi", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(eip, "eip", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(esp, "esp", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(ebp, "ebp", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(err, "err", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(cs, "cs", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(ss, "ss", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(ds, "ds", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(es, "es", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(gs, "gs", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(fs, "fs", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(efl, "efl", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(dr0, "dr0", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(dr1, "dr1", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(dr2, "dr2", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(dr3, "dr3", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(dr4, "dr4", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(dr5, "dr5", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(dr6, "dr6", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);
			XREF_SEARCH_HIT_FOUND |= this.check_value(dr7, "dr7", search_chars_from_user, search_chars_from_user_lower, jta, searching_proces, container_search_name);

			
			
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
	
	
	
	/**
	 * continuation mtd
	 * @param pw
	 * @param key
	 * @param value
	 * @return
	 */
	public boolean write_manifest(PrintWriter pw, String header, String delimiter, boolean include_underline)
	{
		try
		{
			if(pw == null)
				return false;	
			
			delimiter = delimiter + " ";
			
			driver.write_manifest_entry(pw, header, "ethread_address", ethread_address); 
			driver.write_manifest_entry(pw, header, "PID", pid);
			driver.write_manifest_entry(pw, header, "TID", TID);
			driver.write_manifest_entry(pw, header, "tags", tags);
			driver.write_manifest_entry(pw, header, "created", created);
			driver.write_manifest_entry(pw, header, "exited", exited);
			driver.write_manifest_entry(pw, header, "owning_process_name", owning_process_name);
			driver.write_manifest_entry(pw, header, "attached_process_name", attached_process_name);
			driver.write_manifest_entry(pw, header, "state", state);
			driver.write_manifest_entry(pw, header, "base_priority", base_priority);
			driver.write_manifest_entry(pw, header, "priority", priority);
			driver.write_manifest_entry(pw, header, "TEB", TEB);
			driver.write_manifest_entry(pw, header, "start_address", start_address);
			driver.write_manifest_entry(pw, header, "service_table_address", service_table_address);
			driver.write_manifest_entry(pw, header, "service_table_0", service_table_0);
			driver.write_manifest_entry(pw, header, "service_table_1", service_table_1);
			driver.write_manifest_entry(pw, header, "service_table_2", service_table_2);
			driver.write_manifest_entry(pw, header, "service_table_3", service_table_3);
			driver.write_manifest_entry(pw, header, "win32thread", win32thread);
			driver.write_manifest_entry(pw, header, "crossThreadFlags", crossThreadFlags);
			driver.write_manifest_entry(pw, header, "eax", eax);
			driver.write_manifest_entry(pw, header, "ebx", ebx);
			driver.write_manifest_entry(pw, header, "ecx", ecx);
			driver.write_manifest_entry(pw, header, "edx", edx);
			driver.write_manifest_entry(pw, header, "esi", esi);
			driver.write_manifest_entry(pw, header, "edi", edi);
			driver.write_manifest_entry(pw, header, "eip", eip);
			driver.write_manifest_entry(pw, header, "esp", esp);
			driver.write_manifest_entry(pw, header, "ebp", ebp);
			driver.write_manifest_entry(pw, header, "err", err);
			driver.write_manifest_entry(pw, header, "cs", cs);
			driver.write_manifest_entry(pw, header, "ss", ss);
			driver.write_manifest_entry(pw, header, "ds", ds);
			driver.write_manifest_entry(pw, header, "es", es);
			driver.write_manifest_entry(pw, header, "gs", gs);
			driver.write_manifest_entry(pw, header, "fs", fs);
			driver.write_manifest_entry(pw, header, "efl", efl);
			driver.write_manifest_entry(pw, header, "dr0", dr0);
			driver.write_manifest_entry(pw, header, "dr1", dr1);
			driver.write_manifest_entry(pw, header, "dr2", dr2);
			driver.write_manifest_entry(pw, header, "dr3", dr3);
			driver.write_manifest_entry(pw, header, "dr4", dr4);
			driver.write_manifest_entry(pw, header, "dr5", dr5);
			driver.write_manifest_entry(pw, header, "dr6", dr6);
			driver.write_manifest_entry(pw, header, "dr7", dr7);											
			
			
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
