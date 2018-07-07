/**
 * The purpose of this class
 * 
 * @author Solomon Sonya
 */

package Interface;

import java.io.*;
import java.awt.*;
import java.awt.event.*;
import java.net.*;
import java.security.*;
import java.util.*;
import javax.imageio.ImageIO;
import javax.swing.*;
import javax.swing.Timer;
import javax.swing.border.BevelBorder;
import javax.swing.border.TitledBorder;
import Driver.*;
//import Sound.ThreadSound;
import java.util.*;

public class JPanelNetworkInterface_Solomon extends JPanel implements ActionListener
{
	public static volatile Driver driver = new Driver();
	public static final String myClassName = "JPanelNetworkInterface_Solomon";
	public volatile Timer tmr = null;

	public volatile boolean handle_interrupt = true;
	
	public static volatile TreeMap<String, InterfaceAddress> tree_interfaces = new TreeMap<String, InterfaceAddress>();
	public static volatile LinkedList<String> list_ip_addresses = new LinkedList<String>();
	public static volatile LinkedList<InetAddress> list_interfaces = new LinkedList<InetAddress>();
	public static volatile String ip_address = "";
	
	public static volatile boolean only_store_ip_v4 = true;
	public static volatile boolean do_not_store_loopback = true;
	
	public static volatile TreeMap<String, NetworkInterface_Solomon> tree_network_interface = new TreeMap<String, NetworkInterface_Solomon>();
	
	public JPanel jpnlInterfaces = new JPanel();
	public JLabel jlblInterfaces = new JLabel("  Network Interfaces:  ");
	public JLabel[] arrJLabels = null;
	
	public static Font fntTahoma = new Font("Helvetica", Font.PLAIN, 16);
	
	
	
	public JPanelNetworkInterface_Solomon()
	{
		try
		{
			this.setLayout(new BorderLayout());
			this.add(BorderLayout.WEST, jlblInterfaces);
			this.add(BorderLayout.CENTER, jpnlInterfaces);			
			jlblInterfaces.setFont(fntTahoma);
			
			update_network_interface_configuration();
			
			tmr = new Timer(1000*60*10, this);
			tmr.start();
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
	}
	
	
	
	
	
	
	
	
	public void actionPerformed(ActionEvent ae)
	{
		try
		{
			if(ae.getSource() == tmr)
			{
				process_interrupt();
			}
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "ae", e);
		}
	}
	
	
	
	
	
	public boolean process_interrupt()
	{
		try
		{
			if(!handle_interrupt)
				return true;
			
			handle_interrupt = false;
			
			
			update_network_interface_configuration();
			
			
			handle_interrupt = true;
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "ae", e);
		}
		
		
		handle_interrupt = true;
		return false;
	}
	
	
	
	public boolean update_network_interface_configuration()
	{
		try
		{					
			 Enumeration<NetworkInterface> enum_interface = NetworkInterface.getNetworkInterfaces();
		     
			 try	{	tree_interfaces.clear();	}	catch(Exception e){tree_interfaces = new TreeMap<String, InterfaceAddress>();}
			 try	{	list_ip_addresses.clear();	}	catch(Exception e){list_ip_addresses = new LinkedList<String>();}
			 try	{	list_interfaces.clear();	}	catch(Exception e){list_interfaces = new LinkedList<InetAddress>();}
			 
		     NetworkInterface iface = null;
		     InetAddress inet = null;
		     ip_address = "";
		     driver.myIPAddress = "";
		     
		     while(enum_interface.hasMoreElements())
		     {
		    	 iface = enum_interface.nextElement();
		    	 
		    	 if(iface == null)
		    		 continue;
		    	 
		    	 if(!iface.isUp())
		    		 continue;
		    	
		    	 Enumeration<InetAddress> interface_addresses = iface.getInetAddresses();
		    	 
		    	 while(interface_addresses.hasMoreElements())
		    	 {
		    		 try
		    		 {
		    			 inet = interface_addresses.nextElement();
		    			 
		    			 if(inet == null)
		    				 continue;
		    			 
		    			 		    			 
		    			 if(only_store_ip_v4 && inet.toString().contains(":"))
		    				 continue;
		    				 
		    			//store myIPAddress
		    			 if(!inet.toString().trim().startsWith("/127") && driver.myIPAddress.equals(""))
		    				 driver.myIPAddress = inet.toString();
		    			 
		    			 if(do_not_store_loopback && inet.toString().contains("127.0.0"))
		    				 continue;
		    			 
		    			 list_interfaces.addFirst(inet);
		    			 list_ip_addresses.add("  [ "+iface.getDisplayName() + " ]  " + inet + "      ");
		    		 }
		    		 
		    		 catch(Exception e)
		    		 {
		    			 continue;
		    		 }
		    		 
		    	 }
		    	 
		    	 //special thanks - https://stackoverflow.com/questions/494465/how-to-enumerate-ip-addresses-of-all-enabled-nic-cards-from-java
		    	 
		    	  /* Enumeration<NetworkInterface> theIntfList = NetworkInterface.getNetworkInterfaces();
		    	     List<InterfaceAddress> theAddrList = null;
		    	     NetworkInterface theIntf = null;
		    	     InetAddress theAddr = null;

		    	     while(theIntfList.hasMoreElements())
		    	     {
		    	        theIntf = theIntfList.nextElement();

		    	        System.out.println("--------------------");
		    	        System.out.println(" " + theIntf.getDisplayName());
		    	        System.out.println("          name: " + theIntf.getName());
		    	        System.out.println("           mac: " + toMACAddrString(theIntf.getHardwareAddress()));
		    	        System.out.println("           mtu: " + theIntf.getMTU());
		    	        System.out.println("        mcast?: " + theIntf.supportsMulticast());
		    	        System.out.println("     loopback?: " + theIntf.isLoopback());
		    	        System.out.println("          ptp?: " + theIntf.isPointToPoint());
		    	        System.out.println("      virtual?: " + theIntf.isVirtual());
		    	        System.out.println("           up?: " + theIntf.isUp());

		    	        theAddrList = theIntf.getInterfaceAddresses();
		    	        System.out.println("     int addrs: " + theAddrList.size() + " total.");
		    	        int addrindex = 0;
		    	        for(InterfaceAddress intAddr : theAddrList)
		    	        {
		    	           addrindex++;
		    	           theAddr = intAddr.getAddress();
		    	           System.out.println("            " + addrindex + ").");
		    	           System.out.println("            host: " + theAddr.getHostName());
		    	           System.out.println("           class: " + theAddr.getClass().getSimpleName());
		    	           System.out.println("              ip: " + theAddr.getHostAddress() + "/" + intAddr.getNetworkPrefixLength());
		    	           System.out.println("           bcast: " + intAddr.getBroadcast().getHostAddress());
		    	           int maskInt = Integer.MIN_VALUE >> (intAddr.getNetworkPrefixLength()-1);
		    	           System.out.println("            mask: " + toIPAddrString(maskInt));
		    	           System.out.println("           chost: " + theAddr.getCanonicalHostName());
		    	           System.out.println("        byteaddr: " + toMACAddrString(theAddr.getAddress()));
		    	           System.out.println("      sitelocal?: " + theAddr.isSiteLocalAddress());
		    	           System.out.println("");
		    	        }*/
		     }
		     
		     
		     if(list_ip_addresses == null || list_ip_addresses.isEmpty())
		    	 return false;		    		    
		     
		     try	{	this.jpnlInterfaces.removeAll();}	catch(Exception e){driver.directive("network interface enumeration...");}
		     arrJLabels = null;
		     
		     arrJLabels = new JLabel[list_ip_addresses.size()];
		     
		     for(int i = 0; i < this.list_ip_addresses.size(); i++)
		     {
		    	 ip_address = list_ip_addresses.get(i);
		    	 
		    	 if(ip_address == null)
		    		 continue;
		    	 
		    	 arrJLabels[i] = new JLabel(ip_address, JLabel.CENTER);
		    	 arrJLabels[i].setToolTipText(ip_address);
		    	 
		    	 
		    	 
		    	 arrJLabels[i].setFont(fntTahoma);
		    	 arrJLabels[i].setForeground(Color.blue.darker());
		     }
		     
		     jpnlInterfaces.setLayout(new GridLayout(1,list_ip_addresses.size(), 2,2));
		     
		     for(JLabel jlbl : arrJLabels)
		     {
		    	 try
		    	 {
		    		 if(jlbl == null)
		    			 continue;
		    		 
		    		 jpnlInterfaces.add(jlbl);
		    	 }
		    	 catch(Exception e){}
		     }
			
		     
		     this.validate();
		    System.gc();
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "update_network_interface_configuration", e);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	

}
