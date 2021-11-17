/**
 * @author Solomon Sonya
 */


package Interface;

import java.net.*;

import Driver.Driver;

public class NetworkInterface_Solomon 
{
	public static final String myClassName = "NetworkInterface_Solomon";
	public static volatile Driver driver = new Driver();
	
	public volatile NetworkInterface network_interface = null;

	public volatile String display_name = "";
	public volatile boolean is_loopback = false;
	
	public NetworkInterface_Solomon(NetworkInterface iface)
	{
		try
		{
			network_interface = iface;
			
			if(iface != null)
				init();
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
	}
	
	public boolean init()
	{
		try
		{
			if(network_interface == null)
				return false;
			
			display_name = network_interface.getDisplayName();
			
			//https://stackoverflow.com/questions/494465/how-to-enumerate-ip-addresses-of-all-enabled-nic-cards-from-java
			/*//
			System.out.println(" " + network_interface.getDisplayName());
	         System.out.println("          name: " + network_interface.getName());
	         //System.out.println("           mac: " + toMACAddrString(theIntf.getHardwareAddress()));
	         System.out.println("           mtu: " + network_interface.getMTU());
	         System.out.println("        mcast?: " + network_interface.supportsMulticast());
	         System.out.println("     loopback?: " + network_interface.isLoopback());
	         System.out.println("          ptp?: " + network_interface.isPointToPoint());
	         System.out.println("      virtual?: " + network_interface.isVirtual());
	         System.out.println("           up?: " + network_interface.isUp());
			
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
	            System.out.println("");*/
	         
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "init", e);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
