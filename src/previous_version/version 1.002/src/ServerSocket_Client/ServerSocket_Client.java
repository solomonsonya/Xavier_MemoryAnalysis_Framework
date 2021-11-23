/**
 * This ServerSocket is established to listen for new Socket Connections for clients
 * seeking to determine whois connection information
 * 
 * Thus, RSL (Rough Socket Listener), Themis (Network Sensor and Analyzer), Munin (Memory Analyzer), etc can establish a connection to 
 * Wreaper to derive the Whois, Geo Locaion, and Nslookup data for each request
 *  
 * 
 * @author Solomon Sonya
 */

package ServerSocket_Client;

import java.io.*;
import java.util.*;

import Driver.Driver;

import java.net.*;

public class ServerSocket_Client extends Thread implements Runnable
{
	public static final String myClassName = "ServerSocket_Client";
	public volatile static Driver driver = new Driver();

	public static volatile LinkedList<ServerSocket_Client> list_server_sockets = new LinkedList<ServerSocket_Client>();
	
	public static final int DEFAULT_CLIENT_PORT = 9996;
	
	public static final int DEFAULT_PORT = DEFAULT_CLIENT_PORT;
	
	public volatile int PORT = DEFAULT_PORT;
	
	public volatile ServerSocket svrskt = null;
	
	public static volatile boolean continue_run = true;
	
	public volatile String myBoundInterface = "";
	
	public volatile LinkedList<ThdClientSocket> list_connections = new LinkedList<ThdClientSocket>();
	
	public ServerSocket_Client(int preferred_port)
	{
		try
		{
			PORT = preferred_port;
			this.start();
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
	}
	
	public void run()
	{
		try
		{
			//start serversocket
			driver.directive("Attempting to establish sensor server socket on port [" + PORT + "]");
			
			try
			{
				svrskt = new ServerSocket(PORT);
			}
			catch(Exception e)
			{
				driver.sop("ERROR! I WAS UNABLE TO BIND SENSOR SERVER SOCKET TO PORT: " + PORT + ".  It is appears this port is already bound by a separate process!  I am attempting to bind to a free port...");
				svrskt = new ServerSocket(0);
				PORT = svrskt.getLocalPort();
			}
			
			myBoundInterface = svrskt.getInetAddress().getHostAddress() + ":" + PORT;
			
			driver.directive("SUCCESS! " + myClassName + " is bound to " + svrskt.getInetAddress().getHostAddress() + ":" + PORT + ".  Ready for new connections across port " + PORT);
			
			//add self to list
			list_server_sockets.add(this);
			
			//
			//LISTEN FOR NEW CONNECTIONS
			//
			while(continue_run)
			{
				Socket skt = svrskt.accept();
				
				ThdClientSocket thd = new ThdClientSocket(this, skt);
			}
			
			driver.directive("\nPUNT PUNT! SENSOR ServerSocket is closed for " + myBoundInterface);
		}
		catch(Exception e)
		{
			
		}
	}
	
	
	public String get_status()
	{
		try
		{
			try
			{	return "" + svrskt.getInetAddress().getHostAddress() + ":" + PORT + " \tNum Connections: [" + this.list_connections.size() + "]";	}
			catch(Exception ee)
			{	return myBoundInterface;	}
					
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_status", e);			
		}
		
		return "SENSOR ServerSocket - " + PORT;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
