package org.pcap4j.sample;

import java.io.IOException;
import java.net.Inet4Address;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;

public class PcapDemo {
	
	
	private PcapDemo() {}
	
	  public static void main(String[] args) throws PcapNativeException, NotOpenException {
		   		    
	try {
		PcapNetworkInterface nif;
	    try {
	      nif = Pcaps.findAllDevs().get(1);
	    } catch (Exception e) {
	      e.printStackTrace();
	      return;
	    }
	int snapLen = 65536;
	PromiscuousMode mode = PromiscuousMode.PROMISCUOUS;
	int timeout = 1000;
	PcapHandle handle = nif.openLive(snapLen, mode, timeout);
	int n=0;
	while(n<10000) {
	Packet packet = handle.getNextPacketEx();
	
	IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
	//Inet4Address srcAddr = ipV4Packet.getHeader().getSrcAddr();
	//System.out.println(srcAddr);
	
	if(packet.get(IpV6Packet.class)!=null)
   	 System.out.println("BLESS"+packet.get(IpV6Packet.class).getHeader().getDstAddr().getHostName().toString().substring(1));
   if(packet.get(IpV4Packet.class)!=null)
   	 System.out.println("BLESS"+packet.get(IpV4Packet.class).getHeader().getDstAddr().getHostName().toString().substring(1));
	n++;
	}
	handle.close();
	}catch ( Exception e) {
	     
	    }}
}
