package bayes;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Http.Request;
import org.jnetpcap.protocol.tcpip.Tcp;


public class PacketCaptureEngine implements Runnable{

	/**
	 * Main startup method
	 * 
	 * @param args
	 *            ignored
	 */
	public void run() {
		boolean first=true;
		
		
		while (!DriverEngine.terminate) {		
		List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs
		StringBuilder errbuf = new StringBuilder(); // For any error msgs

		/***************************************************************************
		 * First get a list of devices on this system
		 **************************************************************************/
		int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
			System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
			return;
		}
if(first)
		System.out.println("Network devices found:");

		int i = 0;
		for (PcapIf device : alldevs) {
			if(first) {
			String description = (device.getDescription() != null) ? device.getDescription()
					: "No description available";
			System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);
			}}

		PcapIf device = alldevs.get(4); // We know we have atleast 1 device
		if(first) 
			System.out.printf("\nChoosing '%s' on your behalf:\n",
				(device.getDescription() != null) ? device.getDescription() : device.getName());

		/***************************************************************************
		 * Second we open up the selected device
		 **************************************************************************/
		int snaplen = 64 * 1024; // Capture all packets, no trucation
		int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
		int timeout = 4* 1000; // 10 seconds in millis
		Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

		if (pcap == null) {
			System.err.printf("Error while opening device for capture: " + errbuf.toString());
			return;
		}

		/***************************************************************************
		 * Third we create a packet handler which will receive packets from the libpcap
		 * loop.
		 **************************************************************************/
		

		PcapPacketHandler<String> handler = new PcapPacketHandler<String>() {
			// Protocol handlers
			private final Tcp tcp = new Tcp();
			private final Http http = new Http();

			@Override
			public void nextPacket(PcapPacket packet, String userString) {
				if (!packet.hasHeader(tcp)) {
					return; // not a TCP package, skip
				}
				if (!packet.hasHeader(http)) {
					return; // not a HTTP package, skip
				}
				if (http.isResponse()) {
					return; // not a HTTP request, skip
				}

				 if (http.fieldValue(Request.Referer) != null) {
					try {
						while(new DriverEngine().isUnderTesting(http.fieldValue(Request.Referer)));
						
						float p=new DriverEngine().HaveTested(http.fieldValue(Request.Referer));
						if(p>=0)	
						{	BayesClassifer.recentSites.removeIf(obj -> obj.url.equalsIgnoreCase(http.fieldValue(Request.Referer)));
							BayesClassifer.recentSites.add(new Site(http.fieldValue(Request.Referer), new Date(), p));
					    
						if ( p>0.9)
									System.out.println("Site : "+http.fieldValue(Request.Referer)+" is harmful according to earlier calculation");
							else
									System.out.println("Site : "+http.fieldValue(Request.Referer)+" is not harmful according to earlier calculation");
						} 
						else	
						{	
							BayesClassifer.sitesundertest.add(new Site(http.fieldValue(Request.Referer), new Date(), 0));
							new DriverEngine().driver(http.fieldValue(Request.Referer));
						}
				 	} catch (Exception ex) {
						ex.printStackTrace();
					}
				}
			}
		};

		/***************************************************************************
		 * Fourth we enter the loop and tell it to capture 10 packets. The loop method
		 * does a mapping of pcap.datalink() DLT value to JProtocol ID, which is needed
		 * by JScanner. The scanner scans the packet buffer and decodes the headers. The
		 * mapping is done automatically, although a variation on the loop method exists
		 * that allows the programmer to sepecify exactly which protocol ID to use as
		 * the data link type for this pcap interface.
		 **************************************************************************/
		
		first=false;
			// pcap.loop(10, jpacketHandler, "");
			int ret=pcap.loop(10000000, handler, "");
			System.out.println("Return code is "+ret);
			
		 /***************************************************************************
			 * Last thing to do is close the pcap handle
			 **************************************************************************/
		pcap.close();
		}
	}
	
	
	
}
