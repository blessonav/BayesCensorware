package jnetpcapDemo;

import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Http.Request;
import org.jnetpcap.protocol.tcpip.Tcp;



public class NetworkInterfaces {
	public static void main(String[] args) {
		List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs
		StringBuilder errbuf = new StringBuilder(); // For any error msgs
		int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
			System.err.printf("Can't read list of devices, error is %s",
					errbuf.toString());
			return;
		}
		System.out.println("Network devices found:");
		int i = 0;
		for (PcapIf device : alldevs) {
			String description = (device.getDescription() != null) ? device
					.getDescription() : "No description available";
			System.out.printf("#%d: %s [%s]\n", i++, device.getName(),
					description);
		}
		
		
		
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

		        System.out.println("Referer: " + http.fieldValue(Request.Referer));
		        System.out.println("Request URL: " + http.fieldValue(Request.RequestUrl));
		        System.out.println("Host: " + http.fieldValue(Request.Host));
		    }
		};
	}
}