package org.pcap4j.sample;

import java.io.EOFException;
import java.util.concurrent.TimeoutException;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapHandle.TimestampPrecision;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;

@SuppressWarnings("javadoc")
public class ReadPacketFile {

  private static final int COUNT = 5;

  private static final String PCAP_FILE_KEY
    = ReadPacketFile.class.getName() + ".pcapFile";
  private static final String PCAP_FILE
    = System.getProperty(PCAP_FILE_KEY, "src/main/resources/echoAndEchoReply.pcap");

  private ReadPacketFile() {}

  public static void main(String[] args) throws PcapNativeException, NotOpenException {
    PcapHandle handle;
    
    
    try {
      handle = Pcaps.openOffline(PCAP_FILE, TimestampPrecision.NANO);
    } catch (PcapNativeException e) {
      handle = Pcaps.openOffline(PCAP_FILE);
    }

    for (int i = 0; i < COUNT; i++) {
      try {
        Packet packet = handle.getNextPacketEx();
       // System.out.println(handle.getTimestamp());
       System.out.println(packet);
        if(packet.get(IpV6Packet.class)!=null)
        	 System.out.println("BLESS"+packet.get(IpV6Packet.class).getHeader().getDstAddr().getHostName().toString().substring(1));
        if(packet.get(IpV4Packet.class)!=null)
        	 System.out.println("BLESS"+packet.get(IpV4Packet.class).getHeader().getDstAddr().getHostName().toString().substring(1));
        
        //packet.get(TcpPacket.class).getHeader().getSrcPort();
        
      } catch (TimeoutException e) {
      } catch (EOFException e) {
       // System.out.println("EOF");
        break;
      }
    }

    handle.close();
  }

}
