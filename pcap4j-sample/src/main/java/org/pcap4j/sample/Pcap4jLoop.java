package org.pcap4j.sample;

import java.io.IOException;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;

public class Pcap4jLoop {

  public static void main(String [] args) throws PcapNativeException, IOException, NotOpenException, InterruptedException {
    String filter = null;
    if (args.length != 0) {
      filter = args[0];
    }

    PcapNetworkInterface nif = new NifSelector().selectNetworkInterface();
    if (nif == null) {
      System.exit(1);
    }

    final PcapHandle handle = nif.openLive(65536, PromiscuousMode.PROMISCUOUS, 10);

    if (filter != null && filter.length() != 0) {
      handle.setFilter(filter, BpfCompileMode.OPTIMIZE);
    }

    PacketListener listener = new PacketListener() {
      @Override
      public void gotPacket(Packet packet) {
        printPacket(packet, handle);
      }
    };

    handle.loop(5, listener);
  }

  private static void printPacket(Packet packet, PcapHandle ph) {
    StringBuilder sb = new StringBuilder();
    sb.append("A packet captured at ")
      .append(ph.getTimestamp())
      .append(":");
    System.out.println(sb);
    System.out.println(packet);
  }

}
