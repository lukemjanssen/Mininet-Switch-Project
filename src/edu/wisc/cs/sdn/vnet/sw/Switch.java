package edu.wisc.cs.sdn.vnet.sw;

import net.floodlightcontroller.packet.Ethernet;
import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Timer;
import java.util.TimerTask;

/**
 * @author Aaron Gember-Jacobson
 */
public class Switch extends Device
{	
	// MAC Address Table: Maps MAC Address -> (Interface, Timestamp)
	private Map<Long, MacTableEntry> macTable;

	/**
	 * Creates a switch for a specific host.
	 * @param host hostname for the switch
	 */
	public Switch(String host, DumpFile logfile)
	{
		super(host, logfile);
		this.macTable = new ConcurrentHashMap<>();

		// Cleanup every second
		Timer cleanupTimer = new Timer(true);
		cleanupTimer.schedule(new TimerTask() {
			@Override
			public void run() {
				cleanupMacTable();
			}
		}, 1000, 1000);
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Received packet: " +
				etherPacket.toString().replace("\n", "\n\t"));

		long srcMAC = etherPacket.getSourceMAC().toLong();
		long dstMAC = etherPacket.getDestinationMAC().toLong();

		macTable.put(srcMAC, new MacTableEntry(inIface));
		MacTableEntry entry = macTable.get(dstMAC);

		if (entry != null) {
			sendPacket(etherPacket, entry.getIface());
		} else {
			// Unknown MAC, broadcast to all interfaces except incoming one
			for (Iface iface : interfaces.values()) {
				if (!iface.equals(inIface)) {
					sendPacket(etherPacket, iface);
				}
			}
		}
	}

	/**
	 * Remove Stale MAC entries from the MAC table.
	 */
	private void cleanupMacTable()
	{
		long currentTime = System.currentTimeMillis();
		macTable.entrySet().removeIf(entry -> 
			(currentTime - entry.getValue().getTimestamp()) > 15000);
	}

	/**
	 * Helper class to store MAC address entries with timestamps.
	 */
	private static class MacTableEntry {
		private final Iface iface;
		private final long timestamp;

		public MacTableEntry(Iface iface) {
			this.iface = iface;
			this.timestamp = System.currentTimeMillis();
		}

		public Iface getIface() {
			return iface;
		}

		public long getTimestamp() {
			return timestamp;
		}
	}
}
