package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;
	
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
	}
	
	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable()
	{ return this.routeTable; }
	
	/**
	 * Load a new routing table from a file.
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile)
	{
		if (!routeTable.load(routeTableFile, this))
		{
			System.err.println("Error setting up routing table from file "
					+ routeTableFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}
	
	/**
	 * Load a new ARP cache from a file.
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile)
	{
		if (!arpCache.load(arpCacheFile))
		{
			System.err.println("Error setting up ARP cache from file "
					+ arpCacheFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
	}

	/**
	 * Helper method to caclulate checksum for IPv4 packets
	 * @param header serialized IPv4 packet
	 * @return checksum value
	 */
	private short computeChecksum(byte[] header) {
		int length = header.length;
		int i = 0;
		long sum = 0;
		
		// Sum each consecutive 16-bit word
		while (length > 1) {
			int word = ((header[i] << 8) & 0xFF00) | (header[i+1] & 0xFF);
			sum += word;
			i += 2;
			length -= 2;
		}
		
		// Handle odd byte, if present
		if (length > 0) {
			int word = (header[i] << 8) & 0xFF00;
			sum += word;
		}
		
		// Add back carry outs from top 16 bits to low 16 bits
		while ((sum >> 16) != 0) {
			sum = (sum & 0xFFFF) + (sum >> 16);
		}
		
		// One's complement and truncate to 16 bits
		return (short) (~sum & 0xFFFF);
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
		
		/********************************************************************/
		/* TODO: Handle packets                                             */
		
		// CHECKING PACKET
		// Check if frame has IPv4 packet, if not, drop it
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4) {
			System.out.println("Packet dropped: Not an IPv4 packet");
			return;
		}

		// Verify checksum 
		IPv4 ipPacket = (IPv4) etherPacket.getPayload();
		short checksum = ipPacket.getChecksum();

		// Compute checksum
		ipPacket.resetChecksum();
		byte[] serializedPacket = ipPacket.serialize();
		short computedChecksum = computeChecksum(serializedPacket);

		// Drop packet if checksum is invalid
		if (checksum != computedChecksum) {
			System.out.println("Packet dropped: Invalid checksum");
			return;
		}
		ipPacket.setChecksum(checksum);

		// Decrement TTL
		ipPacket.setTtl((byte) (ipPacket.getTtl() - 1));
		if (ipPacket.getTtl() == 0) {
			System.out.println("Packet dropped: TTL expired");
			return;
		}

		// Check if packet is destined for router
		for (Iface iface : interfaces.values()) {
			if (ipPacket.getDestinationAddress() == iface.getIpAddress()) {
				System.out.println("Packet dropped: Destination is router");
				return;
			}
		}

		// FORWARDING PACKET
		// Lookup interface for destination IP address
		int destinationAddress = ipPacket.getDestinationAddress();
		RouteEntry bestMatch = routeTable.lookup(destinationAddress);
		if (bestMatch == null) {
			System.out.println("Packet dropped: No matching route");
			return;
		}

		// Determine next hop MAC address
		ArpEntry mac = arpCache.lookup(destinationAddress);

		// Update header fields
		etherPacket.setSourceMACAddress(bestMatch.getInterface().getMacAddress().toBytes());
		etherPacket.setDestinationMACAddress(mac.getMac().toBytes());

		// Send packet
		sendPacket(etherPacket, bestMatch.getInterface());

		/********************************************************************/
	}
}
