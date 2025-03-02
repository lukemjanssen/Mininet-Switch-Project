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

		// Compute checksum, we can do this by serializing the packet and then deserializing it
		// as the checksum will be recomputed during deserialization
		ipPacket.resetChecksum();
		byte[] serializedPacket = ipPacket.serialize();
		ipPacket = (IPv4) ipPacket.deserialize(serializedPacket, 0, serializedPacket.length);
		short computedChecksum = ipPacket.getChecksum();
		
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
