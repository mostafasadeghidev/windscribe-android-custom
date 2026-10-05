package com.windscribe.common;

import static android.system.OsConstants.AF_UNIX;
import static android.system.OsConstants.SOCK_SEQPACKET;

import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.system.ErrnoException;
import android.system.Os;
import android.util.Log;
import android.util.Pair;

import org.minidns.dnsmessage.DnsMessage;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.IpSelector;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.UdpPort;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV6CommonPacket;

import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.FileChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.security.SecureRandom;

public class VPNTunnelWrapper {
    private static final String TAG = "VPNTunnelWrapper";

    private final boolean enablePacketLogging;

    private final FileChannel vpnInputChannel;
    private final FileChannel vpnOutputChannel;
    private final FileChannel socketInputChannel;
    private final FileChannel socketOutputChannel;
    private final ExecutorService threadPool;
    private final ByteBuffer vpnBuffer = ByteBuffer.allocateDirect(65536);
    private final ByteBuffer socketBuffer = ByteBuffer.allocateDirect(65536);
    private final ParcelFileDescriptor parcelFileDescriptor;
    private final BlockingQueue<Packet> dnsPackets = new LinkedBlockingQueue<>(300);
    private static final int DNS_READ_TIMEOUT_MS = 5000;
    private InetSocketAddress controlDAddress;
    private ParcelFileDescriptor socketFileDescriptor;
    private ParcelFileDescriptor detachFileDescriptor;
    private DatagramChannel controlDChannel;
    private Boolean byPassControlD = true;

    // Removed file logging - only log to logcat for privacy
    private final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US);

    public VPNTunnelWrapper(ParcelFileDescriptor parcelFileDescriptor, VpnService vpnService) throws ErrnoException, IOException {
        this(parcelFileDescriptor, vpnService, 5355, false);
    }

    public VPNTunnelWrapper(ParcelFileDescriptor parcelFileDescriptor, VpnService vpnService, int controlDPort) throws ErrnoException, IOException {
        this(parcelFileDescriptor, vpnService, controlDPort, false);
    }

    public VPNTunnelWrapper(ParcelFileDescriptor parcelFileDescriptor, VpnService vpnService, int controlDPort, boolean enableLogging) throws ErrnoException, IOException {
        this.enablePacketLogging = enableLogging;
        this.controlDAddress = new InetSocketAddress("127.0.0.1", controlDPort);
        this.parcelFileDescriptor = parcelFileDescriptor;
        vpnInputChannel = new FileInputStream(parcelFileDescriptor.getFileDescriptor()).getChannel();
        vpnOutputChannel = new FileOutputStream(parcelFileDescriptor.getFileDescriptor()).getChannel();
        buildSocketPair();
        vpnService.protect(socketFileDescriptor.getFd());
        socketInputChannel = new FileInputStream(socketFileDescriptor.getFileDescriptor()).getChannel();
        socketOutputChannel = new FileOutputStream(socketFileDescriptor.getFileDescriptor()).getChannel();
        threadPool = Executors.newFixedThreadPool(3);
        // File logging removed - only use logcat for privacy
        if (enablePacketLogging) {
            Log.v(TAG, "VPNTunnelWrapper initialized with packet logging enabled (logcat only), port: " + controlDPort);
        }
    }

    // Logging to logcat only when enabled - no file writing for privacy
    private void logToFile(String message) {
        if (enablePacketLogging) {
            String timestamp = dateFormat.format(new Date());
            Log.v(TAG, "[VPNTunnel] " + timestamp + " " + message);
        }
    }

    private void logPacket(String message) {
        if (enablePacketLogging) {
            logToFile(message);
        }
    }

    void log(String message) {
        Log.v("VPNTunnelWrapper", message);
    }

    public ParcelFileDescriptor getParcelDescriptor() {
        return detachFileDescriptor;
    }

    public void start() {
        logToFile("Starting VPN tunnel wrapper with 3 threads");
        threadPool.submit(this::forwardSocketToVpn);
        threadPool.submit(this::forwardVpnToSocket);
        threadPool.submit(this::forwardToControlD);
        logToFile("All threads submitted to thread pool");
    }

    public void stop() {
        logToFile("Stopping VPN tunnel wrapper");
        try {
            parcelFileDescriptor.close();
            socketBuffer.clear();
            vpnBuffer.clear();
            vpnInputChannel.close();
            socketInputChannel.close();
            vpnOutputChannel.close();
            vpnInputChannel.close();
            controlDChannel.close();
            threadPool.shutdownNow();

            // Shutdown DNS executor services if they exist
            if (timeoutExecutor != null) {
                timeoutExecutor.shutdownNow();
            }
            if (dnsWorkerPool != null) {
                dnsWorkerPool.shutdownNow();
            }
        } catch (IOException e) {
            log(e.getMessage());
        }

        logToFile("=== VPNTunnelWrapper stopped ===");
    }

    private void buildSocketPair() throws ErrnoException, IOException {
        final FileDescriptor fd0 = new FileDescriptor();
        final FileDescriptor fd1 = new FileDescriptor();
        Os.socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fd0, fd1);
        socketFileDescriptor = ParcelFileDescriptor.dup(fd0);
        detachFileDescriptor = ParcelFileDescriptor.dup(fd1);
    }

    private void forwardSocketToVpn() {
        try {
            logToFile("VPN→Apps thread started");
            int MAX_BATCH_SIZE = 1600;
            long totalBytesForwarded = 0;
            long packetCount = 0;
            long droppedCount = 0;
            while (true) {
                int bytesRead = socketInputChannel.read(socketBuffer);
                if (bytesRead > 0) {
                    packetCount++;

                    socketBuffer.flip();

                    byte[] firstPacketData = new byte[bytesRead];
                    socketBuffer.get(firstPacketData);
                    socketBuffer.rewind();


                    if (enablePacketLogging) {
                        String packetInfo = analyzePacket(firstPacketData, "VPN→Apps");
                        if (packetInfo != null) {
                            logPacket("[VPN→Apps #" + packetCount + "] " + packetInfo + " [" + bytesRead + " bytes]");
                        } else {
                            logPacket("[VPN→Apps #" + packetCount + "] Received " + bytesRead + " bytes from VPN");
                        }
                    }

                    int written = vpnOutputChannel.write(socketBuffer);
                    if (written > 0) {
                        totalBytesForwarded += written;
                    }
                    socketBuffer.clear();
                }
            }
        } catch (IOException e) {
            log("Forward VPN to Apps: " + e.getMessage());
            logToFile("VPN→Apps thread stopped: " + e.getMessage());
        }
    }

    private void forwardVpnToSocket() {
        try {
            logToFile("Apps→VPN thread started (intercepting DNS from apps)");
            long totalPackets = 0;

            while (true) {
                int bytesRead = vpnInputChannel.read(vpnBuffer);
                if (bytesRead > 0) {
                    totalPackets++;

                    try {
                        Pair<Packet, Boolean> packet = ipToDnsPacket(vpnBuffer);
                        if (packet != null) {
                            String packetDetails = enablePacketLogging ? getPacketDetails(packet.first) : null;

                            if (packet.second) {
                                if (enablePacketLogging) {
                                    logPacket("[Apps→ControlD #" + totalPackets + "] " + packetDetails + " (intercepted DNS)");
                                }
                                try {
                                    dnsPackets.put(packet.first);
                                } catch (InterruptedException ie) {
                                    Thread.currentThread().interrupt();
                                    break;
                                }
                            } else {
                                if (enablePacketLogging) {
                                    if (packetDetails != null && packetDetails.contains("→53")) {
                                        logPacket("[WARNING] DNS packet not intercepted: " + packetDetails);
                                    }
                                    logPacket("[Apps→VPN #" + totalPackets + "] " + packetDetails);

                                    if (packetDetails != null && packetDetails.contains("Protocol:Unknown")) {
                                        byte[] rawData = packet.first.getRawData();
                                        logPacket("  └─ Raw packet (first 64 bytes): " + bytesToHex(rawData, 64));
                                    }
                                }
                                int written = socketOutputChannel.write(ByteBuffer.wrap(packet.first.getRawData()));
                            }
                        } else {
                            if (enablePacketLogging) {
                                logPacket("Failed to parse packet #" + totalPackets + " from Apps (null packet)");
                            }
                        }
                    } catch (Exception e) {
                        logToFile("Error processing Apps packet #" + totalPackets + ": " + e.getMessage());
                    }
                }
                vpnBuffer.compact();
            }
        } catch (IOException e) {
            log("Forward Apps to VPN: " + e.getMessage());
            logToFile("Apps→VPN thread stopped: " + e.getMessage());
        }
    }

    // Non-blocking DNS handling
    private static class DnsQuery {
        final Packet packet;
        final long queryId;
        final long startTime;
        final String queryName;

        final int originalTransactionId;
        final DnsQueryKey key;

        DnsQuery(Packet packet, long queryId, int originalTransactionId, DnsQueryKey key) {
            this.packet = packet;
            this.queryId = queryId;
            this.startTime = System.currentTimeMillis();
            this.queryName = extractQueryName(packet);
            this.originalTransactionId = originalTransactionId;
            this.key = key;
        }

        private static String extractQueryName(Packet packet) {
            try {
                if (packet != null && packet.getPayload() instanceof UdpPacket udpPacket) {
                    byte[] dnsData = udpPacket.getPayload().getRawData();
                    DnsMessage message = new DnsMessage(dnsData);
                    if (message.questions != null && !message.questions.isEmpty()) {
                        return message.questions.get(0).name.toString();
                    }
                }
            } catch (Exception ignored) {}
            return "unknown";
        }
    }

    // Composite key to prevent DNS transaction ID collisions between apps
    private static class DnsQueryKey {
        final int transactionId;
        final String srcAddr;
        final int srcPort;

        DnsQueryKey(int transactionId, String srcAddr, int srcPort) {
            this.transactionId = transactionId;
            this.srcAddr = srcAddr;
            this.srcPort = srcPort;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof DnsQueryKey)) return false;
            DnsQueryKey that = (DnsQueryKey) o;
            return transactionId == that.transactionId &&
                   srcPort == that.srcPort &&
                   Objects.equals(srcAddr, that.srcAddr);
        }

        @Override
        public int hashCode() {
            return Objects.hash(transactionId, srcAddr, srcPort);
        }

        @Override
        public String toString() {
            return "DnsQueryKey[txId=" + transactionId + ", src=" + srcAddr + ":" + srcPort + "]";
        }
    }

    /**
     * In-flight queries keyed by the upstream transaction ID this wrapper assigned - NOT by the ID
     * the requesting app chose. A response from the resolver carries only a transaction ID, so if
     * apps' own IDs were used for matching, two apps picking the same ID would be
     * indistinguishable and one app's answer could be delivered to the other. See
     * allocateUpstreamTransactionId.
     */
    private final Map<Integer, DnsQuery> pendingQueries = new ConcurrentHashMap<>();
    private ScheduledExecutorService timeoutExecutor;
    private ExecutorService dnsWorkerPool;
    private long nextQueryId = 1;
    private final AtomicInteger nextUpstreamTransactionId =
            new AtomicInteger(new SecureRandom().nextInt(0x10000));
    /** Bounds both memory and transaction-ID exhaustion when an app floods queries. */
    private static final int MAX_PENDING_DNS_QUERIES = 4096;

    private void forwardToControlD() {
        connectToControlD();
        timeoutExecutor = Executors.newScheduledThreadPool(1);
        dnsWorkerPool = Executors.newFixedThreadPool(5);

        logToFile("DNS→ControlD thread started, listening on 127.0.0.1:" + controlDAddress.getPort());

        dnsWorkerPool.submit(this::readDnsResponses);

        while (true) {
            try {
                if (dnsPackets.remainingCapacity() < 100) {
                    logToFile("DNS queue low capacity, reconnecting to ControlD");
                    connectToControlD();
                }

                Packet packet = dnsPackets.take();
                if (packet != null) {
                    // Extract transaction ID and source details from DNS packet for mapping
                    int transactionId = extractTransactionId(packet);
                    if (transactionId >= 0 && packet instanceof IpPacket ipPacket &&
                        ipPacket.getPayload() instanceof UdpPacket udpPacket) {

                        // Identifies the app that asked. Used for logging and for the timeout
                        // record; it cannot be used to match responses, which carry no source.
                        String srcAddr = ipPacket.getHeader().getSrcAddr().getHostAddress();
                        int srcPort = udpPacket.getHeader().getSrcPort().valueAsInt();
                        DnsQueryKey queryKey = new DnsQueryKey(transactionId, srcAddr, srcPort);

                        if (pendingQueries.size() >= MAX_PENDING_DNS_QUERIES) {
                            logToFile("DNS in-flight limit reached, dropping query from " + queryKey);
                            continue;
                        }

                        Integer upstreamTransactionId = allocateUpstreamTransactionId();
                        if (upstreamTransactionId == null) {
                            logToFile("No free upstream DNS transaction ID, dropping query from " + queryKey);
                            continue;
                        }

                        long queryId = nextQueryId++;
                        DnsQuery query = new DnsQuery(packet, queryId, transactionId, queryKey);
                        pendingQueries.put(upstreamTransactionId, query);

                        if (enablePacketLogging) {
                            String packetDetails = getPacketDetails(packet);
                            logPacket("[DNS Query #" + queryId + " " + queryKey +
                                    " upstreamTxId=" + upstreamTransactionId + "] " + packetDetails);
                            logPacket("  └─ Query: " + query.queryName + " → ControlD");
                        }

                        // Send query without waiting for response
                        writeDNSRequestToControlD(packet, upstreamTransactionId);

                        // Schedule timeout check
                        final int timeoutTransactionId = upstreamTransactionId;
                        timeoutExecutor.schedule(() -> handleTimeout(timeoutTransactionId),
                                               DNS_READ_TIMEOUT_MS, TimeUnit.MILLISECONDS);
                    }
                }
            } catch (InterruptedException e) {
                log(e.getMessage());
                logToFile("DNS→ControlD interrupted: " + e.getMessage());
                break;
            }
        }

        // Cleanup
        timeoutExecutor.shutdown();
        dnsWorkerPool.shutdown();
    }

    private void readDnsResponses() {
        ByteBuffer responseBuffer = ByteBuffer.allocateDirect(1024);

        try {
            controlDChannel.configureBlocking(false);
            Selector selector = Selector.open();
            controlDChannel.register(selector, SelectionKey.OP_READ);

            while (!Thread.currentThread().isInterrupted()) {
                // Wait for responses with a short timeout
                if (selector.select(100) > 0) {
                    selector.selectedKeys().clear();

                    responseBuffer.clear();
                    int bytesRead = controlDChannel.read(responseBuffer);

                    if (bytesRead > 0) {
                        responseBuffer.flip();
                        byte[] responseData = new byte[responseBuffer.remaining()];
                        responseBuffer.get(responseData);

                        // The ID in the response is the one this wrapper assigned, which is unique
                        // per in-flight query, so this identifies exactly one requesting app.
                        int upstreamTransactionId = extractTransactionIdFromResponse(responseData);
                        DnsQuery matchedQuery = upstreamTransactionId >= 0
                                ? pendingQueries.remove(upstreamTransactionId)
                                : null;

                        if (matchedQuery == null) {
                            if (enablePacketLogging) {
                                logPacket("  └─ Unexpected response TxID:" + upstreamTransactionId +
                                        " (no matching query)");
                            }
                        } else if (!responseMatchesQuestion(responseData, matchedQuery)) {
                            logToFile("  └─ Dropped response for " + matchedQuery.key +
                                    ": question does not match " + matchedQuery.queryName);
                        } else {
                            long responseTime = System.currentTimeMillis() - matchedQuery.startTime;

                            // Hand back the ID the app itself used; it matches its own query on it.
                            writeTransactionId(responseData, matchedQuery.originalTransactionId);

                            if (enablePacketLogging) {
                                logPacket("  └─ Response for " + matchedQuery.key + " (" + matchedQuery.queryName +
                                        ") [" + bytesRead + " bytes, " + responseTime + "ms]");
                            }

                            // Send response back to the correct app
                            writeDNSResponseData(matchedQuery.packet, responseData);
                        }
                    }
                }
            }
        } catch (IOException e) {
            logToFile("DNS response reader error: " + e.getMessage());
        }
    }

    private void handleTimeout(int upstreamTransactionId) {
        DnsQuery query = pendingQueries.remove(upstreamTransactionId);
        if (query != null) {
            long elapsed = System.currentTimeMillis() - query.startTime;
            if (enablePacketLogging) {
                logPacket("  └─ TIMEOUT " + query.key + " (" + query.queryName +
                        ") after " + elapsed + "ms");
            }
        }
    }

    /**
     * Reserves a 16-bit transaction ID that is not currently in flight, or null if the entire space
     * is in use. Only the single DNS forwarding thread allocates, and getAndIncrement hands out
     * distinct candidates regardless, so no two concurrent callers can receive the same ID.
     */
    private Integer allocateUpstreamTransactionId() {
        for (int attempt = 0; attempt < 0x10000; attempt++) {
            int candidate = nextUpstreamTransactionId.getAndIncrement() & 0xFFFF;
            if (!pendingQueries.containsKey(candidate)) {
                return candidate;
            }
        }
        return null;
    }

    private static void writeTransactionId(byte[] dnsData, int transactionId) {
        if (dnsData != null && dnsData.length >= 2) {
            dnsData[0] = (byte) ((transactionId >> 8) & 0xFF);
            dnsData[1] = (byte) (transactionId & 0xFF);
        }
    }

    /**
     * True if the response's question section asks the name recorded for this query. The upstream
     * ID already fixes which app the answer belongs to; this additionally rejects a resolver that
     * answers a different name than the one asked. When neither side yields a parseable question
     * there is nothing to compare, so the ID match is allowed to stand.
     */
    private boolean responseMatchesQuestion(byte[] responseData, DnsQuery query) {
        try {
            DnsMessage response = new DnsMessage(responseData);
            if (response.questions == null || response.questions.isEmpty()) {
                return "unknown".equals(query.queryName);
            }
            return response.questions.get(0).name.toString().equalsIgnoreCase(query.queryName);
        } catch (Exception e) {
            logToFile("  └─ Failed to parse DNS response question: " + e.getMessage());
            return false;
        }
    }

    private int extractTransactionId(Packet packet) {
        try {
            if (packet != null && packet.getPayload() instanceof UdpPacket udpPacket) {
                byte[] dnsData = udpPacket.getPayload().getRawData();
                if (dnsData.length >= 2) {
                    return ((dnsData[0] & 0xFF) << 8) | (dnsData[1] & 0xFF);
                }
            }
        } catch (Exception e) {
            logToFile("Error extracting transaction ID: " + e.getMessage());
        }
        return -1;
    }

    private int extractTransactionIdFromResponse(byte[] responseData) {
        if (responseData != null && responseData.length >= 2) {
            return ((responseData[0] & 0xFF) << 8) | (responseData[1] & 0xFF);
        }
        return -1;
    }

    private void writeDNSResponseData(Packet requestPacket, byte[] responseData) {
        try {
            DnsMessage dnsResponse = new DnsMessage(responseData);
            IpPacket rebuiltIpPacket = dnsToIpPacket((IpPacket) requestPacket, dnsResponse.toArray());

            int written = vpnOutputChannel.write(ByteBuffer.wrap(rebuiltIpPacket.getRawData()));
            if (enablePacketLogging && written > 0) {
                logPacket("  └─ Written response to Apps: " + written + " bytes");
            }
        } catch (IOException e) {
            logToFile("  └─ ERROR: Failed to write DNS response: " + e.getMessage());
        }
    }


    private String analyzePacket(byte[] data, String direction) {
        try {
            Packet packet = IpSelector.newPacket(data, 0, data.length);
            return direction + ": " + getPacketDetails(packet);
        } catch (Exception e) {
            return null;
        }
    }

    private String bytesToHex(byte[] bytes, int limit) {
        StringBuilder sb = new StringBuilder();
        int count = Math.min(bytes.length, limit);
        for (int i = 0; i < count; i++) {
            sb.append(String.format("%02X ", bytes[i]));
            if ((i + 1) % 16 == 0) {
                sb.append("\n  ");
            }
        }
        if (bytes.length > limit) {
            sb.append("... (").append(bytes.length).append(" bytes total)");
        }
        return sb.toString();
    }


    private String getPacketDetails(Packet packet) {
        try {
            StringBuilder details = new StringBuilder();

            if (packet instanceof IpV4Packet ipv4) {
                details.append("IPv4 ");
                details.append(ipv4.getHeader().getSrcAddr().getHostAddress());
                details.append("→");
                details.append(ipv4.getHeader().getDstAddr().getHostAddress());
            } else if (packet instanceof IpV6Packet ipv6) {
                details.append("IPv6 ");
                details.append(ipv6.getHeader().getSrcAddr().getHostAddress());
                details.append("→");
                details.append(ipv6.getHeader().getDstAddr().getHostAddress());
            }

            if (packet.getPayload() instanceof UdpPacket udp) {
                details.append(" UDP:");
                details.append(udp.getHeader().getSrcPort().valueAsInt());
                details.append("→");
                details.append(udp.getHeader().getDstPort().valueAsInt());
                if (udp.getHeader().getDstPort().valueAsInt() == 53) {
                    details.append(" [DNS]");
                }
            } else if (packet.getPayload() instanceof TcpPacket tcp) {
                details.append(" TCP:");
                details.append(tcp.getHeader().getSrcPort().valueAsInt());
                details.append("→");
                details.append(tcp.getHeader().getDstPort().valueAsInt());
            } else if (packet.getPayload() instanceof IcmpV4CommonPacket) {
                details.append(" ICMPv4");
            } else if (packet.getPayload() instanceof IcmpV6CommonPacket) {
                details.append(" ICMPv6");
                if (packet instanceof IpV6Packet ipv6) {
                    String dstAddr = ipv6.getHeader().getDstAddr().getHostAddress();
                    if (dstAddr != null && dstAddr.startsWith("ff02::")) {
                        details.append(" [Multicast]");
                    }
                }
            } else {
                if (packet instanceof IpV6Packet ipv6) {
                    int nextHeader = ipv6.getHeader().getNextHeader().value().intValue();
                    switch (nextHeader) {
                        case 0:
                            details.append(" IPv6-HopByHop");
                            // Check if it's MLDv2 multicast (ff02::16)
                            String dstAddr = ipv6.getHeader().getDstAddr().getHostAddress();
                            if ("ff02::16".equals(dstAddr)) {
                                details.append(" [MLDv2 Multicast]");
                            } else if (dstAddr != null && dstAddr.startsWith("ff02::")) {
                                details.append(" [Multicast]");
                            }
                            break;
                        case 43:
                            details.append(" IPv6-Routing");
                            break;
                        case 44:
                            details.append(" IPv6-Fragment");
                            break;
                        case 60:
                            details.append(" IPv6-DestOptions");
                            break;
                        default:
                            details.append(" Protocol:Unknown");
                            details.append(" (NextHeader:").append(nextHeader).append(")");
                    }
                } else if (packet instanceof IpV4Packet ipv4) {
                    details.append(" Protocol:Unknown");
                    details.append(" (Proto:").append(ipv4.getHeader().getProtocol().valueAsString()).append(")");
                } else {
                    details.append(" Protocol:Unknown");
                }
            }

            return details.toString();
        } catch (Exception e) {
            return "Error parsing packet: " + e.getMessage();
        }
    }

    private void connectToControlD() {
        int MAX_RETRIES = 3;
        int retryDelay = 500;
        for (int i = 0; i < MAX_RETRIES; i++) {
            try {
                if (controlDChannel != null && controlDChannel.isOpen()) {
                    controlDChannel.close();
                }
                controlDChannel = DatagramChannel.open();
                controlDChannel.configureBlocking(true);
                controlDChannel.connect(controlDAddress);
                log("Connected to controlD");
                logToFile("Connected to ControlD at " + controlDAddress);
                return;
            } catch (IOException e) {
                log("Error connecting to proxy (attempt " + (i + 1) + "): " + e.getMessage());
                try {
                    Thread.sleep(retryDelay);
                } catch (InterruptedException ignored) {
                }
                retryDelay *= 2;
            }
        }
        log("Failed to connect to proxy after multiple attempts.");
    }

    public Pair<Packet, Boolean> ipToDnsPacket(ByteBuffer vpnBuffer) {
        vpnBuffer.flip();
        byte[] ipPacketData = new byte[vpnBuffer.remaining()];
        vpnBuffer.get(ipPacketData);
        Packet ipPacket;
        try {
            ipPacket = IpSelector.newPacket(ipPacketData, 0, ipPacketData.length);
            if ((ipPacket instanceof IpV4Packet || ipPacket instanceof IpV6Packet) && ipPacket.getPayload() instanceof UdpPacket requestUdpPacket) {
                if (requestUdpPacket.getHeader().getDstPort().value() == 53) {
                    try {
                        byte[] dnsQueryData = requestUdpPacket.getPayload().getRawData();
                        DnsMessage dnsMessage = new DnsMessage(dnsQueryData);
                        if (dnsMessage.questions != null && !dnsMessage.questions.isEmpty()) {
                            String domain = dnsMessage.questions.get(0).name.toString();
                            if (domain.endsWith("windscribe.com") && byPassControlD) {
                                byPassControlD = false;
                                return new Pair<>(ipPacket, false);
                            }
                        }
                    } catch (Exception ignored) { }
                    return new Pair<>(ipPacket, true);
                }
            }
            return new Pair<>(ipPacket, false);
        } catch (IllegalRawDataException e) {
            log(e.getMessage());
            return null;
        }
    }

    public IpPacket dnsToIpPacket(IpPacket requestPacket, byte[] responsePayload) {
        UdpPacket udpOutPacket = (UdpPacket) requestPacket.getPayload();
        UnknownPacket.Builder payloadBuilder = new UnknownPacket.Builder().rawData(responsePayload);
        UdpPacket.Builder udpBuilder = new UdpPacket.Builder(udpOutPacket).srcPort(UdpPort.getInstance(udpOutPacket.getHeader().getDstPort().value())).dstPort(UdpPort.getInstance(udpOutPacket.getHeader().getSrcPort().value())).srcAddr(requestPacket.getHeader().getDstAddr()).dstAddr(requestPacket.getHeader().getSrcAddr()).correctChecksumAtBuild(true).correctLengthAtBuild(true).payloadBuilder(payloadBuilder);
        if (requestPacket instanceof IpV4Packet) {
            return new IpV4Packet.Builder((IpV4Packet) requestPacket).srcAddr((Inet4Address) requestPacket.getHeader().getDstAddr()).dstAddr((Inet4Address) requestPacket.getHeader().getSrcAddr()).correctChecksumAtBuild(true).correctLengthAtBuild(true).payloadBuilder(udpBuilder).build();
        } else {
            return new IpV6Packet.Builder((IpV6Packet) requestPacket).srcAddr((Inet6Address) requestPacket.getHeader().getDstAddr()).dstAddr((Inet6Address) requestPacket.getHeader().getSrcAddr()).correctLengthAtBuild(true).payloadBuilder(udpBuilder).build();
        }
    }


    public void writeDNSRequestToControlD(Packet ipPacket, int upstreamTransactionId) {
        UdpPacket requestUdpPacket = (UdpPacket) ipPacket.getPayload();
        // Copy before rewriting: the pending query keeps the original packet so the response can be
        // rebuilt against it, and pcap4j raw data must not be mutated in place.
        byte[] dnsPayload = requestUdpPacket.getPayload().getRawData().clone();
        writeTransactionId(dnsPayload, upstreamTransactionId);
        ByteBuffer payLoadSendToProxy = ByteBuffer.wrap(dnsPayload);
        try {
            controlDChannel.write(payLoadSendToProxy);
        } catch (IOException e) {
            log(e.getMessage());
            logToFile("  └─ ERROR: Failed to send DNS request: " + e.getMessage());
            connectToControlD();
        }
    }

}