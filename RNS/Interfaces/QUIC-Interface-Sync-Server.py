#!/usr/bin/env python3
"""
QUIC Server Interface for Reticulum

This module provides a QUIC-based transport interface for the Reticulum mesh networking stack.
It implements a server that can accept QUIC connections and forward Reticulum packets bidirectionally.

The interface runs in its own dedicated thread with an asyncio event loop, communicating
with the main Reticulum thread through thread-safe queues.

Author: Reticulum QUIC Implementation
License: Reticulum License
"""

import RNS
try:
    from RNS.Interface import Interface
except ImportError:
    # Fallback for different RNS installations
    from RNS.Interfaces.Interface import Interface
import threading
import time
import socket
import queue
import ipaddress
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timezone, timedelta

try:
    import aioquic
    from aioquic.asyncio import QuicConnectionProtocol, serve
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.events import QuicEvent, StreamDataReceived, ConnectionTerminated
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    HAS_AIOQUIC = True
except ImportError:
    HAS_AIOQUIC = False

if HAS_AIOQUIC:
    H3_ALPN = ["h3"]


class QUICSyncServerInterface(Interface):
    """
    QUIC Server Interface for Reticulum
    
    This interface implements a QUIC server that accepts connections from QUIC clients
    and forwards Reticulum packets bidirectionally. It uses a dedicated thread with
    an asyncio event loop for QUIC operations and communicates with Reticulum through
    thread-safe queues.
    
    The interface supports:
    - Multiple concurrent QUIC connections
    - Bidirectional data transfer
    - Automatic certificate generation
    - Keepalive mechanism
    - Thread-safe operation
    
    Configuration parameters:
    - name: Interface name for identification
    - listen_ip: IP address to bind to (default: 0.0.0.0)
    - listen_port: Port to listen on (default: 8443)
    - certificate_file: Path to TLS certificate file (optional)
    - private_key_file: Path to TLS private key file (optional)
    - verify_certificate: Whether to verify client certificates (default: True)
    """
    
    BITRATE_GUESS = 10*1000*1000  # 10 Mbps estimated bandwidth
    DEFAULT_IFAC_SIZE = 16        # Default interface size
    HW_MTU = 1200                 # Hardware MTU for QUIC
    
    @staticmethod
    def create_configuration(cert_path=None, key_path=None, verify_mode=None):
        """
        Create and configure a QuicConfiguration object for the server.
        
        Args:
            cert_path (str, optional): Path to TLS certificate file
            key_path (str, optional): Path to TLS private key file  
            verify_mode (int, optional): Certificate verification mode
                                       0 = SSL_VERIFY_NONE, 1 = SSL_VERIFY_PEER
        
        Returns:
            QuicConfiguration: Configured QUIC configuration object
            
        Raises:
            Exception: If certificate loading or generation fails
        """
        configuration = QuicConfiguration(
            alpn_protocols=H3_ALPN,
            is_client=False,
            max_datagram_frame_size=65536,
        )
        
        if verify_mode is not None:
            configuration.verify_mode = verify_mode
        
        # Configure idle timeout to prevent connection drops
        configuration.idle_timeout = 300.0  # 5 minutes
        configuration.max_idle_timeout = 300.0  # 5 minutes
        
        # Load or generate certificates
        if cert_path and key_path:
            try:
                configuration.load_cert_chain(cert_path, key_path)
                RNS.log(f"Loaded QUIC certificates from {cert_path}", RNS.LOG_DEBUG)
            except Exception as e:
                RNS.log(f"Failed to load QUIC certificates: {e}", RNS.LOG_WARNING)
                RNS.log("Generating self-signed certificates...", RNS.LOG_INFO)
                QUICSyncServerInterface._generate_self_signed_cert(configuration)
        else:
            RNS.log("No certificate paths provided, generating self-signed certificates...", RNS.LOG_INFO)
            QUICSyncServerInterface._generate_self_signed_cert(configuration)
        
        return configuration
    
    @staticmethod
    def _generate_self_signed_cert(configuration):
        """
        Generate a self-signed TLS certificate for QUIC server operation.
        
        Creates a 2048-bit RSA key pair and a self-signed certificate valid for 1 year
        with Subject Alternative Names for localhost and 127.0.0.1.
        
        Args:
            configuration (QuicConfiguration): Configuration object to load certificates into
            
        Raises:
            Exception: If certificate generation fails
        """
        try:
            # Generate 2048-bit RSA private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            
            # Create certificate subject and issuer
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "QUIC"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Reticulum"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Reticulum QUIC"),
                x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
            ])
            
            # Build certificate with 1-year validity
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.now(timezone.utc)
            ).not_valid_after(
                datetime.now(timezone.utc) + timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]),
                critical=False,
            ).sign(private_key, hashes.SHA256())
            
            # Serialize to PEM format
            cert_pem = cert.public_bytes(serialization.Encoding.PEM)
            key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Write to temporary files
            import tempfile
            cert_file = tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pem')
            key_file = tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pem')
            
            cert_file.write(cert_pem)
            key_file.write(key_pem)
            cert_file.close()
            key_file.close()
            
            # Load into configuration
            configuration.load_cert_chain(cert_file.name, key_file.name)
            RNS.log(f"Generated self-signed QUIC certificates", RNS.LOG_DEBUG)
            
        except Exception as e:
            RNS.log(f"Failed to generate self-signed certificate: {e}", RNS.LOG_ERROR)
            raise

    def __init__(self, owner, configuration):
        """
        Initialize the QUIC server interface.
        
        Args:
            owner: Reticulum instance that owns this interface
            configuration: Configuration object containing interface parameters
        """
        super().__init__()
        
        # Parse configuration parameters
        c = Interface.get_config_obj(configuration)
        name = c["name"]
        listen_ip = c.get("listen_ip", "0.0.0.0")
        listen_port = c.get("listen_port", 8443)
        cert_path = c.get("certificate_file")
        key_path = c.get("private_key_file")
        verify_certificate = c.as_bool("verify_certificate") if "verify_certificate" in c else True
        
        # Set required attributes for Reticulum compatibility
        self.owner = owner
        self.name = name
        
        if not HAS_AIOQUIC:
            raise ImportError("aioquic library is required for QUIC interfaces")
        
        # Store configuration parameters
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.cert_path = cert_path
        self.key_path = key_path
        self.verify_certificate = verify_certificate
        
        # Interface properties required by Reticulum
        self.HW_MTU = 1200
        self.bitrate = 1000000  # 1 Mbps estimate
        self.online = False
        self.IN = True
        self.OUT = True
        self.detached = False
        
        # Thread-safe communication with Reticulum
        self.incoming_queue = queue.Queue()  # QUIC → Reticulum
        self.outgoing_queue = queue.Queue()  # Reticulum → QUIC
        
        # QUIC server state
        self.server = None
        self.event_loop = None
        self.configuration = None
        self.active_connections = {}  # Store active QUIC connections
        self.connection_lock = threading.Lock()
        
        # Statistics
        self.rxb = 0  # Received bytes
        self.txb = 0  # Transmitted bytes
        
        # Start the QUIC server thread
        self.server_thread = threading.Thread(target=self._server_thread, daemon=True)
        self.server_thread.start()
        
        # Start the queue processor thread
        self.queue_thread = threading.Thread(target=self._queue_processor, daemon=True)
        self.queue_thread.start()
        
        RNS.log(f"QUICSyncServerInterface configured for {listen_ip}:{listen_port}", RNS.LOG_INFO)

    def _server_thread(self):
        """
        Main QUIC server thread that runs the asyncio event loop.
        
        This method runs in a separate thread and handles all QUIC server operations
        including accepting connections, processing events, and managing the server lifecycle.
        """
        try:
            import asyncio
            
            # Create new event loop for this thread
            self.event_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.event_loop)
            
            # Create QUIC configuration
            self.configuration = QUICSyncServerInterface.create_configuration(
                cert_path=self.cert_path,
                key_path=self.key_path,
                verify_mode=1 if self.verify_certificate else 0
            )
            
            # Start server
            RNS.log(f"Starting QUIC server on {self.listen_ip}:{self.listen_port}", RNS.LOG_INFO)
            
            async def start_server_async():
                """Async function to start the QUIC server"""
                self.server = await serve(
                    self.listen_ip,
                    self.listen_port,
                    configuration=self.configuration,
                    create_protocol=self._create_protocol
                )
                RNS.log("QUIC server started successfully", RNS.LOG_INFO)
                self.online = True
                
                # Keep server running
                while self.online:
                    await asyncio.sleep(1)
            
            # Run the server
            self.event_loop.run_until_complete(start_server_async())
            
        except Exception as e:
            RNS.log(f"Failed to start QUIC server: {e}", RNS.LOG_ERROR)
            import traceback
            RNS.log(traceback.format_exc(), RNS.LOG_ERROR)
            self.online = False

    def _create_protocol(self, quic=None, stream_handler=None):
        """
        Create a QUIC protocol instance for a new connection.
        
        Args:
            quic: QUIC connection object
            stream_handler: Stream handler for the connection
            
        Returns:
            QUICSyncServerProtocol: Protocol instance for the connection
        """
        return QUICSyncServerProtocol(self, quic, stream_handler)

    def _queue_processor(self):
        """
        Process data queues between QUIC and Reticulum.
        
        This method runs in a separate thread and continuously processes data
        flowing between the QUIC connections and the Reticulum transport layer.
        """
        while not self.detached:
            try:
                # Process outgoing data from Reticulum to QUIC clients
                try:
                    data = self.outgoing_queue.get(timeout=0.1)
                    self._send_to_quic_clients(data)
                except queue.Empty:
                    pass
                
                # Process incoming data from QUIC clients to Reticulum
                try:
                    data = self.incoming_queue.get(timeout=0.1)
                    self.process_incoming(data)
                except queue.Empty:
                    pass
                    
            except Exception as e:
                RNS.log(f"Error in queue processor: {e}", RNS.LOG_ERROR)
                time.sleep(0.1)

    def _send_to_quic_clients(self, data):
        """
        Send data to all connected QUIC clients.
        
        Args:
            data (bytes): Data to send to clients
        """
        if not self.online:
            return
            
        with self.connection_lock:
            if self.active_connections:
                # Create a list of connections to remove if they fail
                connections_to_remove = []
                
                for connection_id, connection_info in self.active_connections.items():
                    try:
                        quic_connection = connection_info['quic_connection']
                        stream_id = connection_info['stream_id']  # Server-initiated stream (3)
                        protocol = connection_info['protocol']
                        
                        # Send Reticulum data on server-initiated stream 3
                        quic_connection.send_stream_data(stream_id, data, end_stream=False)
                        protocol.transmit()
                        
                        self.txb += len(data)
                        
                    except Exception as e:
                        RNS.log(f"Error sending to connection {connection_id}: {e}", RNS.LOG_ERROR)
                        connections_to_remove.append(connection_id)
                
                # Remove failed connections
                for connection_id in connections_to_remove:
                    if connection_id in self.active_connections:
                        del self.active_connections[connection_id]

    def process_incoming(self, data):
        """
        Handle incoming data from QUIC clients and forward to Reticulum.
        
        Args:
            data (bytes): Incoming data from QUIC client
        """
        self.rxb += len(data)
        self.owner.inbound(data, self)

    def process_outgoing(self, data):
        """
        Handle outgoing data from Reticulum and queue for QUIC transmission.
        
        Args:
            data (bytes): Outgoing data from Reticulum
        """
        self.outgoing_queue.put(data)

    def __str__(self):
        """Return string representation of the interface."""
        return f"QUICSyncServerInterface[{self.name}/{self.listen_ip}:{self.listen_port}]"


class QUICSyncServerProtocol(QuicConnectionProtocol):
    """
    QUIC Protocol handler for server connections.
    
    This class handles individual QUIC connections to the server, processing
    incoming data and managing connection state.
    """
    
    def __init__(self, parent, quic=None, stream_handler=None):
        """
        Initialize the server protocol.
        
        Args:
            parent: Parent QUICSyncServerInterface instance
            quic: QUIC connection object
            stream_handler: Stream handler for the connection
        """
        super().__init__(quic, stream_handler)
        self.parent = parent
        self.connection_id = None
    
    def quic_event_received(self, event: QuicEvent) -> None:
        """
        Handle QUIC events from the connection.
        
        Args:
            event (QuicEvent): QUIC event to process
        """
        super().quic_event_received(event)
        
        if isinstance(event, StreamDataReceived):
            # Store connection info for sending replies (reuse existing stream if available)
            with self.parent.connection_lock:
                if self.connection_id not in self.parent.active_connections:
                    # Create a new stream for server-to-client communication (Reticulum data)
                    # Use stream 3 for Reticulum data (odd ID = server-initiated)
                    reply_stream_id = 3
                    self.parent.active_connections[self.connection_id] = {
                        'quic_connection': self._quic,
                        'stream_id': reply_stream_id,  # Stream 3 for Reticulum data
                        'keepalive_stream_id': 1,      # Stream 1 for keepalive
                        'protocol': self
                    }
            
            # Handle keepalive packets on stream 1
            if event.stream_id == 1:
                # Echo back the keepalive on the same stream
                try:
                    self._quic.send_stream_data(event.stream_id, event.data, end_stream=False)
                    self.transmit()
                except Exception as e:
                    RNS.log(f"Failed to echo keepalive: {e}", RNS.LOG_ERROR)
            else:
                # Handle regular Reticulum data
                if event.data:
                    self.parent.incoming_queue.put(event.data)
            
        elif isinstance(event, ConnectionTerminated):
            # Remove from active connections
            with self.parent.connection_lock:
                if self.connection_id in self.parent.active_connections:
                    del self.parent.active_connections[self.connection_id]

    def connection_made(self, transport):
        """
        Called when a QUIC connection is established.
        
        Args:
            transport: Transport object for the connection
        """
        super().connection_made(transport)
        self.connection_id = id(self._quic)
        RNS.log(f"QUIC client connected: {self.connection_id}", RNS.LOG_INFO)

    def connection_lost(self, exc):
        """
        Called when a QUIC connection is lost.
        
        Args:
            exc: Exception that caused the connection loss, or None
        """
        super().connection_lost(exc)
        if exc:
            RNS.log(f"QUIC client disconnected: {self.connection_id}, error: {exc}", RNS.LOG_WARNING)
        else:
            RNS.log(f"QUIC client disconnected: {self.connection_id}", RNS.LOG_INFO)
        
        # Remove from active connections
        with self.parent.connection_lock:
            if self.connection_id in self.parent.active_connections:
                del self.parent.active_connections[self.connection_id]


# Define the interface class for RNS
interface_class = QUICSyncServerInterface