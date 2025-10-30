#!/usr/bin/env python3
"""
QUIC Client Interface for Reticulum

This module provides a QUIC-based transport interface for the Reticulum mesh networking stack.
It implements a client that connects to QUIC servers and forwards Reticulum packets bidirectionally.

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
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timezone, timedelta

try:
    import aioquic
    from aioquic.asyncio import QuicConnectionProtocol, connect
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.events import QuicEvent, StreamDataReceived, ConnectionTerminated
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    HAS_AIOQUIC = True
except ImportError:
    HAS_AIOQUIC = False

if HAS_AIOQUIC:
    H3_ALPN = ["h3"]


class QUICSyncClientInterface(Interface):
    """
    QUIC Client Interface for Reticulum
    
    This interface implements a QUIC client that connects to QUIC servers
    and forwards Reticulum packets bidirectionally. It uses a dedicated thread with
    an asyncio event loop for QUIC operations and communicates with Reticulum through
    thread-safe queues.
    
    The interface supports:
    - Automatic connection to QUIC servers
    - Bidirectional data transfer
    - Automatic reconnection on connection loss
    - Keepalive mechanism
    - Thread-safe operation
    
    Configuration parameters:
    - name: Interface name for identification
    - target_host: Hostname or IP address of the QUIC server
    - target_port: Port number of the QUIC server (default: 8443)
    - verify_certificate: Whether to verify server certificates (default: True)
    - reconnect_enabled: Enable automatic reconnection (default: True)
    - reconnect_interval: Initial reconnection interval in seconds (default: 5.0)
    - max_reconnect_interval: Maximum reconnection interval in seconds (default: 60.0)
    - max_reconnect_attempts: Maximum reconnection attempts, 0 = unlimited (default: 0)
    """
    
    BITRATE_GUESS = 10*1000*1000  # 10 Mbps estimated bandwidth
    DEFAULT_IFAC_SIZE = 16        # Default interface size
    HW_MTU = 1200                 # Hardware MTU for QUIC
    
    @staticmethod
    def create_configuration(verify_certificate=True):
        """
        Create and configure a QuicConfiguration object for the client.
        
        Args:
            verify_certificate (bool): Whether to verify server certificates
        
        Returns:
            QuicConfiguration: Configured QUIC configuration object
        """
        configuration = QuicConfiguration(
            alpn_protocols=H3_ALPN,
            is_client=True,
            max_datagram_frame_size=65536,
        )
        
        configuration.verify_mode = 1 if verify_certificate else 0
        
        # Configure idle timeout to prevent connection drops
        configuration.idle_timeout = 300.0  # 5 minutes
        configuration.max_idle_timeout = 300.0  # 5 minutes
        
        return configuration

    def __init__(self, owner, configuration):
        """
        Initialize the QUIC client interface.
        
        Args:
            owner: Reticulum instance that owns this interface
            configuration: Configuration object containing interface parameters
        """
        super().__init__()
        
        # Parse configuration parameters
        c = Interface.get_config_obj(configuration)
        name = c["name"]
        target_host = c["target_host"]
        target_port = c.get("target_port", 8443)
        verify_certificate = c.as_bool("verify_certificate") if "verify_certificate" in c else True
        
        # Parse reconnection settings
        self.reconnect_enabled = c.as_bool("reconnect_enabled") if "reconnect_enabled" in c else True
        self.reconnect_interval = c.get("reconnect_interval", 5.0)
        self.max_reconnect_interval = c.get("max_reconnect_interval", 60.0)
        self.max_reconnect_attempts = c.get("max_reconnect_attempts", 0)  # 0 = unlimited
        
        # Set required attributes for Reticulum compatibility
        self.owner = owner
        self.name = name
        
        if not HAS_AIOQUIC:
            raise ImportError("aioquic library is required for QUIC interfaces")
        
        # Store configuration parameters
        self.target_host = target_host
        self.target_port = target_port
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
        
        # QUIC client state
        self.protocol = None
        self.event_loop = None
        self.configuration = None
        self.stream_id = 2  # Use stream 2 for client-to-server data (bidirectional)
        self.keepalive_stream_id = 0  # Use stream 0 for keepalive (client-initiated bidirectional)
        
        # Reconnection state
        self.reconnect_attempts = 0
        
        # Statistics
        self.rxb = 0  # Received bytes
        self.txb = 0  # Transmitted bytes
        
        # Start the QUIC client thread
        self.client_thread = threading.Thread(target=self._client_thread, daemon=True)
        self.client_thread.start()
        
        # Start the queue processor thread
        self.queue_thread = threading.Thread(target=self._queue_processor, daemon=True)
        self.queue_thread.start()
        
        RNS.log(f"QUICSyncClientInterface configured for {target_host}:{target_port}", RNS.LOG_INFO)

    def _client_thread(self):
        """
        Main QUIC client thread that runs the asyncio event loop with automatic reconnection.
        
        This method runs in a separate thread and handles all QUIC client operations
        including connecting to servers, processing events, and managing the connection lifecycle.
        It includes automatic reconnection logic with exponential backoff.
        """
        try:
            import asyncio
            
            # Create new event loop for this thread
            self.event_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.event_loop)
            
            # Create QUIC configuration
            self.configuration = QUICSyncClientInterface.create_configuration(
                verify_certificate=self.verify_certificate
            )
            
            # Main connection loop with reconnection
            while not self.detached and self.reconnect_enabled:
                try:
                    # Check if we should attempt reconnection
                    if self.max_reconnect_attempts > 0 and self.reconnect_attempts >= self.max_reconnect_attempts:
                        RNS.log(f"Maximum reconnection attempts ({self.max_reconnect_attempts}) reached. Giving up.", RNS.LOG_ERROR)
                        break
                    
                    # Reset reconnection interval on successful connection
                    if self.reconnect_attempts > 0:
                        self.reconnect_interval = 5.0
                        self.reconnect_attempts = 0
                        RNS.log("Connection restored, resetting reconnection interval", RNS.LOG_INFO)
                    
                    # Start client connection
                    RNS.log(f"Connecting to QUIC server at {self.target_host}:{self.target_port}", RNS.LOG_INFO)
                    
                    async def connect_async():
                        """Async function to connect to the QUIC server"""
                        try:
                            async with connect(
                                self.target_host,
                                self.target_port,
                                configuration=self.configuration,
                                create_protocol=lambda quic, stream_handler: QUICSyncClientProtocol(self, quic, stream_handler)
                            ) as protocol:
                                self.protocol = protocol
                                RNS.log("QUIC connection established", RNS.LOG_INFO)
                                self.online = True
                                
                                # Keep connection alive
                                try:
                                    await protocol.wait_closed()
                                except Exception as e:
                                    RNS.log(f"QUIC connection error: {e}", RNS.LOG_ERROR)
                        except Exception as e:
                            RNS.log(f"Failed to connect to QUIC server: {e}", RNS.LOG_ERROR)
                            import traceback
                            RNS.log(traceback.format_exc(), RNS.LOG_ERROR)
                            self.online = False
                    
                    # Run the client
                    self.event_loop.run_until_complete(connect_async())
                    
                    # If we reach here, the connection was lost
                    self.online = False
                    self.protocol = None
                    
                    # Attempt reconnection if enabled
                    if self.reconnect_enabled and not self.detached:
                        self.reconnect_attempts += 1
                        RNS.log(f"Connection lost. Attempting reconnection {self.reconnect_attempts} in {self.reconnect_interval:.1f} seconds...", RNS.LOG_WARNING)
                        
                        # Wait before reconnecting with exponential backoff
                        time.sleep(self.reconnect_interval)
                        
                        # Increase interval for next attempt (exponential backoff)
                        self.reconnect_interval = min(self.reconnect_interval * 1.5, self.max_reconnect_interval)
                        
                except Exception as e:
                    RNS.log(f"Error in client thread: {e}", RNS.LOG_ERROR)
                    import traceback
                    RNS.log(traceback.format_exc(), RNS.LOG_ERROR)
                    self.online = False
                    
                    # Wait before retrying
                    if self.reconnect_enabled and not self.detached:
                        time.sleep(self.reconnect_interval)
            
            RNS.log("QUIC client thread exiting", RNS.LOG_INFO)
            
        except Exception as e:
            RNS.log(f"Failed to start QUIC client: {e}", RNS.LOG_ERROR)
            import traceback
            RNS.log(traceback.format_exc(), RNS.LOG_ERROR)
            self.online = False

    def _create_protocol(self, *args, **kwargs):
        """
        Create a QUIC protocol instance for the connection.
        
        Args:
            *args: Variable length argument list
            **kwargs: Arbitrary keyword arguments
            
        Returns:
            QUICSyncClientProtocol: Protocol instance for the connection
        """
        return QUICSyncClientProtocol(self)

    def _queue_processor(self):
        """
        Process data queues between QUIC and Reticulum.
        
        This method runs in a separate thread and continuously processes data
        flowing between the QUIC connection and the Reticulum transport layer.
        """
        while not self.detached:
            try:
                # Process outgoing data from Reticulum to QUIC server
                try:
                    data = self.outgoing_queue.get(timeout=0.1)
                    self._send_to_quic_server(data)
                except queue.Empty:
                    pass
                
                # Process incoming data from QUIC server to Reticulum
                try:
                    data = self.incoming_queue.get(timeout=0.1)
                    self.process_incoming(data)
                except queue.Empty:
                    pass
                    
            except Exception as e:
                RNS.log(f"Error in queue processor: {e}", RNS.LOG_ERROR)
                time.sleep(0.1)

    def _send_to_quic_server(self, data):
        """
        Send data to the QUIC server.
        
        Args:
            data (bytes): Data to send to the server
        """
        if not self.online or not self.protocol:
            return
            
        try:
            # Send data using the protocol on client-initiated stream 2
            self.protocol._quic.send_stream_data(self.stream_id, data, end_stream=False)
            self.protocol.transmit()
            
            self.txb += len(data)
            
        except Exception as e:
            RNS.log(f"Error sending to QUIC server: {e}", RNS.LOG_ERROR)
            # Mark as offline and clear protocol if we can't send
            self.online = False
            self.protocol = None

    def process_incoming(self, data):
        """
        Handle incoming data from QUIC server and forward to Reticulum.
        
        Args:
            data (bytes): Incoming data from QUIC server
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

    def set_reconnect_enabled(self, enabled):
        """
        Enable or disable automatic reconnection.
        
        Args:
            enabled (bool): True to enable reconnection, False to disable
        """
        self.reconnect_enabled = enabled
        if enabled:
            RNS.log("Automatic reconnection enabled", RNS.LOG_INFO)
        else:
            RNS.log("Automatic reconnection disabled", RNS.LOG_INFO)

    def reset_reconnect_attempts(self):
        """Reset the reconnection attempt counter."""
        self.reconnect_attempts = 0
        self.reconnect_interval = 5.0
        RNS.log("Reconnection attempts reset", RNS.LOG_DEBUG)

    def __str__(self):
        """Return string representation of the interface."""
        return f"QUICSyncClientInterface[{self.name}/{self.target_host}:{self.target_port}]"


class QUICSyncClientProtocol(QuicConnectionProtocol):
    """
    QUIC Protocol handler for client connections.
    
    This class handles the QUIC connection to the server, processing
    incoming data and managing connection state including keepalive.
    """
    
    def __init__(self, parent, quic=None, stream_handler=None):
        """
        Initialize the client protocol.
        
        Args:
            parent: Parent QUICSyncClientInterface instance
            quic: QUIC connection object
            stream_handler: Stream handler for the connection
        """
        super().__init__(quic, stream_handler)
        self.parent = parent
        self.keepalive_task = None
    
    def quic_event_received(self, event: QuicEvent) -> None:
        """
        Handle QUIC events from the connection.
        
        Args:
            event (QuicEvent): QUIC event to process
        """
        super().quic_event_received(event)
        
        if isinstance(event, StreamDataReceived):
            if event.stream_id == self.parent.keepalive_stream_id:
                # Handle keepalive response - no action needed
                pass
            elif event.stream_id == 3:
                # Handle Reticulum data on stream 3 (server-initiated)
                if event.data:
                    self.parent.incoming_queue.put(event.data)
            elif event.stream_id == 2:
                # Handle Reticulum data on stream 2 (client-initiated, bidirectional)
                if event.data:
                    self.parent.incoming_queue.put(event.data)
            
        elif isinstance(event, ConnectionTerminated):
            RNS.log(f"QUIC connection terminated: {event.error_code}", RNS.LOG_INFO)
            self.parent.online = False

    def connection_made(self, transport):
        """
        Called when a QUIC connection is established.
        
        Args:
            transport: Transport object for the connection
        """
        super().connection_made(transport)
        RNS.log("QUIC client connection established", RNS.LOG_INFO)
        
        # Start keepalive task after a short delay to ensure parent.online is set
        import asyncio
        async def delayed_keepalive_start():
            await asyncio.sleep(0.5)  # Wait for parent.online to be set
            self.keepalive_task = asyncio.create_task(self._keepalive_loop())
        
        asyncio.create_task(delayed_keepalive_start())

    def connection_lost(self, exc):
        """
        Called when a QUIC connection is lost.
        
        Args:
            exc: Exception that caused the connection loss, or None
        """
        super().connection_lost(exc)
        if exc:
            RNS.log(f"QUIC client connection lost: {exc}", RNS.LOG_WARNING)
        else:
            RNS.log("QUIC client connection lost", RNS.LOG_INFO)
        self.parent.online = False
        self.parent.protocol = None
        
        # Cancel keepalive task
        if self.keepalive_task:
            self.keepalive_task.cancel()
    
    async def _keepalive_loop(self):
        """
        Send periodic keepalive packets to maintain the connection.
        
        Sends a single byte 'K' on stream 0 every 10 seconds to prevent
        the connection from timing out due to inactivity.
        """
        import asyncio
        try:
            while self.parent.online and not self.parent.detached:
                await asyncio.sleep(10)  # Send keepalive every 10 seconds
                if self.parent.online and self.parent.protocol and not self.parent.detached:
                    try:
                        # Send 1 byte keepalive on dedicated stream
                        keepalive_data = b"K"  # Single byte keepalive
                        self._quic.send_stream_data(self.parent.keepalive_stream_id, keepalive_data, end_stream=False)
                        self.transmit()
                    except Exception as e:
                        RNS.log(f"Keepalive failed: {e}", RNS.LOG_DEBUG)
                        break
        except asyncio.CancelledError:
            # Task was cancelled, which is expected when connection is lost
            pass
        except Exception as e:
            RNS.log(f"Keepalive loop error: {e}", RNS.LOG_ERROR)


# Define the interface class for RNS
interface_class = QUICSyncClientInterface