#!/usr/bin/env python3

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
    Simple QUIC Client Interface for Reticulum
    Runs in its own thread, uses queues for communication with RNS
    """
    
    BITRATE_GUESS = 10*1000*1000  # 10 Mbps
    DEFAULT_IFAC_SIZE = 16
    HW_MTU = 1200
    
    @staticmethod
    def create_configuration(verify_certificate=True):
        """Create QUIC configuration for client"""
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
        super().__init__()
        
        # Parse configuration
        c = Interface.get_config_obj(configuration)
        name = c["name"]
        target_host = c["target_host"]
        target_port = c.get("target_port", 8443)
        verify_certificate = c.as_bool("verify_certificate") if "verify_certificate" in c else True
        
        # Set required attributes
        self.owner = owner
        self.name = name
        
        if not HAS_AIOQUIC:
            raise ImportError("aioquic library is required for QUIC interfaces")
        
        self.target_host = target_host
        self.target_port = target_port
        self.verify_certificate = verify_certificate
        
        # Interface properties
        self.HW_MTU = 1200
        self.bitrate = 1000000  # 1 Mbps estimate
        self.online = False
        self.IN = True
        self.OUT = True
        self.detached = False
        
        # Thread-safe communication with RNS
        self.incoming_queue = queue.Queue()  # QUIC → RNS
        self.outgoing_queue = queue.Queue()  # RNS → QUIC
        
        # QUIC client state
        self.protocol = None
        self.event_loop = None
        self.configuration = None
        self.stream_id = 2  # Use stream 2 for data (bidirectional)
        self.keepalive_stream_id = 1  # Use stream 1 for keepalive
        
        # Statistics
        self.rxb = 0
        self.txb = 0
        
        # Start the QUIC client thread
        self.client_thread = threading.Thread(target=self._client_thread, daemon=True)
        self.client_thread.start()
        
        # Start the queue processor thread
        self.queue_thread = threading.Thread(target=self._queue_processor, daemon=True)
        self.queue_thread.start()
        
        RNS.log(f"QUICSyncClientInterface configured for {target_host}:{target_port}", RNS.LOG_INFO)

    def _client_thread(self):
        """Main QUIC client thread - runs asyncio event loop"""
        try:
            import asyncio
            
            # Create new event loop for this thread
            self.event_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.event_loop)
            
            # Create QUIC configuration
            self.configuration = QUICSyncClientInterface.create_configuration(
                verify_certificate=self.verify_certificate
            )
            
            # Start client connection
            RNS.log(f"Connecting to QUIC server at {self.target_host}:{self.target_port}", RNS.LOG_INFO)
            
            async def connect_async():
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
            
        except Exception as e:
            RNS.log(f"Failed to start QUIC client: {e}", RNS.LOG_ERROR)
            import traceback
            RNS.log(traceback.format_exc(), RNS.LOG_ERROR)
            self.online = False

    def _create_protocol(self, *args, **kwargs):
        """Create a QUIC protocol instance"""
        return QUICSyncClientProtocol(self)

    def _queue_processor(self):
        """Process queues - forwards data between QUIC and RNS"""
        while not self.detached:
            try:
                # Process outgoing data from RNS to QUIC server
                try:
                    data = self.outgoing_queue.get(timeout=0.1)
                    self._send_to_quic_server(data)
                except queue.Empty:
                    pass
                
                # Process incoming data from QUIC server to RNS
                try:
                    data = self.incoming_queue.get(timeout=0.1)
                    self.process_incoming(data)
                except queue.Empty:
                    pass
                    
            except Exception as e:
                RNS.log(f"Error in queue processor: {e}", RNS.LOG_ERROR)
                time.sleep(0.1)

    def _send_to_quic_server(self, data):
        """Send data to QUIC server"""
        if not self.online or not self.protocol:
            RNS.log(f"Cannot send data: online={self.online}, protocol={self.protocol is not None}", RNS.LOG_DEBUG)
            return
            
        try:
            RNS.log(f"Sending {len(data)} bytes to QUIC server", RNS.LOG_DEBUG)
            
            # Send data using the protocol
            self.protocol._quic.send_stream_data(self.stream_id, data, end_stream=False)
            self.protocol.transmit()
            
            self.txb += len(data)
            
        except Exception as e:
            RNS.log(f"Error sending to QUIC server: {e}", RNS.LOG_ERROR)
            # Mark as offline and clear protocol if we can't send
            self.online = False
            self.protocol = None

    def process_incoming(self, data):
        """Handle incoming data from Transport layer - forward to RNS"""
        self.rxb += len(data)
        self.owner.inbound(data, self)

    def process_outgoing(self, data):
        """Handle outgoing data from Transport layer - put in outgoing queue"""
        self.outgoing_queue.put(data)

    def __str__(self):
        return f"QUICSyncClientInterface[{self.name}/{self.target_host}:{self.target_port}]"


class QUICSyncClientProtocol(QuicConnectionProtocol):
    """QUIC Protocol handler for synchronous client"""
    
    def __init__(self, parent, quic=None, stream_handler=None):
        super().__init__(quic, stream_handler)
        self.parent = parent
        self.keepalive_task = None
    
    def quic_event_received(self, event: QuicEvent) -> None:
        """Handle QUIC events"""
        super().quic_event_received(event)
        
        if isinstance(event, StreamDataReceived):
            if event.stream_id == self.parent.keepalive_stream_id:
                # Handle keepalive response
                RNS.log(f"Client received keepalive response: {event.data}", RNS.LOG_DEBUG)
            elif event.stream_id == 3:
                # Handle RNS data on stream 3 (server-initiated)
                RNS.log(f"Client received {len(event.data)} bytes from QUIC server on stream 3", RNS.LOG_INFO)
                
                # Put data in incoming queue for RNS
                if event.data:
                    self.parent.incoming_queue.put(event.data)
            elif event.stream_id == 2:
                # Handle RNS data on stream 2 (client-initiated, bidirectional)
                RNS.log(f"Client received {len(event.data)} bytes from QUIC server on stream 2", RNS.LOG_INFO)
                
                # Put data in incoming queue for RNS
                if event.data:
                    self.parent.incoming_queue.put(event.data)
            else:
                # Handle other streams
                RNS.log(f"Client received {len(event.data)} bytes on stream {event.stream_id}", RNS.LOG_DEBUG)
            
        elif isinstance(event, ConnectionTerminated):
            RNS.log(f"QUIC connection terminated: {event.error_code}", RNS.LOG_INFO)
            self.parent.online = False

    def connection_made(self, transport):
        """Called when connection is established"""
        super().connection_made(transport)
        RNS.log("QUIC client connection established", RNS.LOG_INFO)
        
        # Start keepalive task
        import asyncio
        self.keepalive_task = asyncio.create_task(self._keepalive_loop())
        RNS.log("Started keepalive task", RNS.LOG_DEBUG)

    def connection_lost(self, exc):
        """Called when connection is lost"""
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
        """Send periodic keepalive packets on dedicated stream"""
        try:
            RNS.log("Keepalive loop started", RNS.LOG_DEBUG)
            RNS.log(f"Initial state: online={self.parent.online}, detached={self.parent.detached}", RNS.LOG_DEBUG)
            while self.parent.online and not self.parent.detached:
                await asyncio.sleep(10)  # Send keepalive every 10 seconds
                RNS.log(f"Keepalive check: online={self.parent.online}, protocol={self.parent.protocol is not None}, detached={self.parent.detached}", RNS.LOG_DEBUG)
                if self.parent.online and self.parent.protocol and not self.parent.detached:
                    try:
                        # Send 1 byte keepalive on dedicated stream
                        keepalive_data = b"K"  # Single byte keepalive
                        self._quic.send_stream_data(self.parent.keepalive_stream_id, keepalive_data, end_stream=False)
                        self.transmit()
                        RNS.log("Sent keepalive packet on stream 1", RNS.LOG_DEBUG)
                    except Exception as e:
                        RNS.log(f"Keepalive failed: {e}", RNS.LOG_DEBUG)
                        break
                else:
                    RNS.log("Skipping keepalive: not online or no protocol", RNS.LOG_DEBUG)
        except asyncio.CancelledError:
            RNS.log("Keepalive task cancelled", RNS.LOG_DEBUG)
        except Exception as e:
            RNS.log(f"Keepalive loop error: {e}", RNS.LOG_ERROR)

# Define the interface class for RNS
interface_class = QUICSyncClientInterface