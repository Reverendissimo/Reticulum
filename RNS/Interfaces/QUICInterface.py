# Reticulum License
#
# Copyright (c) 2016-2025 Mark Qvist
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# - The Software shall not be used in any kind of system which includes amongst
#   its functions the ability to purposefully do harm to human beings.
#
# - The Software shall not be used, directly or indirectly, in the creation of
#   an artificial intelligence, machine learning or language model training
#   dataset, including but not limited to any use that contributes to the
#   training or development of such a model or algorithm.
#
# - The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE USE OR OTHER DEALINGS IN THE SOFTWARE.

from RNS.Interfaces.Interface import Interface
import importlib
import threading
import socket
import time
import sys
import RNS

# Import aioquic if available
try:
    import importlib.util
    if importlib.util.find_spec('aioquic') != None:
        import asyncio
        from aioquic.asyncio import connect, serve
        from aioquic.quic.configuration import QuicConfiguration
        from aioquic.quic.events import StreamDataReceived, ConnectionTerminated, StreamReset
        from aioquic.tls import CipherSuite
        HAS_AIOQUIC = True
    else:
        HAS_AIOQUIC = False
except Exception as e:
    HAS_AIOQUIC = False

# Obfuscation profiles (only defined if aioquic is available)
OBFUSCATION_PROFILES = {} if not HAS_AIOQUIC else {
    'chrome': {
        'transport_params': {
            'max_idle_timeout': 300,
            'max_udp_payload_size': 1472,
            'initial_max_data': 10000000,
            'initial_max_stream_data_bidi_local': 1000000,
            'initial_max_stream_data_bidi_remote': 1000000,
            'initial_max_stream_data_uni': 1000000,
            'initial_max_streams_bidi': 100,
            'initial_max_streams_uni': 100,
            'ack_delay_exponent': 3,
            'max_ack_delay': 25,
            'disable_active_migration': False,
        },
        'cipher_suites': [
            CipherSuite.AES_128_GCM_SHA256,
            CipherSuite.AES_256_GCM_SHA384,
            CipherSuite.CHACHA20_POLY1305_SHA256,
        ],
    },
    'firefox': {
        'transport_params': {
            'max_idle_timeout': 300,
            'max_udp_payload_size': 1472,
            'initial_max_data': 10000000,
            'initial_max_stream_data_bidi_local': 1000000,
            'initial_max_stream_data_bidi_remote': 1000000,
            'initial_max_stream_data_uni': 1000000,
            'initial_max_streams_bidi': 100,
            'initial_max_streams_uni': 100,
            'ack_delay_exponent': 3,
            'max_ack_delay': 25,
            'disable_active_migration': False,
        },
        'cipher_suites': [
            CipherSuite.AES_128_GCM_SHA256,
            CipherSuite.AES_256_GCM_SHA384,
            CipherSuite.CHACHA20_POLY1305_SHA256,
        ],
    },
    'tor': {
        'transport_params': {
            'max_idle_timeout': 300,
            'max_udp_payload_size': 1472,
            'initial_max_data': 10000000,
            'initial_max_stream_data_bidi_local': 1000000,
            'initial_max_stream_data_bidi_remote': 1000000,
            'initial_max_stream_data_uni': 1000000,
            'initial_max_streams_bidi': 100,
            'initial_max_streams_uni': 100,
            'ack_delay_exponent': 3,
            'max_ack_delay': 25,
            'disable_active_migration': True,
        },
        'cipher_suites': [
            CipherSuite.AES_128_GCM_SHA256,
            CipherSuite.AES_256_GCM_SHA384,
            CipherSuite.CHACHA20_POLY1305_SHA256,
        ],
    }
}

class QUICInterface(Interface):
    """
    QUIC interface for Reticulum using aioquic.
    Supports configurable obfuscation profiles to mimic normal HTTPS traffic.
    """
    
    BITRATE_GUESS = 100*1000*1000  # 100 Mbps
    DEFAULT_IFAC_SIZE = 16
    HW_MTU = 1472
    DEFAULT_KEEPALIVE_INTERVAL = 30
    
    def __init__(self, owner, configuration):
        super().__init__()
        
        if not HAS_AIOQUIC:
            RNS.log("Using the QUIC interface requires the 'aioquic' module to be installed.", RNS.LOG_CRITICAL)
            RNS.log("You can install it with the command: pip install aioquic", RNS.LOG_CRITICAL)
            RNS.panic()
        
        # Parse configuration
        c = Interface.get_config_obj(configuration)
        name = c["name"]
        target_host = c["target_host"] if "target_host" in c else None
        target_port = int(c["target_port"]) if "target_port" in c else 443
        
        # Obfuscation profile
        obf_profile = c.get("obfuscation_profile", "chrome")
        if obf_profile not in OBFUSCATION_PROFILES:
            obf_profile = "chrome"
        
        # Keepalive
        self.keepalive_interval = float(c.get("keepalive_interval", self.DEFAULT_KEEPALIVE_INTERVAL))
        
        # Certificate verification
        verify_cert = c.as_bool("verify_certificate") if "verify_certificate" in c else True
        
        if target_host == None:
            raise ValueError("No target_host specified for QUIC interface")
        
        # Store configuration
        self.name = name
        self.target_host = target_host
        self.target_port = target_port
        self.owner = owner
        self.online = False
        self.obf_profile = obf_profile
        self.profile_config = OBFUSCATION_PROFILES[obf_profile]
        self.verify_certificate = verify_cert
        
        # Setup QUIC configuration
        self.quic_config = self._create_quic_config()
        
        # Connection state
        self.connection = None
        self._quic = None  # QUIC connection object
        self.event_loop = None
        self.event_loop_thread = None
        self.stream_id = None
        self.data_queue = []
        
        # Start asyncio event loop in separate thread
        self._start_event_loop()
        RNS.log("Event loop started", RNS.LOG_DEBUG)
        
        # Start connection
        self._connect()
        RNS.log("Connect called", RNS.LOG_DEBUG)
        
        RNS.log("QUICInterface configured for "+self.target_host+":"+str(self.target_port), RNS.LOG_INFO)
    
    def _create_quic_config(self):
        """Create QUIC configuration based on obfuscation profile."""
        from aioquic.h3.connection import H3_ALPN
        config = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
        
        # Apply cipher suites from profile
        if 'cipher_suites' in self.profile_config:
            config.cipher_suites = self.profile_config['cipher_suites']
        
        # Apply transport parameters from profile
        if 'transport_params' in self.profile_config:
            for param, value in self.profile_config['transport_params'].items():
                setattr(config, param, value)
        
        # Certificate verification (0 = SSL_VERIFY_NONE, 1 = SSL_VERIFY_PEER)
        # When verify_certificate is False, we don't verify (use 0)
        # When verify_certificate is True, we verify (use 1)
        config.verify_mode = 1 if self.verify_certificate else 0
        
        return config
    
    def _start_event_loop(self):
        """Start asyncio event loop in separate thread."""
        def run_loop():
            self.event_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.event_loop)
            self.event_loop.run_forever()
        
        self.event_loop_thread = threading.Thread(target=run_loop, daemon=True)
        self.event_loop_thread.start()
        
        # Wait for loop to be ready
        while self.event_loop is None:
            time.sleep(0.01)
    
    def _connect(self):
        """Connect to QUIC server."""
        async def connect_async():
            try:
                RNS.log("Connecting to QUIC server at "+self.target_host+":"+str(self.target_port)+"...", RNS.LOG_DEBUG)
                
                # Define client protocol class - MUST inherit from QuicConnectionProtocol
                from aioquic.asyncio.protocol import QuicConnectionProtocol
                
                class ClientProtocol(QuicConnectionProtocol):
                    def __init__(self, quic, stream_handler=None):
                        self.parent = self.parent_ref
                        RNS.log(f"ClientProtocol.__init__ called with quic={quic}, stream_handler={stream_handler}", RNS.LOG_DEBUG)
                        super().__init__(quic, stream_handler=stream_handler)
                        self._quic = quic
                    
                    def connection_made(self, transport):
                        """Called when connection is made."""
                        RNS.log(f"ClientProtocol.connection_made called with transport={transport}", RNS.LOG_DEBUG)
                        super().connection_made(transport)
                    
                    def connection_lost(self, exc):
                        """Called when connection is lost."""
                        RNS.log(f"ClientProtocol.connection_lost called with exc={exc}", RNS.LOG_DEBUG)
                        super().connection_lost(exc)
                    
                    def datagram_received(self, data, addr):
                        """Called when a datagram is received."""
                        RNS.log(f"ClientProtocol.datagram_received: {len(data)} bytes from {addr}", RNS.LOG_DEBUG)
                        super().datagram_received(data, addr)
                    
                    def quic_event_received(self, event):
                        """Handle QUIC events from the server."""
                        RNS.log(f"Client received QUIC event: {type(event).__name__}", RNS.LOG_DEBUG)
                        super().quic_event_received(event)
                        
                        if isinstance(event, StreamDataReceived):
                            data = event.data
                            RNS.log(f"Received {len(data)} bytes from QUIC server", RNS.LOG_DEBUG)
                            # Send data to Transport
                            def process():
                                self.parent.owner.inbound(data, self.parent)
                            threading.Thread(target=process, daemon=True).start()
                        
                        elif isinstance(event, ConnectionTerminated):
                            RNS.log("QUIC connection terminated", RNS.LOG_INFO)
                            self.parent.online = False
                
                # Store parent reference in the class
                ClientProtocol.parent_ref = self
                
                # Use context manager properly with create_protocol
                async with connect(
                    self.target_host,
                    self.target_port,
                    configuration=self.quic_config,
                    create_protocol=ClientProtocol,
                ) as protocol:
                    RNS.log("Protocol obtained from connect", RNS.LOG_DEBUG)
                    self.connection = protocol
                    
                    # Store reference to the quic connection for sending
                    self._quic = protocol._quic
                    RNS.log(f"Stored _quic reference: {self._quic}", RNS.LOG_DEBUG)
                    
                    # Send initial data to establish stream
                    stream_id = 0
                    self.stream_id = stream_id
                    
                    self.online = True
                    RNS.log("QUIC connection established", RNS.LOG_INFO)
                    
                    # Start keepalive
                    self._start_keepalive()
                    
                    # Keep connection alive
                    try:
                        await asyncio.sleep(3600)  # Keep for 1 hour
                    except asyncio.CancelledError:
                        RNS.log("Connection cancelled", RNS.LOG_DEBUG)
                    finally:
                        self.online = False
                        RNS.log("Connection closed", RNS.LOG_DEBUG)
                        
            except Exception as e:
                RNS.log("Failed to connect to QUIC server: "+str(e), RNS.LOG_ERROR)
                import traceback
                RNS.log(traceback.format_exc(), RNS.LOG_ERROR)
                self.online = False
        
        if self.event_loop:
            RNS.log("Starting QUIC connection task in event loop", RNS.LOG_DEBUG)
            # Schedule the coroutine in the event loop
            asyncio.run_coroutine_threadsafe(connect_async(), self.event_loop)
        else:
            RNS.log("Event loop not available, cannot start connection", RNS.LOG_ERROR)
    
    def _start_keepalive(self):
        """Start keepalive mechanism."""
        def send_keepalive():
            while self.online:
                time.sleep(self.keepalive_interval)
                if self.online and self.connection:
                    # Send PING frame
                    try:
                        if self.event_loop:
                            asyncio.run_coroutine_threadsafe(
                                self._send_ping(),
                                self.event_loop
                            )
                    except Exception as e:
                        RNS.log("Error sending keepalive: "+str(e), RNS.LOG_DEBUG)
        
        keepalive_thread = threading.Thread(target=send_keepalive, daemon=True)
        keepalive_thread.start()
    
    async def _send_ping(self):
        """Send QUIC PING frame."""
        if self._quic:
            self._quic.send_ping()
    
    async def _run_in_loop(self, func):
        """Run a function in the asyncio event loop"""
        func()
    
    def process_incoming(self, data):
        """Handle incoming data from Transport."""
        self.rxb += len(data)
        # Data is already handled in _handle_events
    
    def process_outgoing(self, data):
        """Send data to QUIC peer."""
        if not self.online or not self._quic:
            return
        
        try:
            if self.stream_id is not None:
                # Schedule the send operation on the asyncio event loop
                def send_data_async():
                    try:
                        RNS.log(f"Sending {len(data)} bytes to QUIC server (stream_id={self.stream_id})", RNS.LOG_DEBUG)
                        RNS.log(f"_quic object: {self._quic}", RNS.LOG_DEBUG)
                        if self._quic is None:
                            RNS.log("ERROR: _quic is None!", RNS.LOG_ERROR)
                        else:
                            self._quic.send_stream_data(self.stream_id, data, end_stream=False)
                            RNS.log(f"Successfully called send_stream_data on stream_id={self.stream_id}", RNS.LOG_DEBUG)
                            RNS.log(f"Sent data (first 64 bytes): {data[:64].hex()}", RNS.LOG_DEBUG)
                            # Call transmit to actually send the data
                            if self.connection:
                                self.connection.transmit()
                                RNS.log(f"Called transmit() to flush data", RNS.LOG_DEBUG)
                            self.txb += len(data)
                    except Exception as e:
                        RNS.log("Error sending QUIC data: "+str(e), RNS.LOG_ERROR)
                        import traceback
                        RNS.log(traceback.format_exc(), RNS.LOG_ERROR)
                
                # Schedule on the event loop
                if self.event_loop:
                    asyncio.run_coroutine_threadsafe(self._run_in_loop(send_data_async), self.event_loop)
                else:
                    RNS.log("No event loop available for sending data", RNS.LOG_ERROR)
        except Exception as e:
            RNS.log("Error in process_outgoing: "+str(e), RNS.LOG_ERROR)
    
    def __str__(self):
        return "QUICInterface["+self.name+"/"+self.target_host+":"+str(self.target_port)+"]"

# Register the interface
interface_class = QUICInterface


