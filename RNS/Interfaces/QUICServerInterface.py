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
import os
import RNS

# Import aioquic if available
try:
    import importlib.util
    if importlib.util.find_spec('aioquic') != None:
        import asyncio
        from aioquic.asyncio import connect, serve
        from aioquic.asyncio.protocol import QuicConnectionProtocol
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
        self.event_loop = None
        self.event_loop_thread = None
        self.stream_id = None
        self.data_queue = []
        self.connection_lock = threading.Lock()
        RNS.log(f"[DEBUG] QUICServerInterface.__init__: connection_lock created: {self.connection_lock}", RNS.LOG_DEBUG)
        
        # Start asyncio event loop in separate thread
        self._start_event_loop()
        
        # Start connection
        self._connect()
        
        RNS.log("QUICInterface configured for "+self.target_host+":"+str(self.target_port), RNS.LOG_INFO)
    
    def _create_quic_config(self):
        """Create QUIC configuration based on obfuscation profile."""
        config = QuicConfiguration(is_client=True)
        
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
                
                # aioquic.connect returns an async context manager that yields the protocol
                async with connect(
                    self.target_host,
                    self.target_port,
                    configuration=self.quic_config,
                ) as protocol:
                    self.connection = protocol
                    
                    # Send initial data to establish stream
                    stream_id = 0
                    self.stream_id = stream_id
                    
                    # Start receiving data
                    self.event_loop.create_task(self._handle_events())
                    
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
                
            except Exception as e:
                RNS.log("Failed to connect to QUIC server: "+str(e), RNS.LOG_ERROR)
                self.online = False
        
        if self.event_loop:
            asyncio.run_coroutine_threadsafe(connect_async(), self.event_loop)
    
    async def _handle_events(self):
        """Handle QUIC connection events."""
        try:
            while True:
                events = self.connection.session.receive_datagram()
                if events:
                    for event in events:
                        if isinstance(event, StreamDataReceived):
                            data = event.data
                            # Send data to Transport
                            def process():
                                self.owner.inbound(data, self)
                            threading.Thread(target=process, daemon=True).start()
                        
                        elif isinstance(event, ConnectionTerminated):
                            RNS.log("QUIC connection terminated", RNS.LOG_INFO)
                            self.online = False
                            break
                        
                        elif isinstance(event, StreamReset):
                            RNS.log("QUIC stream reset", RNS.LOG_WARNING)
                
                await asyncio.sleep(0.01)
        except Exception as e:
            RNS.log("Error in QUIC event handler: "+str(e), RNS.LOG_ERROR)
            self.online = False
    
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
        if self.connection:
            self.connection.ping()
    
    def process_incoming(self, data):
        """Handle incoming data from Transport."""
        self.rxb += len(data)
        # Data is already handled in _handle_events
    
    def process_outgoing(self, data):
        """Send data to QUIC peer."""
        if not self.online or not self.connection:
            return
        
        try:
            if self.stream_id is not None:
                def send():
                    try:
                        self.connection.send_stream_data(self.stream_id, data, end_stream=False)
                        self.connection.send_datagram_frame(data)
                        self.txb += len(data)
                    except Exception as e:
                        RNS.log("Error sending QUIC data: "+str(e), RNS.LOG_ERROR)
                
                if self.event_loop:
                    asyncio.run_coroutine_threadsafe(send(), self.event_loop)
        except Exception as e:
            RNS.log("Error in process_outgoing: "+str(e), RNS.LOG_ERROR)
    
    def __str__(self):
        return "QUICInterface["+self.name+"/"+self.target_host+":"+str(self.target_port)+"]"

# Register the interface
interface_class = QUICInterface


# Register the interface
interface_class = QUICInterface


class QUICServerInterface(Interface):
    """
    QUIC server interface for Reticulum using aioquic.
    Listens for incoming QUIC connections.
    """
    
    BITRATE_GUESS = 100*1000*1000  # 100 Mbps
    DEFAULT_IFAC_SIZE = 16
    HW_MTU = 1472
    DEFAULT_KEEPALIVE_INTERVAL = 30
    
    def __init__(self, owner, configuration):
        super().__init__()
        
        if not HAS_AIOQUIC:
            RNS.log("Using the QUIC server interface requires the 'aioquic' module to be installed.", RNS.LOG_CRITICAL)
            RNS.log("You can install it with the command: pip install aioquic", RNS.LOG_CRITICAL)
            RNS.panic()
        
        # Parse configuration
        c = Interface.get_config_obj(configuration)
        name = c["name"]
        listen_ip = c.get("listen_ip", "0.0.0.0")
        listen_port = int(c.get("listen_port", 4433))
        
        # Certificate and key for server mode
        certificate_file = c.get("certificate_file", None)
        private_key_file = c.get("private_key_file", None)
        
        # Obfuscation profile
        obf_profile = c.get("obfuscation_profile", "chrome")
        if obf_profile not in OBFUSCATION_PROFILES:
            obf_profile = "chrome"
        
        # Keepalive
        self.keepalive_interval = float(c.get("keepalive_interval", self.DEFAULT_KEEPALIVE_INTERVAL))
        
        # Store configuration
        self.name = name
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.owner = owner
        self.online = False
        self.obf_profile = obf_profile
        self.profile_config = OBFUSCATION_PROFILES[obf_profile]
        self.certificate_file = certificate_file
        self.private_key_file = private_key_file
        
        # Connection tracking
        self.connections = {}  # Track multiple client connections
        self.event_loop = None
        self.event_loop_thread = None
        self.protocol_class = None
        
        # Setup QUIC configuration
        self.quic_config = self._create_quic_config()
        
        # Start asyncio event loop in separate thread
        self._start_event_loop()
        
        # Start server
        self._start_server()
        
        RNS.log("QUICServerInterface configured to listen on "+self.listen_ip+":"+str(self.listen_port), RNS.LOG_INFO)
    
    def _create_quic_config(self):
        """Create QUIC configuration based on obfuscation profile."""
        from aioquic.h3.connection import H3_ALPN
        config = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
        
        certificate_loaded = False
        
        # Load certificates if provided
        if self.certificate_file and self.private_key_file:
            try:
                # Expand ~ to home directory
                cert_path = os.path.expanduser(self.certificate_file)
                key_path = os.path.expanduser(self.private_key_file)
                RNS.log(f"Looking for certificate at {cert_path} and key at {key_path}", RNS.LOG_DEBUG)
                if os.path.exists(cert_path) and os.path.exists(key_path):
                    RNS.log(f"Certificate files exist, loading...", RNS.LOG_DEBUG)
                    try:
                        config.load_cert_chain(cert_path, key_path)
                        RNS.log("Loaded certificate and key for QUIC server successfully", RNS.LOG_DEBUG)
                        certificate_loaded = True
                    except Exception as load_error:
                        RNS.log(f"Error loading certificate: {load_error}", RNS.LOG_ERROR)
                        import traceback
                        RNS.log(traceback.format_exc(), RNS.LOG_ERROR)
                else:
                    RNS.log(f"Certificate files not found at {cert_path} (exists: {os.path.exists(cert_path)}), {key_path} (exists: {os.path.exists(key_path)})", RNS.LOG_WARNING)
            except Exception as e:
                RNS.log("Could not load certificate/key files: "+str(e), RNS.LOG_WARNING)
        
        # If no certificate loaded, create a self-signed one
        if not certificate_loaded:
            try:
                from cryptography import x509
                from cryptography.hazmat.primitives import hashes, serialization
                from cryptography.hazmat.primitives.asymmetric import rsa
                from datetime import datetime, timedelta
                
                RNS.log("Creating self-signed certificate for QUIC server", RNS.LOG_INFO)
                
                # Generate private key
                private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                
                # Create certificate
                subject = issuer = x509.Name([
                    x509.NameAttribute(x509.NameOID.COMMON_NAME, u'localhost'),
                ])
                certificate = x509.CertificateBuilder().subject_name(
                    subject
                ).issuer_name(
                    issuer
                ).public_key(
                    private_key.public_key()
                ).serial_number(
                    x509.random_serial_number()
                ).not_valid_before(
                    datetime.utcnow()
                ).not_valid_after(
                    datetime.utcnow() + timedelta(days=365)
                ).sign(private_key, hashes.SHA256())
                
                # Determine certificate file paths
                if self.certificate_file and self.private_key_file:
                    cert_path = os.path.expanduser(self.certificate_file)
                    key_path = os.path.expanduser(self.private_key_file)
                else:
                    # Default to reticulum directory
                    ret_dir = RNS.Reticulum.configdir
                    cert_path = os.path.join(ret_dir, f"cert_{self.name}.crt")
                    key_path = os.path.join(ret_dir, f"cert_{self.name}.key")
                
                RNS.log(f"Creating certificate at {cert_path}", RNS.LOG_DEBUG)
                
                # Ensure directory exists
                cert_dir = os.path.dirname(cert_path)
                if cert_dir:
                    os.makedirs(cert_dir, exist_ok=True)
                
                # Write certificate and key to files
                cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
                key_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                
                with open(cert_path, 'wb') as f:
                    f.write(cert_pem)
                with open(key_path, 'wb') as f:
                    f.write(key_pem)
                
                RNS.log(f"Self-signed certificate created and saved to {cert_path}", RNS.LOG_INFO)
                
                # Load into config using file paths
                config.load_cert_chain(cert_path, key_path)
                
            except Exception as e:
                RNS.log("Failed to create self-signed certificate: "+str(e), RNS.LOG_ERROR)
                RNS.log("Install cryptography package: pip install cryptography", RNS.LOG_ERROR)
        
        # Apply cipher suites from profile
        if 'cipher_suites' in self.profile_config:
            config.cipher_suites = self.profile_config['cipher_suites']
        
        # Apply transport parameters from profile
        if 'transport_params' in self.profile_config:
            for param, value in self.profile_config['transport_params'].items():
                setattr(config, param, value)
        
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
    
    def _start_server(self):
        """Start QUIC server."""
        RNS.log("_start_server() called, scheduling async server start", RNS.LOG_DEBUG)
        async def start_server_async():
            try:
                RNS.log("Starting QUIC server on "+self.listen_ip+":"+str(self.listen_port)+"...", RNS.LOG_DEBUG)
                
                # Define protocol handler - subclass QuicConnectionProtocol
                class ServerProtocol(QuicConnectionProtocol):
                    def __init__(self, quic, stream_handler=None):
                        RNS.log(f"ServerProtocol.__init__ called with quic={quic}, stream_handler={stream_handler}", RNS.LOG_DEBUG)
                        self.parent = self.parent_ref
                        self._quic = quic
                        # Call parent constructor
                        super().__init__(quic, stream_handler=stream_handler)
                        
                    def connection_made(self, transport):
                        """Called when a connection is made."""
                        RNS.log(f"ServerProtocol.connection_made called with transport={transport}", RNS.LOG_DEBUG)
                        RNS.log(f"This means the datagram endpoint was created successfully!", RNS.LOG_INFO)
                        super().connection_made(transport)
                        
                    def connection_lost(self, exc):
                        """Called when a connection is lost."""
                        RNS.log(f"ServerProtocol.connection_lost called with exc={exc}", RNS.LOG_DEBUG)
                        super().connection_lost(exc)
                        
                    def datagram_received(self, data, addr):
                        """Called when a datagram is received."""
                        RNS.log(f"ServerProtocol.datagram_received: {len(data)} bytes from {addr}", RNS.LOG_DEBUG)
                        RNS.log(f"Datagram data (first 100 bytes): {data[:100].hex()}", RNS.LOG_DEBUG)
                        try:
                            super().datagram_received(data, addr)
                            RNS.log("Successfully passed datagram to parent protocol", RNS.LOG_DEBUG)
                        except Exception as e:
                            RNS.log(f"Error in parent datagram_received: {e}", RNS.LOG_ERROR)
                            import traceback
                            RNS.log(traceback.format_exc(), RNS.LOG_ERROR)
                        
                    def quic_event_received(self, event):
                        RNS.log(f"Server received QUIC event: {type(event).__name__}", RNS.LOG_DEBUG)
                        RNS.log(f"Event details: {event}", RNS.LOG_DEBUG)
                        
                        # Call parent to ensure proper handling
                        super().quic_event_received(event)
                        
                        if isinstance(event, StreamDataReceived):
                            data = event.data
                            stream_id = event.stream_id
                            RNS.log(f"Server received {len(data)} bytes on stream_id={stream_id} from QUIC client", RNS.LOG_INFO)
                            RNS.log(f"Data hex dump (first 64 bytes): {data[:64].hex()}", RNS.LOG_DEBUG)
                            
                            # Store this connection so we can send replies
                            # Use thread-safe assignment since process_outgoing runs on different thread
                            with self.parent.connection_lock:
                                self.parent.active_connection = self._quic
                                self.parent.active_stream_id = stream_id
                                self.parent.active_protocol = self  # Store the protocol for transmit()
                            
                            # Send data to Transport
                            def process():
                                self.parent.owner.inbound(data, self.parent)
                            threading.Thread(target=process, daemon=True).start()
                        
                        elif isinstance(event, ConnectionTerminated):
                            RNS.log("QUIC client connection terminated", RNS.LOG_DEBUG)
                
                # Store parent reference in the class
                ServerProtocol.parent_ref = self
                
                # Return the protocol class directly
                create_protocol = ServerProtocol
                
                self.protocol_class = ServerProtocol
                
                # Start server
                RNS.log("Starting aioquic serve()...", RNS.LOG_DEBUG)
                RNS.log(f"Configuration: host={self.listen_ip}, port={self.listen_port}", RNS.LOG_DEBUG)
                has_cert = hasattr(self.quic_config, 'certificate') and self.quic_config.certificate is not None
                RNS.log(f"Config has certificate: {has_cert}", RNS.LOG_DEBUG)
                try:
                    # Start the server
                    server = await serve(
                        host=self.listen_ip,
                        port=self.listen_port,
                        configuration=self.quic_config,
                        create_protocol=create_protocol,
                    )
                    RNS.log(f"serve() returned: {server}", RNS.LOG_DEBUG)
                    
                    # Wait a bit for the endpoint to be fully initialized
                    RNS.log("Waiting for endpoint initialization...", RNS.LOG_DEBUG)
                    await asyncio.sleep(0.5)
                    
                    # Check if transport is set
                    if hasattr(server, '_transport') and server._transport is not None:
                        RNS.log(f"Transport created: {server._transport}", RNS.LOG_DEBUG)
                    else:
                        RNS.log("WARNING: Transport not created yet!", RNS.LOG_WARNING)
                    
                    self.online = True
                    RNS.log("QUIC server started and listening", RNS.LOG_INFO)
                    RNS.log(f"Server object type: {type(server)}, methods: {dir(server)}", RNS.LOG_DEBUG)
                    
                    # Keep the server running
                    # The serve() function should block, but if it doesn't, we need to keep the event loop alive
                    try:
                        # Wait forever to keep the server running
                        RNS.log("Server event loop started, waiting for connections...", RNS.LOG_DEBUG)
                        RNS.log(f"Event loop is running: {asyncio.get_running_loop().is_running()}", RNS.LOG_DEBUG)
                        tick = 0
                        while True:
                            await asyncio.sleep(1)
                            tick += 1
                            if tick % 10 == 0:
                                RNS.log(f"Server still running, tick={tick}, loop running: {asyncio.get_running_loop().is_running()}", RNS.LOG_DEBUG)
                    except asyncio.CancelledError:
                        RNS.log("Server cancelled", RNS.LOG_DEBUG)
                        self.online = False
                        server.close()
                
                except Exception as e:
                    RNS.log("Failed to start QUIC server: "+str(e), RNS.LOG_ERROR)
                    import traceback
                    RNS.log(traceback.format_exc(), RNS.LOG_ERROR)
                    self.online = False
                
            except Exception as e:
                RNS.log("Failed to start QUIC server: "+str(e), RNS.LOG_ERROR)
                self.online = False
        
        if self.event_loop:
            RNS.log("Scheduling start_server_async in event loop", RNS.LOG_DEBUG)
            RNS.log(f"Event loop thread is alive: {self.event_loop_thread.is_alive()}", RNS.LOG_DEBUG)
            future = asyncio.run_coroutine_threadsafe(start_server_async(), self.event_loop)
            RNS.log(f"Scheduled start_server_async, future: {future}", RNS.LOG_DEBUG)
        else:
            RNS.log("ERROR: event_loop is None, cannot start server!", RNS.LOG_ERROR)
    
    def _transmit_in_loop(self):
        """Transmit queued data in the event loop"""
        async def do_transmit():
            if hasattr(self, 'active_protocol') and self.active_protocol:
                self.active_protocol.transmit()
        
        if self.event_loop:
            asyncio.run_coroutine_threadsafe(do_transmit(), self.event_loop)
    
    async def _run_in_loop(self, func):
        """Run a function in the asyncio event loop"""
        func()
    
    def process_incoming(self, data):
        """Handle incoming data from Transport."""
        self.rxb += len(data)
        # Data handling is done in the protocol handler
    
    def process_outgoing(self, data):
        """Send data to all connected QUIC clients."""
        RNS.log(f"[SERVER] process_outgoing called with {len(data)} bytes on QUIC server", RNS.LOG_INFO)
        RNS.log(f"[SERVER] Has active_connection: {hasattr(self, 'active_connection')}", RNS.LOG_INFO)
        if not self.online:
            RNS.log("QUIC server not online, dropping data", RNS.LOG_DEBUG)
            return
        
        try:
            # Schedule the send operation on the asyncio event loop
            def send_data_async():
                with self.connection_lock:
                    if hasattr(self, 'active_connection') and self.active_connection:
                        RNS.log(f"Sending {len(data)} bytes to QUIC client on stream_id={self.active_stream_id}", RNS.LOG_DEBUG)
                        RNS.log(f"Data hex dump (first 64 bytes): {data[:64].hex()}", RNS.LOG_DEBUG)
                        
                        # Send data using the stored connection
                        if hasattr(self.active_connection, 'send_stream_data'):
                            self.active_connection.send_stream_data(self.active_stream_id, data, end_stream=False)
                            RNS.log(f"Successfully called send_stream_data on server", RNS.LOG_DEBUG)
                            # Call transmit to actually send the data
                            if hasattr(self, 'active_protocol') and self.active_protocol:
                                self.active_protocol.transmit()
                                RNS.log(f"Called transmit() on server", RNS.LOG_DEBUG)
                            self.txb += len(data)
                        else:
                            RNS.log("ERROR: active_connection has no send_stream_data method", RNS.LOG_ERROR)
                    else:
                        RNS.log("No active connection to send data to", RNS.LOG_DEBUG)
            
            # Schedule on the event loop
            if self.event_loop:
                asyncio.run_coroutine_threadsafe(self._run_in_loop(send_data_async), self.event_loop)
            else:
                RNS.log("No event loop available for sending data", RNS.LOG_ERROR)
        except Exception as e:
            RNS.log("Error in process_outgoing: "+str(e), RNS.LOG_ERROR)
    
    def __str__(self):
        return "QUICServerInterface["+self.name+"/"+self.listen_ip+":"+str(self.listen_port)+"]"


interface_class = QUICServerInterface
