from mirage.libs import ble,bt,utils
from mirage.libs import io as m_io
from mirage.core import module
from mirage.core import app
from scapy.all import *
from configparser import ConfigParser
from pprint import pprint

class bt_pair(module.WirelessModule):
    def __init__(self):
        self.technology = "bluetooth"
        self.type = "action"
        self.description = "Pairing module for Bluetooth devices"
        self.args = {
            'INTERFACE': 'hci0',
            'TARGET': 'XX:XX:XX:XX:XX:XX',
            'TIMEOUT': 15,
            'SSP': True,
            'IO_CAPABILITY': 'DisplayYesNo',
            'OOB': 0,
            'MITM': 3,
            'PIN_CODE': 1234,
            'VERBOSE': True
        }
        self.bt_receiver = bt.BluetoothReceiver(interface=self.args['INTERFACE'])
        self.bt_emitter = bt.BluetoothEmitter(interface=self.args['INTERFACE'])
        self.app = app.App()
        # Received packets //Debug purpose
        self.q = []
        # Set the event listeners
        self.set_events()
        # Authentication result
        self.auth = None

    def run(self):
        """
            Initiate the connection.
        """
        self.q = []
        self.connect()

    def get_io_capabilities(self):
        """
            Return the different capability modes.
        """
        return ('DisplayYesNo', 'NoInputNoOutput', 'KeyboardOnly', 'DisplayOnly', 'NoInputNoOutput')

    def set_events(self):
        """
            Set the event listeners.
        """
        self.bt_receiver.onEvent("*", callback=self.show)
        self.bt_receiver.onEvent("BluetoothConnectResponse", callback=self._start_pairing)
        self.bt_receiver.onEvent("BluetoothPINCodeRequest", callback=self._PIN_Code_Reply)
        self.bt_receiver.onEvent("BluetoothLinkKeyRequest", callback=self._Link_Key_Reply)
        self.bt_receiver.onEvent("BluetoothIOCapabilityRequest", callback=self._IO_Capability_Reply)
        self.bt_receiver.onEvent("BluetoothUserConfirmationRequest", callback=self._User_Confirmation_Reply)
        self.bt_receiver.onEvent("BluetoothPasskeyRequest", callback=self._Passkey_Reply)
        self.bt_receiver.onEvent("BluetoothAuthenticationComplete", callback=self._Authentication_Complete)

    def show(self, packet):
        """
            Display a packet and  it to the packet queue.
        """
        if self.args['VERBOSE']:
            m_io.info('Packet received:')
        self.q.append(packet)
        packet.show()

    def connect(self, target=None, timeout=None ):
        """
            Initiate the connection to the target.
        """
        if target is None:
            target=self.args['TARGET']
        if timeout is None:
            timeout=self.args['TIMEOUT']

        # Set simple pairing mode to enable IO Capability Request
        if self.args['SSP']:
            self.bt_emitter.sendp(bt.BluetoothSimplePairingMode(mode=1))

        self.bt_emitter.sendp(bt.BluetoothConnect(target))
        while not self.bt_receiver.isConnected() and timeout > 0:
            timeout -= 1
            utils.wait(seconds=1)
        if self.bt_receiver.isConnected():
            if self.args['VERBOSE']:
                m_io.success(f"Connected to {target}")
            return self.ok()
        else:
            if self.args['VERBOSE']:
                m_io.fail(f"Failed to connect to {target}.")
            return self.nok()

    def _start_pairing(self, packet):
        """
            Send a pairing request to the target.
        """
        if self.args['VERBOSE']:
            m_io.info('Sending Pairing Request..')
        self.auth_success = None
        self.bt_emitter.send(bt.BluetoothPairing())

    def _Link_Key_Reply(self, packet):
        """
            Reply to a Link Key request.
        """
        if self.args['VERBOSE']:
            m_io.info('Replying to the Link Key Request..')

        link_key = None
        try:
            ini = ConfigParser().read(f"/var/lib/bluetooth/{self.args['INTERFACE']}/{self.args['TARGET']}/info")
            link_key = ini['LinkKey']['Key']
        except:
            pass
        if link_key:
            if self.args['VERBOSE']:
                m_io.success(f'Link Key: {link_key}')
            self.bt_emitter.send(bt.BluetoothLinkKeyReply(self.args['TARGET'], link_key=link_key))
        else:
            if self.args['VERBOSE']:
                m_io.fail(f'No Link Key found.')
            self.bt_emitter.send(bt.BluetoothLinkKeyReply(self.args['TARGET']))

    def _IO_Capability_Reply(self, packet, IOCapability=None, OOBDataPresent=None, AuthenticationRequirements=None):
        """
            Reply to an IO Capability request.
        """
        if self.args['VERBOSE']:
            m_io.info('Replying to the IO Capability Request..')

        if IOCapability is None:
            IOCapability=self.args['IO_CAPABILITY']
        if OOBDataPresent is None:
            OOBDataPresent=self.args['OOB']
        if AuthenticationRequirements is None:
            AuthenticationRequirements=self.args['MITM']

        self.bt_emitter.send(bt.BluetoothIOCapabilityReply(address=self.args['TARGET'],
                                                           IOCapability=IOCapability,
                                                           OOBDataPresent=OOBDataPresent,
                                                           AuthenticationRequirements=AuthenticationRequirements))

    def _PIN_Code_Reply(self, packet):
        """
            Reply to an LMP pairing (PIN code) request.
        """
        if self.args['VERBOSE']:
            m_io.info('Replying to an LMP pairing (PIN code) request.. ')
        self.bt_emitter.send(bt.BluetoothPINCodeReply(address=self.args['TARGET'], pin_code=self.args['PIN_CODE']))

    def _User_Confirmation_Reply(self, packet):
        """
             Reply to an User Confirmation Request.
        """
        if self.args['VERBOSE']:
            m_io.info('Replying to the User Confirmation Request..')
        self.bt_emitter.send(bt.BluetoothUserConfirmationReply(address=self.args['TARGET']))

    def _Passkey_Reply(self, packet):
        """
            Reply to a Passkey request.
        """
        if self.args['VERBOSE']:
            m_io.info('Replying to the Passkey Request..')
        passkey = input('Enter passkey: ')
        self.bt_emitter.send(bt.BluetoothPasskeyReply(address=self.args['TARGET'], passkey=passkey))

    def _Authentication_Complete(self, packet):
        """
            Notify that the Authentication has been completed.
        """
        if packet.status == 0:
            self.auth = {'success':True, 'reason':None}
            if self.args['VERBOSE']:
                m_io.success('Authentication Complete!')
        else:
            self.auth = {'success':False, 'reason': packet.status_desc}
            if self.args['VERBOSE']:
                m_io.fail(f'Authentication Failed: {packet.status_desc}.')

    def disconnect(self):
        if self.bt_receiver.isConnected():
            self.bt_emitter.sendp(bt.BluetoothDisconnect())
        while self.bt_receiver.isConnected():
            utils.wait(seconds=1)
