import logging
import os
import sys
import time

from pydnp3 import opendnp3, openpal, asiopal, asiodnp3
from visitors import *

FILTERS = opendnp3.levels.NORMAL | opendnp3.levels.ALL_COMMS

# ---- Hardcoded lab settings: this host (Vision) is the master ----
HOST = "10.10.54.158"       # the slave (Hulk outstation) to connect to
LOCAL = "0.0.0.0"           # local bind address for the TCP client
PORT = 20000
MASTER_ADDR = 1             # this master's DNP3 link address
OUTSTATION_ADDR = 10        # the slave's (Hulk) DNP3 link address
READS = 10                  # number of Class 0 integrity polls to issue
DELAY = 2                   # seconds between reads

stdout_stream = logging.StreamHandler(sys.stdout)
stdout_stream.setFormatter(logging.Formatter('%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s'))

_log = logging.getLogger(__name__)
_log.addHandler(stdout_stream)
_log.setLevel(logging.DEBUG)


class VisionMaster:
    """
        The Vision master: a DNP3 master (TCP client) with fixed lab settings.

        Connects to the Hulk slave at HOST:PORT, then issues Class 0 integrity
        polls (READ/RESPONSE) on demand. No periodic background scans are
        registered, so captured traffic contains only the reads we issue.
    """

    def __init__(self,
                 soe_handler=None,
                 master_application=None):
        _log.debug('Creating a DNP3Manager.')
        self.log_handler = asiodnp3.ConsoleLogger().Create()
        self.manager = asiodnp3.DNP3Manager(1, self.log_handler)

        _log.debug('Creating the DNP3 channel, a TCP client to {}:{} (local {}).'.format(HOST, PORT, LOCAL))
        self.retry = asiopal.ChannelRetry().Default()
        self.listener = AppChannelListener()
        self.channel = self.manager.AddTCPClient("tcpclient",
                                                 FILTERS,
                                                 self.retry,
                                                 HOST,
                                                 LOCAL,
                                                 PORT,
                                                 self.listener)

        _log.debug('Configuring the DNP3 stack.')
        self.stack_config = asiodnp3.MasterStackConfig()
        self.stack_config.master.responseTimeout = openpal.TimeDuration().Seconds(2)
        # Suppress OpenDNP3's automatic startup traffic so the capture contains
        # only the Class 0 reads we issue: no startup integrity poll, and no
        # disable-unsolicited request at Enable() time.
        self.stack_config.master.startupIntegrityClassMask = opendnp3.ClassField()
        self.stack_config.master.disableUnsolOnStartup = False
        self.stack_config.link.LocalAddr = MASTER_ADDR
        self.stack_config.link.RemoteAddr = OUTSTATION_ADDR

        _log.debug('Adding the master to the channel.')
        self.soe_handler = soe_handler if soe_handler else SOEHandler()
        self.master_application = master_application if master_application else MasterApplication()
        self.master = self.channel.AddMaster("master",
                                             self.soe_handler,
                                             self.master_application,
                                             self.stack_config)

        self.channel.SetLogFilters(openpal.LogFilters(opendnp3.levels.ALL_COMMS))
        self.master.SetLogFilters(openpal.LogFilters(opendnp3.levels.ALL_COMMS))

        _log.debug('Enabling the master. Traffic will start to flow between Master and Outstation.')
        self.master.Enable()
        time.sleep(2)

    def scan_class0(self):
        """Issue a one-shot Class 0 integrity poll (all static data)."""
        _log.info('Scanning Class 0 (static data integrity poll).')
        self.master.ScanClasses(opendnp3.ClassField(opendnp3.ClassField.CLASS_0),
                                opendnp3.TaskConfig().Default())

    def shutdown(self):
        """Tear down the master, channel, and manager in order."""
        del self.master
        del self.channel
        self.manager.Shutdown()


class SOEHandler(opendnp3.ISOEHandler):
    """
        Override ISOEHandler to handle measurements received from the outstation.

        Dispatches each received collection to the matching visitor (see
        visitors.py) and logs the extracted index/value pairs.
    """

    def __init__(self):
        super(SOEHandler, self).__init__()

    def Process(self, info, values):
        """
            Process measurement data received from the Hulk outstation.

        :param info: HeaderInfo.
        :param values: A collection of values received from the outstation.
        """
        visitor_class_types = {
            opendnp3.ICollectionIndexedBinary: VisitorIndexedBinary,
            opendnp3.ICollectionIndexedDoubleBitBinary: VisitorIndexedDoubleBitBinary,
            opendnp3.ICollectionIndexedCounter: VisitorIndexedCounter,
            opendnp3.ICollectionIndexedFrozenCounter: VisitorIndexedFrozenCounter,
            opendnp3.ICollectionIndexedAnalog: VisitorIndexedAnalog,
            opendnp3.ICollectionIndexedBinaryOutputStatus: VisitorIndexedBinaryOutputStatus,
            opendnp3.ICollectionIndexedAnalogOutputStatus: VisitorIndexedAnalogOutputStatus,
            opendnp3.ICollectionIndexedTimeAndInterval: VisitorIndexedTimeAndInterval
        }
        visitor_class = visitor_class_types[type(values)]
        visitor = visitor_class()
        values.Foreach(visitor)
        for index, value in visitor.index_and_value:
            log_string = 'SOEHandler.Process {0}\theaderIndex={1}\tdata_type={2}\tindex={3}\tvalue={4}'
            _log.debug(log_string.format(info.gv, info.headerIndex, type(values).__name__, index, value))

    def Start(self):
        _log.debug('In SOEHandler.Start')

    def End(self):
        _log.debug('In SOEHandler.End')


class MasterApplication(opendnp3.IMasterApplication):
    def __init__(self):
        super(MasterApplication, self).__init__()

    # Overridden method
    def AssignClassDuringStartup(self):
        _log.debug('In MasterApplication.AssignClassDuringStartup')
        return False

    # Overridden method
    def OnClose(self):
        _log.debug('In MasterApplication.OnClose')

    # Overridden method
    def OnOpen(self):
        _log.debug('In MasterApplication.OnOpen')

    # Overridden method
    def OnReceiveIIN(self, iin):
        _log.debug('In MasterApplication.OnReceiveIIN')

    # Overridden method
    def OnTaskComplete(self, info):
        _log.debug('In MasterApplication.OnTaskComplete')

    # Overridden method
    def OnTaskStart(self, type, id):
        _log.debug('In MasterApplication.OnTaskStart')


class AppChannelListener(asiodnp3.IChannelListener):
    """
        Override IChannelListener in this manner to implement application-specific
        channel behavior.
    """

    def __init__(self):
        super(AppChannelListener, self).__init__()

    def OnStateChange(self, state):
        _log.debug('In AppChannelListener.OnStateChange: state={}'.format(opendnp3.ChannelStateToString(state)))


def main():
    """Connect to the Hulk slave and issue READS Class 0 reads, DELAY apart."""
    app = VisionMaster()
    try:
        for i in range(READS):
            _log.info('Read {}/{}'.format(i + 1, READS))
            app.scan_class0()
            time.sleep(DELAY)
        time.sleep(3)
    finally:
        app.shutdown()
    # pydnp3 can double-free its C++ objects during interpreter teardown even
    # after a clean shutdown; hard-exit to avoid that abort.
    os._exit(0)


if __name__ == '__main__':
    main()
