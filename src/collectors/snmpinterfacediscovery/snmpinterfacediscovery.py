# coding=utf-8

"""
The SNMPInterfaceDiscovery is designed for collecting interface data from
remote SNMP-enabled devices such as routers and switches using SNMP IF_MIB

This collector does not collect anything. It simply discovers interfaces worth
polling. It should be run infrequently by the Diamond scheduler.

#### Installation

The snmpinterfacediscovery.py module should be installed into your Diamond
installation collectors directory. This directory is defined
in diamond.cfg under the *collectors_path* directive. This defaults to
*/usr/lib/diamond/collectors/* on Ubuntu.

The SNMPInterfaceDiscovery.cfg file should be installed into your diamond
installation config directory. This directory is defined
in diamond.cfg under the *collectors_config_path* directive. This defaults to
*/etc/diamond/* on Ubuntu.

Once the collector is installed and configured, you can wait for diamond to
pick up the new collector automatically, or simply restart diamond.

#### Configuration

Below is an example configuration for the SNMPInterfaceDiscovery. The collector
can collect data any number of devices by adding configuration sections
under the *devices* header. Since this is just for interface discovery, you
should run it infrequently, like every 4 hours.

```
    # Options for SNMPInterfaceDiscovery
    path = interface
    interval = 14400

    [devices]

    [[router1]]
    host = router1.example.com
    port = 161
    community = public

    [[router2]]
    host = router1.example.com
    port = 161
    community = public
```

Note: If you modify the SNMPInterfaceDiscovery configuration, you will need to
restart diamond, and wait for it to generate an oids.lst file.

#### Dependencies

 * pysmnp

"""

import os
import sys
import time
import re

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)),
                                'snmp'))
from snmp import SNMPCollector as parent_SNMPCollector
from diamond.metric import Metric
import diamond.convertor


class SNMPInterfaceDiscovery(parent_SNMPCollector):

    OIDFILE = '/etc/diamond/collectors/SNMPInterfacePoll.d/oids.lst'

    OIDS = []

    # IF-MIB OID
    IF_MIB_INDEX_OID = '1.3.6.1.2.1.2.2.1.1'
    IF_MIB_NAME_OID = '1.3.6.1.2.1.31.1.1.1.1'
    IF_MIB_TYPE_OID = '1.3.6.1.2.1.2.2.1.3'
    IF_MIB_STATUS_OID = '1.3.6.1.2.1.2.2.1.8'

    # A list of helpful OID objects to poll.
    VENDOR_DESC_OID = '1.3.6.1.2.1.1.1.0'
    IOS_XE_CPU_OID = '1.3.6.1.4.1.9.9.109.1.1.1.1.7.2'
    CISCO_LEGACY_CPU_OID = '1.3.6.1.4.1.9.9.109.1.1.1.1.7.1'
    GENERIC_CPU_OID = '1.3.6.1.4.1.1588.2.1.1.1.26.1.0'

    # A list of IF-MIB the 32bit counters to walk
    IF_MIB_GAUGE_OID_TABLE = {
                              'ifInDiscards': '1.3.6.1.2.1.2.2.1.13',
                              'ifInErrors': '1.3.6.1.2.1.2.2.1.14',
                              'ifOutDiscards': '1.3.6.1.2.1.2.2.1.19',
                              'ifOutErrors': '1.3.6.1.2.1.2.2.1.20'
                             }

    # A list of IF-MIB 64bit counters to walk
    IF_MIB_COUNTER_OID_TABLE = {
                                'ifInOctets': '1.3.6.1.2.1.31.1.1.1.6',
                                'ifInUcastPkts': '1.3.6.1.2.1.31.1.1.1.7',
                                'ifInMulticastPkts': '1.3.6.1.2.1.31.1.1.1.8',
                                'ifInBroadcastPkts': '1.3.6.1.2.1.31.1.1.1.9',
                                'ifOutOctets': '1.3.6.1.2.1.31.1.1.1.10',
                                'ifOutUcastPkts': '1.3.6.1.2.1.31.1.1.1.11',
                                'ifOutMulticastPkts': '1.3.6.1.2.1.31.1.1.1.12',
                                'ifOutBroadcastPkts': '1.3.6.1.2.1.31.1.1.1.13'
                               }

    # A list of interface types, and statuses we care about
    IF_TYPES = ['6','135','131']
    IF_STATUS = ['1']

    def get_default_config_help(self):
        config_help = super(SNMPInterfaceDiscovery,
                            self).get_default_config_help()
        config_help.update({
        })
        return config_help

    def get_default_config(self):
        """
        Override SNMPCollector.get_default_config method to provide
        default_config for the SNMPInterfaceDiscovery
        """
        default_config = super(SNMPInterfaceDiscovery,
                               self).get_default_config()
        default_config['path'] = 'interface'
        default_config['byte_unit'] = ['bit', 'byte']
        return default_config

    def parse_oid_file(self, host):
        curOids = []
        oidlist = []
        
        # Open the all hosts OID list file and delete all entries for the host
        # we are discovering.  
        try:
            with open(self.OIDFILE) as f:
                curOids = f.read().splitlines()
        except IOError:
            self.log.info('File', self.OIDFILE, 'does not exist, creating it..')

        # Delete the current host's OIDs from the list until we re-discover it.
        oidlist = [item for item in curOids if host not in item]
        return oidlist

    def get_interface_indexes(self, device, host, port, community):
        ifIndexes = []

        # Get Interface Indexes
        ifIndexOid = '.'.join([self.IF_MIB_INDEX_OID])
        ifIndexData = self.walk(ifIndexOid, host, port, community)
        ifIndexes = [v for v in ifIndexData.values()]
        for ifIndex in ifIndexes:
            # Get Interface Type
            ifTypeOid = '.'.join([self.IF_MIB_TYPE_OID, ifIndex])
            ifTypeData = self.get(ifTypeOid, host, port, community)
            ifStatusOid = '.'.join([self.IF_MIB_STATUS_OID, ifIndex])
            ifStatusData = self.get(ifStatusOid, host, port, community)

            if (ifTypeData[ifTypeOid] not in self.IF_TYPES or
                    ifStatusData[ifStatusOid] not in self.IF_STATUS):
            # Skip Interface, not a status or type we care about.
                continue
            # Get Interface Name
            ifNameOid = '.'.join([self.IF_MIB_NAME_OID, ifIndex])
            ifNameData = self.get(ifNameOid, host, port, community)
            ifName = ifNameData[ifNameOid]
            # Remove quotes from string
            ifName = re.sub(r'(\"|\')', '', ifName)
            if ifTypeData[ifTypeOid] == '135':
                self.make_counter_desc(device, host, community, ifName, ifIndex)
            else:
                self.make_gauge_desc(device, host, community, ifName, ifIndex)
                self.make_counter_desc(device, host, community, ifName, ifIndex)
    def make_gauge_desc(self, device, host, community, ifName, ifIndex):
        for gaugeName, gaugeOid in self.IF_MIB_GAUGE_OID_TABLE.items():
            ifGaugeOid = '.'.join([self.IF_MIB_GAUGE_OID_TABLE[gaugeName],
                                  ifIndex])
            # Get Metric Name and Value
            metricIfDescr = re.sub(r'\W', '_', ifName)
            metricName = '.'.join([metricIfDescr, gaugeName])
            # Get Metric Path
            metricPath = '.'.join(['devices',
                                  device,
                                  self.config['path'],
                                  metricName])
            # Create OID description to write to a file later.
            oidDesc = 'G,{0},{1},{2},{3}'.format(host,
                                                 community,
                                                 ifGaugeOid,
                                                 metricPath
                                                 )
            self.OIDS.append(oidDesc)

    def make_counter_desc(self, device, host, community, ifName, ifIndex):
        counterItems = self.IF_MIB_COUNTER_OID_TABLE.items()
        for counterName, counterOid in counterItems:
            ifCounterOid = '.'.join(
               [self.IF_MIB_COUNTER_OID_TABLE[counterName], ifIndex])

            metricIfDescr = re.sub(r'\W', '_', ifName)
            if counterName in ['ifHCInOctets', 'ifHCOutOctets']:
                for unit in self.config['byte_unit']:
                    # Convert Metric
                    metricName = '.'.join([metricIfDescr,
                                          counterName.replace('Octets',
                                          unit)])

                    # Get Metric Path
                    metricPath = '.'.join(['devices',
                                          device,
                                          self.config['path'],
                                          metricName])
            else:
                metricName = '.'.join([metricIfDescr, counterName])
                # Get Metric Path
                metricPath = '.'.join(['devices',
                                      device,
                                      self.config['path'],
                                      metricName])
                
            oidDesc = 'C,{0},{1},{2},{3}'.format(host,
                                                 community,
                                                 ifCounterOid,
                                                 metricPath
                                                 )
            self.OIDS.append(oidDesc)
    
    def get_environment_oid(self, device, host, port, community):
        vendorData = self.get(self.VENDOR_DESC_OID, host, port, community)
        vendorHexString = vendorData[self.VENDOR_DESC_OID]
        vendorHexString.strip()
        # 494f532d5845 = IOS-XE, so let's get that CPU OID.
        if '494f532d5845' in vendorHexString:
            metricPath = '.'.join(['devices',
                                  device,
                                  'cpu',
                                  '1min_average_percent'])
            oidDesc = 'G,{0},{1},{2},{3}'.format(host,
                                                 community,
                                                 self.IOS_XE_CPU_OID,
                                                 metricPath
                                                 )
            self.OIDS.append(oidDesc)

        # 436973636f = Cisco, so let's get the legacy CPU OID.
        elif '436973636f' in vendorHexString:
            metricPath = '.'.join(['devices',
                                  device,
                                  'cpu',
                                  '1min_average_percent'])
            oidDesc = 'G,{0},{1},{2},{3}'.format(host,
                                                 community,
                                                 self.CISCO_LEGACY_CPU_OID,
                                                 metricPath
                                                 )
            self.OIDS.append(oidDesc)
        # Some other device, let's try the generic CPU OID.
        else:
            metricPath = '.'.join(['devices',
                                  device,
                                  'cpu',
                                  'current_percent'])
            oidDesc = 'G,{0},{1},{2},{3}'.format(host,
                                                 community,
                                                 self.GENERIC_CPU_OID,
                                                 metricPath
                                                 )
            self.OIDS.append(oidDesc)          

    def collect_snmp(self, device, host, port, community):
        """
        Collect SNMP interface OID catalog from device
        """
        self.OIDS = self.parse_oid_file(host)
        self.log.info('Discovering active SNMP interfaces for: %s', device)
        self.get_interface_indexes(device, host, port, community)
        self.get_environment_oid(device, host, port, community)
        with open(self.OIDFILE, 'w') as oidf:
            for oid in self.OIDS:
                oidf.write('{0}\n'.format(oid))
