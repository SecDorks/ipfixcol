#<a name="top"></a>IPFIX Generator input plugin for IPFIXcol

## Table of Contents
1.  [Description](#description)
2.  [Installation](#installation)
3.  [Configuration](#configuration)
4.  [Contact](#contact)
    *  [Reporting bugs](#contact_bugs)
    *  [Other](#contact_other)

##<a name="description"></a> Plugin description

This input plugin for IPFIXcol generates semi-random IPFIX messages for a
configured set of IPFIX Information Elements (IEs). It is therefore especially
useful for performance testing of both IPFIXcol and any processing applications
that rely on data collected by IPFIXcol.

##<a name="installation"></a> Plugin installation

Installation of this plugin is consistent with the installation procedure for
other IPFIXcol components:

```sh
autoreconf -if
./configure
make
make install
```

##<a name="configuration"></a> Plugin configuration

This plugin can be configured in the same way as other IPFIXcol components, namely
by means of `startup.xml`. If no explicit configuration is provided in `startup.xml`,
the plugin will use default values.

Example:

```xml
<collectingProcess>
    <name>IPFIX traffic generator</name>
        <ipfixgenerator>
            <!-- Targeted number of flows per second (default: 1000) -->
            <fps>1000</fps>

            <!-- IPFIXcol will terminate automatically after generating this number of packets (default: 0 - no termination) -->
            <maxPackets>0</maxPackets>

            <!-- IPFIXcol will terminate automatically after generating this number of data records (default: 0 - no termination) -->
            <maxRecords>0</maxRecords>

            <!-- ODID to be used in generated messages (default: 44913) -->
            <odid>44913</odid>
        </ipfixgenerator>
        <exportingProcess>Forward</exportingProcess>
</collectingProcess>
```

The run-time configuration of this plugin is reported to stdout (log level 'notice') when starting
IPFIXcol.

##<a name="contact"></a> Contact
###<a name="contact_bugs"></a> Reporting bugs

Please report any bugs using the GitHub [issue tracker](https://github.com/SecDorks/ipfixcol/issues).

###<a name="contact"></a> Other

In case you have generic comments, questions or suggestions, please feel free to drop us an e-mail at `kirc&secdorks.net`.

[Back to Top](#top)