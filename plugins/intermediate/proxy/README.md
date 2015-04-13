#<a name="top"></a>Proxy intermediate plugin for IPFIXcol

## Table of Contents
1.  [Description](#description)
2.  [Installation](#installation)
3.  [Configuration](#configuration)
4.  [Contact](#contact)
    *  [Reporting bugs](#contact_bugs)
    *  [Other](#contact_other)

##<a name="description"></a> Plugin description

This intermediate plugin for IPFIXcol that 'translates' flows related to Web proxies,
useful for monitoring applications that need to be aware of the real hosts 'behind'
the proxy. If this plugin is not used, all HTTP(S) flows will have the Web proxy as
their source or destination. Specifically, this plugin performs the following tasks:

 - Add 'original' fields to both template and data records.
 - In case the Web proxy is the source of a flow, both the source IPv4/IPv6
        address and port number are copied to the 'original' fields. In case the
        Web proxy is the destination of a flow, both the destination IPv4/IPv6
        address and port number are copied to the 'original' fields.
 - The HTTP host and/or URL are used to resolve the IP address of the 'real'
        host 'behind' the proxy. Only the first result of the domain name resolution
        is used.
 - The IP address obtained by domain name resolution and port are placed in the
        IPv4/IPv6 address and port number fields, respectively.

The enterprise-specific IEs are added to template/data records in the following order
(per IP version):

```
<src_port, src_IP_addr, dst_port, dst_IP_addr>
```

In case a template/data record features both IPv4 and IPv6 IEs, the port number IEs
are added only once (together with the IPv4 IEs), to avoid template/data records that
feature multiple instances of the same IE.

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

This plugin can be configured in the same way as other IPFIXcol components, namely by means
of `startup.xml`. By default, this plugin considers the following ports as proxy ports: 3128, 8080.
This can however be overwritten at run-time, without the need to recompile the source code, as follows:

The configuration section of this proxy in `startup.xml` supports one or more `proxyPort` tags
to be specified, each featuring exactly one port number. This will overwrite the default proxy
port numbers listed above. If no `proxyPort` tags are specified, the default proxy port numbers
are taken.

In addition to proxy ports, the interval in which statistics are reported to the console can be
configured by means of the `statInterval` tag. The configured value must be a non-negative integer,
in seconds. If no `statInterval` tag is present, a default interval of 20 seconds is used.

Example:

```xml
<!-- List of active Intermediate Plugins -->
<intermediatePlugins>
    <proxy>
        <!-- List of proxy ports. Zero or more 'proxyPort' nodes can be specified -->
        <proxyPort>3128</proxyPort>
        <proxyPort>8080</proxyPort>

        <!-- Interval (in seconds) in which plugins statistics are calculated and shown (0: disabled) -->
        <!-- <statInterval>20</statInterval> -->

        <!-- Name servers, for overriding system-wide name servers specified in /etc/resolv.conf -->
        <!-- <nameServer>8.8.8.8</nameServer> -->
        <!-- <nameServer>8.8.4.4</nameServer> -->
    </proxy>
</intermediatePlugins>
```

The run-time configuration of this plugin is reported to stdout (log level 'notice') when starting
IPFIXcol.

##<a name="contact"></a> Contact
###<a name="contact_bugs"></a> Reporting bugs

Please report any bugs using the GitHub [issue tracker](https://github.com/SecDorks/ipfixcol/issues).

###<a name="contact"></a> Other

In case you have generic comments, questions or suggestions, please feel free to drop us an e-mail at `kirc&secdorks.net`.

[Back to Top](#top)
