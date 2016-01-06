#<a name="top"></a>httpfieldmerge intermediate plugin for IPFIXcol

## Table of Contents
1.  [Description](#description)
2.  [Installation](#installation)
3.  [Configuration](#configuration)
4.  [Contact](#contact)
    *  [Reporting bugs](#contact_bugs)
    *  [Other](#contact_other)

##<a name="description"></a> Plugin description

This intermediate plugin for IPFIXcol that merges HTTP-related fields from various vendors
into one unified set, such that analysis applications can always rely on the unified
set of fields. The following fields are currently supported:

 - HTTP hostname
 - HTTP URL
 - HTTP user agent (UA)

 Specifically, this plugin performs only a single task:

 - Replace the IE definitions of HTTP-related fields with those of the unified
        set of fields. As such, only templates are modified (and data records are
        not).

HTTP-related fields from the following vendors are currently supported:

 - Cisco,               PEN: 9
 - Masaryk University,  PEN: 16982
 - INVEA-TECH,          PEN: 39499
 - ntop,                PEN: 35632

The unified set of fields uses PEN '44913'.

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

This plugin requires no configuration.

##<a name="contact"></a> Contact
###<a name="contact_bugs"></a> Reporting bugs

Please report any bugs using the GitHub [issue tracker](https://github.com/SecDorks/ipfixcol/issues).

###<a name="contact"></a> Other

In case you have generic comments, questions or suggestions, please feel free to drop us an e-mail at `kirc&secdorks.net`.

[Back to Top](#top)
