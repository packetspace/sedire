# `sedire`

`sedire` is a multicast reflector and proxy.  It is most commonly used with service discovery protocols, including DNS-SD/mDNS and DIAL/SSDP, to enable clients and servers to exist on different (V)LANs or even in different locations.  `sedire` makes it possible to keep devices and users isolated and appropriately firewalled even when dynamic service discovery protocols are needed between the networks.

## Project Status

`sedire` is still under active development, but the current version of code-complete and fully-functional.  Users are free to build `sedire` as-is and test it out in their environment.  The remaining key items blocking the formal initial release are:

* Full set of documentation (including manpage)
* Init scripts (i.e. `systemd` unit file)

The goal for the launch of the initial version of `sedire` is by the end of 2022Q3.

## Contributing

Contributions of code and documentation are welcome, as are bug reports and suggestions!  Please see the project's [CONTRIBUTING](CONTRIBUTING.md) page for more information.

## Example Usage

Until full documentation is available, the basic operation of `sedire` can be tested as follows:

```
go build github.com/packetspace/sedire
./sedire -MS -i eth0 -i eth1 -l info < /dev/null > /dev/null 2>&1 &
disown
```

This will launch an instance of `sedire` as a daemon with normal logging to the local syslog.  It will be configured for handling standard mDNS and SSDP protocols, which should enable support for DNS-SD and DIAL in most environments.
