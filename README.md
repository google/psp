# Linux Kernel PSP Preview Release

This document gives a quick overview of the TCP-PSP release for Linux.
The code is shared as is, for demonstration purposes only. It is not
ready for netdev@ submission: it does not follow upstream style, for
one.  A list of caveats is documented as follows:

 1. All the changes are consolidated into one big patch, not cleanly
 separated into per-feature patches yet. Cleaner patch set will come
 later in the future.
 2. Device drivers are not included.  Reference implementation will arrive soon.
 3. Stateful (SADB) version can leak keys, e.g.
     - On device down, after which napi id is invalid
     - During bursts of events, such as segfault of a process with many connections
 4. IPV6 only
 5. The code adds fields to struct sk_buff, but it does not integrate with existing infra (e.g., XFRM).
 6. Integration tests are available in https://github.com/google/neper. Standalone selftests will come later.
 6. The code does not yet clear key structures.

## PSP Architecture Specification

https://github.com/google/psp/blob/main/doc/PSP_Arch_Spec.pdf

## License

The code is provided under the terms of the GNU General Public License version 2.

https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html

## Kernel Config Options

Enable PSP

  * Symbol: INET_PSP
  * Location: -> Networking support (NET [=y]) -> Networking Options -> TCP/IP networking (INET =y)]

## Device Driver Expectations

### Implements PSP virtual function(s) in net_device_ops

```
	int			(*ndo_get_spi_and_key)(struct net_device *dev,
						       struct psp_spi_tuple *tuple);
	int			(*ndo_psp_register_key)(struct net_device *dev, __be32 spi,
							const struct psp_key *key,
						        struct psp_key_idx *index);
	int			(*ndo_psp_unregister_key)(struct net_device *dev, u32 index);
```

> Note: ndo_psp_register_key and ndo_psp_unregister_key are optional and only
> required if the encryption keys need to be stored in the NIC HW (stateful).

### TX data path
Add the following snippet in the beginning of the virtual function `ndo_start_xmit` and the corresponding error handling:

```
@@ ... @@
...
+#include <net/psp_dev.h>
...

@@ ... @@ netdev_tx_t xxx_xmit(struct *skb, struct net_device *dev)
...
+       if (psp_dev_encapsulate(skb) < 0)
+               goto psp_encap_error;
+
...
```

### RX data path
Add the following snippet in the rx path after the skb is allocated, the corresponding error handling:

```
@@ ... @@
...
+#include <net/psp_dev.h>
...

@@ ... @@ struct sk_buff *xxx_rx_skb(...)
...
+       if (psp_dev_decapsulate(skb) < 0)
+               goto psp_decap_error;
+
...
```


## Sanity Check

```
sysctl -n net.ipv4.psp_enable_conn
```

## Contact

https://github.com/google/psp/issues

