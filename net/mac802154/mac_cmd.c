/*
 * MAC commands interface
 *
 * Copyright 2007-2012 Siemens AG
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Written by:
 * Sergey Lapin <slapin@ossfans.org>
 * Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 * Alexander Smirnov <alex.bluesman.smirnov@gmail.com>
 */

#include <linux/skbuff.h>
#include <linux/if_arp.h>

#include <net/ieee802154.h>
#include <net/ieee802154_netdev.h>
#include <net/wpan-phy.h>
#include <net/mac802154.h>
#include <net/nl802154.h>

#include "mac802154.h"

static int mac802154_cmd_assoc_resp(struct sk_buff *skb)
{
	u8 status;
	u16 short_addr;

	if (skb->len != 4)
		return -EINVAL;

	if (skb->pkt_type != PACKET_HOST)
		return 0;

	if (mac_cb(skb)->sa.addr_type != IEEE802154_ADDR_LONG ||
	    !(mac_cb(skb)->flags & MAC_CB_FLAG_INTRAPAN))
		return -EINVAL;

	/* FIXME: check that we requested association ? */

	status = skb->data[3];
	short_addr = skb->data[1] | (skb->data[2] << 8);
	pr_info("Received ASSOC-RESP status %x, addr %hx\n", status,
			short_addr);
	if (status) {
		mac802154_dev_set_short_addr(skb->dev,
				IEEE802154_ADDR_BROADCAST);
		mac802154_dev_set_pan_id(skb->dev,
				IEEE802154_PANID_BROADCAST);
	} else
		mac802154_dev_set_short_addr(skb->dev, short_addr);

	return ieee802154_nl_assoc_confirm(skb->dev, short_addr, status);
}

int mac802154_process_cmd(struct net_device *dev, struct sk_buff *skb)
{
	u8 cmd;

	if (skb->len < 1) {
		pr_warning("Uncomplete command frame!\n");
		goto drop;
	}

	cmd = *(skb->data);
	pr_debug("Command %02x on device %s\n", cmd, dev->name);

	switch (cmd) {
	case IEEE802154_CMD_ASSOCIATION_RESP:
		mac802154_cmd_assoc_resp(skb);
		break;
//	case IEEE802154_CMD_DISASSOCIATION_NOTIFY:
//		mac802154_cmd_disassoc_notify(skb);
//		break;
	default:
		pr_debug("Frame type is not supported yet\n");
		goto drop;
	}


	kfree_skb(skb);
	return NET_RX_SUCCESS;

drop:
	kfree_skb(skb);
	return NET_RX_DROP;
}

static int mac802154_send_cmd(struct net_device *dev,
			      struct ieee802154_addr *addr,
			      struct ieee802154_addr *saddr,
			      const u8 *buf, int len)
{
	struct sk_buff *skb;
	int err, hlen, tlen;

	BUG_ON(dev->type != ARPHRD_IEEE802154);

	//skb = alloc_skb(LL_ALLOCATED_SPACE(dev) + len, GFP_KERNEL);
	hlen = LL_RESERVED_SPACE(dev);
	tlen = dev->needed_tailroom;
	skb = alloc_skb(hlen + tlen + len, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	skb_reserve(skb, LL_RESERVED_SPACE(dev));

	skb_reset_network_header(skb);

	mac_cb(skb)->flags = IEEE802154_FC_TYPE_MAC_CMD | MAC_CB_FLAG_ACKREQ;
	mac_cb(skb)->seq = ieee802154_mlme_ops(dev)->get_dsn(dev);
	err = dev_hard_header(skb, dev, ETH_P_IEEE802154, addr, saddr, len);
	if (err < 0) {
		kfree_skb(skb);
		return err;
	}

	skb_reset_mac_header(skb);
	memcpy(skb_put(skb, len), buf, len);

	skb->dev = dev;
	skb->protocol = htons(ETH_P_IEEE802154);

	return dev_queue_xmit(skb);
}


int mac802154_send_beacon_req(struct net_device *dev)
{
	struct ieee802154_addr addr;
	struct ieee802154_addr saddr;
	u8 cmd = IEEE802154_CMD_BEACON_REQ;
	addr.addr_type = IEEE802154_ADDR_SHORT;
	addr.short_addr = IEEE802154_ADDR_BROADCAST;
	addr.pan_id = IEEE802154_PANID_BROADCAST;
	saddr.addr_type = IEEE802154_ADDR_NONE;
	return mac802154_send_cmd(dev, &addr, &saddr, &cmd, 1);
}

static int mac802154_mlme_data_req(struct net_device *dev,
				   struct ieee802154_addr *addr)
{
	struct ieee802154_addr saddr;
	u8 buf[1];
	int pos = 0;

	saddr.addr_type = IEEE802154_ADDR_LONG;
	saddr.pan_id = addr->pan_id;
	memcpy(saddr.hwaddr, dev->dev_addr, IEEE802154_ADDR_LEN);

	buf[pos++] = IEEE802154_CMD_DATA_REQ;

	return mac802154_send_cmd(dev, addr, &saddr, buf, pos);
}

static int mac802154_mlme_assoc_req(struct net_device *dev,
				    struct ieee802154_addr *addr,
				    u8 channel, u8 page, u8 cap)
{
	struct ieee802154_addr saddr;
	u8 buf[2];
	int rc, pos = 0;

	saddr.addr_type = IEEE802154_ADDR_LONG;
	saddr.pan_id = IEEE802154_PANID_BROADCAST;
	memcpy(saddr.hwaddr, dev->dev_addr, IEEE802154_ADDR_LEN);


	/* FIXME: set PIB/MIB info */
	mac802154_dev_set_pan_id(dev, addr->pan_id);
	mac802154_dev_set_page_channel(dev, page, channel);
	mac802154_dev_set_ieee_addr(dev);

	buf[pos++] = IEEE802154_CMD_ASSOCIATION_REQ;
	buf[pos++] = cap;

	printk("sending assoc_req\n");
	rc = mac802154_send_cmd(dev, addr, &saddr, buf, pos);
	if (rc < 0)
		goto err;

	// FIXME we should sleep aResponseWaitTime
	msleep(1);

	printk("sending data_req\n");
	rc = mac802154_mlme_data_req(dev, addr);
err:
	return rc;
}

static int mac802154_mlme_start_req(struct net_device *dev,
				    struct ieee802154_addr *addr,
				    u8 channel, u8 page,
				    u8 bcn_ord, u8 sf_ord,
				    u8 pan_coord, u8 blx,
				    u8 coord_realign)
{
	BUG_ON(addr->addr_type != IEEE802154_ADDR_SHORT);

	mac802154_dev_set_pan_id(dev, addr->pan_id);
	mac802154_dev_set_short_addr(dev, addr->short_addr);
	mac802154_dev_set_ieee_addr(dev);
	mac802154_dev_set_page_channel(dev, page, channel);

	/* FIXME: add validation for unused parameters to be sane
	 * for SoftMAC
	 */
	ieee802154_nl_start_confirm(dev, IEEE802154_SUCCESS);

	return 0;
}

static struct wpan_phy *mac802154_get_phy(const struct net_device *dev)
{
	struct mac802154_sub_if_data *priv = netdev_priv(dev);

	BUG_ON(dev->type != ARPHRD_IEEE802154);

	return to_phy(get_device(&priv->hw->phy->dev));
}

struct ieee802154_reduced_mlme_ops mac802154_mlme_reduced = {
	.get_phy = mac802154_get_phy,
};

struct ieee802154_mlme_ops mac802154_mlme_wpan = {
	.assoc_req = mac802154_mlme_assoc_req,
	.get_phy = mac802154_get_phy,
	.start_req = mac802154_mlme_start_req,
	.scan_req = mac802154_mlme_scan_req,
	.get_pan_id = mac802154_dev_get_pan_id,
	.get_short_addr = mac802154_dev_get_short_addr,
	.get_dsn = mac802154_dev_get_dsn,
};
