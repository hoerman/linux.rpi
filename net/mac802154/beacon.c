/*
 * MAC beacon interface
 *
 * Copyright 2007, 2008 Siemens AG
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
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/if_arp.h>
#include <linux/list.h>

#include <net/af_ieee802154.h>
#include <net/nl802154.h>
#include <net/mac802154.h>
#include <net/ieee802154.h>
#include <net/ieee802154_netdev.h>

#include "mac802154.h"
//#include "beacon_hash.h"

/* Beacon frame format per specification is the followinf:
 * Standard MAC frame header:
 * FC (2) SEQ (1)
 * Addressing (4-20)
 * Beacon fields:
 * <Superframe specification> (2)
 * <GTS> (?)
 * <Pending address> (?)
 * <Beacon payload> (?)
 * FCS (2)
 *
 * Superframe specification:
 * bit   Value
 * 15    Association permit
 * 14    PAN coordinator
 * 13    Reserved
 * 12    Battery life extension
 * 8-11  Final CAP slot
 * 4-7   Superframe order
 * 0-3   Beacon order
 *
 * GTS:
 * <GTS specification> (1)
 * <GTS directions> (0-1)
 * <GTS list> (?)
 *
 * Pending address:
 * <Pending address specification> (1)
 * <Pending address list (?)
 *
 * GTS specification:
 * bit   Value
 * 7     GTS permit
 * 3-6   Reserved
 * 0-2   GTS descriptor count
 *
 * Pending address specification:
 * bit   Value
 * 7     Reserved
 * 4-6   Number of extended addresses pendinf
 * 3     Reserved
 * 0-2   Number of short addresses pending
 * */

#define IEEE802154_BEACON_SF_BO_BEACONLESS	(15 << 0)
#define IEEE802154_BEACON_SF_SO(x)		(((x) & 0xf) << 4)
#define IEEE802154_BEACON_SF_SO_INACTIVE	IEEE802154_BEACON_SF_SO(15)
#define IEEE802154_BEACON_SF_PANCOORD		(1 << 14)
#define IEEE802154_BEACON_SF_CANASSOC		(1 << 15)
#define IEEE802154_BEACON_GTS_COUNT(x)		((x) << 0)
#define IEEE802154_BEACON_GTS_PERMIT		(1 << 7)
#define IEEE802154_BEACON_PA_SHORT(x)		(((x) & 7) << 0)
#define IEEE802154_BEACON_PA_LONG(x)		(((x) & 7) << 4)

/* Flags parameter */
#define IEEE802154_BEACON_FLAG_PANCOORD	(1 << 0)
#define IEEE802154_BEACON_FLAG_CANASSOC	(1 << 1)
#define IEEE802154_BEACON_FLAG_GTSPERMIT	(1 << 2)

/* Per spec; optimizations are needed */
struct mac802154_pandsc {
	struct list_head list;
	struct ieee802154_addr addr; /* Contains panid */
	int channel;
	u16 sf;
	bool gts_permit;
	u8 lqi;
/* FIXME: Aging of stored PAN descriptors is not decided yet,
 * because no PAN descriptor storage is implemented yet */
	u32			timestamp;
};

/* at entry to this function we need skb->data to point to start
 * of beacon field and MAC frame already parsed into MAC_CB */
static int parse_beacon_frame(struct sk_buff *skb, u8 *buf,
			      int *flags, struct list_head *al)
{
	int offt = 0;
	u8 gts_spec;
	u8 pa_spec;
	struct mac802154_pandsc *pd;
	u16 sf = skb->data[0] + (skb->data[1] << 8);

	pd = kzalloc(sizeof(*pd), GFP_KERNEL);

	/* Filling-up pre-parsed values */
	pd->lqi = mac_cb(skb)->lqi;
	pd->sf = sf;
	/* FIXME: make sure we do it right */
	memcpy(&pd->addr, &mac_cb(skb)->sa, sizeof(pd->addr));

	/* Supplying our notifiers with data */
	ieee802154_nl_beacon_indic(skb->dev, pd->addr.pan_id,
				   pd->addr.short_addr);
	/* FIXME: We don't cache PAN descriptors yet */
	kfree(pd);

	offt += 2;
	gts_spec = skb->data[offt++];
	/* FIXME !!! */
	if ((gts_spec & 7) != 0) {
		pr_debug("We still don't parse GTS part properly");
		return -ENOTSUPP;
	}
	pa_spec = skb->data[offt++];
	/* FIXME !!! */
	if (pa_spec != 0) {
		pr_debug("We still don't parse PA part properly");
		return -ENOTSUPP;
	}

	*flags = 0;

	if (sf & IEEE802154_BEACON_SF_PANCOORD)
		*flags |= IEEE802154_BEACON_FLAG_PANCOORD;

	if (sf & IEEE802154_BEACON_SF_CANASSOC)
		*flags |= IEEE802154_BEACON_FLAG_CANASSOC;
	BUG_ON(skb->len - offt < 0);
	/* FIXME */
	if (buf && (skb->len - offt > 0))
		memcpy(buf, skb->data + offt, skb->len - offt);
	return 0;
}

int mac802154_process_beacon(struct net_device *dev, struct sk_buff *skb)
{
	int flags;
	int ret;
	ret = parse_beacon_frame(skb, NULL, &flags, NULL);

	/* Here we have cb->sa = coordinator address, and PAN address */

	if (ret < 0) {
		ret = NET_RX_DROP;
		goto fail;
	}
	dev_dbg(&dev->dev, "got beacon from pan %04x\n",
		mac_cb(skb)->sa.pan_id);
	//mac802154_beacon_hash_add(&mac_cb(skb)->sa);
	//mac802154_beacon_hash_dump();
	ret = NET_RX_SUCCESS;
fail:
	kfree_skb(skb);
	return ret;
}
