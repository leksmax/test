/*
 **************************************************************************
 * Copyright (c) 2017, The Linux Foundation. All rights reserved.
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all copies.
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 **************************************************************************
 */

/*
 * nss_edma_stats.c
 *	NSS EDMA statistics APIs
 */

#include "nss_stats.h"
#include "nss_tx_rx_common.h"
#include "nss_edma_stats.h"

struct nss_edma_stats edma_stats;

/*
 * nss_edma_stats_str_node
 */
static int8_t *nss_edma_stats_str_node[NSS_STATS_NODE_MAX] = {
	"rx_packets",
	"rx_bytes",
	"tx_packets",
	"tx_bytes",
	"rx_queue_0_dropped",
	"rx_queue_1_dropped",
	"rx_queue_2_dropped",
	"rx_queue_3_dropped",
};

/*
 * nss_edma_stats_str_tx
 */
static int8_t *nss_edma_stats_str_tx[NSS_EDMA_STATS_TX_MAX] = {
	"tx_err",
	"tx_dropped",
	"desc_cnt"
};

/*
 * nss_edma_stats_str_rx
 */
static int8_t *nss_edma_stats_str_rx[NSS_EDMA_STATS_RX_MAX] = {
	"rx_csum_err",
	"desc_cnt",
	"qos_err"
};

/*
 * nss_edma_stats_str_txcmpl
 */
static int8_t *nss_edma_stats_str_txcmpl[NSS_EDMA_STATS_TXCMPL_MAX] = {
	"desc_cnt"
};

/*
 * nss_edma_stats_str_rxfill
 */
static int8_t *nss_edma_stats_str_rxfill[NSS_EDMA_STATS_RXFILL_MAX] = {
	"desc_cnt"
};

/*
 * nss_edma_stats_str_port_type
 */
static int8_t *nss_edma_stats_str_port_type[NSS_EDMA_PORT_TYPE_MAX] = {
	"physical_port",
	"virtual_port"
};

/*
 * nss_edma_stats_str_port_ring_map
 */
static int8_t *nss_edma_stats_str_port_ring_map[NSS_EDMA_PORT_RING_MAP_MAX] = {
	"rx_ring",
	"tx_ring"
};

/*
 * nss_edma_stats_str_err_map
 */
static int8_t *nss_edma_stats_str_err_map[NSS_EDMA_ERR_STATS_MAX] = {
	"axi_rd_err",
	"axi_wr_err",
	"rx_desc_fifo_full_err",
	"rx_buf_size_err",
	"tx_sram_full_err",
	"tx_cmpl_buf_full_err",
	"pkt_len_la64k_err",
	"pkt_len_le33_err",
	"data_len_err",
	"alloc_fail_cnt"
};

/*
 **********************************
 EDMA statistics APIs
 **********************************
 */

/*
 * nss_edma_port_stats_read()
 *	Read EDMA port statistics
 */
static ssize_t nss_edma_port_stats_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	int32_t i;

	/*
	 * max output lines = #stats + start tag line + end tag line + three blank lines
	 */
	uint32_t max_output_lines = (NSS_STATS_NODE_MAX + 2) + 3;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint64_t *stats_shadow;
	struct nss_stats_data *data = fp->private_data;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	/*
	 * Note: The assumption here is that we do not have more than 64 stats
	 */
	stats_shadow = kzalloc(64 * 8, GFP_KERNEL);
	if (unlikely(stats_shadow == NULL)) {
		nss_warning("Could not allocate memory for local shadow buffer");
		kfree(lbuf);
		return 0;
	}

	size_wr = scnprintf(lbuf, size_al, "edma stats start:\n\n");

	/*
	 * Common node stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "edma port %d stats:\n\n", data->edma_id);

	spin_lock_bh(&nss_top_main.stats_lock);
	for (i = 0; (i < NSS_STATS_NODE_MAX); i++) {
		stats_shadow[i] = edma_stats.port[data->edma_id].port_stats[i];
	}

	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; (i < NSS_STATS_NODE_MAX); i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_edma_stats_str_node[i], stats_shadow[i]);
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nedma stats end\n\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(stats_shadow);

	return bytes_read;
}

/*
 * nss_edma_port_type_stats_read()
 *	Read EDMA port type
 */
static ssize_t nss_edma_port_type_stats_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	/*
	 * max output lines = #stats + start tag line + end tag line + three blank lines
	 */
	uint32_t max_output_lines = (1 + 2) + 3;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint64_t port_type;
	struct nss_stats_data *data = fp->private_data;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	size_wr = scnprintf(lbuf, size_al, "edma port type start:\n\n");
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "edma port %d type:\n\n", data->edma_id);

	/*
	 * Port type
	 */
	spin_lock_bh(&nss_top_main.stats_lock);
	port_type = edma_stats.port[data->edma_id].port_type;
	spin_unlock_bh(&nss_top_main.stats_lock);

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"port_type = %s\n", nss_edma_stats_str_port_type[port_type]);

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nedma stats end\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);

	return bytes_read;
}

/*
 * nss_edma_port_ring_map_stats_read()
 *	Read EDMA port ring map
 */
static ssize_t nss_edma_port_ring_map_stats_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	int32_t i;

	/*
	 * max output lines = #stats + start tag line + end tag line + three blank lines
	 */
	uint32_t max_output_lines = (4 + 2) + 3;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint64_t *stats_shadow;
	struct nss_stats_data *data = fp->private_data;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	/*
	 * Note: The assumption here is that we do not have more than 64 stats
	 */
	stats_shadow = kzalloc(64 * 8, GFP_KERNEL);
	if (unlikely(stats_shadow == NULL)) {
		nss_warning("Could not allocate memory for local shadow buffer");
		kfree(lbuf);
		return 0;
	}

	size_wr = scnprintf(lbuf, size_al, "edma port ring map start:\n\n");

	/*
	 * Port ring map
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "edma port %d ring map:\n\n", data->edma_id);
	spin_lock_bh(&nss_top_main.stats_lock);
	for (i = 0; i < NSS_EDMA_PORT_RING_MAP_MAX; i++) {
		stats_shadow[i] = edma_stats.port[data->edma_id].port_ring_map[i];
	}

	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; i < NSS_EDMA_PORT_RING_MAP_MAX; i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_edma_stats_str_port_ring_map[i], stats_shadow[i]);
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nedma stats end\n\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(stats_shadow);

	return bytes_read;
}

/*
 * nss_edma_txring_stats_read()
 *	Read EDMA Tx ring stats
 */
static ssize_t nss_edma_txring_stats_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	int32_t i;

	/*
	 * max output lines = #stats + start tag line + end tag line + three blank lines
	 */
	uint32_t max_output_lines = (NSS_EDMA_STATS_TX_MAX + 2) + 3;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint64_t *stats_shadow;
	struct nss_stats_data *data = fp->private_data;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	/*
	 * Note: The assumption here is that we do not have more than 64 stats
	 */
	stats_shadow = kzalloc(64 * 8, GFP_KERNEL);
	if (unlikely(stats_shadow == NULL)) {
		nss_warning("Could not allocate memory for local shadow buffer");
		kfree(lbuf);
		return 0;
	}

	size_wr = scnprintf(lbuf, size_al, "edma Tx ring stats start:\n\n");

	/*
	 * Tx ring stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "Tx ring %d stats:\n\n", data->edma_id);
	spin_lock_bh(&nss_top_main.stats_lock);
	for (i = 0; i < NSS_EDMA_STATS_TX_MAX; i++) {
		stats_shadow[i] = edma_stats.tx_stats[data->edma_id][i];
	}

	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; i < NSS_EDMA_STATS_TX_MAX; i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_edma_stats_str_tx[i], stats_shadow[i]);
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nedma Tx ring stats end\n\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(stats_shadow);

	return bytes_read;
}

/*
 * nss_edma_rxring_stats_read()
 *	Read EDMA rxring stats
 */
static ssize_t nss_edma_rxring_stats_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	int32_t i;

	/*
	 * max output lines = #stats + start tag line + end tag line + three blank lines
	 */
	uint32_t max_output_lines = (NSS_EDMA_STATS_RX_MAX + 2) + 3;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint64_t *stats_shadow;
	struct nss_stats_data *data = fp->private_data;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	/*
	 * Note: The assumption here is that we do not have more than 64 stats
	 */
	stats_shadow = kzalloc(64 * 8, GFP_KERNEL);
	if (unlikely(stats_shadow == NULL)) {
		nss_warning("Could not allocate memory for local shadow buffer");
		kfree(lbuf);
		return 0;
	}

	size_wr = scnprintf(lbuf, size_al, "edma Rx ring stats start:\n\n");

	/*
	 * RX ring stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "Rx ring %d stats:\n\n", data->edma_id);
	spin_lock_bh(&nss_top_main.stats_lock);
	for (i = 0; i < NSS_EDMA_STATS_RX_MAX; i++) {
		stats_shadow[i] = edma_stats.rx_stats[data->edma_id][i];
	}

	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; i < NSS_EDMA_STATS_RX_MAX; i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_edma_stats_str_rx[i], stats_shadow[i]);
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nedma Rx ring stats end\n\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(stats_shadow);

	return bytes_read;
}

/*
 * nss_edma_txcmplring_stats_read()
 *	Read EDMA txcmplring stats
 */
static ssize_t nss_edma_txcmplring_stats_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	int32_t i;

	/*
	 * max output lines = #stats + start tag line + end tag line + three blank lines
	 */
	uint32_t max_output_lines = (NSS_EDMA_STATS_TXCMPL_MAX + 2) + 3;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint64_t *stats_shadow;
	struct nss_stats_data *data = fp->private_data;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	/*
	 * Note: The assumption here is that we do not have more than 64 stats
	 */
	stats_shadow = kzalloc(64 * 8, GFP_KERNEL);
	if (unlikely(stats_shadow == NULL)) {
		nss_warning("Could not allocate memory for local shadow buffer");
		kfree(lbuf);
		return 0;
	}

	size_wr = scnprintf(lbuf, size_al, "edma Tx cmpl ring stats start:\n\n");

	/*
	 * Tx cmpl ring stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "Tx cmpl ring %d stats:\n\n", data->edma_id);
	spin_lock_bh(&nss_top_main.stats_lock);
	for (i = 0; i < NSS_EDMA_STATS_TXCMPL_MAX; i++) {
		stats_shadow[i] = edma_stats.txcmpl_stats[data->edma_id][i];
	}

	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; i < NSS_EDMA_STATS_TXCMPL_MAX; i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_edma_stats_str_txcmpl[i], stats_shadow[i]);
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nedma Tx cmpl ring stats end\n\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(stats_shadow);

	return bytes_read;
}

/*
 * nss_edma_rxfillring_stats_read()
 *	Read EDMA rxfillring stats
 */
static ssize_t nss_edma_rxfillring_stats_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	int32_t i;

	/*
	 * max output lines = #stats + start tag line + end tag line + three blank lines
	 */
	uint32_t max_output_lines = (NSS_EDMA_STATS_RXFILL_MAX + 2) + 3;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint64_t *stats_shadow;
	struct nss_stats_data *data = fp->private_data;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	/*
	 * Note: The assumption here is that we do not have more than 64 stats
	 */
	stats_shadow = kzalloc(64 * 8, GFP_KERNEL);
	if (unlikely(stats_shadow == NULL)) {
		nss_warning("Could not allocate memory for local shadow buffer");
		kfree(lbuf);
		return 0;
	}

	size_wr = scnprintf(lbuf, size_al, "edma Rx fill ring stats start:\n\n");

	/*
	 * Rx fill ring stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "Rx fill ring %d stats:\n\n", data->edma_id);
	spin_lock_bh(&nss_top_main.stats_lock);
	for (i = 0; i < NSS_EDMA_STATS_RXFILL_MAX; i++) {
		stats_shadow[i] = edma_stats.rxfill_stats[data->edma_id][i];
	}

	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; i < NSS_EDMA_STATS_RXFILL_MAX; i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_edma_stats_str_rxfill[i], stats_shadow[i]);
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nedma Rx fill ring stats end\n\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(stats_shadow);

	return bytes_read;
}

/*
 * nss_edma_err_stats_read()
 *      Read EDMA err stats
 */
static ssize_t nss_edma_err_stats_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	int32_t i;

	/*
	 * max output lines = #stats + start tag line + end tag line + three blank lines
	 */
	uint32_t max_output_lines = (NSS_EDMA_ERR_STATS_MAX + 2) + 3;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint64_t *stats_shadow;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	/*
	 * Note: The assumption here is that we do not have more than 64 stats
	 */
	stats_shadow = kzalloc(64 * 8, GFP_KERNEL);
	if (unlikely(stats_shadow == NULL)) {
		nss_warning("Could not allocate memory for local shadow buffer");
		kfree(lbuf);
		return 0;
	}

	size_wr = scnprintf(lbuf, size_al, "edma error stats start:\n\n");

	/*
	 * Common node stats
	 */
	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "edma error stats:\n\n");
	spin_lock_bh(&nss_top_main.stats_lock);

	for (i = 0; (i < NSS_EDMA_ERR_STATS_MAX); i++)
		stats_shadow[i] = edma_stats.misc_err[i];

	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; (i < NSS_EDMA_ERR_STATS_MAX); i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_edma_stats_str_err_map[i], stats_shadow[i]);
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nedma error stats end\n\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(stats_shadow);

	return bytes_read;
}

/*
 * edma_port_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(edma_port)

/*
 * edma_port_type_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(edma_port_type)

/*
 * edma_port_ring_map_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(edma_port_ring_map)

/*
 * edma_txring_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(edma_txring)

/*
 * edma_rxring_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(edma_rxring)

/*
 * edma_txcmplring_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(edma_txcmplring)

/*
 * edma_rxfillring_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(edma_rxfillring)

/*
 * edma_err_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(edma_err)

/*
 * nss_edma_stats_dentry_create()
 *	Create edma statistics debug entry.
 */
void nss_edma_stats_dentry_create(void)
{
	int i;
	struct dentry *edma_d = NULL;
	struct dentry *edma_port_dir_d = NULL;
	struct dentry *edma_port_d = NULL;
	struct dentry *edma_port_type_d = NULL;
	struct dentry *edma_port_stats_d = NULL;
	struct dentry *edma_port_ring_map_d = NULL;
	struct dentry *edma_rings_dir_d = NULL;
	struct dentry *edma_tx_dir_d = NULL;
	struct dentry *edma_tx_d = NULL;
	struct dentry *edma_rx_dir_d = NULL;
	struct dentry *edma_rx_d = NULL;
	struct dentry *edma_txcmpl_dir_d = NULL;
	struct dentry *edma_txcmpl_d = NULL;
	struct dentry *edma_rxfill_dir_d = NULL;
	struct dentry *edma_rxfill_d = NULL;
	struct dentry *edma_err_stats_d = NULL;
	char file_name[10];

	edma_d = debugfs_create_dir("edma", nss_top_main.stats_dentry);
	if (unlikely(edma_d == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/edma directory");
		return;
	}

	/*
	 * edma port stats
	 */
	edma_port_dir_d = debugfs_create_dir("ports", edma_d);
	if (unlikely(edma_port_dir_d == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/edma/ports directory");
		return;
	}

	for (i = 0; i < NSS_EDMA_NUM_PORTS_MAX; i++) {
		memset(file_name, 0, sizeof(file_name));
		snprintf(file_name, sizeof(file_name), "%d", i);

		edma_port_d = debugfs_create_dir(file_name, edma_port_dir_d);
		if (unlikely(edma_port_d == NULL)) {
			nss_warning("Failed to create qca-nss-drv/stats/edma/ports/%d directory", i);
			return;
		}

		edma_port_stats_d = debugfs_create_file("stats", 0400, edma_port_d, (void *)(nss_ptr_t)i, &nss_edma_port_stats_ops);
		if (unlikely(edma_port_stats_d == NULL)) {
			nss_warning("Failed to create qca-nss-drv/stats/edma/ports/%d/stats file", i);
			return;
		}

		edma_port_type_d = debugfs_create_file("type", 0400, edma_port_d, (void *)(nss_ptr_t)i, &nss_edma_port_type_stats_ops);
		if (unlikely(edma_port_type_d == NULL)) {
			nss_warning("Failed to create qca-nss-drv/stats/edma/ports/%d/type file", i);
			return;
		}

		edma_port_ring_map_d = debugfs_create_file("ring_map", 0400, edma_port_d, (void *)(nss_ptr_t)i, &nss_edma_port_ring_map_stats_ops);
		if (unlikely(edma_port_ring_map_d == NULL)) {
			nss_warning("Failed to create qca-nss-drv/stats/edma/ports/%d/ring_map file", i);
			return;
		}
	}

	/*
	 *  edma error stats
	 */
	edma_err_stats_d = NULL;
	edma_err_stats_d = debugfs_create_file("err_stats", 0400, edma_d, &nss_top_main, &nss_edma_err_stats_ops);
	if (unlikely(edma_port_stats_d == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/edma/%d/err_stats file", 0);
		return;
	}

	/*
	 * edma ring stats
	 */
	edma_rings_dir_d = debugfs_create_dir("rings", edma_d);
	if (unlikely(edma_rings_dir_d == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/edma/rings directory");
		return;
	}

	/*
	 * edma tx ring stats
	 */
	edma_tx_dir_d = debugfs_create_dir("tx", edma_rings_dir_d);
	if (unlikely(edma_tx_dir_d == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/edma/rings/tx directory");
		return;
	}

	for (i = 0; i < NSS_EDMA_NUM_TX_RING_MAX; i++) {
		memset(file_name, 0, sizeof(file_name));
		scnprintf(file_name, sizeof(file_name), "%d", i);
		edma_tx_d = debugfs_create_file(file_name, 0400, edma_tx_dir_d, (void *)(nss_ptr_t)i, &nss_edma_txring_stats_ops);
		if (unlikely(edma_tx_d == NULL)) {
			nss_warning("Failed to create qca-nss-drv/stats/edma/rings/tx/%d file", i);
			return;
		}
	}

	/*
	 * edma rx ring stats
	 */
	edma_rx_dir_d = debugfs_create_dir("rx", edma_rings_dir_d);
	if (unlikely(edma_rx_dir_d == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/edma/rings/rx directory");
		return;
	}

	for (i = 0; i < NSS_EDMA_NUM_RX_RING_MAX; i++) {
		memset(file_name, 0, sizeof(file_name));
		scnprintf(file_name, sizeof(file_name), "%d", i);
		edma_rx_d = debugfs_create_file(file_name, 0400, edma_rx_dir_d, (void *)(nss_ptr_t)i, &nss_edma_rxring_stats_ops);
		if (unlikely(edma_rx_d == NULL)) {
			nss_warning("Failed to create qca-nss-drv/stats/edma/rings/rx/%d file", i);
			return;
		}
	}

	/*
	 * edma tx cmpl ring stats
	 */
	edma_txcmpl_dir_d = debugfs_create_dir("txcmpl", edma_rings_dir_d);
	if (unlikely(edma_txcmpl_dir_d == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/edma/rings/txcmpl directory");
		return;
	}

	for (i = 0; i < NSS_EDMA_NUM_TXCMPL_RING_MAX; i++) {
		memset(file_name, 0, sizeof(file_name));
		scnprintf(file_name, sizeof(file_name), "%d", i);
		edma_txcmpl_d = debugfs_create_file(file_name, 0400, edma_txcmpl_dir_d, (void *)(nss_ptr_t)i, &nss_edma_txcmplring_stats_ops);
		if (unlikely(edma_txcmpl_d == NULL)) {
			nss_warning("Failed to create qca-nss-drv/stats/edma/rings/txcmpl/%d file", i);
			return;
		}
	}

	/*
	 * edma rx fill ring stats
	 */
	edma_rxfill_dir_d = debugfs_create_dir("rxfill", edma_rings_dir_d);
	if (unlikely(edma_rxfill_dir_d == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/edma/rings/rxfill directory");
		return;
	}

	for (i = 0; i < NSS_EDMA_NUM_RXFILL_RING_MAX; i++) {
		memset(file_name, 0, sizeof(file_name));
		scnprintf(file_name, sizeof(file_name), "%d", i);
		edma_rxfill_d = debugfs_create_file(file_name, 0400, edma_rxfill_dir_d, (void *)(nss_ptr_t)i, &nss_edma_rxfillring_stats_ops);
		if (unlikely(edma_rxfill_d == NULL)) {
			nss_warning("Failed to create qca-nss-drv/stats/edma/rings/rxfill/%d file", i);
			return;
		}
	}
}

/*
 * nss_edma_metadata_port_stats_sync()
 *	Handle the syncing of EDMA port statistics.
 */
void nss_edma_metadata_port_stats_sync(struct nss_ctx_instance *nss_ctx, struct nss_edma_port_stats_sync *nepss)
{
	uint16_t i, j = 0;
	struct nss_top_instance *nss_top = nss_ctx->nss_top;

	spin_lock_bh(&nss_top->stats_lock);

	/*
	 * edma port stats
	 * We process a subset of port stats since msg payload is not enough to hold all ports at once.
	 */
	for (i = nepss->start_port; i < nepss->end_port; i++) {
		int k;

		edma_stats.port[i].port_stats[NSS_STATS_NODE_RX_PKTS] += nepss->port_stats[j].node_stats.rx_packets;
		edma_stats.port[i].port_stats[NSS_STATS_NODE_RX_BYTES] += nepss->port_stats[j].node_stats.rx_bytes;
		edma_stats.port[i].port_stats[NSS_STATS_NODE_TX_PKTS] += nepss->port_stats[j].node_stats.tx_packets;
		edma_stats.port[i].port_stats[NSS_STATS_NODE_TX_BYTES] += nepss->port_stats[j].node_stats.tx_bytes;

		for (k = 0; k < NSS_MAX_NUM_PRI; k++) {
			edma_stats.port[i].port_stats[NSS_STATS_NODE_RX_QUEUE_0_DROPPED + k] += nepss->port_stats[j].node_stats.rx_dropped[k];
		}

		edma_stats.port[i].port_type = nepss->port_stats[j].port_type;
		edma_stats.port[i].port_ring_map[NSS_EDMA_PORT_RX_RING] = nepss->port_stats[j].edma_rx_ring;
		edma_stats.port[i].port_ring_map[NSS_EDMA_PORT_TX_RING] = nepss->port_stats[j].edma_tx_ring;
		j++;
	}

	spin_unlock_bh(&nss_top->stats_lock);
}

/*
 * nss_edma_metadata_ring_stats_sync()
 *	Handle the syncing of EDMA ring statistics.
 */
void nss_edma_metadata_ring_stats_sync(struct nss_ctx_instance *nss_ctx, struct nss_edma_ring_stats_sync *nerss)
{
	int32_t i;
	struct nss_top_instance *nss_top = nss_ctx->nss_top;

	spin_lock_bh(&nss_top->stats_lock);

	/*
	 * edma tx ring stats
	 */
	for (i = 0; i < NSS_EDMA_NUM_TX_RING_MAX; i++) {
		edma_stats.tx_stats[i][NSS_EDMA_STATS_TX_ERR] += nerss->tx_ring[i].tx_err;
		edma_stats.tx_stats[i][NSS_EDMA_STATS_TX_DROPPED] += nerss->tx_ring[i].tx_dropped;
		edma_stats.tx_stats[i][NSS_EDMA_STATS_TX_DESC] += nerss->tx_ring[i].desc_cnt;
	}

	/*
	 * edma rx ring stats
	 */
	for (i = 0; i < NSS_EDMA_NUM_RX_RING_MAX; i++) {
		edma_stats.rx_stats[i][NSS_EDMA_STATS_RX_CSUM_ERR] += nerss->rx_ring[i].rx_csum_err;
		edma_stats.rx_stats[i][NSS_EDMA_STATS_RX_DESC] += nerss->rx_ring[i].desc_cnt;
	}

	/*
	 * edma tx cmpl ring stats
	 */
	for (i = 0; i < NSS_EDMA_NUM_TXCMPL_RING_MAX; i++) {
		edma_stats.txcmpl_stats[i][NSS_EDMA_STATS_TXCMPL_DESC] += nerss->txcmpl_ring[i].desc_cnt;
	}

	/*
	 * edma rx fill ring stats
	 */
	for (i = 0; i < NSS_EDMA_NUM_RXFILL_RING_MAX; i++) {
		edma_stats.rxfill_stats[i][NSS_EDMA_STATS_RXFILL_DESC] += nerss->rxfill_ring[i].desc_cnt;
	}

	spin_unlock_bh(&nss_top->stats_lock);
}

/*
 * nss_edma_metadata_err_stats_sync()
 *	Handle the syncing of EDMA error statistics.
 */
void nss_edma_metadata_err_stats_sync(struct nss_ctx_instance *nss_ctx, struct nss_edma_err_stats_sync *nerss)
{

	struct nss_top_instance *nss_top = nss_ctx->nss_top;

	spin_lock_bh(&nss_top->stats_lock);

	edma_stats.misc_err[NSS_EDMA_AXI_RD_ERR] += nerss->msg_err_stats.axi_rd_err;
	edma_stats.misc_err[NSS_EDMA_AXI_WR_ERR] += nerss->msg_err_stats.axi_wr_err;
	edma_stats.misc_err[NSS_EDMA_RX_DESC_FIFO_FULL_ERR] += nerss->msg_err_stats.rx_desc_fifo_full_err;
	edma_stats.misc_err[NSS_EDMA_RX_BUF_SIZE_ERR] += nerss->msg_err_stats.rx_buf_size_err;
	edma_stats.misc_err[NSS_EDMA_TX_SRAM_FULL_ERR] += nerss->msg_err_stats.tx_sram_full_err;
	edma_stats.misc_err[NSS_EDMA_TX_CMPL_BUF_FULL_ERR] += nerss->msg_err_stats.tx_cmpl_buf_full_err;
	edma_stats.misc_err[NSS_EDMA_PKT_LEN_LA64K_ERR] += nerss->msg_err_stats.pkt_len_la64k_err;
	edma_stats.misc_err[NSS_EDMA_PKT_LEN_LE33_ERR] += nerss->msg_err_stats.pkt_len_le33_err;
	edma_stats.misc_err[NSS_EDMA_DATA_LEN_ERR] += nerss->msg_err_stats.data_len_err;

	spin_unlock_bh(&nss_top->stats_lock);
}
