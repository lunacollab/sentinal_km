// SPDX-License-Identifier: GPL-2.0-only
/*
 * sentinel_ringmap.c -- mmap event ring backend.
 *
 * Lifecycle:
 *   init:  validate the ringmap_size param, misc registration only.
 *   first open: allocate PAGE_ALIGN(capacity) + meta page, wire meta with a
 *          fresh epoch, mark busy.
 *   mmap:  map the whole block MAP_SHARED (producer never writes tail and
 *          consumer writes it, so SHARED is mandatory).
 *   poll:  POLLIN when head != tail.
 *   close: free pages, clear busy.
 *
 * Capacity is runtime-configurable (module param ringmap_size, KiB of data,
 * power of two); resize is allowed only while no consumer holds the device.
 * meta.epoch is a strictly increasing incarnation counter assigned on every
 * open, so a memory mapping that outlives a close/reload is identifiable as
 * stale against the epoch of a fresh open (the re-open handshake).
 *
 * Producer side (sentinel_ringmap_emit) is called from the per-CPU drain
 * workers. Records are appended with a spinlock; head is published with
 * release semantics. Because tail only ever grows and producers never write
 * past (head + free) computed from the last observed tail, a slightly
 * stale tail can only cause an early drop, never an overwrite of unconsumed
 * data.
 */
#include <linux/fs.h>
#include <linux/log2.h>
#include <linux/mm.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/export.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "sentinel_ringmap.h"
#include "sentinel_proto.h"

/* Current data-ring capacity (bytes). Runtime-configurable; never a power
 * of two is obviously rejected up front, so mask == capacity - 1 holds.
 */
static unsigned int ringmap_capacity = SENTINEL_RINGMAP_DEFAULT_CAPACITY;

static struct sentinel_ringmap_meta *ringmap_meta;
static struct page *ringmap_pages;
static bool ringmap_busy;
static spinlock_t ringmap_lock = __SPIN_LOCK_UNLOCKED(ringmap_lock);
static wait_queue_head_t ringmap_waitq =
	__WAIT_QUEUE_HEAD_INITIALIZER(ringmap_waitq);
static atomic64_t ringmap_drop_total = ATOMIC64_INIT(0);

/* m->drop_count / ringmap_drop_total split by event type. Written under
 * ringmap_lock only (the emit drop path); read under the same lock.
 */
static u64 ringmap_drops_by_type[SENTINEL_EV__MAX];

/* Monotonic incarnation counter; the first open sees epoch 1, never 0. */
static unsigned int ringmap_epoch_counter = 1;

static bool ringmap_kib_valid(unsigned int kib)
{
	if (kib < SENTINEL_RINGMAP_MIN_KIB || kib > SENTINEL_RINGMAP_MAX_KIB)
		return false;
	return is_power_of_2(kib);
}

unsigned int sentinel_ringmap_capacity(void)
{
	return READ_ONCE(ringmap_capacity) / 1024;
}

int sentinel_ringmap_resize(unsigned int kib)
{
	unsigned long flags;

	if (!ringmap_kib_valid(kib))
		return -EINVAL;
	spin_lock_irqsave(&ringmap_lock, flags);
	if (ringmap_busy) {
		spin_unlock_irqrestore(&ringmap_lock, flags);
		return -EBUSY;
	}
	WRITE_ONCE(ringmap_capacity, kib * 1024);
	spin_unlock_irqrestore(&ringmap_lock, flags);
	return 0;
}

/* Chunked copy that wraps at the capacity-1 mask; base is the data region,
 * src/dst may overlap the wrap. The mask is a power-of-two minus one, so
 * both the position and the wrap are pure &. */
static void ringmap_copy(void *base, unsigned int at, const void *src,
			 unsigned int len, unsigned int mask)
{
	unsigned int spos = at & mask;
	unsigned int first = min(len, mask + 1 - spos);

	memcpy((char *)base + spos, src, first);
	if (len > first)
		memcpy((char *)base, (const char *)src + first, len - first);
}

void sentinel_ringmap_emit(struct sentinel_capture *cap)
{
	struct sentinel_ringmap_meta *m;
	struct sentinel_event_hdr hdr;
	unsigned int rec_len, head, tail, free_bytes;
	unsigned long flags;
	bool wake = false;

	if (!READ_ONCE(ringmap_meta))
		return;
	if (WARN_ON_ONCE(cap->payload_len > SENTINEL_MAX_PAYLOAD))
		return;

	rec_len = SENTINEL_RING_REC_HDR_SIZE + cap->payload_len;

	spin_lock_irqsave(&ringmap_lock, flags);
	m = READ_ONCE(ringmap_meta);
	if (!m) {
		spin_unlock_irqrestore(&ringmap_lock, flags);
		return;
	}
	head = m->head;
	tail = READ_ONCE(m->tail);
	free_bytes = (m->mask + 1) - (head - tail);
	if (rec_len > free_bytes) {
		m->drop_count++;
		atomic64_inc(&ringmap_drop_total);
		if (cap->event_type < SENTINEL_EV__MAX)
			ringmap_drops_by_type[cap->event_type]++;
		goto out;
	}

	sentinel_event_hdr_fill(&hdr, cap);
	sentinel_event_hdr_sign(&hdr, cap);

	/* rec_len lives right before the hdr in the record. */
	ringmap_copy((char *)ringmap_pages + PAGE_SIZE, head, &rec_len,
		     sizeof(rec_len), m->mask);
	ringmap_copy((char *)ringmap_pages + PAGE_SIZE, head + sizeof(rec_len),
		     &hdr, sizeof(hdr), m->mask);
	ringmap_copy((char *)ringmap_pages + PAGE_SIZE,
		     head + SENTINEL_RING_REC_HDR_SIZE, cap->payload,
		     cap->payload_len, m->mask);
	head += rec_len;
	/* Publish data before the consumer may observe the new head. */
	smp_store_release(&m->head, head);
	wake = true;
out:
	spin_unlock_irqrestore(&ringmap_lock, flags);
	if (wake)
		wake_up_interruptible(&ringmap_waitq);
}
EXPORT_SYMBOL_GPL(sentinel_ringmap_emit);

u64 sentinel_ringmap_drop_total(void)
{
	return atomic64_read(&ringmap_drop_total);
}

/* mmap-ring overflow drops attributable to one event type
 * (sentinel_ringmap_drop_total() is the sum over types).
 */
u64 sentinel_ringmap_dropped_by_type(unsigned int type)
{
	unsigned long flags;
	u64 v;

	if (type >= SENTINEL_EV__MAX)
		return 0;
	spin_lock_irqsave(&ringmap_lock, flags);
	v = ringmap_drops_by_type[type];
	spin_unlock_irqrestore(&ringmap_lock, flags);
	return v;
}

/*
 * Wrap-around selftest for the chunked copy, run at module init (refuse
 * the load on mismatch, like the capture_store differential test). Uses a
 * private linear buffer sized to a ring "capacity" and plays the absolute-
 * offset write back against a mask-indexed reference -- the same mapping
 * the wire format promises. Runs at the default and the smallest runtime
 * capacities to cover both wrap widths.
 */
static int ringmap_copy_selftest_cap(unsigned int capacity)
{
	unsigned int mask = capacity - 1;
	u8 *data = kmalloc(capacity, GFP_KERNEL);
	u8 blob[64];
	unsigned int at;
	unsigned int i;
	int rc = 0;

	if (!data)
		return -ENOMEM;
	memset(data, 0xa5, capacity);

	/* Stride across the ring so every (alignment, wrap-distance) class is
	 * hit, including offsets past the end of the buffer (spos wraps). */
	for (at = 0; at <= capacity; at += 997) {
		for (i = 0; i < sizeof(blob); i++)
			blob[i] = (u8)(i * 13 + at);

		ringmap_copy(data, at, blob, sizeof(blob), mask);
		for (i = 0; i < sizeof(blob); i++) {
			unsigned int pos = (at + i) & mask;

			if (data[pos] != blob[i]) {
				pr_err("sentinel_km: ringmap_copy mismatch cap=%u at=%u\n",
				       capacity, at);
				rc = -EINVAL;
				goto out;
			}
		}
	}

	/* A single record straddling the wrap must read back contiguously. */
	for (i = 0; i < sizeof(blob); i++)
		blob[i] = (u8)(i + 1);
	at = capacity - 16;
	ringmap_copy(data, at, blob, sizeof(blob), mask);
	for (i = 0; i < sizeof(blob); i++) {
		unsigned int pos = (at + i) & mask;

		if (data[pos] != blob[i]) {
			pr_err("sentinel_km: ringmap_copy straddle mismatch cap=%u\n",
			       capacity);
			rc = -EINVAL;
			goto out;
		}
	}
out:
	kfree(data);
	return rc;
}

static int ringmap_copy_selftest(void)
{
	int rc;

	rc = ringmap_copy_selftest_cap(SENTINEL_RINGMAP_DEFAULT_CAPACITY);
	if (rc)
		return rc;
	return ringmap_copy_selftest_cap(SENTINEL_RINGMAP_MIN_KIB * 1024);
}

/* ------------------------------------------------------------------ */
/* non-mmap read() backend (single consumer)                          */
/* ------------------------------------------------------------------ */

static ssize_t ringmap_read_user_wrap(struct sentinel_ringmap_meta *m,
				      unsigned int from, char __user *ubuf,
				      size_t len)
{
	unsigned int pos = from & m->mask;
	size_t first = min_t(size_t, len, m->mask + 1 - pos);

	if (copy_to_user(ubuf, (const char *)ringmap_pages + PAGE_SIZE + pos, first))
		return -EFAULT;
	if (len > first) {
		if (copy_to_user(ubuf + first, (const char *)ringmap_pages + PAGE_SIZE,
				 len - first))
			return -EFAULT;
	}
	return len;
}

static ssize_t ringmap_read(struct file *file, char __user *ubuf,
			    size_t count, loff_t *ppos)
{
	struct sentinel_ringmap_meta *m = READ_ONCE(ringmap_meta);
	unsigned int head, tail, avail;
	u32 rec_len;
	ssize_t ret;
	unsigned long flags;

	if (!m)
		return -ENODEV;
	if (count < sizeof(rec_len))
		return -EINVAL;

retry:
	spin_lock_irqsave(&ringmap_lock, flags);
	m = READ_ONCE(ringmap_meta);
	if (!m) {
		spin_unlock_irqrestore(&ringmap_lock, flags);
		return -ENODEV;
	}

	head = smp_load_acquire(&m->head);
	tail = m->tail;
	avail = head - tail;

	if (avail < sizeof(rec_len)) {
		if (file->f_flags & O_NONBLOCK) {
			ret = -EAGAIN;
			goto out;
		}
		spin_unlock_irqrestore(&ringmap_lock, flags);
		ret = wait_event_interruptible(ringmap_waitq,
			(READ_ONCE(ringmap_meta) &&
			 smp_load_acquire(&READ_ONCE(ringmap_meta)->head) !=
				 READ_ONCE(ringmap_meta)->tail));
		if (ret)
			return ret;
		goto retry;
	}

	ret = ringmap_read_user_wrap(m, tail, (char *)&rec_len, sizeof(rec_len));
	if (IS_ERR_VALUE(ret))
		goto out;

	if (rec_len < sizeof(rec_len) || rec_len > avail || rec_len > count) {
		ret = (rec_len > count) ? -EMSGSIZE : -EFAULT;
		goto out;
	}

	ret = ringmap_read_user_wrap(m, tail, ubuf, rec_len);
	if (IS_ERR_VALUE(ret))
		goto out;

	smp_store_release(&m->tail, tail + rec_len);
	ret = rec_len;
out:
	spin_unlock_irqrestore(&ringmap_lock, flags);
	return ret;
}

/* ------------------------------------------------------------------ */
/* misc device backend                                                 */
/* ------------------------------------------------------------------ */

static int ringmap_open(struct inode *inode, struct file *file)
{
	unsigned int capacity = READ_ONCE(ringmap_capacity);
	unsigned int order = get_order(PAGE_SIZE + capacity);
	struct sentinel_ringmap_meta *m;
	int ret = 0;

	if (!try_module_get(THIS_MODULE))
		return -ENODEV;

	spin_lock_irq(&ringmap_lock);
	if (ringmap_busy) {
		ret = -EBUSY;
		goto out_unlock;
	}
	ringmap_busy = true;
	spin_unlock_irq(&ringmap_lock);

	ringmap_pages = alloc_pages(GFP_KERNEL | __GFP_ZERO, order);
	if (!ringmap_pages) {
		spin_lock_irq(&ringmap_lock);
		ringmap_busy = false;
		spin_unlock_irq(&ringmap_lock);
		module_put(THIS_MODULE);
		return -ENOMEM;
	}
	m = page_address(ringmap_pages);
	m->magic = SENTINEL_RINGMAP_MAGIC;
	m->capacity = capacity;
	m->mask = capacity - 1;
	m->epoch = ringmap_epoch_counter++;
	m->head = 0;
	m->tail = 0;
	m->drop_count = 0;
	/* Publish before any mmap() can map the pages and poll() can run. */
	smp_store_release(&ringmap_meta, m);
	file->private_data = m;
	return 0;

out_unlock:
	spin_unlock_irq(&ringmap_lock);
	module_put(THIS_MODULE);
	return ret;
}

static int ringmap_release(struct inode *inode, struct file *file)
{
	struct sentinel_ringmap_meta *m = file->private_data;

	if (m && ringmap_meta == m) {
		WRITE_ONCE(ringmap_meta, NULL);
		__free_pages(ringmap_pages, get_order(PAGE_SIZE + m->capacity));
		ringmap_pages = NULL;
	}
	spin_lock_irq(&ringmap_lock);
	ringmap_busy = false;
	spin_unlock_irq(&ringmap_lock);
	module_put(THIS_MODULE);
	return 0;
}

static __poll_t ringmap_poll(struct file *file, poll_table *wait)
{
	struct sentinel_ringmap_meta *m = ringmap_meta;
	__poll_t mask = 0;

	poll_wait(file, &ringmap_waitq, wait);
	/* head is only advanced under ringmap_lock, but poll must still see
	 * the latest published value without taking that lock; the acquire
	 * load pairs with the release store in the producer.
	 */
	if (m && smp_load_acquire(&m->head) != READ_ONCE(m->tail))
		mask |= EPOLLIN | EPOLLRDNORM;
	return mask;
}

static int ringmap_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct sentinel_ringmap_meta *m = file->private_data;
	unsigned long size, full_size;

	if (!m)
		return -ENODEV;
	size = vma->vm_end - vma->vm_start;
	full_size = PAGE_SIZE + m->capacity;
	if (vma->vm_pgoff != 0 ||
	    (size != PAGE_SIZE && size != full_size))
		return -EINVAL;
	/* vm_flags became read-mostly with the vm_flags_set() helper (6.3). */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	vm_flags_set(vma, VM_IO | VM_DONTEXPAND | VM_DONTDUMP);
#else
	vma->vm_flags |= VM_IO | VM_DONTEXPAND | VM_DONTDUMP;
#endif
	if (remap_pfn_range(vma, vma->vm_start, page_to_pfn(ringmap_pages),
			    size, vma->vm_page_prot))
		return -EAGAIN;
	return 0;
}

static const struct file_operations ringmap_fops = {
	.owner		= THIS_MODULE,
	.open		= ringmap_open,
	.release	= ringmap_release,
	.poll		= ringmap_poll,
	.mmap		= ringmap_mmap,
	.read		= ringmap_read,
};

static struct miscdevice ringmap_miscdev = {
	.minor		= MISC_DYNAMIC_MINOR,
	.name		= "sentinel_ring",
	.fops		= &ringmap_fops,
	.mode		= 0666,
};

static unsigned int ringmap_size = SENTINEL_RINGMAP_DEFAULT_KIB;
module_param(ringmap_size, uint, 0444);
MODULE_PARM_DESC(ringmap_size, "mmap ring data capacity in KiB (power of two)");

int sentinel_ringmap_init(void)
{
	int ret;

	if (!ringmap_kib_valid(ringmap_size)) {
		pr_err("sentinel_km: bad ringmap_size=%u (power of two, %u..%u)\n",
		       ringmap_size, SENTINEL_RINGMAP_MIN_KIB,
		       SENTINEL_RINGMAP_MAX_KIB);
		return -EINVAL;
	}
	ringmap_capacity = ringmap_size * 1024;

	ret = misc_register(&ringmap_miscdev);
	if (ret) {
		pr_err("sentinel_km: ringmap misc register failed (%d)\n", ret);
		return ret;
	}

	ret = ringmap_copy_selftest();
	if (ret) {
		pr_err("sentinel_km: ringmap_copy selftest failed (%d); refusing to load\n",
		       ret);
		misc_deregister(&ringmap_miscdev);
	}
	return ret;
}

void sentinel_ringmap_exit(void)
{
	misc_deregister(&ringmap_miscdev);
}
