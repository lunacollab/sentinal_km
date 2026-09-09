// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
/*
 * sentinel_crc.c -- CRC-32C (Castagnoli) reference, shared verbatim by the
 *                   kernel module and the userspace daemon.
 *
 * This is the byte-exact implementation the daemon's differential unit tests
 * pin down (see tests/unit/crc_test.c). The daemon always runs this table
 * path; on x86_64 with SSE4.2 the kernel streams through the asm primitive
 * (arch/x86_64/sentinel_crc32c.S) behind a static key, and the two are
 * proven equal at module init and again in userspace by
 * tests/unit/crc_asm_test.c.
 *
 * The inner step is the classic crc32c loop: xor one input byte into the low
 * byte of the accumulator, shift right 8, and fold through the reflected
 * lookup table. The 256-entry table is generated and transcribed as a
 * compile-time constant (the generator is a throwaway, not shipped), so the
 * hot path has no init work and the module / daemon threads share no mutable
 * state.
 */
#include "sentinel_crc.h"
#include "sentinel_proto.h"

#if defined(__KERNEL__) && defined(CONFIG_X86_64)
#include <linux/jump_label.h>
#include <linux/printk.h>
#include <asm/cpufeature.h>
#include <asm/cpufeatures.h>

/* The SSE4.2 feature bit has two spellings across kernel releases. */
#if defined(X86_FEATURE_SSE4_2)
#define SENTINEL_CRC32C_FEATURE	X86_FEATURE_SSE4_2
#elif defined(X86_FEATURE_XMM4_2)
#define SENTINEL_CRC32C_FEATURE	X86_FEATURE_XMM4_2
#endif

DEFINE_STATIC_KEY_FALSE(sentinel_crc_fast_key);

static bool sentinel_crc32c_isa_ok(void)
{
#if defined(SENTINEL_CRC32C_FEATURE)
	return boot_cpu_has(SENTINEL_CRC32C_FEATURE);
#else
	return false;
#endif
}
#endif

static const __u32 crc32c_table[256] = {
	0x00000000U, 0xf26b8303U, 0xe13b70f7U, 0x1350f3f4U,
	0xc79a971fU, 0x35f1141cU, 0x26a1e7e8U, 0xd4ca64ebU,
	0x8ad958cfU, 0x78b2dbccU, 0x6be22838U, 0x9989ab3bU,
	0x4d43cfd0U, 0xbf284cd3U, 0xac78bf27U, 0x5e133c24U,
	0x105ec76fU, 0xe235446cU, 0xf165b798U, 0x030e349bU,
	0xd7c45070U, 0x25afd373U, 0x36ff2087U, 0xc494a384U,
	0x9a879fa0U, 0x68ec1ca3U, 0x7bbcef57U, 0x89d76c54U,
	0x5d1d08bfU, 0xaf768bbcU, 0xbc267848U, 0x4e4dfb4bU,
	0x20bd8edeU, 0xd2d60dddU, 0xc186fe29U, 0x33ed7d2aU,
	0xe72719c1U, 0x154c9ac2U, 0x061c6936U, 0xf477ea35U,
	0xaa64d611U, 0x580f5512U, 0x4b5fa6e6U, 0xb93425e5U,
	0x6dfe410eU, 0x9f95c20dU, 0x8cc531f9U, 0x7eaeb2faU,
	0x30e349b1U, 0xc288cab2U, 0xd1d83946U, 0x23b3ba45U,
	0xf779deaeU, 0x05125dadU, 0x1642ae59U, 0xe4292d5aU,
	0xba3a117eU, 0x4851927dU, 0x5b016189U, 0xa96ae28aU,
	0x7da08661U, 0x8fcb0562U, 0x9c9bf696U, 0x6ef07595U,
	0x417b1dbcU, 0xb3109ebfU, 0xa0406d4bU, 0x522bee48U,
	0x86e18aa3U, 0x748a09a0U, 0x67dafa54U, 0x95b17957U,
	0xcba24573U, 0x39c9c670U, 0x2a993584U, 0xd8f2b687U,
	0x0c38d26cU, 0xfe53516fU, 0xed03a29bU, 0x1f682198U,
	0x5125dad3U, 0xa34e59d0U, 0xb01eaa24U, 0x42752927U,
	0x96bf4dccU, 0x64d4cecfU, 0x77843d3bU, 0x85efbe38U,
	0xdbfc821cU, 0x2997011fU, 0x3ac7f2ebU, 0xc8ac71e8U,
	0x1c661503U, 0xee0d9600U, 0xfd5d65f4U, 0x0f36e6f7U,
	0x61c69362U, 0x93ad1061U, 0x80fde395U, 0x72966096U,
	0xa65c047dU, 0x5437877eU, 0x4767748aU, 0xb50cf789U,
	0xeb1fcbadU, 0x197448aeU, 0x0a24bb5aU, 0xf84f3859U,
	0x2c855cb2U, 0xdeeedfb1U, 0xcdbe2c45U, 0x3fd5af46U,
	0x7198540dU, 0x83f3d70eU, 0x90a324faU, 0x62c8a7f9U,
	0xb602c312U, 0x44694011U, 0x5739b3e5U, 0xa55230e6U,
	0xfb410cc2U, 0x092a8fc1U, 0x1a7a7c35U, 0xe811ff36U,
	0x3cdb9bddU, 0xceb018deU, 0xdde0eb2aU, 0x2f8b6829U,
	0x82f63b78U, 0x709db87bU, 0x63cd4b8fU, 0x91a6c88cU,
	0x456cac67U, 0xb7072f64U, 0xa457dc90U, 0x563c5f93U,
	0x082f63b7U, 0xfa44e0b4U, 0xe9141340U, 0x1b7f9043U,
	0xcfb5f4a8U, 0x3dde77abU, 0x2e8e845fU, 0xdce5075cU,
	0x92a8fc17U, 0x60c37f14U, 0x73938ce0U, 0x81f80fe3U,
	0x55326b08U, 0xa759e80bU, 0xb4091bffU, 0x466298fcU,
	0x1871a4d8U, 0xea1a27dbU, 0xf94ad42fU, 0x0b21572cU,
	0xdfeb33c7U, 0x2d80b0c4U, 0x3ed04330U, 0xccbbc033U,
	0xa24bb5a6U, 0x502036a5U, 0x4370c551U, 0xb11b4652U,
	0x65d122b9U, 0x97baa1baU, 0x84ea524eU, 0x7681d14dU,
	0x2892ed69U, 0xdaf96e6aU, 0xc9a99d9eU, 0x3bc21e9dU,
	0xef087a76U, 0x1d63f975U, 0x0e330a81U, 0xfc588982U,
	0xb21572c9U, 0x407ef1caU, 0x532e023eU, 0xa145813dU,
	0x758fe5d6U, 0x87e466d5U, 0x94b49521U, 0x66df1622U,
	0x38cc2a06U, 0xcaa7a905U, 0xd9f75af1U, 0x2b9cd9f2U,
	0xff56bd19U, 0x0d3d3e1aU, 0x1e6dcdeeU, 0xec064eedU,
	0xc38d26c4U, 0x31e6a5c7U, 0x22b65633U, 0xd0ddd530U,
	0x0417b1dbU, 0xf67c32d8U, 0xe52cc12cU, 0x1747422fU,
	0x49547e0bU, 0xbb3ffd08U, 0xa86f0efcU, 0x5a048dffU,
	0x8ecee914U, 0x7ca56a17U, 0x6ff599e3U, 0x9d9e1ae0U,
	0xd3d3e1abU, 0x21b862a8U, 0x32e8915cU, 0xc083125fU,
	0x144976b4U, 0xe622f5b7U, 0xf5720643U, 0x07198540U,
	0x590ab964U, 0xab613a67U, 0xb831c993U, 0x4a5a4a90U,
	0x9e902e7bU, 0x6cfbad78U, 0x7fab5e8cU, 0x8dc0dd8fU,
	0xe330a81aU, 0x115b2b19U, 0x020bd8edU, 0xf0605beeU,
	0x24aa3f05U, 0xd6c1bc06U, 0xc5914ff2U, 0x37faccf1U,
	0x69e9f0d5U, 0x9b8273d6U, 0x88d28022U, 0x7ab90321U,
	0xae7367caU, 0x5c18e4c9U, 0x4f48173dU, 0xbd23943eU,
	0xf36e6f75U, 0x0105ec76U, 0x12551f82U, 0xe03e9c81U,
	0x34f4f86aU, 0xc69f7b69U, 0xd5cf889dU, 0x27a40b9eU,
	0x79b737baU, 0x8bdcb4b9U, 0x988c474dU, 0x6ae7c44eU,
	0xbe2da0a5U, 0x4c4623a6U, 0x5f16d052U, 0xad7d5351U,
};

static __u32 crc32c_stream(__u32 crc, const __u8 *p, unsigned long len)
{
#if defined(__KERNEL__) && defined(CONFIG_X86_64)
	if (static_branch_likely(&sentinel_crc_fast_key))
		return sentinel_crc32c_seed(crc, p, len);
#endif
	while (len--)
		crc = (crc >> 8) ^ crc32c_table[(crc ^ *p++) & 0xff];
	return crc;
}

__u32 sentinel_crc32c(void const *data, unsigned long len)
{
	return crc32c_stream(0xffffffffU, data, len) ^ 0xffffffffU;
}

__u32 sentinel_crc_payload(void const *crc_hdr, void const *payload,
			   unsigned long payload_len)
{
	const __u8 *h = crc_hdr;
	__u32 crc;

	/* Feed the 48 header bytes before crc32, then the payload, in one
	 * running fold -- exactly the window the producer signed.
	 */
	crc = crc32c_stream(0xffffffffU, h, SENTINEL_EVENT_HDR_CRC_OFF);
	if (payload_len)
		crc = crc32c_stream(crc, payload, payload_len);
	return crc ^ 0xffffffffU;
}

#if defined(__KERNEL__) && defined(CONFIG_X86_64)
int sentinel_crc_init(void)
{
	if (sentinel_crc32c_isa_ok()) {
		static_branch_enable(&sentinel_crc_fast_key);
		pr_info("sentinel_km: crc32c via SSE4.2 hardware path\n");
	}
	return 0;
}

/* Differential battery: the asm seed fold vs the table reference over every
 * length 0..sizeof(buf), plus chained windows. A mismatch must refuse the
 * module load -- the daemon verifies exactly the same stream the producer
 * signs, so producer and consumer can never drift.
 */
int sentinel_crc_selftest(void)
{
	u8 buf[512];
	__u32 seed, once, chained;
	int rc = 0;
	size_t i, n;

	if (!sentinel_crc32c_isa_ok())
		return 0;

	for (i = 0; i < sizeof(buf); i++)
		buf[i] = (__u8)(i * 37 + 11);

	for (n = 0; n <= sizeof(buf) && !rc; n++) {
		once = sentinel_crc32c(buf, n);
		if ((sentinel_crc32c_seed(0xffffffffU, buf, n) ^
		     0xffffffffU) != once) {
			pr_err("sentinel_km: crc32c mismatch len=%zu\n", n);
			rc = -EINVAL;
		}
	}

	/* A split window seeded across the fold boundary must equal a single
	 * pass -- the exact composition sentinel_crc_payload() relies on.
	 */
	if (!rc) {
		for (n = 1; n < sizeof(buf) / 2 && !rc; n++) {
			seed = sentinel_crc32c_seed(0xffffffffU, buf, n);
			chained = sentinel_crc32c_seed(seed, buf + n,
						       sizeof(buf) - n);
			if ((chained ^ 0xffffffffU) !=
			    sentinel_crc32c(buf, sizeof(buf))) {
				pr_err("sentinel_km: crc32c chain mismatch len=%zu\n",
				       n);
				rc = -EINVAL;
			}
		}
	}

	if (rc)
		pr_err("sentinel_km: crc32c differential test failed\n");
	return rc;
}
#else
int sentinel_crc_init(void)
{
	return 0;
}

int sentinel_crc_selftest(void)
{
	return 0;
}
#endif
