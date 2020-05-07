/*
 * Copyright (C) 2017 Google, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/device-mapper.h>
#include <linux/module.h>
#include <linux/pfk.h>
#ifdef CONFIG_DM_PERUSER_KEY
	#include <linux/fs.h>
	#include <linux/fscrypt.h>
#endif

#define DM_MSG_PREFIX "default-key"

#ifdef CONFIG_DM_PERUSER_KEY
#define UNKNOWN_USER (-1)
struct user_key{
	int32_t user_id;
	uint8_t me_key_ref[FS_KEY_DESCRIPTOR_SIZE];
	struct blk_encryption_key me_key;
	uint8_t de_key_ref[FS_KEY_DESCRIPTOR_SIZE];
	uint8_t ce_key_ref[FS_KEY_DESCRIPTOR_SIZE];
	
};
#endif

struct default_key_c {
	struct dm_dev *dev;
	sector_t start;
	struct blk_encryption_key key;
#ifdef CONFIG_DM_PERUSER_KEY
	#define ANDROID_USERS_LIMIT 16
	struct user_key user_keys[ANDROID_USERS_LIMIT];
#endif
};

static void default_key_dtr(struct dm_target *ti)
{
	struct default_key_c *dkc = ti->private;

	if (dkc->dev)
		dm_put_device(ti, dkc->dev);
	kzfree(dkc);
}

/*
 * Construct a default-key mapping: <mode> <key> <dev_path> <start>
 */
static int default_key_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct default_key_c *dkc;
	size_t key_size;
	unsigned long long tmp;
	char dummy;
	int err;
#ifdef CONFIG_DM_PERUSER_KEY
	uint8_t i;
#endif

	if (argc != 4) {
		ti->error = "Invalid argument count";
		return -EINVAL;
	}

	dkc = kzalloc(sizeof(*dkc), GFP_KERNEL);
	if (!dkc) {
		ti->error = "Out of memory";
		return -ENOMEM;
	}
	ti->private = dkc;

	if (strcmp(argv[0], "AES-256-XTS") != 0) {
		ti->error = "Unsupported encryption mode";
		err = -EINVAL;
		goto bad;
	}

	key_size = strlen(argv[1]);
	if (key_size != 2 * BLK_ENCRYPTION_KEY_SIZE_AES_256_XTS) {
		ti->error = "Unsupported key size";
		err = -EINVAL;
		goto bad;
	}
	key_size /= 2;

	if (hex2bin(dkc->key.raw, argv[1], key_size) != 0) {
		ti->error = "Malformed key string";
		err = -EINVAL;
		goto bad;
	}

	err = dm_get_device(ti, argv[2], dm_table_get_mode(ti->table),
			    &dkc->dev);
	if (err) {
		ti->error = "Device lookup failed";
		goto bad;
	}

	if (sscanf(argv[3], "%llu%c", &tmp, &dummy) != 1) {
		ti->error = "Invalid start sector";
		err = -EINVAL;
		goto bad;
	}
	dkc->start = tmp;

	if (!blk_queue_inlinecrypt(bdev_get_queue(dkc->dev->bdev))) {
		ti->error = "Device does not support inline encryption";
		err = -EINVAL;
		goto bad;
	}

	/* Pass flush requests through to the underlying device. */
	ti->num_flush_bios = 1;

	/*
	 * We pass discard requests through to the underlying device, although
	 * the discarded blocks will be zeroed, which leaks information about
	 * unused blocks.  It's also impossible for dm-default-key to know not
	 * to decrypt discarded blocks, so they will not be read back as zeroes
	 * and we must set discard_zeroes_data_unsupported.
	 */
	ti->num_discard_bios = 1;
	ti->discard_zeroes_data_unsupported = true;

	/*
	 * It's unclear whether WRITE_SAME would work with inline encryption; it
	 * would depend on whether the hardware duplicates the data before or
	 * after encryption.  But since the internal storage in "muskie" devices
	 * (MSM8998-based) doesn't claim to support WRITE_SAME anyway, we don't
	 * currently have a way to test it.  Leave it disabled it for now.
	 */
	/*ti->num_write_same_bios = 1;*/

#ifdef CONFIG_DM_PERUSER_KEY
	for (i = 0; i < ANDROID_USERS_LIMIT; i++){
		dkc->user_keys[i].user_id = UNKNOWN_USER;
	}
#endif

	return 0;

bad:
	default_key_dtr(ti);
	return err;
}

#ifdef CONFIG_DM_PERUSER_KEY
static struct inode *dm_bio_get_inode(const struct bio *bio)
{
	if (!bio)
		return NULL;
	if (!bio_has_data((struct bio *)bio))
		return NULL;
	if (!bio->bi_io_vec)
		return NULL;
	if (!bio->bi_io_vec->bv_page)
		return NULL;

	if (PageAnon(bio->bi_io_vec->bv_page)) {
		struct inode *inode;

		// Using direct-io (O_DIRECT) without page cache
		inode = dio_bio_get_inode((struct bio *)bio);

		return inode;
	}

	if (!page_mapping(bio->bi_io_vec->bv_page))
		return NULL;

	return page_mapping(bio->bi_io_vec->bv_page)->host;
}

static int dm_get_key(const struct default_key_c *dkc, struct bio *bio,
						const struct blk_encryption_key **me_key)
{
	struct inode *inode;
	int i;
	const struct blk_encryption_key *key = NULL;
	uint8_t *key_ref = NULL;

	if (!bio)
		return -EINVAL;
	if (!bio_has_data((struct bio *)bio))
		return -EINVAL;
	inode = dm_bio_get_inode(bio);
	if (!inode){
		return -EINVAL;
	}
	if (!IS_ENCRYPTED(inode)){
		return -EINVAL;
	}
	// check key descriptor is not empty
	for (i = 0; i < FS_KEY_DESCRIPTOR_SIZE; i++){
		if (inode->i_key_desc[i] != 0){
			key_ref = inode->i_key_desc;
			break;
		}
	}
	if (!key_ref){
		return -EINVAL;
	}
	// search for user key
	for (i = 0; i < ANDROID_USERS_LIMIT; i++){
		if (!memcmp(key_ref, dkc->user_keys[i].de_key_ref, FS_KEY_DESCRIPTOR_SIZE)
		  || !memcmp(key_ref, dkc->user_keys[i].ce_key_ref, FS_KEY_DESCRIPTOR_SIZE)){
			key = &dkc->user_keys[i].me_key;
			*me_key = key;
			break;
		}
	}
	if (!key){
		return -EINVAL;
	}
	return 0;
}
#endif

static int default_key_map(struct dm_target *ti, struct bio *bio)
{
	const struct default_key_c *dkc = ti->private;
#ifdef CONFIG_DM_PERUSER_KEY
	const struct blk_encryption_key *key = NULL;
#endif

	bio->bi_bdev = dkc->dev->bdev;
	if (bio_sectors(bio)) {
		bio->bi_iter.bi_sector = dkc->start +
			dm_target_offset(ti, bio->bi_iter.bi_sector);
	}
	if (!bio->bi_crypt_key && !bio->bi_crypt_skip){
		#ifdef CONFIG_DM_PERUSER_KEY
			// use me key if valid
			if (!dm_get_key(dkc, bio, &key)){
				bio->bi_crypt_key = key;
			} else {
				bio->bi_crypt_key = &dkc->key;
			}
		#else
			bio->bi_crypt_key = &dkc->key;
		#endif
	}

	return DM_MAPIO_REMAPPED;
}

static int default_key_message(struct dm_target *ti, unsigned argc, char **argv)
{
#ifdef CONFIG_DM_PERUSER_KEY
	struct default_key_c *dkc = ti->private;
	uint8_t i;
	uint16_t me_num;
	int8_t err;

	if (!argc){
		return -ENODATA;
	}
#define TOKENS_IN_MESSAGE 5 //4 keys + 1 user_id
	// Parse message with keys info from vold
	sscanf(argv[0], "%d", &me_num);
	if (argc != (1 + me_num*TOKENS_IN_MESSAGE)){
		DMERR("Failed to read keys: %d", argc);
		return -ENODATA;
	}
	if (me_num > ANDROID_USERS_LIMIT) me_num = ANDROID_USERS_LIMIT;
	for (i = 0 ; i < me_num ; i++){
		err = true;
		if (sscanf(argv[i*TOKENS_IN_MESSAGE+1], "%d", &dkc->user_keys[i].user_id) == 1){
			if (hex2bin(dkc->user_keys[i].me_key_ref, argv[i*TOKENS_IN_MESSAGE+2],
					FS_KEY_DESCRIPTOR_SIZE) == 0) {
				err = false;
			}
			if (hex2bin(dkc->user_keys[i].me_key.raw, argv[i*TOKENS_IN_MESSAGE+3],
					BLK_ENCRYPTION_KEY_SIZE_AES_256_XTS) == 0) {
				err = false;
			}
			if (hex2bin(dkc->user_keys[i].de_key_ref, argv[i*TOKENS_IN_MESSAGE+4],
					FS_KEY_DESCRIPTOR_SIZE) == 0) {
				err = false;
			}
			if (hex2bin(dkc->user_keys[i].ce_key_ref, argv[i*TOKENS_IN_MESSAGE+5],
					FS_KEY_DESCRIPTOR_SIZE) == 0) {
				err = false;
			}
		}
		if (err){
			dkc->user_keys[i].user_id = UNKNOWN_USER;
			DMERR("Failed to parse keys: %s", argv[i*TOKENS_IN_MESSAGE+1]);
		}
	}
#endif
	return 0;
}

static void default_key_status(struct dm_target *ti, status_type_t type,
			       unsigned int status_flags, char *result,
			       unsigned int maxlen)
{
	const struct default_key_c *dkc = ti->private;
	unsigned int sz = 0;

	switch (type) {
	case STATUSTYPE_INFO:
		result[0] = '\0';
		break;

	case STATUSTYPE_TABLE:

		/* encryption mode */
		DMEMIT("AES-256-XTS");

		/* reserved for key; dm-crypt shows it, but we don't for now */
		DMEMIT(" -");

		/* name of underlying device, and the start sector in it */
		DMEMIT(" %s %llu", dkc->dev->name,
		       (unsigned long long)dkc->start);
		break;
	}
}

static int default_key_prepare_ioctl(struct dm_target *ti,
				     struct block_device **bdev, fmode_t *mode)
{
	struct default_key_c *dkc = ti->private;
	struct dm_dev *dev = dkc->dev;

	*bdev = dev->bdev;

	/*
	 * Only pass ioctls through if the device sizes match exactly.
	 */
	if (dkc->start ||
	    ti->len != i_size_read(dev->bdev->bd_inode) >> SECTOR_SHIFT)
		return 1;
	return 0;
}

static int default_key_iterate_devices(struct dm_target *ti,
				       iterate_devices_callout_fn fn,
				       void *data)
{
	struct default_key_c *dkc = ti->private;

	return fn(ti, dkc->dev, dkc->start, ti->len, data);
}

static struct target_type default_key_target = {
	.name   = "default-key",
	.version = {1, 0, 0},
	.module = THIS_MODULE,
	.ctr    = default_key_ctr,
	.dtr    = default_key_dtr,
	.map    = default_key_map,
	.message = default_key_message,
	.status = default_key_status,
	.prepare_ioctl = default_key_prepare_ioctl,
	.iterate_devices = default_key_iterate_devices,
};

static int __init dm_default_key_init(void)
{
	return dm_register_target(&default_key_target);
}

static void __exit dm_default_key_exit(void)
{
	dm_unregister_target(&default_key_target);
}

module_init(dm_default_key_init);
module_exit(dm_default_key_exit);

MODULE_AUTHOR("Paul Lawrence <paullawrence@google.com>");
MODULE_AUTHOR("Paul Crowley <paulcrowley@google.com>");
MODULE_AUTHOR("Eric Biggers <ebiggers@google.com>");
MODULE_DESCRIPTION(DM_NAME " target for encrypting filesystem metadata");
MODULE_LICENSE("GPL");
