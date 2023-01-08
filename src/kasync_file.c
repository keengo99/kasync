#include "kasync_file.h"
#include "kfile.h"
#include "klog.h"
#include "katom.h"
#include "kmalloc.h"
#ifdef LINUX
#include <mntent.h>
#include <sys/ioctl.h>  
#include <linux/fs.h> 
#endif

void init_aio_align_size()
{
	kgl_aio_align_size = 512;
#ifdef LINUX
#ifdef ANDROID
		//android
#else
	FILE *mntfile = setmntent("/proc/mounts", "r");
	if (mntfile == NULL) {
		kgl_aio_align_size = 4096;
		klog(KLOG_ERR, "open /proc/mounts file failed. now set kgl_aio_align_size=[%d]\n", kgl_aio_align_size);
		return;
	}
	struct mntent *mntent;
	while (NULL != (mntent = getmntent(mntfile))) {
		int fd = open(mntent->mnt_fsname, O_RDONLY);
		if (fd < 0) {
			continue;
		}
		int lbs = 0;
		if (0 == ioctl(fd, BLKSSZGET, &lbs)) {
			if (lbs > kgl_aio_align_size) {
				kgl_aio_align_size = lbs;
			}
		}
		close(fd);
	}
	endmntent(mntfile);
#endif
#endif
	klog(KLOG_ERR, "kgl_aio_align_size=[%d]\n", kgl_aio_align_size);
}
void *aio_alloc_buffer(size_t size)
{
#ifdef _WIN32
	return xmalloc(size);
#else
	size = kgl_align(size, kgl_aio_align_size);
	return kgl_memalign(kgl_aio_align_size, size);
#endif
}
void aio_free_buffer(void *buf)
{
#ifdef _WIN32
	xfree(buf);
#else
	kgl_align_free(buf);
#endif
}
